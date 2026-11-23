//! Vigie: router status and a light view of the network, on http://<router>:8080.
//!
//! Sources (nothing is copied to disk except two small state files):
//! - /sys/class/net: instantaneous rate per interface; vnstat: WAN history
//! - /proc/net/nf_conntrack: rate per device and connections to IPs never resolved by DNS
//! - dnsmasq query log (/run, in memory): who asks for what, blocked and new domains
//! - dnsmasq DHCP leases: devices, and an alert on new ones
//!
//! The DNS log is only kept as 24 h aggregates, in memory.
//! IPv6: flows and queries are attributed to the device of the same MAC (neighbour table -> MAC -> IPv4 lease/ARP),
//! an address with no known MAC is shown as is.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::hash::Hash;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WINDOW: f64 = 24.0 * 3600.0;
const MAX_SEEN_DOMAINS: usize = 20_000;
const EMBEDDED_PAGE: &str = include_str!("../index.html");

struct Config {
    wan: String,
    listen: String,
    lists: String,
    state_dir: String,
    dns_log: String,
    leases: String,
    page: Option<String>,
    local_nets: Vec<(u32, u32)>,   // (network, mask)
    local_nets6: Vec<(u128, u128)>, // same, IPv6
    dhcp: Vec<(String, u32, u32)>, // (name, start, end)
    probes: Vec<String>,
    services: Vec<String>,
    known: Vec<String>,            // "expected" domain suffixes, kept apart from the ranking
    names: HashMap<String, String>, // ip -> name, fallback when the DHCP lease has none
}

/// Common time domains: the only "expected" traffic known by default.
const NTP: &str = "pool.ntp.org time.cloudflare.com time.google.com time.apple.com time.windows.com time.nist.gov ntp.ubuntu.com";

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn nets() -> Vec<String> {
    env("VIGIE_NETWORKS", "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10 fc00::/7").split_whitespace().map(String::from).collect()
}

fn cfg() -> &'static Config {
    static CFG: OnceLock<Config> = OnceLock::new();
    CFG.get_or_init(|| Config {
        wan: env("VIGIE_WAN", "enp1s0"),
        listen: env("VIGIE_LISTEN", "0.0.0.0:8080"),
        lists: env("VIGIE_LISTS", "/var/lib/listes"),
        state_dir: env("STATE_DIRECTORY", "/var/lib/vigie"),
        dns_log: env("VIGIE_DNS_LOG", "/run/dnsmasq/requetes.log"),
        leases: env("VIGIE_LEASES", "/var/lib/dnsmasq/dnsmasq.leases"),
        page: std::env::var("VIGIE_PAGE").ok(),
        local_nets: nets().iter().filter(|n| !n.contains(':'))
            .map(|n| cidr(n).unwrap_or_else(|| panic!("invalid VIGIE_NETWORKS entry: {n}")))
            .collect(),
        local_nets6: nets().iter().filter(|n| n.contains(':'))
            .map(|n| cidr6(n).unwrap_or_else(|| panic!("invalid VIGIE_NETWORKS entry: {n}")))
            .collect(),
        dhcp: env("VIGIE_DHCP", "").split_whitespace().map(|p| parse_range(p).unwrap_or_else(|| panic!("invalid VIGIE_DHCP entry: {p}"))).collect(),
        probes: env("VIGIE_PROBES", "1.1.1.1").split_whitespace().map(String::from).collect(),
        services: env("VIGIE_SERVICES", "dnsmasq unbound nftables").split_whitespace().map(String::from).collect(),
        known: env("VIGIE_KNOWN_DOMAINS", NTP).split_whitespace().map(|d| d.trim_matches('.').to_lowercase()).collect(),
        names: parse_names(&env("VIGIE_NAMES", "")),
    })
}

/// `ip=name ip=name` -> ip -> name table (malformed entries ignored).
fn parse_names(s: &str) -> HashMap<String, String> {
    s.split_whitespace()
        .filter_map(|p| p.split_once('='))
        .filter(|(_, name)| !name.is_empty())
        .filter_map(|(ip, name)| Some((ip.parse::<IpAddr>().ok()?.to_string(), name.into())))
        .collect()
}

/// `d` is one of the suffixes or a subdomain of one (`a.pool.ntp.org` for `pool.ntp.org`).
fn is_known(d: &str, suffixes: &[String]) -> bool {
    let d = d.trim_end_matches('.');
    suffixes.iter().any(|s| d.strip_suffix(s.as_str()).is_some_and(|r| r.is_empty() || r.ends_with('.')))
}

/// Main domain: last two labels, three if the second-to-last is a short suffix (`bbc.co.uk`).
/// shortcut: heuristic without the Public Suffix List (misses github.io, blogspot...), to replace if the grouping gets in the way.
fn main_domain(d: &str) -> &str {
    let d = d.trim_end_matches('.');
    let l: Vec<&str> = d.split('.').collect();
    if l.len() <= 2 {
        return d;
    }
    const SHORT: [&str; 11] = ["co", "com", "net", "org", "gov", "gouv", "ac", "edu", "ne", "or", "go"];
    let n = if l[l.len() - 1].len() == 2 && SHORT.contains(&l[l.len() - 2]) { 3 } else { 2 };
    let keep: usize = l[l.len() - n..].iter().map(|x| x.len() + 1).sum::<usize>() - 1;
    &d[d.len() - keep..]
}

/// "Plumbing" traffic (reverse DNS, mDNS, WPAD, short names...): counted but never ranked nor flagged as new.
fn is_technical(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    let ends = |suf: &str| d.len() >= suf.len() && d[d.len() - suf.len()..].eq_ignore_ascii_case(suf);
    d.is_empty() || !d.contains('.') || ends(".arpa") || ends(".local")
        || d.split('.').any(|l| l.starts_with('_')) || d.split('.').next().is_some_and(|l| l.eq_ignore_ascii_case("wpad"))
}

/// A device is "new" if it appeared after vigie's first hour (otherwise everything is new on first start) and less than 7 days ago.
fn is_new(first_seen: f64, oldest: f64, t: f64) -> bool {
    first_seen > oldest + 3600.0 && t - first_seen < 7.0 * 86400.0
}

/// Address of the router itself (loopback or one of its interfaces).
fn is_router(ip: &str, own: &[(String, u32, u32, String)], own6: &[(String, u128, u128, String)]) -> bool {
    ip.parse::<IpAddr>().is_ok_and(|a| a.is_loopback()) || own.iter().any(|p| p.3 == ip) || own6.iter().any(|p| p.3 == ip)
}

/// Above `max` entries, drops the oldest half.
fn cap_map<K>(m: &mut HashMap<K, f64>, max: usize) {
    if m.len() > max {
        let mut ts: Vec<f64> = m.values().copied().collect();
        let mid = ts.len() / 2;
        let (_, &mut med, _) = ts.select_nth_unstable_by(mid, f64::total_cmp);
        m.retain(|_, &mut v| v >= med);
    }
}

/// `name,start,end` (name optional) -> DHCP range.
fn parse_range(s: &str) -> Option<(String, u32, u32)> {
    let mut p = s.split(',');
    let (name, start, end) = (p.next()?, ip_u32(p.next()?)?, ip_u32(p.next()?)?);
    (start <= end).then(|| (name.into(), start, end))
}

// The aliases read the state files written before the English rename.
#[derive(Serialize, Deserialize)]
struct Device {
    #[serde(alias = "premier")]
    first_seen: f64,
    #[serde(default, alias = "nom")]
    name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default, alias = "vu")]
    last_seen: Option<f64>,
}

#[derive(Default)]
struct State {
    queries: VecDeque<(f64, String, String)>,                // (ts, client, domain)
    blocked: VecDeque<(f64, String, String, &'static str)>,  // (ts, client, domain, list)
    ip_to_name: HashMap<String, String>,                     // public IP -> last domain resolved to it
    no_dns: HashMap<(String, String), f64>,                  // (client, ip) -> last ts
    if_rates: BTreeMap<String, (f64, f64)>,                  // interface -> (rx B/s, tx B/s)
    device_rates: HashMap<String, f64>,                      // ip -> B/s
    seen_domains: HashMap<String, f64>,                      // domain -> first ts
    devices: HashMap<String, Device>,                        // mac -> device
    latencies: Vec<(String, String, Option<f64>)>,           // (name, target, ms)
    services: Vec<(String, String)>,                         // (unit, is-active)
    vnstat: Option<Vnstat>,                                  // cache refreshed every minute
    addresses: Vec<(String, u32, u32, String)>,              // `ip addr` cache: (interface, network, mask, address)
    addresses6: Vec<(String, u128, u128, String)>,           // same, global IPv6 addresses
    v6_prefix: Option<String>,                               // delegated prefix (unreachable route), if visible
    v6_mac: HashMap<String, String>,                         // IPv6 neighbour -> MAC, <= MAX_V6 entries
    mac_ip: HashMap<String, String>,                         // MAC -> IPv4 (DHCP leases, else ARP)
    ring_5s: VecDeque<(f32, f32)>,                           // WAN rate (rx, tx) every 5 s, <= 720 points (1 h)
    ring_min: VecDeque<(f32, f32)>,                          // per-minute average, <= 1440 points (24 h)
    lat_hist: Vec<(String, String, VecDeque<Option<f32>>)>,  // (name, target, ms) every 30 s, <= 8 probes x 120 points (1 h)
}

const PTS_5S: usize = 720;
const PTS_MIN: usize = 1440;
const PTS_LAT: usize = 120;
const MAX_PROBES: usize = 8;
const MAX_V6: usize = 8192;

fn push_capped<T>(q: &mut VecDeque<T>, v: T, max: usize) {
    q.push_back(v);
    while q.len() > max {
        q.pop_front();
    }
}

fn average(v: &[(f32, f32)]) -> (f32, f32) {
    let n = v.len().max(1) as f32;
    v.iter().fold((0.0, 0.0), |a, p| (a.0 + p.0 / n, a.1 + p.1 / n))
}

/// Hour bucket (0 = oldest, 23 = the hour that just elapsed) of an event at time `ts`.
fn hour_bucket(t: f64, ts: f64) -> Option<usize> {
    let age = ((t - ts) / 3600.0).floor();
    (0.0..24.0).contains(&age).then(|| 23 - age as usize)
}

/// vnstat totals for the WAN: (rx, tx) for the day, the month, and the last 30 days (oldest first).
struct Vnstat {
    day: (u64, u64),
    month: (u64, u64),
    days: Vec<(u64, u64)>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Default::default);

fn lock() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

// --- addresses ---
fn cidr(s: &str) -> Option<(u32, u32)> {
    let (a, p) = s.split_once('/')?;
    let p: u32 = p.parse().ok().filter(|&p| p <= 32)?;
    let mask = if p == 0 { 0 } else { !0u32 << (32 - p) };
    Some((u32::from(a.parse::<Ipv4Addr>().ok()?) & mask, mask))
}

fn cidr6(s: &str) -> Option<(u128, u128)> {
    let (a, p) = s.split_once('/')?;
    let p: u32 = p.parse().ok().filter(|&p| p <= 128)?;
    let mask = if p == 0 { 0 } else { !0u128 << (128 - p) };
    Some((u128::from(a.parse::<Ipv6Addr>().ok()?) & mask, mask))
}

/// Normalised text form (IPv6 is compressed differently by dnsmasq, conntrack and `ip`).
fn norm(s: &str) -> String {
    if s.contains(':') { s.parse::<Ipv6Addr>().map_or_else(|_| s.into(), |a| a.to_string()) } else { s.into() }
}

/// Link-local and multicast IPv6: not counted in the traffic stats.
fn v6_ignored(ip: &str) -> bool {
    ip.parse::<Ipv6Addr>().is_ok_and(|a| a.is_multicast() || a.segments()[0] & 0xffc0 == 0xfe80)
}

/// Local IPv4 or IPv6: configured blocks, plus the IPv6 prefixes of the LAN interfaces (`lan6`).
fn is_local_ip(ip: &str, lan6: &[(u128, u128)]) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => is_local(ip),
        Ok(IpAddr::V6(a)) => {
            let a = u128::from(a);
            cfg().local_nets6.iter().chain(lan6).any(|&(n, m)| a & m == n)
        }
        Err(_) => false,
    }
}

fn is_local(ip: &str) -> bool {
    let Ok(a) = ip.parse::<Ipv4Addr>() else { return false };
    let a = u32::from(a);
    cfg().local_nets.iter().any(|&(n, m)| a & m == n)
}

/// Same meaning as Python's `is_global`: outside private, reserved and shared (100.64/10) ranges.
fn is_public(ip: &str) -> bool {
    const NON_GLOBAL: [([u8; 4], u32); 15] = [
        ([0, 0, 0, 0], 8), ([10, 0, 0, 0], 8), ([100, 64, 0, 0], 10), ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16), ([172, 16, 0, 0], 12), ([192, 0, 0, 0], 29), ([192, 0, 0, 170], 31),
        ([192, 0, 2, 0], 24), ([192, 168, 0, 0], 16), ([198, 18, 0, 0], 15), ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24), ([240, 0, 0, 0], 4), ([255, 255, 255, 255], 32),
    ];
    if let Ok(a) = ip.parse::<Ipv6Addr>() {
        // global unicast 2000::/3, minus the documentation prefix 2001:db8::/32
        let x = u128::from(a);
        return x >> 125 == 1 && x >> 96 != 0x2001_0db8;
    }
    let Ok(a) = ip.parse::<Ipv4Addr>() else { return false };
    let a = u32::from(a);
    !NON_GLOBAL.iter().any(|&(r, p)| {
        let m = if p == 0 { 0 } else { !0u32 << (32 - p) };
        a & m == u32::from(Ipv4Addr::from(r))
    })
}

// --- state on disk (kept from one restart to the next) ---
/// Reads `new` from the state dir, or the pre-rename file name `old` if `new` does not exist yet.
fn read_state_file<T: serde::de::DeserializeOwned>(new: &str, old: &str) -> Option<T> {
    let dir = &cfg().state_dir;
    let new_path = format!("{dir}/{new}");
    let path = if Path::new(&new_path).exists() { new_path } else { format!("{dir}/{old}") };
    read_json(&path)
}

fn load_state() {
    let mut e = lock();
    if let Some(d) = read_state_file::<HashMap<String, f64>>("domains.json", "domaines.json") {
        e.seen_domains.extend(d.into_iter().filter(|(k, _)| !is_technical(k)));
        cap_map(&mut e.seen_domains, MAX_SEEN_DOMAINS);
    }
    if let Some(a) = read_state_file::<HashMap<String, Device>>("devices.json", "appareils.json") {
        e.devices.extend(a);
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Option<T> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn save_state() {
    let (domains, devices) = {
        let e = lock();
        (serde_json::to_vec(&e.seen_domains), serde_json::to_vec(&e.devices))
    };
    for (name, data) in [("domains.json", domains), ("devices.json", devices)] {
        let Ok(data) = data else { continue };
        let path = format!("{}/{name}", cfg().state_dir);
        let tmp = format!("{path}.tmp");
        if let Err(err) = fs::write(&tmp, data).and_then(|_| fs::rename(&tmp, &path)) {
            eprintln!("vigie: cannot save {name}: {err}");
        }
    }
}

// --- dnsmasq DNS log (log-queries=extra) ---
enum Event<'a> {
    Query { client: &'a str, domain: &'a str },
    Blocked { client: &'a str, list: &'static str, domain: &'a str },
    Reply { domain: &'a str, ip: &'a str },
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// The device of an address: an IPv6 address becomes the IPv4 of the same MAC when known, else stays itself.
fn device_key(e: &State, ip: &str) -> String {
    if !ip.contains(':') {
        return ip.into();
    }
    let n = norm(ip);
    e.v6_mac.get(&n).and_then(|m| e.mac_ip.get(m)).cloned().unwrap_or(n)
}

/// Lines like `... ]: 123 192.168.1.5/5432 query[A] example.org from 192.168.1.5` (the client may be IPv6, the reply AAAA).
fn parse_dns_log(l: &str) -> Option<Event<'_>> {
    let rest = &l[l.find("]: ")? + 3..];
    let t: Vec<&str> = rest.split_whitespace().collect();
    if t.len() < 5 || !digits(t[0]) {
        return None;
    }
    let (client, port) = t[1].split_once('/')?;
    if !is_ip(client) || !digits(port) {
        return None;
    }
    let kind = t[2];
    if let Some(qtype) = kind.strip_prefix("query[").and_then(|g| g.strip_suffix(']')) {
        let word = !qtype.is_empty() && qtype.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        if word && t[4] == "from" && t.len() > 5 {
            return Some(Event::Query { client, domain: t[3] });
        }
    }
    if t[4] == "is" && t.len() > 5 {
        for list in ["threats", "ads"] {
            if kind.strip_suffix(&format!("/{list}.hosts")).is_some() {
                return Some(Event::Blocked { client, list, domain: t[3] });
            }
        }
    }
    if (kind == "reply" || kind == "cached") && t[4] == "is" && t.len() == 6 && is_ip(t[5]) {
        return Some(Event::Reply { domain: t[3], ip: t[5] });
    }
    None
}

fn read_dns_log(mut position: u64) -> u64 {
    let path = &cfg().dns_log;
    let Ok(size) = fs::metadata(path).map(|m| m.len()) else { return 0 };
    if size < position {
        position = 0;
    }
    let mut raw = Vec::new();
    let read = File::open(path).and_then(|mut f| {
        f.seek(SeekFrom::Start(position))?;
        f.read_to_end(&mut raw)
    });
    if read.is_err() {
        return position;
    }
    position += raw.len() as u64;
    let text = String::from_utf8_lossy(&raw);
    let t = now();
    {
        let mut guard = lock();
        let e = &mut *guard;
        for l in text.lines() {
            match parse_dns_log(l.trim_end()) {
                Some(Event::Query { client, domain }) => {
                    let c = device_key(e, client);
                    e.queries.push_back((t, c, domain.into()));
                    if e.queries.len() > 150_000 {
                        e.queries.pop_front();
                    }
                    if !is_technical(domain) {
                        e.seen_domains.entry(domain.into()).or_insert(t);
                    }
                }
                Some(Event::Blocked { client, list, domain }) => {
                    let c = device_key(e, client);
                    e.blocked.push_back((t, c, domain.into(), list));
                    if e.blocked.len() > 20_000 {
                        e.blocked.pop_front();
                    }
                }
                Some(Event::Reply { domain, ip }) => {
                    e.ip_to_name.insert(norm(ip), domain.into());
                }
                None => {}
            }
        }
        cap_map(&mut e.seen_domains, MAX_SEEN_DOMAINS);
        if e.ip_to_name.len() > 200_000 {
            e.ip_to_name.clear();
        }
    }
    // dnsmasq appends (O_APPEND): the in-memory file is emptied beyond 4 MB
    if position > 4_000_000 {
        let _ = File::create(path);
        position = 0;
    }
    position
}

// --- counters ---
fn read_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn interface_bytes() -> HashMap<String, (u64, u64)> {
    let mut r = HashMap::new();
    let Ok(dir) = fs::read_dir("/sys/class/net") else { return r };
    for i in dir.flatten() {
        let name = i.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        let base = format!("/sys/class/net/{name}/statistics");
        if let (Some(rx), Some(tx)) = (read_u64(&format!("{base}/rx_bytes")), read_u64(&format!("{base}/tx_bytes"))) {
            r.insert(name, (rx, tx));
        }
    }
    r
}

/// Conntrack line: `... src=A dst=B ... bytes=N ... src=B dst=A ... bytes=M ...` -> (A, B, N, M).
fn parse_conntrack(l: &str) -> Option<(&str, &str, u64, u64)> {
    let t: Vec<&str> = l.split_whitespace().collect();
    let pair = |from: usize| (from..t.len().saturating_sub(1)).find(|&i| {
        t[i].strip_prefix("src=").is_some_and(is_ip) && t[i + 1].strip_prefix("dst=").is_some_and(is_ip)
    });
    let bytes = |from: usize| {
        (from..t.len()).find_map(|j| t[j].strip_prefix("bytes=").map(|v| (j, v.parse::<u64>().ok())))
    };
    let i = pair(0)?;
    let (j, b1) = bytes(i + 2)?;
    let k = pair(j + 1)?;
    let (_, b2) = bytes(k + 2)?;
    Some((&t[i][4..], &t[i + 1][4..], b1?, b2?))
}

/// Bytes per local source address (sum of live connections, IPv4 and IPv6) + connections to public IPs.
fn conntrack_bytes(lan6: &[(u128, u128)]) -> (HashMap<String, u64>, Vec<(String, String)>) {
    let (mut per_ip, mut targets) = (HashMap::new(), Vec::new());
    let Ok(f) = File::open("/proc/net/nf_conntrack") else { return (per_ip, targets) };
    let mut f = BufReader::new(f);
    let mut line = Vec::new();
    while f.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
        if let Some((src, dst, b1, b2)) = parse_conntrack(&String::from_utf8_lossy(&line)) {
            if is_local_ip(src, lan6) && !v6_ignored(src) && !v6_ignored(dst) {
                *per_ip.entry(norm(src)).or_insert(0) += b1 + b2;
                if is_public(dst) && !is_local_ip(dst, lan6) {
                    targets.push((norm(src), norm(dst)));
                }
            }
        }
        line.clear();
    }
    (per_ip, targets)
}

/// Main sampling loop, every 5 s.
fn sampler() {
    let mut position = 0;
    let mut prev_if = interface_bytes();
    let mut prev_ct: HashMap<String, u64> = HashMap::new();
    let mut prev_t = now();
    let mut last_save = prev_t;
    let mut step = 0u32;
    loop {
        thread::sleep(Duration::from_secs(5));
        refresh_neighbours();
        position = read_dns_log(position);
        let t = now();
        let dt = (t - prev_t).max(0.001);
        let cur_if = interface_bytes();
        let lan6: Vec<_> = lan_prefixes6(&lock().addresses6, &cfg().wan).iter().map(|a| (a.1, a.2)).collect();
        let (ct_raw, targets) = conntrack_bytes(&lan6);
        let mut ct: HashMap<String, u64> = HashMap::new();
        {
            let mut guard = lock();
            let e = &mut *guard;
            for (ip, b) in ct_raw {
                *ct.entry(device_key(e, &ip)).or_insert(0) += b;
            }
            e.if_rates.clear();
            for (i, &(rx, tx)) in &cur_if {
                if let Some(&(prx, ptx)) = prev_if.get(i) {
                    e.if_rates.insert(i.clone(), (rx.saturating_sub(prx) as f64 / dt, tx.saturating_sub(ptx) as f64 / dt));
                }
            }
            let wan = e.if_rates.get(&cfg().wan).copied().unwrap_or((0.0, 0.0));
            push_capped(&mut e.ring_5s, (wan.0 as f32, wan.1 as f32), PTS_5S);
            step += 1;
            if step % 12 == 0 {
                let last: Vec<_> = e.ring_5s.iter().rev().take(12).copied().collect();
                push_capped(&mut e.ring_min, average(&last), PTS_MIN);
            }
            e.device_rates.clear();
            for (ip, &o) in &ct {
                let d = (o as f64 - prev_ct.get(ip).copied().unwrap_or(0) as f64) / dt;
                if d > 0.0 {
                    e.device_rates.insert(ip.clone(), d);
                }
            }
            for (src, dst) in targets {
                if !e.ip_to_name.contains_key(&dst) {
                    let src = device_key(e, &src);
                    e.no_dns.insert((src, dst), t);
                }
            }
            e.no_dns.retain(|_, &mut v| t - v <= WINDOW);
            cap_map(&mut e.no_dns, 20_000);
            let limit = t - WINDOW;
            while e.queries.front().is_some_and(|r| r.0 < limit) {
                e.queries.pop_front();
            }
            while e.blocked.front().is_some_and(|r| r.0 < limit) {
                e.blocked.pop_front();
            }
        }
        (prev_if, prev_ct, prev_t) = (cur_if, ct, t);
        read_leases();
        if t - last_save > 3600.0 {
            save_state();
            last_save = t;
        }
    }
}

fn read_leases() {
    let Ok(text) = fs::read_to_string(&cfg().leases) else { return };
    let t = now();
    let mut e = lock();
    for l in text.split('\n') {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p.len() >= 4 {
            let a = e.devices.entry(p[1].into()).or_insert(Device { first_seen: t, name: None, ip: None, last_seen: None });
            a.ip = Some(p[2].into());
            a.name = (p[3] != "*").then(|| p[3].into());
            a.last_seen = Some(t);
        }
    }
}

// --- infrastructure view: neighbours, addresses, links, probes ---
fn ip_u32(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// `/proc/net/arp`: complete entries (flag 0x2) -> (ip, mac, interface).
/// shortcut: a complete entry stays for a few minutes after the last activity; use `ip neigh` (REACHABLE) if precision is needed.
fn parse_arp(text: &str) -> Vec<(String, String, String)> {
    text.lines().skip(1).filter_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() >= 6 && p[2] == "0x2" && p[3] != "00:00:00:00:00:00").then(|| (p[0].into(), p[3].to_lowercase(), p[5].into()))
    }).collect()
}

/// `/proc/net/route`: gateway of the default route.
fn parse_route(text: &str) -> Option<String> {
    text.lines().skip(1).find_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() > 2 && p[1] == "00000000" && p[2] != "00000000")
            .then(|| u32::from_str_radix(p[2], 16).ok())
            .flatten()
            .map(|g| Ipv4Addr::from(u32::from_be(g)).to_string())
    })
}

/// Current dnsmasq leases: `expiry mac ip name id` -> (mac, ip).
fn current_leases() -> Vec<(String, String)> {
    fs::read_to_string(&cfg().leases).unwrap_or_default().lines().filter_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() >= 3).then(|| (p[1].to_lowercase(), p[2].into()))
    }).collect()
}

/// `ip -j addr` output -> (interface, address, prefix length, scope).
fn parse_addr_json(raw: &[u8]) -> Vec<(String, String, u64, String)> {
    let v: Value = serde_json::from_slice(raw).unwrap_or(Value::Null);
    let mut r = vec![];
    for i in v.as_array().into_iter().flatten() {
        for a in i["addr_info"].as_array().into_iter().flatten() {
            if let (Some(name), Some(ip), Some(p)) = (i["ifname"].as_str(), a["local"].as_str(), a["prefixlen"].as_u64()) {
                r.push((name.into(), ip.into(), p, a["scope"].as_str().unwrap_or("").into()));
            }
        }
    }
    r
}

fn ip_addr(family: &str) -> Vec<(String, String, u64, String)> {
    Command::new("ip").args(["-j", family, "addr", "show"]).stderr(Stdio::null()).output().map(|o| parse_addr_json(&o.stdout)).unwrap_or_default()
}

/// `ip -j -4 addr` -> (interface, network, mask, address).
fn interface_addresses() -> Vec<(String, u32, u32, String)> {
    ip_addr("-4").into_iter().filter_map(|(name, ip, p, _)| cidr(&format!("{ip}/{p}")).map(|(net, m)| (name, net, m, ip))).collect()
}

/// `ip -j -6 addr`: global addresses -> (interface, network, mask, address).
fn interface_addresses6() -> Vec<(String, u128, u128, String)> {
    ip_addr("-6").into_iter().filter(|a| a.3 == "global")
        .filter_map(|(name, ip, p, _)| cidr6(&format!("{ip}/{p}")).map(|(net, m)| (name, net, m, norm(&ip)))).collect()
}

/// Prefixes of the non-WAN interfaces (one entry per interface and prefix): local by definition, and shown as networks.
/// The delegated prefix changes, so this is read from the interfaces rather than configured.
fn lan_prefixes6(addrs: &[(String, u128, u128, String)], wan: &str) -> Vec<(String, u128, u128, String)> {
    let mut v: Vec<(String, u128, u128, String)> = vec![];
    for a in addrs.iter().filter(|a| a.0 != wan && a.2.count_ones() <= 126) {
        if !v.iter().any(|b| (&b.0, b.1, b.2) == (&a.0, a.1, a.2)) {
            v.push(a.clone());
        }
    }
    v.sort_unstable();
    v
}

/// `ip -6 neigh` -> (address, MAC) of the entries that have a MAC (FAILED/INCOMPLETE ones do not).
fn parse_neigh(text: &str) -> Vec<(String, String)> {
    text.lines().filter_map(|l| {
        let t: Vec<&str> = l.split_whitespace().collect();
        let mac = t.iter().position(|&w| w == "lladdr").and_then(|i| t.get(i + 1))?;
        t.first()?.parse::<Ipv6Addr>().ok().map(|a| (a.to_string(), mac.to_lowercase()))
    }).collect()
}

/// `ip -6 route show type unreachable`: the delegated prefix (a global /48 to /63), when the DHCPv6 client installs it.
fn parse_prefix(text: &str) -> Option<String> {
    text.split_whitespace().find(|w| {
        w.split_once('/').and_then(|(a, p)| Some((a.parse::<Ipv6Addr>().ok()?, p.parse::<u8>().ok()?)))
            .is_some_and(|(a, p)| (48..=63).contains(&p) && is_public(&a.to_string()))
    }).map(String::from)
}

/// Every cycle: IPv6 neighbour -> MAC cache, and MAC -> IPv4 (leases, else ARP). Costs one `ip` call.
fn refresh_neighbours() {
    let out = Command::new("ip").args(["-6", "neigh", "show"]).stderr(Stdio::null()).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let mut mac_ip: HashMap<String, String> = parse_arp(&fs::read_to_string("/proc/net/arp").unwrap_or_default()).into_iter().map(|a| (a.1, a.0)).collect();
    mac_ip.extend(current_leases());
    let mut e = lock();
    if e.v6_mac.len() > MAX_V6 {
        e.v6_mac.clear();
    }
    e.v6_mac.extend(parse_neigh(&out));
    e.mac_ip = mac_ip;
}

/// Networks to show: the interface subnets (except WAN) whose address is in a local block.
/// The configured blocks (/8, /16...) are too wide to make cards; with no known interface they are shown as is.
fn displayed_networks(addresses: &[(String, u32, u32, String)], wan: &str, local: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let within = |ip: u32| local.iter().any(|&(n, m)| ip & m == n);
    let mut v: Vec<(u32, u32)> = addresses.iter()
        .filter(|a| a.0 != wan && a.2.count_ones() <= 30 && ip_u32(&a.3).is_some_and(within))
        .map(|a| (a.1, a.2)).collect();
    v.sort_unstable();
    v.dedup();
    if v.is_empty() { local.to_vec() } else { v }
}

/// `time=1.23 ms` in ping output.
fn parse_ping(out: &str) -> Option<f64> {
    let t = &out[out.find("time=")? + 5..];
    t.split(|c: char| c != '.' && !c.is_ascii_digit()).next()?.parse().ok()
}

fn ping(target: &str) -> Option<f64> {
    let s = Command::new("ping").env("LC_ALL", "C").args(["-n", "-c1", "-W1", target]).stderr(Stdio::null()).output().ok()?;
    parse_ping(&String::from_utf8_lossy(&s.stdout))
}

/// Every 30 s: latencies (WAN gateway + configured targets) and service states.
fn probes() {
    loop {
        let gateway = parse_route(&fs::read_to_string("/proc/net/route").unwrap_or_default());
        let mut latencies = vec![];
        if let Some(g) = gateway {
            latencies.push(("Gateway".to_string(), g.clone(), ping(&g)));
        }
        for c in &cfg().probes {
            latencies.push(("Internet".to_string(), c.clone(), ping(c)));
        }
        let states = Command::new("systemctl").arg("is-active").args(&cfg().services).stderr(Stdio::null()).output()
            .map(|s| String::from_utf8_lossy(&s.stdout).lines().map(String::from).collect::<Vec<_>>())
            .unwrap_or_default();
        let services = cfg().services.iter().enumerate()
            .map(|(i, s)| (s.clone(), states.get(i).cloned().unwrap_or_else(|| "unknown".into())))
            .collect();
        let addresses = interface_addresses();
        let addresses6 = interface_addresses6();
        let v6_prefix = Command::new("ip").args(["-6", "route", "show", "type", "unreachable"]).stderr(Stdio::null()).output()
            .ok().and_then(|o| parse_prefix(&String::from_utf8_lossy(&o.stdout)));
        {
            let mut e = lock();
            for (n, c, ms) in &latencies {
                let i = e.lat_hist.iter().position(|h| h.0 == *n && h.1 == *c).unwrap_or_else(|| {
                    if e.lat_hist.len() >= MAX_PROBES {
                        e.lat_hist.remove(0);
                    }
                    e.lat_hist.push((n.clone(), c.clone(), VecDeque::new()));
                    e.lat_hist.len() - 1
                });
                push_capped(&mut e.lat_hist[i].2, ms.map(|m| m as f32), PTS_LAT);
            }
            e.latencies = latencies;
            e.services = services;
            e.addresses = addresses;
            e.addresses6 = addresses6;
            e.v6_prefix = v6_prefix;
        }
        thread::sleep(Duration::from_secs(30));
    }
}

fn link(name: &str, rx: f64, tx: f64) -> Value {
    let read = |f: &str| fs::read_to_string(format!("/sys/class/net/{name}/{f}")).ok().map(|s| s.trim().to_string());
    let stat = |f: &str| read_u64(&format!("/sys/class/net/{name}/statistics/{f}")).unwrap_or(0);
    json!({
        "rx": rx, "tx": tx,
        "state": read("operstate"),
        "speed": read("speed").and_then(|v| v.parse::<i64>().ok()).filter(|&v| v > 0),
        "errors": stat("rx_errors") + stat("tx_errors"),
        "drops": stat("rx_dropped") + stat("tx_dropped"),
    })
}

// --- published status ---
/// `vnstat --json dm` -> day and month totals, and the last 30 days.
fn parse_vnstat(raw: &[u8]) -> Option<Vnstat> {
    let d: Value = serde_json::from_slice(raw).ok()?;
    let tr = d.pointer("/interfaces/0/traffic")?;
    let pair = |v: &Value| Some((v["rx"].as_u64()?, v["tx"].as_u64()?));
    let days: Vec<(u64, u64)> = tr["day"].as_array()?.iter().filter_map(pair).collect();
    Some(Vnstat {
        day: *days.last()?,
        month: pair(tr["month"].as_array()?.last()?)?,
        days: days[days.len().saturating_sub(30)..].to_vec(),
    })
}

/// Queries vnstat (<= 5 s); only called by `track_vnstat`, never by an HTTP request.
fn wan_vnstat() -> Option<Vnstat> {
    let mut child = Command::new("vnstat")
        .args(["--json", "dm", "-i", &cfg().wan])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take().expect("stdout requested");
    let reader = thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    while child.try_wait().ok().flatten().is_none() {
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    parse_vnstat(&reader.join().unwrap_or_default())
}

/// Once a minute: the cache read by /api/status.
fn track_vnstat() {
    loop {
        let v = wan_vnstat();
        lock().vnstat = v;
        thread::sleep(Duration::from_secs(60));
    }
}

fn count_lines(name: &str) -> usize {
    let Ok(f) = File::open(Path::new(&cfg().lists).join(name)) else { return 0 };
    let (mut f, mut line, mut n) = (BufReader::new(f), Vec::new(), 0);
    while f.read_until(b'\n', &mut line).is_ok_and(|k| k > 0) {
        n += 1;
        line.clear();
    }
    n
}

fn system() -> Value {
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0);
    let load: Vec<f64> = fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect();
    let mut mem: HashMap<String, u64> = HashMap::new();
    for l in fs::read_to_string("/proc/meminfo").unwrap_or_default().lines() {
        if let Some((k, v)) = l.split_once(':') {
            if let Some(n) = v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()) {
                mem.insert(k.into(), n * 1024);
            }
        }
    }
    let mut temp = None;
    for h in fs::read_dir("/sys/class/hwmon").into_iter().flatten().flatten() {
        let base = h.path();
        if fs::read_to_string(base.join("name")).is_ok_and(|n| n.trim() == "k10temp") {
            if let Some(m) = read_u64(&base.join("temp1_input").to_string_lossy()) {
                temp = Some(m as f64 / 1000.0);
            }
        }
    }
    json!({
        "uptime": uptime, "load": load,
        "memory": {"total": mem.get("MemTotal"), "available": mem.get("MemAvailable")},
        "temperature": temp,
        "blocklists": {"threats": count_lines("threats.hosts"), "ads": count_lines("ads.hosts"), "ip": count_lines("ip.txt")},
    })
}

/// The `n` most frequent keys; on a tie, the first seen comes first (like `Counter.most_common`).
fn most_frequent<K: Hash + Eq + Copy>(keys: impl Iterator<Item = K>, n: usize) -> Vec<(K, usize)> {
    let (mut index, mut v): (HashMap<K, usize>, Vec<(K, usize)>) = Default::default();
    for k in keys {
        match index.get(&k) {
            Some(&i) => v[i].1 += 1,
            None => {
                index.insert(k, v.len());
                v.push((k, 1));
            }
        }
    }
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(n);
    v
}

/// The `n` top entries of a counter; on a tie, alphabetical order.
fn top<'a>(m: &HashMap<&'a str, usize>, n: usize) -> Vec<(&'a str, usize)> {
    let mut v: Vec<_> = m.iter().map(|(&k, &c)| (k, c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.truncate(n);
    v
}

/// Domain counter (technical traffic excluded) -> (expected traffic, domains grouped by main domain), as JSON.
fn split_expected(per_domain: &HashMap<&str, usize>) -> (Value, Value) {
    let (mut known, mut groups): (Vec<(&str, usize)>, HashMap<&str, (usize, Vec<(&str, usize)>)>) = Default::default();
    for (&d, &n) in per_domain {
        if is_known(d, &cfg().known) {
            known.push((d, n));
        } else {
            let g = groups.entry(main_domain(d)).or_default();
            g.0 += n;
            g.1.push((d, n));
        }
    }
    let by_count = |a: &(&str, usize), b: &(&str, usize)| b.1.cmp(&a.1).then(a.0.cmp(b.0));
    known.sort_by(by_count);
    let total: usize = known.iter().map(|c| c.1).sum();
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
    groups.truncate(25);
    let groups: Vec<Value> = groups.into_iter().map(|(g, (n, mut subs))| {
        subs.sort_by(by_count);
        let sub_count = subs.len();
        subs.truncate(10);
        json!({"domain": g, "n": n, "sub_count": sub_count, "subs": subs})
    }).collect();
    known.truncate(20);
    (json!({"n": total, "domains": known}), json!(groups))
}

/// Card of a device: its domains and what was blocked for it over 24 h.
fn device_card(ip: &str) -> Value {
    let e = lock();
    let t = now();
    let name = name_of(&e, ip);
    let (mut total, mut per_domain, mut per_hour) = (0, HashMap::new(), [0u32; 24]);
    for r in e.queries.iter().filter(|r| r.1 == ip) {
        total += 1;
        if let Some(h) = hour_bucket(t, r.0) {
            per_hour[h] += 1;
        }
        if !is_technical(&r.2) {
            *per_domain.entry(r.2.as_str()).or_default() += 1;
        }
    }
    let (expected, groups) = split_expected(&per_domain);
    let blocked: Vec<_> = e.blocked.iter().filter(|b| b.1 == ip).collect();
    json!({
        "ip": ip, "name": name, "queries_24h": total, "per_hour": per_hour,
        "groups": groups, "expected": expected,
        "ads": blocked.iter().filter(|b| b.3 == "ads").count(),
        "threats": blocked.iter().filter(|b| b.3 == "threats").count(),
        "blocked": most_frequent(blocked.iter().map(|b| (b.2.as_str(), b.3)), 20).into_iter()
            .map(|((d, l), n)| json!({"domain": d, "list": l, "n": n})).collect::<Vec<_>>(),
    })
}

fn name_of(e: &State, ip: &str) -> Option<String> {
    e.devices.values().find(|a| a.ip.as_deref() == Some(ip)).and_then(|a| a.name.clone())
        .or_else(|| cfg().names.get(ip).cloned())
        .or_else(|| is_router(ip, &e.addresses, &e.addresses6).then(|| "router".into()))
}

/// Domain name acceptable for /api/domain: 1 to 253 characters of [a-z0-9._-].
fn valid_domain(d: &str) -> bool {
    !d.is_empty() && d.len() <= 253 && d.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

/// `c` is `d` or one of its subdomains.
fn is_subdomain(c: &str, d: &str) -> bool {
    c.strip_suffix(d).is_some_and(|r| r.is_empty() || r.ends_with('.'))
}

/// Card of a domain (and its subdomains) over 24 h. `None` if `d` is invalid.
fn domain_card(d: &str) -> Option<Value> {
    let d = d.to_ascii_lowercase();
    let d = d.trim_end_matches('.');
    if !valid_domain(d) {
        return None;
    }
    let (e, t) = (lock(), now());
    let (mut total, mut clients, mut subs, mut per_hour) = (0, HashMap::<&str, usize>::new(), HashMap::<&str, usize>::new(), [0u32; 24]);
    for r in e.queries.iter().filter(|r| is_subdomain(&r.2, d)) {
        total += 1;
        *clients.entry(r.1.as_str()).or_default() += 1;
        *subs.entry(r.2.as_str()).or_default() += 1;
        if let Some(h) = hour_bucket(t, r.0) {
            per_hour[h] += 1;
        }
    }
    let first_seen = e.seen_domains.iter().filter(|(k, _)| is_subdomain(k, d)).map(|(_, &ts)| ts).reduce(f64::min);
    Some(json!({
        "domain": d, "queries_24h": total, "first_seen": first_seen, "per_hour": per_hour,
        "clients": top(&clients, 20).into_iter().map(|(ip, n)| json!({"ip": ip, "name": name_of(&e, ip), "n": n})).collect::<Vec<_>>(),
        "subs": top(&subs, 20),
    }))
}

/// GET /api/history?p=1h|24h|30d: WAN series (and latencies over 1 h). `None` if `p` is invalid.
fn history(p: &str) -> Option<Value> {
    let e = lock();
    let t = now();
    let int = |v: f32| v.max(0.0).round() as u64;
    let (step, unit, rx, tx, latencies): (u64, &str, Vec<u64>, Vec<u64>, Value) = match p {
        "1h" => (5, "B/s", e.ring_5s.iter().map(|p| int(p.0)).collect(), e.ring_5s.iter().map(|p| int(p.1)).collect(),
            json!(e.lat_hist.iter().map(|(n, c, ms)| json!({"name": n, "target": c, "ms": ms})).collect::<Vec<_>>())),
        "24h" => (60, "B/s", e.ring_min.iter().map(|p| int(p.0)).collect(), e.ring_min.iter().map(|p| int(p.1)).collect(), Value::Null),
        "30d" => {
            let j = e.vnstat.as_ref().map(|v| v.days.as_slice()).unwrap_or_default();
            (86400, "B", j.iter().map(|x| x.0).collect(), j.iter().map(|x| x.1).collect(), Value::Null)
        }
        _ => return None,
    };
    let mut r = json!({"end": t, "step": step, "unit": unit, "rx": rx, "tx": tx});
    if !latencies.is_null() {
        r["latencies"] = latencies;
    }
    Some(r)
}

/// Per-client counters, from one pass over the queries and one over the blocks.
#[derive(Default)]
struct ClientStats {
    queries: usize,
    ads: usize,
    threats: usize,
}

fn status() -> Value {
    let t = now();
    let system = system();
    let arp: Vec<_> = parse_arp(&fs::read_to_string("/proc/net/arp").unwrap_or_default())
        .into_iter().filter(|v| is_local(&v.0)).collect();
    let (leases, addresses, addresses6, v6_prefix, wan_totals) = {
        let e = lock();
        (current_leases(), e.addresses.clone(), e.addresses6.clone(), e.v6_prefix.clone(), e.vnstat.as_ref().map(|v| json!({"day": {"rx": v.day.0, "tx": v.day.1}, "month": {"rx": v.month.0, "tx": v.month.1}})))
    };
    let online = |mac: &str| arp.iter().any(|v| v.1 == mac);
    let static_ips: Vec<_> = arp.iter().filter(|v| !leases.iter().any(|b| b.0 == v.1)).collect();
    let within = |ip: &str, n: u32, m: u32| ip_u32(ip).is_some_and(|a| a & m == n);
    let shown = displayed_networks(&addresses, &cfg().wan, &cfg().local_nets);
    let networks: Vec<Value> = shown.iter().map(|&(n, m)| {
        let interface = addresses.iter().find(|a| a.1 == n && a.2 == m);
        let p = cfg().dhcp.iter().find(|p| p.1 & m == n);
        json!({
            "cidr": format!("{}/{}", Ipv4Addr::from(n), m.count_ones()),
            "name": p.map(|p| p.0.as_str()).filter(|n| !n.is_empty()).or(interface.map(|a| a.0.as_str())),
            "interface": interface.map(|a| &a.0),
            "address": interface.map(|a| &a.3),
            "range": p.map(|p| json!({"start": Ipv4Addr::from(p.1).to_string(), "end": Ipv4Addr::from(p.2).to_string(), "size": p.2 - p.1 + 1})),
            "leases": leases.iter().filter(|b| within(&b.1, n, m)).count(),
            "online": arp.iter().filter(|v| within(&v.0, n, m)).count(),
            "static_ips": static_ips.iter().filter(|v| within(&v.0, n, m)).count(),
        })
    }).collect();
    // network (the most specific) of an IP, by its name or else its CIDR
    let networks6: Vec<Value> = lan_prefixes6(&addresses6, &cfg().wan).iter().map(|a| json!({
        "cidr": format!("{}/{}", Ipv6Addr::from(a.1), a.2.count_ones()), "family": 6, "name": a.0, "interface": a.0, "address": a.3,
        "range": null, "leases": 0, "online": 0, "static_ips": 0,
    })).collect();
    let ipv6 = json!({"prefix": v6_prefix, "wan": addresses6.iter().filter(|a| a.0 == cfg().wan).map(|a| &a.3).take(3).collect::<Vec<_>>()});
    let labels: Vec<(u32, u32, &str)> = shown.iter().zip(&networks)
        .map(|(&(n, m), v)| (n, m, v["name"].as_str().or(v["cidr"].as_str()).unwrap_or(""))).collect();
    let network_of = |ip: &str| labels.iter().filter(|x| within(ip, x.0, x.1)).max_by_key(|x| x.1.count_ones()).map(|x| x.2);
    let lists_updated = fs::metadata(Path::new(&cfg().lists).join("threats.hosts")).and_then(|m| m.modified()).ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs_f64());
    let guard = lock();
    let e = &*guard;
    let names: HashMap<&str, Option<&str>> =
        e.devices.values().filter_map(|a| Some((a.ip.as_deref()?, a.name.as_deref()))).collect();
    let name = |ip: &str| names.get(ip).copied().flatten().or_else(|| cfg().names.get(ip).map(String::as_str))
        .or_else(|| is_router(ip, &addresses, &addresses6).then_some("router"));
    let oldest = e.devices.values().map(|a| a.first_seen).fold(f64::INFINITY, f64::min);

    // one pass over the queries, one over the blocks
    let (mut clients, mut per_domain, mut technical_n) = (HashMap::<&str, ClientStats>::new(), HashMap::<&str, usize>::new(), HashMap::<&str, usize>::new());
    let (mut q_hour, mut b_hour) = ([0u32; 24], [0u32; 24]);
    for r in &e.queries {
        clients.entry(r.1.as_str()).or_default().queries += 1;
        *(if is_technical(&r.2) { &mut technical_n } else { &mut per_domain }).entry(r.2.as_str()).or_default() += 1;
        if let Some(h) = hour_bucket(t, r.0) {
            q_hour[h] += 1;
        }
    }
    let (mut n_ads, mut n_threats) = (0, 0);
    let mut threats: HashMap<(&str, &str), usize> = HashMap::new();
    for b in &e.blocked {
        let c = clients.entry(b.1.as_str()).or_default();
        if b.3 == "ads" {
            c.ads += 1;
            n_ads += 1;
        } else {
            c.threats += 1;
            n_threats += 1;
            *threats.entry((b.1.as_str(), b.2.as_str())).or_default() += 1;
        }
        if let Some(h) = hour_bucket(t, b.0) {
            b_hour[h] += 1;
        }
    }
    let counts = |ip: Option<&str>| ip.and_then(|ip| clients.get(ip)).map_or((0, 0), |c| (c.queries, c.ads + c.threats));
    let rate = |ip: Option<&str>| ip.and_then(|ip| e.device_rates.get(ip)).copied().unwrap_or(0.0);

    let mut devices: Vec<_> = e.devices.iter().map(|(m, a)| (m, a, is_new(a.first_seen, oldest, t))).collect();
    devices.sort_by(|a, b| (!a.2, a.1.ip.as_deref().unwrap_or("")).cmp(&(!b.2, b.1.ip.as_deref().unwrap_or(""))));
    let mut top_talkers: Vec<_> = e.device_rates.iter().collect();
    top_talkers.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut no_dns: Vec<_> = e.no_dns.iter().collect();
    no_dns.sort_by(|a, b| b.1.total_cmp(a.1));
    let (expected, groups) = split_expected(&per_domain);
    let mut new_domains: Vec<_> = e.seen_domains.iter().filter(|(_, &ts)| t - ts < WINDOW).collect();
    new_domains.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut ng: HashMap<&str, (usize, f64)> = HashMap::new();
    for (d, &ts) in &new_domains {
        let g = ng.entry(main_domain(d)).or_insert((0, 0.0));
        g.0 += 1;
        g.1 = g.1.max(ts);
    }
    let mut ng: Vec<_> = ng.into_iter().collect();
    ng.sort_by(|a, b| b.1 .1.total_cmp(&a.1 .1).then(a.0.cmp(b.0)));
    let mut tops: Vec<_> = clients.iter().map(|(&c, k)| (c, k.queries)).collect();
    tops.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut ads: Vec<_> = clients.iter().filter(|(_, k)| k.ads > 0).map(|(&c, k)| (c, k.ads)).collect();
    ads.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let mut threats: Vec<_> = threats.into_iter().collect();
    threats.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    json!({
        "now": t,
        "system": system,
        "interfaces": e.if_rates.iter().map(|(i, &(rx, tx))| (i, link(i, rx, tx))).collect::<BTreeMap<_, _>>(),
        "wan": cfg().wan,
        "wan_totals": wan_totals,
        "devices": devices.iter().map(|(m, a, is_new)| {
            let (q, b) = counts(a.ip.as_deref());
            json!({
                "mac": m, "first_seen": a.first_seen, "ip": a.ip, "last_seen": a.last_seen, "is_new": is_new,
                "name": a.name.as_deref().or_else(|| a.ip.as_deref().and_then(|ip| cfg().names.get(ip)).map(String::as_str)),
                "online": online(&m.to_lowercase()), "lease": leases.iter().any(|b| b.0 == m.to_lowercase()),
                "rate": rate(a.ip.as_deref()), "queries": q, "blocked": b, "network": a.ip.as_deref().and_then(network_of),
            })
        }).collect::<Vec<_>>(),
        "networks": networks.iter().chain(&networks6).collect::<Vec<_>>(),
        "ipv6": ipv6,
        "static_ips": static_ips.iter().map(|(ip, mac, dev)| {
            let (q, b) = counts(Some(ip));
            json!({"ip": ip, "mac": mac, "interface": dev, "name": cfg().names.get(ip.as_str()),
                "rate": rate(Some(ip)), "queries": q, "blocked": b, "network": network_of(ip)})
        }).collect::<Vec<_>>(),
        "health": {
            "latencies": e.latencies.iter().map(|(n, c, ms)| json!({"name": n, "target": c, "ms": ms})).collect::<Vec<_>>(),
            "services": e.services.iter().map(|(n, s)| json!({"name": n, "state": s})).collect::<Vec<_>>(),
            "lists_updated": lists_updated,
        },
        "top_talkers": top_talkers.iter().take(10).map(|(ip, d)| json!({"ip": ip, "name": name(ip), "rate": d})).collect::<Vec<_>>(),
        "dns": {
            "queries_24h": e.queries.len(),
            "clients": tops.iter().take(15).map(|&(c, n)| json!({"ip": c, "name": name(c), "n": n})).collect::<Vec<_>>(),
            "domains": top(&per_domain, 25),
            "technical": {"n": technical_n.values().sum::<usize>(), "domains": top(&technical_n, 5)},
            "groups": groups,
            "expected": expected,
            "threats": threats.iter().take(30).map(|&((c, d), n)| json!({"ip": c, "name": name(c), "domain": d, "n": n})).collect::<Vec<_>>(),
            "ads_blocked": ads.iter().take(10).map(|&(c, n)| json!({"ip": c, "name": name(c), "n": n})).collect::<Vec<_>>(),
            "new_domains": new_domains.iter().take(50).collect::<Vec<_>>(),
            "new_groups": ng.iter().take(12).map(|(d, (n, ts))| json!({"domain": d, "n": n, "last": ts})).collect::<Vec<_>>(),
            "per_hour": {"queries": q_hour, "blocked": b_hour},
            "blocked_24h": {"ads": n_ads, "threats": n_threats},
        },
        "no_dns": no_dns.iter().take(30).map(|((c, d), ts)| json!({"ip": c, "name": name(c), "to": d, "seen": ts})).collect::<Vec<_>>(),
    })
}

// --- minimal HTTP server: GET / and the /api/* routes ---
fn respond(s: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.0 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(header.as_bytes()).and_then(|_| s.write_all(body));
}

/// Value of query parameter `key` in a path (`/x?a=1&b=2`).
fn param<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    path.split_once('?')?.1.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn serve(mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let mut r = BufReader::new((&s).take(16384));
    let mut request = String::new();
    if r.read_line(&mut request).is_err() {
        return;
    }
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).map_or(true, |n| n == 0 || h.trim().is_empty()) {
            break;
        }
    }
    let mut words = request.split_whitespace();
    match (words.next(), words.next()) {
        (Some("GET"), Some("/api/status")) => respond(&mut s, "200 OK", "application/json", status().to_string().as_bytes()),
        (Some("GET"), Some(path)) if path.starts_with("/api/history?") => {
            match param(path, "p").and_then(history) {
                Some(h) => respond(&mut s, "200 OK", "application/json", h.to_string().as_bytes()),
                None => respond(&mut s, "400 Bad Request", "text/plain", b"invalid period (1h, 24h or 30d)"),
            }
        }
        (Some("GET"), Some(path)) if path.starts_with("/api/domain?") => {
            match param(path, "d").and_then(domain_card) {
                Some(f) => respond(&mut s, "200 OK", "application/json", f.to_string().as_bytes()),
                None => respond(&mut s, "400 Bad Request", "text/plain", b"invalid domain"),
            }
        }
        (Some("GET"), Some(path)) if path.starts_with("/api/device?") => {
            match param(path, "ip").map(|ip| ip.replace("%3A", ":").replace("%3a", ":")).filter(|ip| ip.parse::<IpAddr>().is_ok()) {
                Some(ip) => respond(&mut s, "200 OK", "application/json", device_card(&norm(&ip)).to_string().as_bytes()),
                None => respond(&mut s, "400 Bad Request", "text/plain", b"invalid ip"),
            }
        }
        (Some("GET"), Some("/" | "/index.html")) => {
            let page = match &cfg().page {
                Some(p) => fs::read(p).ok(),
                None => Some(EMBEDDED_PAGE.as_bytes().to_vec()),
            };
            match page {
                Some(p) => respond(&mut s, "200 OK", "text/html; charset=utf-8", &p),
                None => respond(&mut s, "500 Internal Server Error", "text/plain", b"page unreadable"),
            }
        }
        (Some("GET"), _) => respond(&mut s, "404 Not Found", "text/plain", b"not found"),
        _ => respond(&mut s, "501 Not Implemented", "text/plain", b"not implemented"),
    }
}

fn main() {
    let c = cfg();
    fs::create_dir_all(&c.state_dir).expect("state directory");
    load_state();
    thread::spawn(sampler);
    thread::spawn(probes);
    thread::spawn(track_vnstat);
    let listener = TcpListener::bind(&c.listen).unwrap_or_else(|e| panic!("cannot listen on {}: {e}", c.listen));
    for stream in listener.incoming().flatten() {
        thread::spawn(move || serve(stream));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_log() {
        let pre = "Nov 22 10:00:00 dnsmasq[1]: 12 192.168.1.5/5432 ";
        let query = format!("{pre}query[A] example.org from 192.168.1.5");
        assert!(matches!(parse_dns_log(&query), Some(Event::Query { client: "192.168.1.5", domain: "example.org" })));
        let blocked = format!("{pre}/var/lib/lists/threats.hosts bad.example is 0.0.0.0");
        assert!(matches!(parse_dns_log(&blocked), Some(Event::Blocked { list: "threats", domain: "bad.example", .. })));
        let ad = format!("{pre}/var/lib/lists/ads.hosts ad.example is 0.0.0.0");
        assert!(matches!(parse_dns_log(&ad), Some(Event::Blocked { list: "ads", .. })));
        let reply = format!("{pre}reply example.org is 93.184.216.34");
        assert!(matches!(parse_dns_log(&reply), Some(Event::Reply { ip: "93.184.216.34", .. })));
        assert!(parse_dns_log(&format!("{pre}reply example.org is <CNAME>")).is_none());
        assert!(parse_dns_log(&format!("{pre}config example.org is NXDOMAIN")).is_none());
    }

    #[test]
    fn conntrack() {
        let l = "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.1.5 dst=93.184.216.34 sport=5000 dport=443 packets=10 bytes=1200 \
                 src=93.184.216.34 dst=192.168.0.2 sport=443 dport=5000 packets=9 bytes=3400 [ASSURED] mark=0 use=1";
        assert_eq!(parse_conntrack(l), Some(("192.168.1.5", "93.184.216.34", 1200, 3400)));
        assert_eq!(parse_conntrack("ipv4 2 udp 17 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2"), None);
    }

    #[test]
    fn ipv6() {
        let pre = "Nov 22 10:00:00 dnsmasq[1]: 12 2001:db8:0:1::5/5432 ";
        let q = format!("{pre}query[AAAA] example.org from 2001:db8:0:1::5");
        assert!(matches!(parse_dns_log(&q), Some(Event::Query { client: "2001:db8:0:1::5", domain: "example.org" })));
        let r = format!("{pre}reply example.org is 2606:4700::1111");
        assert!(matches!(parse_dns_log(&r), Some(Event::Reply { ip: "2606:4700::1111", .. })));
        assert!(parse_dns_log(&format!("{pre}cached example.org is NODATA-IPv6")).is_none());
        let b = format!("{pre}/var/lib/lists/ads.hosts ad.example is ::");
        assert!(matches!(parse_dns_log(&b), Some(Event::Blocked { list: "ads", .. })));
        let l = "ipv6 10 tcp 6 300 ESTABLISHED src=2001:db8:0:1::5 dst=2606:4700::1111 sport=5000 dport=443 packets=10 bytes=1200 \
                 src=2606:4700::1111 dst=2001:db8:0:1::5 sport=443 dport=5000 packets=9 bytes=3400 [ASSURED] mark=0 use=1";
        assert_eq!(parse_conntrack(l), Some(("2001:db8:0:1::5", "2606:4700::1111", 1200, 3400)));
        assert!(is_public("2606:4700::1111") && !is_public("2001:db8::1") && !is_public("fe80::1") && !is_public("fd00::1") && !is_public("ff02::1"));
        assert!(v6_ignored("fe80::1") && v6_ignored("ff02::fb") && !v6_ignored("2001:db8::1") && !v6_ignored("192.0.2.1"));
        assert!(is_local_ip("fe80::1", &[]) && is_local_ip("fd12::1", &[]) && !is_local_ip("2001:db8:0:1::5", &[]));
        let lan = [cidr6("2001:db8:0:1::/64").unwrap()];
        assert!(is_local_ip("2001:db8:0:1::5", &lan) && !is_local_ip("2001:db8:0:2::5", &lan));
        assert_eq!(norm("2001:0db8:0:0:0:0:0:5"), "2001:db8::5");
    }

    #[test]
    fn neighbours() {
        let n = "2001:db8:0:1::5 dev br0 lladdr AA:BB:CC:00:11:22 REACHABLE\n\
                 fe80::1 dev br0 lladdr aa:bb:cc:00:11:22 router STALE\n\
                 2001:db8:0:1::9 dev br0  FAILED\n";
        assert_eq!(parse_neigh(n), vec![("2001:db8:0:1::5".into(), "aa:bb:cc:00:11:22".into()), ("fe80::1".into(), "aa:bb:cc:00:11:22".into())]);
        let mut e = State::default();
        e.v6_mac.insert("2001:db8:0:1::5".into(), "aa:bb:cc:00:11:22".into());
        e.mac_ip.insert("aa:bb:cc:00:11:22".into(), "192.0.2.10".into());
        assert_eq!(device_key(&e, "2001:DB8:0:1::5"), "192.0.2.10");
        assert_eq!(device_key(&e, "2001:db8:0:1::6"), "2001:db8:0:1::6");
        assert_eq!(device_key(&e, "192.0.2.77"), "192.0.2.77");
        assert_eq!(parse_prefix("unreachable 2001:db8:abcd::/56 dev lo proto static metric 1024 pref medium"), None, "documentation prefix is not global");
        assert_eq!(parse_prefix("unreachable 2606:4700:abcd::/56 dev lo metric 1024"), Some("2606:4700:abcd::/56".into()));
        assert_eq!(parse_prefix("unreachable 2606:4700::/32 dev lo"), None);
        let j = br#"[{"ifname":"br0","addr_info":[{"local":"2606:4700:0:1::1","prefixlen":64,"scope":"global"},{"local":"fe80::1","prefixlen":64,"scope":"link"}]},
                    {"ifname":"wan","addr_info":[{"local":"2606:4700:9::2","prefixlen":128,"scope":"global"}]}]"#;
        let a: Vec<_> = parse_addr_json(j).into_iter().filter(|a| a.3 == "global").collect();
        assert_eq!(a.len(), 2);
        let adr: Vec<_> = a.iter().filter_map(|(i, ip, p, _)| cidr6(&format!("{ip}/{p}")).map(|(n, m)| (i.clone(), n, m, ip.clone()))).collect();
        let lan = lan_prefixes6(&adr, "wan");
        assert_eq!(lan.len(), 1);
        assert_eq!((lan[0].0.as_str(), lan[0].2.count_ones()), ("br0", 64));
    }

    #[test]
    fn addresses() {
        assert!(is_local("192.168.1.42") && is_local("10.1.2.7") && !is_local("8.8.8.8") && !is_local("not an ip"));
        assert!(is_public("93.184.216.34") && !is_public("192.168.1.1") && !is_public("100.64.0.1") && !is_public("127.0.0.1"));
        assert_eq!(cidr("10.20.0.0/24"), Some((0x0a14_0000, 0xffff_ff00)));
    }

    #[test]
    fn infrastructure() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.1.10     0x1         0x2         AA:BB:CC:00:11:23     *        enp2s0\n\
                   192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        enp2s0\n";
        assert_eq!(parse_arp(arp), vec![("192.168.1.10".into(), "aa:bb:cc:00:11:23".into(), "enp2s0".into())]);
        let route = "Iface\tDestination\tGateway \tFlags\n enp1s0\t00000000\t0100A8C0\t0003\n enp2s0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(parse_route(route).as_deref(), Some("192.168.0.1"));
        assert_eq!(parse_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.4 ms"), Some(12.4));
        assert_eq!(parse_ping("1 packets transmitted, 0 received"), None);
        assert_eq!(parse_range("lan,192.168.1.100,192.168.1.199"), Some(("lan".into(), 0xc0a8_0164, 0xc0a8_01c7)));
        assert_eq!(parse_range(",10.0.0.9,10.0.0.1"), None);
    }

    #[test]
    fn domains() {
        assert_eq!(main_domain("a.b.cdn-example.com"), "cdn-example.com");
        assert_eq!(main_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(main_domain("x.service-public.gouv.fr"), "service-public.gouv.fr");
        assert_eq!(main_domain("example.org"), "example.org");
        assert_eq!(main_domain("router"), "router");
        assert_eq!(main_domain("a.example.org."), "example.org");
        let c = vec!["pool.ntp.org".to_string(), "lan".to_string()];
        assert!(is_known("2.nixos.pool.ntp.org", &c) && is_known("pool.ntp.org", &c) && is_known("nas.lan", &c));
        assert!(!is_known("xpool.ntp.org", &c) && !is_known("ntp.org", &c) && !is_known("plan", &c));
    }

    #[test]
    fn names() {
        let n = parse_names("10.0.0.2=nas  10.0.0.3= notanip=x 10.0.0.4=tv");
        assert_eq!(n.len(), 2);
        assert_eq!(n.get("10.0.0.2").map(String::as_str), Some("nas"));
        assert_eq!(n.get("10.0.0.4").map(String::as_str), Some("tv"));
        assert!(parse_names("").is_empty());
    }

    #[test]
    fn frequent() {
        let v = most_frequent(["a", "b", "b", "c", "c", "d"].into_iter(), 3);
        assert_eq!(v, vec![("b", 2), ("c", 2), ("a", 1)]);
    }

    #[test]
    fn cleanup() {
        for d in ["", ".", "4.3.2.192.in-addr.arpa", "x.IP6.ARPA", "printer", "tv.local", "_dns-sd._udp.example", "a._tcp.example", "wpad.example", "wpad"] {
            assert!(is_technical(d), "{d}");
        }
        for d in ["example.org", "a.b.example", "wpadx.example", "arpa.example", "local.example"] {
            assert!(!is_technical(d), "{d}");
        }
        let (start, t) = (1_000_000.0, 1_000_000.0 + 10.0 * 86400.0);
        assert!(!is_new(start, start, t), "first start");
        assert!(!is_new(start + 3600.0, start, t), "within the first hour");
        assert!(is_new(t - 86400.0, start, t));
        assert!(!is_new(t - 8.0 * 86400.0, start, t), "too old");
        let own = vec![("lan".to_string(), 0, 0, "192.0.2.1".to_string())];
        let own6 = vec![("lan".to_string(), 0, 0, "2001:db8:0:1::1".to_string())];
        assert!(is_router("127.0.0.1", &own, &[]) && is_router("127.3.2.1", &own, &[]) && is_router("192.0.2.1", &own, &[]));
        assert!(is_router("::1", &[], &[]) && is_router("2001:db8:0:1::1", &own, &own6));
        assert!(!is_router("192.0.2.9", &own, &own6) && !is_router("2001:db8:0:1::2", &own, &own6));
        let mut m: HashMap<String, f64> = (0..10).map(|i| (format!("d{i}.example"), i as f64)).collect();
        cap_map(&mut m, 10);
        assert_eq!(m.len(), 10);
        cap_map(&mut m, 8);
        assert_eq!(m.len(), 5);
        assert!(m.contains_key("d9.example") && !m.contains_key("d0.example"));
    }

    #[test]
    fn vnstat() {
        let j = r#"{"interfaces":[{"traffic":{"day":[{"rx":1,"tx":2},{"rx":3,"tx":4}],"month":[{"rx":10,"tx":20}]}}]}"#;
        let v = parse_vnstat(j.as_bytes()).expect("vnstat");
        assert_eq!((v.day, v.month, v.days), ((3, 4), (10, 20), vec![(1, 2), (3, 4)]));
        assert!(parse_vnstat(b"not json").is_none());
        let long: Vec<String> = (0..40).map(|i| format!(r#"{{"rx":{i},"tx":0}}"#)).collect();
        let j = format!(r#"{{"interfaces":[{{"traffic":{{"day":[{}],"month":[{{"rx":0,"tx":0}}]}}}}]}}"#, long.join(","));
        assert_eq!(parse_vnstat(j.as_bytes()).map(|v| (v.days.len(), v.days[0].0)), Some((30, 10)));
    }

    #[test]
    fn wide_networks() {
        let blocks: Vec<_> = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].iter().filter_map(|c| cidr(c)).collect();
        let a = |i: &str, c: &str, ip: &str| { let (r, m) = cidr(c).unwrap(); (i.to_string(), r, m, ip.to_string()) };
        let adr = vec![a("wan", "192.0.2.0/24", "192.0.2.2"), a("lan", "192.168.1.0/24", "192.168.1.1"), a("iot", "10.20.0.0/24", "10.20.0.1"),
            a("vpn", "10.8.0.1/32", "10.8.0.1"), a("ts", "100.64.0.0/10", "100.64.0.5"), a("priv", "172.16.0.0/16", "172.16.0.1")];
        let r = displayed_networks(&adr, "wan", &blocks);
        assert_eq!(r, vec![cidr("10.20.0.0/24").unwrap(), cidr("172.16.0.0/16").unwrap(), cidr("192.168.1.0/24").unwrap()]);
        assert_eq!(displayed_networks(&[], "wan", &blocks), blocks);
        // membership of an IP in the wide blocks
        let within = |ip: &str| blocks.iter().any(|&(r, m)| ip_u32(ip).unwrap() & m == r);
        assert!(within("10.255.255.254") && within("172.31.0.1") && within("192.168.200.3") && !within("172.32.0.1") && !within("192.169.0.1") && !within("11.0.0.1"));
        assert_eq!(cidr("172.16.0.0/12"), Some((0xac10_0000, 0xfff0_0000)));
    }

    #[test]
    fn series() {
        assert_eq!(average(&[(2.0, 4.0), (4.0, 8.0)]), (3.0, 6.0));
        assert_eq!(average(&[]), (0.0, 0.0));
        let mut q = VecDeque::new();
        for i in 0..800 {
            push_capped(&mut q, i, PTS_5S);
        }
        assert_eq!((q.len(), q[0]), (720, 80));
        let t = 100_000.0;
        assert_eq!(hour_bucket(t, t), Some(23));
        assert_eq!(hour_bucket(t, t - 3599.0), Some(23));
        assert_eq!(hour_bucket(t, t - 3600.0), Some(22));
        assert_eq!(hour_bucket(t, t - 24.0 * 3600.0 + 1.0), Some(0));
        assert_eq!(hour_bucket(t, t - 24.0 * 3600.0), None);
        let mut m = HashMap::new();
        m.extend([("b.example", 2), ("a.example", 2), ("c.example", 9)]);
        assert_eq!(top(&m, 2), vec![("c.example", 9), ("a.example", 2)]);
        assert_eq!(param("/api/history?p=1h", "p"), Some("1h"));
        assert_eq!(param("/api/device?x=1&ip=192.0.2.5", "ip"), Some("192.0.2.5"));
        assert_eq!(param("/api/history?pp=1h", "p"), None);
    }

    #[test]
    fn history_periods() {
        assert!(history("2h").is_none() && history("").is_none() && history("1h&x").is_none() && history("30j").is_none());
        let h = history("24h").expect("24h");
        assert_eq!((h["step"].as_u64(), h["unit"].as_str()), (Some(60), Some("B/s")));
        assert!(history("1h").is_some_and(|h| h["latencies"].is_array()));
        assert!(history("30d").is_some_and(|h| h["step"] == 86400 && h["unit"] == "B" && h.get("latencies").is_none()));
    }

    #[test]
    fn domain_cards() {
        assert!(valid_domain("a-b_c.example.example") && valid_domain("x"));
        assert!(!valid_domain("") && !valid_domain("a b.example") && !valid_domain("a/b") && !valid_domain("é.example") && !valid_domain("a%2e.example"));
        assert!(valid_domain(&"a".repeat(253)) && !valid_domain(&"a".repeat(254)));
        assert!(is_subdomain("cdn.example.example", "example.example") && is_subdomain("example.example", "example.example"));
        assert!(!is_subdomain("xexample.example", "example.example") && !is_subdomain("example", "example.example"));
        assert!(domain_card("a b").is_none() && domain_card("").is_none() && domain_card("../etc").is_none());
        assert!(domain_card("Example.Example.").is_some_and(|f| f["domain"] == "example.example" && f["queries_24h"] == 0));
    }

    #[test]
    fn legacy_device_state() {
        // state file written before the English rename
        let old = r#"{"premier":1.5,"nom":"nas","ip":"192.0.2.10","vu":2.5}"#;
        let d: Device = serde_json::from_str(old).expect("old format");
        assert_eq!((d.first_seen, d.name.as_deref(), d.ip.as_deref(), d.last_seen), (1.5, Some("nas"), Some("192.0.2.10"), Some(2.5)));
        let d: Device = serde_json::from_str(r#"{"first_seen":3.0}"#).expect("new format");
        assert_eq!((d.first_seen, d.name, d.last_seen), (3.0, None, None));
    }
}
