//! Vigie : état du routeur et vue légère du réseau, sur http://<routeur>:8080.
//!
//! Sources (rien n'est copié sur le disque hormis deux petits fichiers d'état) :
//! - /sys/class/net : débit instantané par interface ; vnstat : historique du WAN
//! - /proc/net/nf_conntrack : débit par appareil et connexions vers des IP jamais résolues par le DNS
//! - journal des requêtes de dnsmasq (/run, en mémoire) : qui interroge quoi, domaines bloqués et nouveaux
//! - baux DHCP de dnsmasq : appareils, et alerte sur les nouveaux
//!
//! Le journal DNS n'est gardé qu'en agrégats sur 24 h, en mémoire.
//! shortcut: IPv4 seulement (comme les formats lus), à étendre si le routeur sert de l'IPv6.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::hash::Hash;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FENETRE: f64 = 24.0 * 3600.0;
const MAX_DOMAINES_VUS: usize = 20_000;
const PAGE_INTEGREE: &str = include_str!("../index.html");

struct Config {
    wan: String,
    ecoute: String,
    listes: String,
    etat: String,
    journal_dns: String,
    baux: String,
    page: Option<String>,
    locaux: Vec<(u32, u32)>, // (réseau, masque)
    dhcp: Vec<(String, u32, u32)>, // (nom, début, fin)
    sondes: Vec<String>,
    services: Vec<String>,
    connus: Vec<String>,            // suffixes de domaines « attendus », mis à part du classement
    noms: HashMap<String, String>,  // ip -> nom, en repli quand le bail DHCP n'en donne pas
}

/// Domaines de temps courants : le seul trafic « attendu » connu d'office.
const NTP: &str = "pool.ntp.org time.cloudflare.com time.google.com time.apple.com time.windows.com time.nist.gov ntp.ubuntu.com";

fn env(nom: &str, defaut: &str) -> String {
    std::env::var(nom).unwrap_or_else(|_| defaut.into())
}

fn cfg() -> &'static Config {
    static CFG: OnceLock<Config> = OnceLock::new();
    CFG.get_or_init(|| Config {
        wan: env("VIGIE_WAN", "enp1s0"),
        ecoute: env("VIGIE_ECOUTE", "0.0.0.0:8080"),
        listes: env("VIGIE_LISTES", "/var/lib/listes"),
        etat: env("STATE_DIRECTORY", "/var/lib/vigie"),
        journal_dns: env("VIGIE_JOURNAL_DNS", "/run/dnsmasq/requetes.log"),
        baux: env("VIGIE_BAUX", "/var/lib/dnsmasq/dnsmasq.leases"),
        page: std::env::var("VIGIE_PAGE").ok(),
        locaux: env("VIGIE_RESEAUX", "192.168.1.0/24 10.20.0.0/24 10.30.0.0/24 10.99.99.0/24")
            .split_whitespace()
            .map(|n| cidr(n).unwrap_or_else(|| panic!("VIGIE_RESEAUX invalide : {n}")))
            .collect(),
        dhcp: env("VIGIE_DHCP", "").split_whitespace().map(|p| plage(p).unwrap_or_else(|| panic!("VIGIE_DHCP invalide : {p}"))).collect(),
        sondes: env("VIGIE_SONDES", "1.1.1.1").split_whitespace().map(String::from).collect(),
        services: env("VIGIE_SERVICES", "dnsmasq unbound nftables").split_whitespace().map(String::from).collect(),
        connus: env("VIGIE_DOMAINES_CONNUS", NTP).split_whitespace().map(|d| d.trim_matches('.').to_lowercase()).collect(),
        noms: analyser_noms(&env("VIGIE_NOMS", "")),
    })
}

/// `ip=nom ip=nom` → table ip -> nom (entrées mal formées ignorées).
fn analyser_noms(s: &str) -> HashMap<String, String> {
    s.split_whitespace()
        .filter_map(|p| p.split_once('='))
        .filter(|(ip, nom)| ip.parse::<Ipv4Addr>().is_ok() && !nom.is_empty())
        .map(|(ip, nom)| (ip.into(), nom.into()))
        .collect()
}

/// `d` vaut un des suffixes ou en est un sous-domaine (`a.pool.ntp.org` pour `pool.ntp.org`).
fn connu(d: &str, suffixes: &[String]) -> bool {
    let d = d.trim_end_matches('.');
    suffixes.iter().any(|s| d.strip_suffix(s.as_str()).is_some_and(|r| r.is_empty() || r.ends_with('.')))
}

/// Domaine principal : deux derniers labels, trois si l'avant-dernier est un suffixe court (`bbc.co.uk`).
/// shortcut: heuristique sans la Public Suffix List (rate github.io, blogspot…), à remplacer si les regroupements gênent.
fn principal(d: &str) -> &str {
    let d = d.trim_end_matches('.');
    let l: Vec<&str> = d.split('.').collect();
    if l.len() <= 2 {
        return d;
    }
    const COURTS: [&str; 11] = ["co", "com", "net", "org", "gov", "gouv", "ac", "edu", "ne", "or", "go"];
    let n = if l[l.len() - 1].len() == 2 && COURTS.contains(&l[l.len() - 2]) { 3 } else { 2 };
    let garde: usize = l[l.len() - n..].iter().map(|x| x.len() + 1).sum::<usize>() - 1;
    &d[d.len() - garde..]
}

/// Trafic « de plomberie » (reverse DNS, mDNS, WPAD, nom court…) : compté mais jamais classé ni signalé comme nouveau.
fn technique(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    let fin = |suf: &str| d.len() >= suf.len() && d[d.len() - suf.len()..].eq_ignore_ascii_case(suf);
    d.is_empty() || !d.contains('.') || fin(".arpa") || fin(".local")
        || d.split('.').any(|l| l.starts_with('_')) || d.split('.').next().is_some_and(|l| l.eq_ignore_ascii_case("wpad"))
}

/// Un appareil est « nouveau » s'il est apparu après la première heure de la vigie (sinon tout l'est au premier démarrage) et il y a moins de 7 jours.
fn est_nouveau(premier: f64, plus_ancien: f64, t: f64) -> bool {
    premier > plus_ancien + 3600.0 && t - premier < 7.0 * 86400.0
}

/// Adresse du routeur lui-même (boucle locale ou une de ses interfaces).
fn est_routeur(ip: &str, propres: &[(String, u32, u32, String)]) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(|a| a.is_loopback()) || propres.iter().any(|p| p.3 == ip)
}

/// Au-delà de `max` entrées, retire la moitié la plus ancienne.
fn plafonner(m: &mut HashMap<String, f64>, max: usize) {
    if m.len() > max {
        let mut ts: Vec<f64> = m.values().copied().collect();
        let milieu = ts.len() / 2;
        let (_, &mut med, _) = ts.select_nth_unstable_by(milieu, f64::total_cmp);
        m.retain(|_, &mut v| v >= med);
    }
}

/// `nom,début,fin` (nom facultatif) → plage DHCP.
fn plage(s: &str) -> Option<(String, u32, u32)> {
    let mut p = s.split(',');
    let (nom, debut, fin) = (p.next()?, ip_u32(p.next()?)?, ip_u32(p.next()?)?);
    (debut <= fin).then(|| (nom.into(), debut, fin))
}

#[derive(Serialize, Deserialize)]
struct Appareil {
    premier: f64,
    #[serde(default)]
    nom: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    vu: Option<f64>,
}

#[derive(Default)]
struct Etat {
    requetes: VecDeque<(f64, String, String)>,         // (ts, client, domaine)
    bloques: VecDeque<(f64, String, String, &'static str)>, // (ts, client, domaine, liste)
    ip_vers_nom: HashMap<String, String>,              // IP publique -> dernier domaine résolu vers elle
    sans_dns: HashMap<(String, String), f64>,          // (client, ip) -> dernier ts
    debits_if: BTreeMap<String, (f64, f64)>,           // interface -> (rx o/s, tx o/s)
    debits_appareils: HashMap<String, f64>,            // ip -> o/s
    domaines_vus: HashMap<String, f64>,                // domaine -> premier ts
    appareils: HashMap<String, Appareil>,              // mac -> appareil
    latences: Vec<(String, String, Option<f64>)>,      // (nom, cible, ms)
    services: Vec<(String, String)>,                   // (unité, is-active)
    vnstat: Option<Vnstat>,                            // cache rafraîchi chaque minute
    adresses: Vec<(String, u32, u32, String)>,         // cache de `ip addr` : (interface, réseau, masque, adresse)
}

/// Totaux vnstat du WAN : (rx, tx) du jour, du mois, et des 30 derniers jours (le plus ancien d'abord).
struct Vnstat {
    jour: (u64, u64),
    mois: (u64, u64),
    #[allow(dead_code)] // servi par /api/historique?p=30j (étape suivante)
    jours: Vec<(u64, u64)>,
}

static ETAT: LazyLock<Mutex<Etat>> = LazyLock::new(Default::default);

fn verrou() -> MutexGuard<'static, Etat> {
    ETAT.lock().unwrap_or_else(|e| e.into_inner())
}

fn maintenant() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

// --- adresses ---
fn cidr(s: &str) -> Option<(u32, u32)> {
    let (a, p) = s.split_once('/')?;
    let p: u32 = p.parse().ok().filter(|&p| p <= 32)?;
    let masque = if p == 0 { 0 } else { !0u32 << (32 - p) };
    Some((u32::from(a.parse::<Ipv4Addr>().ok()?) & masque, masque))
}

fn local(ip: &str) -> bool {
    let Ok(a) = ip.parse::<Ipv4Addr>() else { return false };
    let a = u32::from(a);
    cfg().locaux.iter().any(|&(r, m)| a & m == r)
}

/// Même sens que `is_global` de Python : hors plages privées, réservées et de partage (100.64/10).
fn public(ip: &str) -> bool {
    const NON_GLOBALES: [([u8; 4], u32); 15] = [
        ([0, 0, 0, 0], 8), ([10, 0, 0, 0], 8), ([100, 64, 0, 0], 10), ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16), ([172, 16, 0, 0], 12), ([192, 0, 0, 0], 29), ([192, 0, 0, 170], 31),
        ([192, 0, 2, 0], 24), ([192, 168, 0, 0], 16), ([198, 18, 0, 0], 15), ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24), ([240, 0, 0, 0], 4), ([255, 255, 255, 255], 32),
    ];
    let Ok(a) = ip.parse::<Ipv4Addr>() else { return false };
    let a = u32::from(a);
    !NON_GLOBALES.iter().any(|&(r, p)| {
        let m = if p == 0 { 0 } else { !0u32 << (32 - p) };
        a & m == u32::from(Ipv4Addr::from(r))
    })
}

// --- état sur disque (hebdomadaire d'un redémarrage à l'autre) ---
fn charger_etat() {
    let mut e = verrou();
    if let Some(d) = lire_json::<HashMap<String, f64>>(&format!("{}/domaines.json", cfg().etat)) {
        e.domaines_vus.extend(d.into_iter().filter(|(k, _)| !technique(k)));
        plafonner(&mut e.domaines_vus, MAX_DOMAINES_VUS);
    }
    if let Some(a) = lire_json::<HashMap<String, Appareil>>(&format!("{}/appareils.json", cfg().etat)) {
        e.appareils.extend(a);
    }
}

fn lire_json<T: serde::de::DeserializeOwned>(chemin: &str) -> Option<T> {
    serde_json::from_slice(&fs::read(chemin).ok()?).ok()
}

fn sauver_etat() {
    let (domaines, appareils) = {
        let e = verrou();
        (serde_json::to_vec(&e.domaines_vus), serde_json::to_vec(&e.appareils))
    };
    for (nom, donnees) in [("domaines.json", domaines), ("appareils.json", appareils)] {
        let Ok(donnees) = donnees else { continue };
        let chemin = format!("{}/{nom}", cfg().etat);
        let tmp = format!("{chemin}.tmp");
        if let Err(err) = fs::write(&tmp, donnees).and_then(|_| fs::rename(&tmp, &chemin)) {
            eprintln!("vigie : sauvegarde de {nom} impossible : {err}");
        }
    }
}

// --- journal DNS de dnsmasq (log-queries=extra) ---
enum Evenement<'a> {
    Requete { client: &'a str, domaine: &'a str },
    Bloque { client: &'a str, liste: &'static str, domaine: &'a str },
    Reponse { domaine: &'a str, ip: &'a str },
}

fn chiffres(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

fn car_ipv4(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit() || c == b'.')
}

/// Lignes du type `... ]: 123 192.168.1.5/5432 query[A] exemple.fr from 192.168.1.5`.
fn analyser_journal(l: &str) -> Option<Evenement<'_>> {
    let reste = &l[l.find("]: ")? + 3..];
    let t: Vec<&str> = reste.split_whitespace().collect();
    if t.len() < 5 || !chiffres(t[0]) {
        return None;
    }
    let (client, port) = t[1].split_once('/')?;
    if !car_ipv4(client) || !chiffres(port) {
        return None;
    }
    let genre = t[2];
    if let Some(type_) = genre.strip_prefix("query[").and_then(|g| g.strip_suffix(']')) {
        let mot = !type_.is_empty() && type_.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        if mot && t[4] == "from" && t.len() > 5 {
            return Some(Evenement::Requete { client, domaine: t[3] });
        }
    }
    if t[4] == "is" && t.len() > 5 {
        for liste in ["menaces", "pub"] {
            if genre.strip_suffix(&format!("/{liste}.hosts")).is_some() {
                return Some(Evenement::Bloque { client, liste, domaine: t[3] });
            }
        }
    }
    if (genre == "reply" || genre == "cached") && t[4] == "is" && t.len() == 6 && car_ipv4(t[5]) {
        return Some(Evenement::Reponse { domaine: t[3], ip: t[5] });
    }
    None
}

fn lire_journal_dns(mut position: u64) -> u64 {
    let chemin = &cfg().journal_dns;
    let Ok(taille) = fs::metadata(chemin).map(|m| m.len()) else { return 0 };
    if taille < position {
        position = 0;
    }
    let mut brut = Vec::new();
    let lu = File::open(chemin).and_then(|mut f| {
        f.seek(SeekFrom::Start(position))?;
        f.read_to_end(&mut brut)
    });
    if lu.is_err() {
        return position;
    }
    position += brut.len() as u64;
    let texte = String::from_utf8_lossy(&brut);
    let t = maintenant();
    {
        let mut guard = verrou();
        let e = &mut *guard;
        for l in texte.lines() {
            match analyser_journal(l.trim_end()) {
                Some(Evenement::Requete { client, domaine }) => {
                    e.requetes.push_back((t, client.into(), domaine.into()));
                    if e.requetes.len() > 150_000 {
                        e.requetes.pop_front();
                    }
                    if !technique(domaine) {
                        e.domaines_vus.entry(domaine.into()).or_insert(t);
                    }
                }
                Some(Evenement::Bloque { client, liste, domaine }) => {
                    e.bloques.push_back((t, client.into(), domaine.into(), liste));
                    if e.bloques.len() > 20_000 {
                        e.bloques.pop_front();
                    }
                }
                Some(Evenement::Reponse { domaine, ip }) => {
                    e.ip_vers_nom.insert(ip.into(), domaine.into());
                }
                None => {}
            }
        }
        plafonner(&mut e.domaines_vus, MAX_DOMAINES_VUS);
        if e.ip_vers_nom.len() > 200_000 {
            e.ip_vers_nom.clear();
        }
    }
    // dnsmasq écrit en ajout (O_APPEND) : on vide le fichier en mémoire au-delà de 4 Mo
    if position > 4_000_000 {
        let _ = File::create(chemin);
        position = 0;
    }
    position
}

// --- compteurs ---
fn lire_u64(chemin: &str) -> Option<u64> {
    fs::read_to_string(chemin).ok()?.trim().parse().ok()
}

fn octets_interfaces() -> HashMap<String, (u64, u64)> {
    let mut r = HashMap::new();
    let Ok(dossier) = fs::read_dir("/sys/class/net") else { return r };
    for i in dossier.flatten() {
        let nom = i.file_name().to_string_lossy().into_owned();
        if nom == "lo" {
            continue;
        }
        let base = format!("/sys/class/net/{nom}/statistics");
        if let (Some(rx), Some(tx)) = (lire_u64(&format!("{base}/rx_bytes")), lire_u64(&format!("{base}/tx_bytes"))) {
            r.insert(nom, (rx, tx));
        }
    }
    r
}

/// Ligne conntrack : `... src=A dst=B ... bytes=N ... src=B dst=A ... bytes=M ...` → (A, B, N, M).
fn analyser_conntrack(l: &str) -> Option<(&str, &str, u64, u64)> {
    let t: Vec<&str> = l.split_whitespace().collect();
    let paire = |de: usize| (de..t.len().saturating_sub(1)).find(|&i| {
        t[i].strip_prefix("src=").is_some_and(car_ipv4) && t[i + 1].strip_prefix("dst=").is_some_and(car_ipv4)
    });
    let octets = |de: usize| {
        (de..t.len()).find_map(|j| t[j].strip_prefix("bytes=").map(|v| (j, v.parse::<u64>().ok())))
    };
    let i = paire(0)?;
    let (j, o1) = octets(i + 2)?;
    let k = paire(j + 1)?;
    let (_, o2) = octets(k + 2)?;
    Some((&t[i][4..], &t[i + 1][4..], o1?, o2?))
}

/// Octets par appareil local (somme des connexions vivantes) + connexions vers des IP publiques.
fn octets_conntrack() -> (HashMap<String, u64>, Vec<(String, String)>) {
    let (mut par_ip, mut cibles) = (HashMap::new(), Vec::new());
    let Ok(f) = File::open("/proc/net/nf_conntrack") else { return (par_ip, cibles) };
    let mut f = BufReader::new(f);
    let mut ligne = Vec::new();
    while f.read_until(b'\n', &mut ligne).is_ok_and(|n| n > 0) {
        if let Some((src, dst, o1, o2)) = analyser_conntrack(&String::from_utf8_lossy(&ligne)) {
            if local(src) {
                *par_ip.entry(src.to_string()).or_insert(0) += o1 + o2;
                if public(dst) {
                    cibles.push((src.into(), dst.into()));
                }
            }
        }
        ligne.clear();
    }
    (par_ip, cibles)
}

fn boucle() {
    let mut position = 0;
    let mut prec_if = octets_interfaces();
    let mut prec_ct: HashMap<String, u64> = HashMap::new();
    let mut prec_t = maintenant();
    let mut derniere_sauvegarde = prec_t;
    loop {
        thread::sleep(Duration::from_secs(5));
        position = lire_journal_dns(position);
        let t = maintenant();
        let dt = (t - prec_t).max(0.001);
        let cur_if = octets_interfaces();
        let (ct, cibles) = octets_conntrack();
        {
            let mut guard = verrou();
            let e = &mut *guard;
            e.debits_if.clear();
            for (i, &(rx, tx)) in &cur_if {
                if let Some(&(prx, ptx)) = prec_if.get(i) {
                    e.debits_if.insert(i.clone(), (rx.saturating_sub(prx) as f64 / dt, tx.saturating_sub(ptx) as f64 / dt));
                }
            }
            e.debits_appareils.clear();
            for (ip, &o) in &ct {
                let d = (o as f64 - prec_ct.get(ip).copied().unwrap_or(0) as f64) / dt;
                if d > 0.0 {
                    e.debits_appareils.insert(ip.clone(), d);
                }
            }
            for (src, dst) in cibles {
                if !e.ip_vers_nom.contains_key(&dst) {
                    e.sans_dns.insert((src, dst), t);
                }
            }
            e.sans_dns.retain(|_, &mut v| t - v <= FENETRE);
            let limite = t - FENETRE;
            while e.requetes.front().is_some_and(|r| r.0 < limite) {
                e.requetes.pop_front();
            }
            while e.bloques.front().is_some_and(|r| r.0 < limite) {
                e.bloques.pop_front();
            }
        }
        (prec_if, prec_ct, prec_t) = (cur_if, ct, t);
        lire_baux();
        if t - derniere_sauvegarde > 3600.0 {
            sauver_etat();
            derniere_sauvegarde = t;
        }
    }
}

fn lire_baux() {
    let Ok(texte) = fs::read_to_string(&cfg().baux) else { return };
    let t = maintenant();
    let mut e = verrou();
    for l in texte.split('\n') {
        let p: Vec<&str> = l.split_whitespace().collect();
        if p.len() >= 4 {
            let a = e.appareils.entry(p[1].into()).or_insert(Appareil { premier: t, nom: None, ip: None, vu: None });
            a.ip = Some(p[2].into());
            a.nom = (p[3] != "*").then(|| p[3].into());
            a.vu = Some(t);
        }
    }
}

// --- vue infra : voisins, adresses, liens, sondes ---
fn ip_u32(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// `/proc/net/arp` : entrées complètes (flag 0x2) → (ip, mac, interface).
/// shortcut: une entrée complète reste quelques minutes après la dernière activité ; `ip neigh` (REACHABLE) si besoin de précision.
fn analyser_arp(texte: &str) -> Vec<(String, String, String)> {
    texte.lines().skip(1).filter_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() >= 6 && p[2] == "0x2" && p[3] != "00:00:00:00:00:00").then(|| (p[0].into(), p[3].to_lowercase(), p[5].into()))
    }).collect()
}

/// `/proc/net/route` : passerelle de la route par défaut.
fn analyser_route(texte: &str) -> Option<String> {
    texte.lines().skip(1).find_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() > 2 && p[1] == "00000000" && p[2] != "00000000")
            .then(|| u32::from_str_radix(p[2], 16).ok())
            .flatten()
            .map(|g| Ipv4Addr::from(u32::from_be(g)).to_string())
    })
}

/// Baux dnsmasq en cours : `expiration mac ip nom id` → (mac, ip).
fn baux_actuels() -> Vec<(String, String)> {
    fs::read_to_string(&cfg().baux).unwrap_or_default().lines().filter_map(|l| {
        let p: Vec<&str> = l.split_whitespace().collect();
        (p.len() >= 3).then(|| (p[1].to_lowercase(), p[2].into()))
    }).collect()
}

/// `ip -j -4 addr` → (interface, réseau, masque, adresse).
fn adresses_interfaces() -> Vec<(String, u32, u32, String)> {
    let Ok(sortie) = Command::new("ip").args(["-j", "-4", "addr", "show"]).stderr(Stdio::null()).output() else { return vec![] };
    let v: Value = serde_json::from_slice(&sortie.stdout).unwrap_or(Value::Null);
    let mut r = vec![];
    for i in v.as_array().into_iter().flatten() {
        for a in i["addr_info"].as_array().into_iter().flatten() {
            if let (Some(nom), Some(ip), Some(p)) = (i["ifname"].as_str(), a["local"].as_str(), a["prefixlen"].as_u64()) {
                if let Some((res, m)) = cidr(&format!("{ip}/{p}")) {
                    r.push((nom.into(), res, m, ip.into()));
                }
            }
        }
    }
    r
}

/// `time=1.23 ms` dans la sortie de ping.
fn analyser_ping(sortie: &str) -> Option<f64> {
    let t = &sortie[sortie.find("time=")? + 5..];
    t.split(|c: char| c != '.' && !c.is_ascii_digit()).next()?.parse().ok()
}

fn ping(cible: &str) -> Option<f64> {
    let s = Command::new("ping").env("LC_ALL", "C").args(["-n", "-c1", "-W1", cible]).stderr(Stdio::null()).output().ok()?;
    analyser_ping(&String::from_utf8_lossy(&s.stdout))
}

/// Toutes les 30 s : latences (passerelle WAN + cibles configurées) et état des services.
fn sondes() {
    loop {
        let passerelle = analyser_route(&fs::read_to_string("/proc/net/route").unwrap_or_default());
        let mut latences = vec![];
        if let Some(g) = passerelle {
            latences.push(("Passerelle".to_string(), g.clone(), ping(&g)));
        }
        for c in &cfg().sondes {
            latences.push(("Internet".to_string(), c.clone(), ping(c)));
        }
        let etats = Command::new("systemctl").arg("is-active").args(&cfg().services).stderr(Stdio::null()).output()
            .map(|s| String::from_utf8_lossy(&s.stdout).lines().map(String::from).collect::<Vec<_>>())
            .unwrap_or_default();
        let services = cfg().services.iter().enumerate()
            .map(|(i, s)| (s.clone(), etats.get(i).cloned().unwrap_or_else(|| "inconnu".into())))
            .collect();
        let adresses = adresses_interfaces();
        {
            let mut e = verrou();
            e.latences = latences;
            e.services = services;
            e.adresses = adresses;
        }
        thread::sleep(Duration::from_secs(30));
    }
}

fn lien(nom: &str, rx: f64, tx: f64) -> Value {
    let lire = |f: &str| fs::read_to_string(format!("/sys/class/net/{nom}/{f}")).ok().map(|s| s.trim().to_string());
    let stat = |f: &str| lire_u64(&format!("/sys/class/net/{nom}/statistics/{f}")).unwrap_or(0);
    json!({
        "rx": rx, "tx": tx,
        "etat": lire("operstate"),
        "vitesse": lire("speed").and_then(|v| v.parse::<i64>().ok()).filter(|&v| v > 0),
        "erreurs": stat("rx_errors") + stat("tx_errors"),
        "pertes": stat("rx_dropped") + stat("tx_dropped"),
    })
}

// --- état publié ---
/// `vnstat --json dm` → totaux du jour et du mois, et les 30 derniers jours.
fn analyser_vnstat(brut: &[u8]) -> Option<Vnstat> {
    let d: Value = serde_json::from_slice(brut).ok()?;
    let tr = d.pointer("/interfaces/0/traffic")?;
    let paire = |v: &Value| Some((v["rx"].as_u64()?, v["tx"].as_u64()?));
    let jours: Vec<(u64, u64)> = tr["day"].as_array()?.iter().filter_map(paire).collect();
    Some(Vnstat {
        jour: *jours.last()?,
        mois: paire(tr["month"].as_array()?.last()?)?,
        jours: jours[jours.len().saturating_sub(30)..].to_vec(),
    })
}

/// Interroge vnstat (≤ 5 s) ; appelé seulement par `suivre_vnstat`, jamais par une requête HTTP.
fn vnstat_wan() -> Option<Vnstat> {
    let mut enfant = Command::new("vnstat")
        .args(["--json", "dm", "-i", &cfg().wan])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut sortie = enfant.stdout.take().expect("stdout demandé");
    let lecteur = thread::spawn(move || {
        let mut v = Vec::new();
        let _ = sortie.read_to_end(&mut v);
        v
    });
    let debut = Instant::now();
    while enfant.try_wait().ok().flatten().is_none() {
        if debut.elapsed() > Duration::from_secs(5) {
            let _ = enfant.kill();
            let _ = enfant.wait();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    analyser_vnstat(&lecteur.join().unwrap_or_default())
}

/// Une fois par minute : le cache lu par /api/etat.
fn suivre_vnstat() {
    loop {
        let v = vnstat_wan();
        verrou().vnstat = v;
        thread::sleep(Duration::from_secs(60));
    }
}

fn compter_lignes(nom: &str) -> usize {
    let Ok(f) = File::open(Path::new(&cfg().listes).join(nom)) else { return 0 };
    let (mut f, mut ligne, mut n) = (BufReader::new(f), Vec::new(), 0);
    while f.read_until(b'\n', &mut ligne).is_ok_and(|k| k > 0) {
        n += 1;
        ligne.clear();
    }
    n
}

fn systeme() -> Value {
    let uptime = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0);
    let charge: Vec<f64> = fs::read_to_string("/proc/loadavg")
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
            if let Some(m) = lire_u64(&base.join("temp1_input").to_string_lossy()) {
                temp = Some(m as f64 / 1000.0);
            }
        }
    }
    json!({
        "uptime": uptime, "charge": charge,
        "memoire": {"totale": mem.get("MemTotal"), "dispo": mem.get("MemAvailable")},
        "temperature": temp,
        "listes": {"menaces": compter_lignes("menaces.hosts"), "pub": compter_lignes("pub.hosts"), "ip": compter_lignes("ip.txt")},
    })
}

/// Les `n` clés les plus fréquentes ; à égalité, la première vue passe devant (comme `Counter.most_common`).
fn plus_frequents<K: Hash + Eq + Copy>(cles: impl Iterator<Item = K>, n: usize) -> Vec<(K, usize)> {
    let (mut index, mut v): (HashMap<K, usize>, Vec<(K, usize)>) = Default::default();
    for k in cles {
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

/// Requêtes → (trafic attendu, domaines groupés par domaine principal), en JSON.
fn repartir<'a>(domaines: impl Iterator<Item = &'a str>) -> (Value, Value) {
    let mut par_domaine: HashMap<&str, usize> = HashMap::new();
    for d in domaines.filter(|d| !technique(d)) {
        *par_domaine.entry(d).or_default() += 1;
    }
    let (mut connus, mut groupes): (Vec<(&str, usize)>, HashMap<&str, (usize, Vec<(&str, usize)>)>) = Default::default();
    for (d, n) in par_domaine {
        if connu(d, &cfg().connus) {
            connus.push((d, n));
        } else {
            let g = groupes.entry(principal(d)).or_default();
            g.0 += n;
            g.1.push((d, n));
        }
    }
    let tri = |a: &(&str, usize), b: &(&str, usize)| b.1.cmp(&a.1).then(a.0.cmp(b.0));
    connus.sort_by(tri);
    let total: usize = connus.iter().map(|c| c.1).sum();
    let mut groupes: Vec<_> = groupes.into_iter().collect();
    groupes.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
    groupes.truncate(25);
    let groupes: Vec<Value> = groupes.into_iter().map(|(g, (n, mut sous))| {
        sous.sort_by(tri);
        let nb_sous = sous.len();
        sous.truncate(10);
        json!({"domaine": g, "n": n, "nb_sous": nb_sous, "sous": sous})
    }).collect();
    connus.truncate(20);
    (json!({"n": total, "domaines": connus}), json!(groupes))
}

/// Fiche d'un appareil : ses domaines et ce qui a été bloqué pour lui sur 24 h.
fn fiche(ip: &str) -> Value {
    let e = verrou();
    let nom = e.appareils.values().find(|a| a.ip.as_deref() == Some(ip)).and_then(|a| a.nom.clone())
        .or_else(|| cfg().noms.get(ip).cloned())
        .or_else(|| est_routeur(ip, &e.adresses).then(|| "routeur".into()));
    let requetes: Vec<&str> = e.requetes.iter().filter(|r| r.1 == ip).map(|r| r.2.as_str()).collect();
    let (attendu, groupes) = repartir(requetes.iter().copied());
    let bloques: Vec<_> = e.bloques.iter().filter(|b| b.1 == ip).collect();
    json!({
        "ip": ip, "nom": nom, "requetes_24h": requetes.len(),
        "groupes": groupes, "attendu": attendu,
        "pub": bloques.iter().filter(|b| b.3 == "pub").count(),
        "menaces": bloques.iter().filter(|b| b.3 == "menaces").count(),
        "bloques": plus_frequents(bloques.iter().map(|b| (b.2.as_str(), b.3)), 20).into_iter()
            .map(|((d, l), n)| json!({"domaine": d, "liste": l, "n": n})).collect::<Vec<_>>(),
    })
}

fn etat() -> Value {
    let t = maintenant();
    let systeme = systeme();
    let arp: Vec<_> = analyser_arp(&fs::read_to_string("/proc/net/arp").unwrap_or_default())
        .into_iter().filter(|v| local(&v.0)).collect();
    let (baux, adresses, historique_wan) = {
        let e = verrou();
        (baux_actuels(), e.adresses.clone(), e.vnstat.as_ref().map(|v| json!({"jour": {"rx": v.jour.0, "tx": v.jour.1}, "mois": {"rx": v.mois.0, "tx": v.mois.1}})))
    };
    let en_ligne = |mac: &str| arp.iter().any(|v| v.1 == mac);
    let ip_fixes: Vec<_> = arp.iter().filter(|v| !baux.iter().any(|b| b.0 == v.1)).collect();
    let dans = |ip: &str, r: u32, m: u32| ip_u32(ip).is_some_and(|a| a & m == r);
    let reseaux: Vec<Value> = cfg().locaux.iter().map(|&(r, m)| {
        let interface = adresses.iter().find(|a| a.1 == r && a.2 == m);
        let p = cfg().dhcp.iter().find(|p| p.1 & m == r);
        json!({
            "cidr": format!("{}/{}", Ipv4Addr::from(r), m.count_ones()),
            "nom": p.map(|p| p.0.as_str()).filter(|n| !n.is_empty()).or(interface.map(|a| a.0.as_str())),
            "interface": interface.map(|a| &a.0),
            "adresse": interface.map(|a| &a.3),
            "plage": p.map(|p| json!({"debut": Ipv4Addr::from(p.1).to_string(), "fin": Ipv4Addr::from(p.2).to_string(), "taille": p.2 - p.1 + 1})),
            "baux": baux.iter().filter(|b| dans(&b.1, r, m)).count(),
            "en_ligne": arp.iter().filter(|v| dans(&v.0, r, m)).count(),
            "ip_fixes": ip_fixes.iter().filter(|v| dans(&v.0, r, m)).count(),
        })
    }).collect();
    let listes_maj = fs::metadata(Path::new(&cfg().listes).join("menaces.hosts")).and_then(|m| m.modified()).ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs_f64());
    let guard = verrou();
    let e = &*guard;
    let noms: HashMap<&str, Option<&str>> =
        e.appareils.values().filter_map(|a| Some((a.ip.as_deref()?, a.nom.as_deref()))).collect();
    let nom = |ip: &str| noms.get(ip).copied().flatten().or_else(|| cfg().noms.get(ip).map(String::as_str))
        .or_else(|| est_routeur(ip, &adresses).then_some("routeur"));
    let plus_ancien = e.appareils.values().map(|a| a.premier).fold(f64::INFINITY, f64::min);

    let mut appareils: Vec<_> = e.appareils.iter().map(|(m, a)| (m, a, est_nouveau(a.premier, plus_ancien, t))).collect();
    appareils.sort_by(|a, b| (!a.2, a.1.ip.as_deref().unwrap_or("")).cmp(&(!b.2, b.1.ip.as_deref().unwrap_or(""))));
    let mut conso: Vec<_> = e.debits_appareils.iter().collect();
    conso.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut nouveaux: Vec<_> = e.domaines_vus.iter().filter(|(_, &ts)| t - ts < FENETRE).collect();
    nouveaux.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut sans_dns: Vec<_> = e.sans_dns.iter().collect();
    sans_dns.sort_by(|a, b| b.1.total_cmp(a.1));
    let (attendu, groupes) = repartir(e.requetes.iter().map(|r| r.2.as_str()));

    json!({
        "maintenant": t,
        "systeme": systeme,
        "interfaces": e.debits_if.iter().map(|(i, &(rx, tx))| (i, lien(i, rx, tx))).collect::<BTreeMap<_, _>>(),
        "wan": cfg().wan,
        "historique_wan": historique_wan,
        "appareils": appareils.iter().map(|(m, a, nouveau)| json!({
            "mac": m, "premier": a.premier, "ip": a.ip, "vu": a.vu, "nouveau": nouveau,
            "nom": a.nom.as_deref().or_else(|| a.ip.as_deref().and_then(|ip| cfg().noms.get(ip)).map(String::as_str)),
            "en_ligne": en_ligne(&m.to_lowercase()), "bail": baux.iter().any(|b| b.0 == m.to_lowercase()),
        })).collect::<Vec<_>>(),
        "reseaux": reseaux,
        "ip_fixes": ip_fixes.iter().map(|(ip, mac, dev)| json!({"ip": ip, "mac": mac, "interface": dev, "nom": cfg().noms.get(ip.as_str())})).collect::<Vec<_>>(),
        "sante": {
            "latences": e.latences.iter().map(|(n, c, ms)| json!({"nom": n, "cible": c, "ms": ms})).collect::<Vec<_>>(),
            "services": e.services.iter().map(|(n, s)| json!({"nom": n, "etat": s})).collect::<Vec<_>>(),
            "listes_maj": listes_maj,
        },
        "gros_consommateurs": conso.iter().take(10).map(|(ip, d)| json!({"ip": ip, "nom": nom(ip), "debit": d})).collect::<Vec<_>>(),
        "dns": {
            "requetes_24h": e.requetes.len(),
            "clients": plus_frequents(e.requetes.iter().map(|r| r.1.as_str()), 15).into_iter()
                .map(|(c, n)| json!({"ip": c, "nom": nom(c), "n": n})).collect::<Vec<_>>(),
            "domaines": plus_frequents(e.requetes.iter().map(|r| r.2.as_str()).filter(|d| !technique(d)), 25),
            "technique": json!({
                "n": e.requetes.iter().filter(|r| technique(&r.2)).count(),
                "domaines": plus_frequents(e.requetes.iter().map(|r| r.2.as_str()).filter(|d| technique(d)), 5),
            }),
            "groupes": groupes,
            "attendu": attendu,
            "menaces": plus_frequents(e.bloques.iter().filter(|b| b.3 == "menaces").map(|b| (b.1.as_str(), b.2.as_str())), 30)
                .into_iter().map(|((c, d), n)| json!({"ip": c, "nom": nom(c), "domaine": d, "n": n})).collect::<Vec<_>>(),
            "pub_bloquee": plus_frequents(e.bloques.iter().filter(|b| b.3 == "pub").map(|b| b.1.as_str()), 10)
                .into_iter().map(|(c, n)| json!({"ip": c, "nom": nom(c), "n": n})).collect::<Vec<_>>(),
            "nouveaux_domaines": nouveaux.iter().take(50).collect::<Vec<_>>(),
        },
        "sans_dns": sans_dns.iter().take(30).map(|((c, d), ts)| json!({"ip": c, "nom": nom(c), "vers": d, "vu": ts})).collect::<Vec<_>>(),
    })
}

// --- serveur HTTP minimal : GET / et GET /api/etat ---
fn repondre(s: &mut TcpStream, statut: &str, type_: &str, corps: &[u8]) {
    let entete = format!(
        "HTTP/1.0 {statut}\r\nContent-Type: {type_}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        corps.len()
    );
    let _ = s.write_all(entete.as_bytes()).and_then(|_| s.write_all(corps));
}

fn servir(mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let mut r = BufReader::new((&s).take(16384));
    let mut requete = String::new();
    if r.read_line(&mut requete).is_err() {
        return;
    }
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).map_or(true, |n| n == 0 || h.trim().is_empty()) {
            break;
        }
    }
    let mut mots = requete.split_whitespace();
    match (mots.next(), mots.next()) {
        (Some("GET"), Some("/api/etat")) => repondre(&mut s, "200 OK", "application/json", etat().to_string().as_bytes()),
        (Some("GET"), Some(chemin)) if chemin.starts_with("/api/appareil?") => {
            let ip = chemin.split_once('?').and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("ip=")));
            match ip.filter(|ip| ip.parse::<Ipv4Addr>().is_ok()) {
                Some(ip) => repondre(&mut s, "200 OK", "application/json", fiche(ip).to_string().as_bytes()),
                None => repondre(&mut s, "400 Bad Request", "text/plain", b"ip invalide"),
            }
        }
        (Some("GET"), Some("/" | "/index.html")) => {
            let page = match &cfg().page {
                Some(p) => fs::read(p).ok(),
                None => Some(PAGE_INTEGREE.as_bytes().to_vec()),
            };
            match page {
                Some(p) => repondre(&mut s, "200 OK", "text/html; charset=utf-8", &p),
                None => repondre(&mut s, "500 Internal Server Error", "text/plain", b"page illisible"),
            }
        }
        (Some("GET"), _) => repondre(&mut s, "404 Not Found", "text/plain", b"introuvable"),
        _ => repondre(&mut s, "501 Not Implemented", "text/plain", b"non gere"),
    }
}

fn main() {
    let c = cfg();
    fs::create_dir_all(&c.etat).expect("dossier d'état");
    charger_etat();
    thread::spawn(boucle);
    thread::spawn(sondes);
    thread::spawn(suivre_vnstat);
    let ecoute = TcpListener::bind(&c.ecoute).unwrap_or_else(|e| panic!("écoute sur {} impossible : {e}", c.ecoute));
    for flux in ecoute.incoming().flatten() {
        thread::spawn(move || servir(flux));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal() {
        let pre = "Nov 22 10:00:00 dnsmasq[1]: 12 192.168.1.5/5432 ";
        let requete = format!("{pre}query[A] exemple.fr from 192.168.1.5");
        assert!(matches!(analyser_journal(&requete), Some(Evenement::Requete { client: "192.168.1.5", domaine: "exemple.fr" })));
        let bloque = format!("{pre}/var/lib/listes/menaces.hosts mal.example is 0.0.0.0");
        assert!(matches!(analyser_journal(&bloque), Some(Evenement::Bloque { liste: "menaces", domaine: "mal.example", .. })));
        let pub_ = format!("{pre}/var/lib/listes/pub.hosts pub.example is 0.0.0.0");
        assert!(matches!(analyser_journal(&pub_), Some(Evenement::Bloque { liste: "pub", .. })));
        let reponse = format!("{pre}reply exemple.fr is 93.184.216.34");
        assert!(matches!(analyser_journal(&reponse), Some(Evenement::Reponse { ip: "93.184.216.34", .. })));
        assert!(analyser_journal(&format!("{pre}reply exemple.fr is <CNAME>")).is_none());
        assert!(analyser_journal(&format!("{pre}config exemple.fr is NXDOMAIN")).is_none());
    }

    #[test]
    fn conntrack() {
        let l = "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.1.5 dst=93.184.216.34 sport=5000 dport=443 packets=10 bytes=1200 \
                 src=93.184.216.34 dst=192.168.254.2 sport=443 dport=5000 packets=9 bytes=3400 [ASSURED] mark=0 use=1";
        assert_eq!(analyser_conntrack(l), Some(("192.168.1.5", "93.184.216.34", 1200, 3400)));
        assert_eq!(analyser_conntrack("ipv4 2 udp 17 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2"), None);
    }

    #[test]
    fn adresses() {
        assert!(local("192.168.1.42") && local("10.99.99.7") && !local("8.8.8.8") && !local("pas une ip"));
        assert!(public("93.184.216.34") && !public("192.168.1.1") && !public("100.64.0.1") && !public("127.0.0.1"));
        assert_eq!(cidr("10.20.0.0/24"), Some((0x0a14_0000, 0xffff_ff00)));
    }

    #[test]
    fn infra() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.1.10     0x1         0x2         AA:BB:CC:00:11:23     *        enp2s0\n\
                   192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        enp2s0\n";
        assert_eq!(analyser_arp(arp), vec![("192.168.1.10".into(), "aa:bb:cc:00:11:23".into(), "enp2s0".into())]);
        let route = "Iface\tDestination\tGateway \tFlags\n enp1s0\t00000000\t01FEA8C0\t0003\n enp2s0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(analyser_route(route).as_deref(), Some("192.168.254.1"));
        assert_eq!(analyser_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.4 ms"), Some(12.4));
        assert_eq!(analyser_ping("1 packets transmitted, 0 received"), None);
        assert_eq!(plage("principal,192.168.1.60,192.168.1.98"), Some(("principal".into(), 0xc0a8_013c, 0xc0a8_0162)));
        assert_eq!(plage(",10.0.0.9,10.0.0.1"), None);
    }

    #[test]
    fn domaines() {
        assert_eq!(principal("a.b.cdn-exemple.com"), "cdn-exemple.com");
        assert_eq!(principal("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(principal("x.service-public.gouv.fr"), "service-public.gouv.fr");
        assert_eq!(principal("exemple.fr"), "exemple.fr");
        assert_eq!(principal("routeur"), "routeur");
        assert_eq!(principal("a.exemple.fr."), "exemple.fr");
        let c = vec!["pool.ntp.org".to_string(), "lan".to_string()];
        assert!(connu("2.nixos.pool.ntp.org", &c) && connu("pool.ntp.org", &c) && connu("nas.lan", &c));
        assert!(!connu("xpool.ntp.org", &c) && !connu("ntp.org", &c) && !connu("plan", &c));
    }

    #[test]
    fn noms() {
        let n = analyser_noms("10.0.0.2=nas  10.0.0.3= pasip=x 10.0.0.4=tele");
        assert_eq!(n.len(), 2);
        assert_eq!(n.get("10.0.0.2").map(String::as_str), Some("nas"));
        assert_eq!(n.get("10.0.0.4").map(String::as_str), Some("tele"));
        assert!(analyser_noms("").is_empty());
    }

    #[test]
    fn frequents() {
        let v = plus_frequents(["a", "b", "b", "c", "c", "d"].into_iter(), 3);
        assert_eq!(v, vec![("b", 2), ("c", 2), ("a", 1)]);
    }

    #[test]
    fn nettoyage() {
        for d in ["", ".", "4.3.2.192.in-addr.arpa", "x.IP6.ARPA", "imprimante", "tele.local", "_dns-sd._udp.example", "a._tcp.example", "wpad.example", "wpad"] {
            assert!(technique(d), "{d}");
        }
        for d in ["exemple.fr", "a.b.example", "wpadx.example", "arpa.example", "local.example"] {
            assert!(!technique(d), "{d}");
        }
        let (debut, t) = (1_000_000.0, 1_000_000.0 + 10.0 * 86400.0);
        assert!(!est_nouveau(debut, debut, t), "premier démarrage");
        assert!(!est_nouveau(debut + 3600.0, debut, t), "dans la première heure");
        assert!(est_nouveau(t - 86400.0, debut, t));
        assert!(!est_nouveau(t - 8.0 * 86400.0, debut, t), "trop ancien");
        let propres = vec![("lan".to_string(), 0, 0, "192.0.2.1".to_string())];
        assert!(est_routeur("127.0.0.1", &propres) && est_routeur("127.3.2.1", &propres) && est_routeur("192.0.2.1", &propres));
        assert!(!est_routeur("192.0.2.9", &propres));
        let mut m: HashMap<String, f64> = (0..10).map(|i| (format!("d{i}.example"), i as f64)).collect();
        plafonner(&mut m, 10);
        assert_eq!(m.len(), 10);
        plafonner(&mut m, 8);
        assert_eq!(m.len(), 5);
        assert!(m.contains_key("d9.example") && !m.contains_key("d0.example"));
    }

    #[test]
    fn vnstat() {
        let j = r#"{"interfaces":[{"traffic":{"day":[{"rx":1,"tx":2},{"rx":3,"tx":4}],"month":[{"rx":10,"tx":20}]}}]}"#;
        let v = analyser_vnstat(j.as_bytes()).expect("vnstat");
        assert_eq!((v.jour, v.mois, v.jours), ((3, 4), (10, 20), vec![(1, 2), (3, 4)]));
        assert!(analyser_vnstat(b"pas du json").is_none());
        let long: Vec<String> = (0..40).map(|i| format!(r#"{{"rx":{i},"tx":0}}"#)).collect();
        let j = format!(r#"{{"interfaces":[{{"traffic":{{"day":[{}],"month":[{{"rx":0,"tx":0}}]}}}}]}}"#, long.join(","));
        assert_eq!(analyser_vnstat(j.as_bytes()).map(|v| (v.jours.len(), v.jours[0].0)), Some((30, 10)));
    }
}
