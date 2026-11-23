# Vigie

A small status page for a NixOS router (tested on a PC Engines APU2): WAN throughput, networks and DHCP ranges, online devices and static addresses, latency and services,
tracked connections, recent DNS queries and blocked domains/IPs. A Rust daemon (a single binary, HTML page embedded,
a few MB of memory) serves a single HTML page (light/dark, refreshed every 5 s, English or French) on
`http://<router>:8080`; the raw data is on `/api/status`.

Vigie does no authentication: restrict access to the port with the router's firewall.

## Sources read

- `/sys/class/net`: interface state and counters
- `vnstat --json`: WAN throughput history
- `/proc/net/nf_conntrack`: tracked connections
- dnsmasq log `/run/dnsmasq/requetes.log` (`log-queries=extra`; truncated by vigie beyond 4 MB)
- DHCP leases `/var/lib/dnsmasq/dnsmasq.leases`
- blocklists `<lists>/{threats.hosts,ads.hosts,ip.txt}` (dnsmasq must load `threats.hosts` and `ads.hosts` as hosts files: the file name in the log is what classifies a block)
- `/proc/net/arp`: devices present right now, and static addresses (present without a DHCP lease)
- `ip -j addr`, `/sys/class/net/*/{operstate,speed}`: networks, link state and speed
- `ping` (every 30 s): latency of the WAN gateway and of the `probes` targets; `systemctl is-active`: service state

## Usage (NixOS)

```nix
# flake.nix
inputs.vigie = { url = "github:Xhelliom/vigie"; inputs.nixpkgs.follows = "nixpkgs"; };
# …
modules = [ vigie.nixosModules.default ];
```

```nix
services.vigie = {
  enable = true;
  wan = "enp1s0";
  # listen = "0.0.0.0:8080";
  # lists = "/var/lib/listes";
  # networks = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" ];  # default: RFC 1918 private ranges
  # probes = [ "1.1.1.1" ];  # Internet latency targets
  # services = [ "dnsmasq" "unbound" "nftables" ];  # systemd units shown
  # Expected traffic, kept apart from the domain ranking (default: common NTP domains)
  # knownDomains = [ "pool.ntp.org" "cache.nixos.org" "home.example" ];
  # Names per IP, in addition to those derived from dnsmasq (dhcp-host "mac,ip,name", host-record "name,ip")
  # names = { "192.0.2.10" = "nas"; };
  # dhcp = [ "lan,192.168.1.100,192.168.1.199" ];  # default: derived from services.dnsmasq.settings.dhcp-range
};
```

| Option | Default | Role |
|---|---|---|
| `wan` | (required) | WAN interface |
| `listen` | `0.0.0.0:8080` | HTTP listen address:port |
| `lists` | `/var/lib/listes` | blocklist directory (`threats.hosts`, `ads.hosts`, `ip.txt`) |
| `networks` | RFC 1918 ranges | blocks considered local |
| `dhcp` | from `services.dnsmasq.settings.dhcp-range` | DHCP ranges shown, `name,start,end` |
| `probes` | `[ "1.1.1.1" ]` | ping targets for Internet latency |
| `services` | `[ "dnsmasq" "unbound" "nftables" ]` | systemd units shown |
| `knownDomains` | common NTP domains | expected-traffic suffixes |
| `names` | `{ }` | fallback names per IP |

The page is a grid (key figures, WAN traffic from 5 min to 30 days, alerts, a sortable and filterable device table,
DNS in three panels). Domains are grouped by main domain, expected traffic is folded away, and clicking a device or a domain
opens its card (side panel from 1100 px). The UI language is English unless the browser prefers French; an EN/FR button in the header
switches it (the choice is saved in the browser). Shortcuts: `/` search, `Esc` closes the card.
Preferences (period, sort, filters) are kept in the browser; a hidden tab makes no requests.

The router must also enable `services.vnstat` and dnsmasq with `log-queries=extra`. The service runs as
root (to read conntrack) but confined (`ProtectSystem=strict`, `MemoryMax=96M`).

## API

Everything is read-only, unauthenticated, and nothing spawns a process per request (vnstat is queried once a minute, `ip addr` every 30 s).

| Endpoint | Content |
|---|---|
| `GET /api/status` | full status (see below) |
| `GET /api/history?p=1h\|24h\|30d` | `{"end","step","unit","rx":[…],"tx":[…]}`: WAN throughput, oldest first, `end` = time of the last point. `1h`: 5 s step, in B/s, with `latencies` (`[{"name","target","ms":[…]}]`, 30 s step, `null` = no answer); `24h`: per-minute averages, in B/s; `30d`: vnstat daily totals, in bytes. Invalid `p`: 400 |
| `GET /api/domain?d=…` | card of a domain and its subdomains over 24 h: `{"domain","queries_24h","first_seen","clients":[{ip,name,n}…20],"subs":[[d,n]…20],"per_hour":[24]}`. `d`: 1 to 253 characters `[a-z0-9._-]`, otherwise 400 |
| `GET /api/device?ip=…` | card of a device: `{"ip","name","queries_24h","per_hour","groups","expected","ads","threats","blocked":[{domain,list,n}]}` (`per_hour`: 24 hourly buckets, the last = the hour just elapsed) |

`/api/status` top-level keys: `now`, `system` (`uptime`, `load`, `memory{total,available}`, `temperature`, `blocklists{threats,ads,ip}`), `interfaces` (per interface: `rx`, `tx`, `state`, `speed`, `errors`, `drops`), `wan`,
`wan_totals{day,month}`, `devices[]`, `networks[]`, `static_ips[]`, `health{latencies,services,lists_updated}`, `top_talkers[]`, `dns`, `no_dns[]`.

Notes:

- `dns.technical` `{"n","domains":[[d,n]…5]}`: reverse DNS, `.local`, `_services`, `wpad`, short names; counted in `queries_24h` but left out of the rankings and of the new-domain lists
- `dns.per_hour` `{"queries":[24],"blocked":[24]}` (index 0 = the oldest), `dns.blocked_24h` `{"ads","threats"}`
- `dns.new_groups`: up to 12 `{"domain","n","last"}`, the new domains of the last 24 h grouped by main domain
- `devices[]` and `static_ips[]`: `rate` (B/s), `queries` and `blocked` over 24 h, `network`
- the `127.0.0.0/8` client or an address of the router is named `router`; a device is only "new" from one hour after vigie's first start, for 7 days

Memory added: WAN series of 720 points (5 s) + 1440 points (minute) + 120 latency points per probe (8 probes max), `seen_domains` capped at 20,000 entries.

## Environment variables

| Variable | Default | Role |
|---|---|---|
| `VIGIE_WAN` | `enp1s0` | WAN interface |
| `VIGIE_LISTEN` | `0.0.0.0:8080` | listen address:port |
| `VIGIE_LISTS` | `/var/lib/listes` | blocklist directory (`threats.hosts`, `ads.hosts`, `ip.txt`) |
| `VIGIE_DNS_LOG` | `/run/dnsmasq/requetes.log` | dnsmasq query log |
| `VIGIE_LEASES` | `/var/lib/dnsmasq/dnsmasq.leases` | DHCP leases |
| `VIGIE_PAGE` | embedded page | HTML file served instead of the embedded page |
| `VIGIE_NETWORKS` | `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16` | local blocks (IP membership); the "Networks" cards are the subnets of the non-WAN interfaces within these blocks |
| `VIGIE_DHCP` | none (the module derives them from `services.dnsmasq.settings.dhcp-range`) | DHCP ranges `name,start,end`, space-separated |
| `VIGIE_PROBES` | `1.1.1.1` | ping targets for Internet latency |
| `VIGIE_SERVICES` | `dnsmasq unbound nftables` | monitored systemd units |
| `VIGIE_KNOWN_DOMAINS` | common NTP domains (`pool.ntp.org`, `time.google.com`…) | expected-traffic suffixes, space-separated |
| `VIGIE_NAMES` | none (the module derives them from dnsmasq) | fallback names `ip=name`, space-separated |
| `STATE_DIRECTORY` | `/var/lib/vigie` | state directory (provided by systemd) |

## State files

Vigie keeps `domains.json` and `devices.json` in the state directory (saved hourly). Older versions wrote `domaines.json` and `appareils.json`:
if the new file does not exist yet, the old one is read (and the old field names `premier`, `nom`, `vu` are still understood), so history survives the upgrade.

## License

MIT.
