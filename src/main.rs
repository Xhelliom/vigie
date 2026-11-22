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
}

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
    })
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
        e.domaines_vus.extend(d);
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
                    e.domaines_vus.entry(domaine.into()).or_insert(t);
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

// --- état publié ---
fn vnstat_wan() -> Value {
    let mut enfant = match Command::new("vnstat")
        .args(["--json", "dm", "-i", &cfg().wan])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(e) => e,
        Err(_) => return Value::Null,
    };
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
    let brut = lecteur.join().unwrap_or_default();
    (|| {
        let d: Value = serde_json::from_slice(&brut).ok()?;
        let tr = d.pointer("/interfaces/0/traffic")?;
        let (jour, mois) = (tr["day"].as_array()?.last()?, tr["month"].as_array()?.last()?);
        Some(json!({"jour": {"rx": jour["rx"], "tx": jour["tx"]}, "mois": {"rx": mois["rx"], "tx": mois["tx"]}}))
    })()
    .unwrap_or(Value::Null)
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

fn etat() -> Value {
    let t = maintenant();
    let (systeme, historique_wan) = (systeme(), vnstat_wan());
    let guard = verrou();
    let e = &*guard;
    let noms: HashMap<&str, Option<&str>> =
        e.appareils.values().filter_map(|a| Some((a.ip.as_deref()?, a.nom.as_deref()))).collect();
    let nom = |ip: &str| noms.get(ip).copied().flatten();

    let mut appareils: Vec<_> = e.appareils.iter().map(|(m, a)| (m, a, t - a.premier < 7.0 * 86400.0)).collect();
    appareils.sort_by(|a, b| (!a.2, a.1.ip.as_deref().unwrap_or("")).cmp(&(!b.2, b.1.ip.as_deref().unwrap_or(""))));
    let mut conso: Vec<_> = e.debits_appareils.iter().collect();
    conso.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut nouveaux: Vec<_> = e.domaines_vus.iter().filter(|(_, &ts)| t - ts < FENETRE).collect();
    nouveaux.sort_by(|a, b| b.1.total_cmp(a.1));
    let mut sans_dns: Vec<_> = e.sans_dns.iter().collect();
    sans_dns.sort_by(|a, b| b.1.total_cmp(a.1));

    json!({
        "maintenant": t,
        "systeme": systeme,
        "interfaces": e.debits_if.iter().map(|(i, &(rx, tx))| (i, json!({"rx": rx, "tx": tx}))).collect::<BTreeMap<_, _>>(),
        "wan": cfg().wan,
        "historique_wan": historique_wan,
        "appareils": appareils.iter().map(|(m, a, nouveau)| json!({
            "mac": m, "premier": a.premier, "ip": a.ip, "nom": a.nom, "vu": a.vu, "nouveau": nouveau,
        })).collect::<Vec<_>>(),
        "gros_consommateurs": conso.iter().take(10).map(|(ip, d)| json!({"ip": ip, "nom": nom(ip), "debit": d})).collect::<Vec<_>>(),
        "dns": {
            "requetes_24h": e.requetes.len(),
            "clients": plus_frequents(e.requetes.iter().map(|r| r.1.as_str()), 15).into_iter()
                .map(|(c, n)| json!({"ip": c, "nom": nom(c), "n": n})).collect::<Vec<_>>(),
            "domaines": plus_frequents(e.requetes.iter().map(|r| r.2.as_str()), 25),
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
    fn frequents() {
        let v = plus_frequents(["a", "b", "b", "c", "c", "d"].into_iter(), 3);
        assert_eq!(v, vec![("b", 2), ("c", 2), ("a", 1)]);
    }
}
