#!@python@
"""Vigie : état du routeur et vue légère du réseau, sur http://<routeur>:8080.

Sources (rien n'est copié sur le disque hormis deux petits fichiers d'état) :
- /sys/class/net : débit instantané par interface ; vnstat : historique du WAN
- /proc/net/nf_conntrack : débit par appareil et connexions vers des IP jamais résolues par le DNS
- journal des requêtes de dnsmasq (/run, en mémoire) : qui interroge quoi, domaines bloqués et nouveaux
- baux DHCP de dnsmasq : appareils, et alerte sur les nouveaux
Le journal DNS n'est gardé qu'en agrégats sur 24 h, en mémoire.
"""
import ipaddress, json, os, re, subprocess, threading, time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WAN = os.environ.get("VIGIE_WAN", "enp1s0")
HOTE, PORT = os.environ.get("VIGIE_ECOUTE", "0.0.0.0:8080").rsplit(":", 1)
LISTES = os.environ.get("VIGIE_LISTES", "/var/lib/listes")
ETAT = os.environ.get("STATE_DIRECTORY", "/var/lib/vigie")
JOURNAL_DNS = os.environ.get("VIGIE_JOURNAL_DNS", "/run/dnsmasq/requetes.log")
BAUX = os.environ.get("VIGIE_BAUX", "/var/lib/dnsmasq/dnsmasq.leases")
PAGE = os.environ.get("VIGIE_PAGE", "@share@/index.html")
FENETRE = 24 * 3600
LOCAUX = [ipaddress.ip_network(n) for n in os.environ.get(
    "VIGIE_RESEAUX", "192.168.1.0/24 10.20.0.0/24 10.30.0.0/24 10.99.99.0/24").split()]

verrou = threading.Lock()
requetes = deque(maxlen=150_000)          # (ts, client, domaine)
bloques = deque(maxlen=20_000)            # (ts, client, domaine, liste)
ip_vers_nom = {}                          # IP publique -> dernier domaine résolu vers elle
sans_dns = {}                             # (client, ip) -> dernier ts
debits_if = {}                            # interface -> (rx o/s, tx o/s)
debits_appareils = {}                     # ip -> o/s
domaines_vus = {}                         # domaine -> premier ts
appareils = {}                            # mac -> {"premier": ts, "nom": ..., "ip": ...}


def local(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LOCAUX)


def public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def charger_etat():
    for nom, cible in (("domaines.json", domaines_vus), ("appareils.json", appareils)):
        try:
            with open(os.path.join(ETAT, nom)) as f:
                cible.update(json.load(f))
        except (OSError, ValueError):
            pass


def sauver_etat():
    with verrou:
        donnees = {"domaines.json": dict(domaines_vus), "appareils.json": dict(appareils)}
    for nom, d in donnees.items():
        tmp = os.path.join(ETAT, nom + ".tmp")
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, os.path.join(ETAT, nom))


# --- journal DNS de dnsmasq (log-queries=extra) ---
RE_REQUETE = re.compile(r"\]: \d+ ([\d.]+)/\d+ query\[\w+\] (\S+) from ")
RE_REPONSE = re.compile(r"\]: \d+ [\d.]+/\d+ (?:reply|cached) (\S+) is ([\d.]+)$")
RE_BLOQUE = re.compile(r"\]: \d+ ([\d.]+)/\d+ \S*/(menaces|pub)\.hosts (\S+) is ")


def lire_journal_dns(position):
    try:
        taille = os.path.getsize(JOURNAL_DNS)
    except OSError:
        return 0
    if taille < position:
        position = 0
    with open(JOURNAL_DNS, errors="replace") as f:
        f.seek(position)
        lignes = f.readlines()
        position = f.tell()
    maintenant = time.time()
    with verrou:
        for l in lignes:
            l = l.rstrip()
            if m := RE_REQUETE.search(l):
                client, dom = m.groups()
                requetes.append((maintenant, client, dom))
                domaines_vus.setdefault(dom, maintenant)
            elif m := RE_BLOQUE.search(l):
                client, liste, dom = m.groups()
                bloques.append((maintenant, client, dom, liste))
            elif m := RE_REPONSE.search(l):
                dom, ip = m.groups()
                ip_vers_nom[ip] = dom
        if len(ip_vers_nom) > 200_000:
            ip_vers_nom.clear()
    # dnsmasq écrit en ajout (O_APPEND) : on vide le fichier en mémoire au-delà de 4 Mo
    if position > 4_000_000:
        with open(JOURNAL_DNS, "w"):
            pass
        position = 0
    return position


# --- compteurs ---
def octets_interfaces():
    r = {}
    for i in os.listdir("/sys/class/net"):
        if i == "lo":
            continue
        try:
            with open(f"/sys/class/net/{i}/statistics/rx_bytes") as a, open(f"/sys/class/net/{i}/statistics/tx_bytes") as b:
                r[i] = (int(a.read()), int(b.read()))
        except OSError:
            pass
    return r


RE_CT = re.compile(r"src=([\d.]+) dst=([\d.]+) .*?bytes=(\d+) .*?src=[\d.]+ dst=[\d.]+ .*?bytes=(\d+)")


def octets_conntrack():
    """Octets par appareil local (somme des connexions vivantes) + connexions vers des IP publiques."""
    par_ip, cibles = Counter(), []
    try:
        with open("/proc/net/nf_conntrack") as f:
            for l in f:
                if m := RE_CT.search(l):
                    src, dst, o1, o2 = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
                    if local(src):
                        par_ip[src] += o1 + o2
                        if public(dst):
                            cibles.append((src, dst))
    except OSError:
        pass
    return par_ip, cibles


def boucle():
    position = 0
    prec_if, prec_ct, prec_t = octets_interfaces(), Counter(), time.time()
    derniere_sauvegarde = time.time()
    while True:
        time.sleep(5)
        position = lire_journal_dns(position)
        t = time.time()
        dt = max(t - prec_t, 0.001)
        cur_if = octets_interfaces()
        ct, cibles = octets_conntrack()
        with verrou:
            debits_if.clear()
            for i, (rx, tx) in cur_if.items():
                if i in prec_if:
                    debits_if[i] = (max(rx - prec_if[i][0], 0) / dt, max(tx - prec_if[i][1], 0) / dt)
            debits_appareils.clear()
            for ip, o in ct.items():
                d = (o - prec_ct.get(ip, 0)) / dt
                if d > 0:
                    debits_appareils[ip] = d
            for src, dst in cibles:
                if dst not in ip_vers_nom:
                    sans_dns[(src, dst)] = t
            for k in [k for k, v in sans_dns.items() if t - v > FENETRE]:
                del sans_dns[k]
            limite = t - FENETRE
            while requetes and requetes[0][0] < limite:
                requetes.popleft()
            while bloques and bloques[0][0] < limite:
                bloques.popleft()
        prec_if, prec_ct, prec_t = cur_if, ct, t
        lire_baux()
        if t - derniere_sauvegarde > 3600:
            sauver_etat()
            derniere_sauvegarde = t


def lire_baux():
    try:
        with open(BAUX) as f:
            lignes = f.read().split("\n")
    except OSError:
        return
    with verrou:
        for l in lignes:
            p = l.split()
            if len(p) >= 4:
                mac, ip, nom = p[1], p[2], p[3]
                a = appareils.setdefault(mac, {"premier": time.time()})
                a.update(ip=ip, nom=None if nom == "*" else nom, vu=time.time())


# --- état publié ---
def vnstat_wan():
    try:
        d = json.loads(subprocess.run(["vnstat", "--json", "dm", "-i", WAN], capture_output=True, timeout=5).stdout)
        tr = d["interfaces"][0]["traffic"]
        jour, mois = tr["day"][-1], tr["month"][-1]
        return {"jour": {"rx": jour["rx"], "tx": jour["tx"]}, "mois": {"rx": mois["rx"], "tx": mois["tx"]}}
    except Exception:
        return None


def systeme():
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    mem = {}
    with open("/proc/meminfo") as f:
        for l in f:
            k, v = l.split(":")
            mem[k] = int(v.split()[0]) * 1024
    temp = None
    for h in os.listdir("/sys/class/hwmon"):
        try:
            with open(f"/sys/class/hwmon/{h}/name") as f:
                if f.read().strip() == "k10temp":
                    with open(f"/sys/class/hwmon/{h}/temp1_input") as g:
                        temp = int(g.read()) / 1000
        except OSError:
            pass

    def compter(nom):
        try:
            with open(os.path.join(LISTES, nom)) as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    return {
        "uptime": uptime, "charge": os.getloadavg(),
        "memoire": {"totale": mem.get("MemTotal"), "dispo": mem.get("MemAvailable")},
        "temperature": temp,
        "listes": {"menaces": compter("menaces.hosts"), "pub": compter("pub.hosts"), "ip": compter("ip.txt")},
    }


def etat():
    t = time.time()
    with verrou:
        noms = {a.get("ip"): a.get("nom") for a in appareils.values()}
        par_client = Counter(c for _, c, _ in requetes)
        par_domaine = Counter(d for _, _, d in requetes)
        menaces = Counter((c, d) for _, c, d, l in bloques if l == "menaces")
        pub = Counter(c for _, c, _, l in bloques if l == "pub")
        nouveaux = sorted(((d, ts) for d, ts in domaines_vus.items() if t - ts < FENETRE), key=lambda x: -x[1])[:50]
        r = {
            "maintenant": t,
            "systeme": systeme(),
            "interfaces": {i: {"rx": rx, "tx": tx} for i, (rx, tx) in debits_if.items()},
            "wan": WAN,
            "historique_wan": vnstat_wan(),
            "appareils": sorted(
                ({"mac": m, **a, "nouveau": t - a["premier"] < 7 * 86400} for m, a in appareils.items()),
                key=lambda a: (not a["nouveau"], a.get("ip") or "")),
            "gros_consommateurs": [{"ip": ip, "nom": noms.get(ip), "debit": d}
                                   for ip, d in sorted(debits_appareils.items(), key=lambda x: -x[1])[:10]],
            "dns": {
                "requetes_24h": len(requetes),
                "clients": [{"ip": c, "nom": noms.get(c), "n": n} for c, n in par_client.most_common(15)],
                "domaines": par_domaine.most_common(25),
                "menaces": [{"ip": c, "nom": noms.get(c), "domaine": d, "n": n} for (c, d), n in menaces.most_common(30)],
                "pub_bloquee": [{"ip": c, "nom": noms.get(c), "n": n} for c, n in pub.most_common(10)],
                "nouveaux_domaines": nouveaux,
            },
            "sans_dns": [{"ip": c, "nom": noms.get(c), "vers": d, "vu": ts}
                         for (c, d), ts in sorted(sans_dns.items(), key=lambda x: -x[1])[:30]],
        }
    return r


class Gestion(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/etat":
            corps, type_ = json.dumps(etat()).encode(), "application/json"
        elif self.path in ("/", "/index.html"):
            with open(PAGE, "rb") as f:
                corps, type_ = f.read(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", type_)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, *args):
        pass


def principal():
    os.makedirs(ETAT, exist_ok=True)
    charger_etat()
    threading.Thread(target=boucle, daemon=True).start()
    ThreadingHTTPServer((HOTE, int(PORT)), Gestion).serve_forever()


if __name__ == "__main__":
    principal()
