# Vigie

Petite page d'état pour un routeur NixOS (testée sur un PC Engines APU2) : débit WAN, réseaux et plages DHCP, appareils en ligne et adresses fixes, latence et services,
connexions suivies, requêtes DNS récentes et domaines/IP bloqués. Un démon Rust (un seul binaire, page
HTML embarquée, quelques Mo de mémoire) sert une page HTML unique (clair/sombre, rafraîchie toutes les 5 s) sur
`http://<routeur>:8080` ; les données brutes sont sur `/api/etat`.

La vigie ne fait aucune authentification : limitez l'accès au port par le pare-feu du routeur.

## Sources lues

- `/sys/class/net` : état et compteurs des interfaces
- `vnstat --json` : historique du débit WAN
- `/proc/net/nf_conntrack` : connexions suivies
- journal dnsmasq `/run/dnsmasq/requetes.log` (`log-queries=extra` ; vidé par la vigie au-delà de 4 Mo)
- baux DHCP `/var/lib/dnsmasq/dnsmasq.leases`
- listes de blocage `<listes>/{menaces.hosts,pub.hosts,ip.txt}`
- `/proc/net/arp` : appareils présents en ce moment, et adresses fixes (présentes sans bail DHCP)
- `ip -j addr`, `/sys/class/net/*/{operstate,speed}` : réseaux, état et vitesse des liens
- `ping` (toutes les 30 s) : latence de la passerelle WAN et des cibles `sondes` ; `systemctl is-active` : état des services

## Utilisation (NixOS)

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
  # ecoute = "0.0.0.0:8080";
  # listes = "/var/lib/listes";
  # reseaux = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" ];  # défaut : plages privées RFC 1918
  # Trafic attendu, mis à part du classement des domaines (défaut : domaines NTP courants)
  # domainesConnus = [ "pool.ntp.org" "cache.nixos.org" "maison.example" ];
  # Noms par IP, en plus de ceux déduits de dnsmasq (dhcp-host "mac,ip,nom", host-record "nom,ip")
  # noms = { "192.0.2.10" = "nas"; };
};
```

La page est rangée en sections : état, sécurité, activité, réseau, système. Les domaines sont regroupés par
domaine principal (dépliables), le trafic attendu est replié à part, et un clic sur un appareil ouvre sa fiche
(domaines demandés et blocages sur 24 h, `GET /api/appareil?ip=…`).

Le routeur doit aussi activer `services.vnstat` et dnsmasq avec `log-queries=extra`. Le service tourne en
root (lecture de conntrack) mais confiné (`ProtectSystem=strict`, `MemoryMax=96M`).

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `VIGIE_WAN` | `enp1s0` | interface WAN |
| `VIGIE_ECOUTE` | `0.0.0.0:8080` | adresse:port d'écoute |
| `VIGIE_LISTES` | `/var/lib/listes` | dossier des listes de blocage |
| `VIGIE_JOURNAL_DNS` | `/run/dnsmasq/requetes.log` | journal des requêtes dnsmasq |
| `VIGIE_BAUX` | `/var/lib/dnsmasq/dnsmasq.leases` | baux DHCP |
| `VIGIE_PAGE` | page embarquée | fichier HTML servi à la place de la page embarquée |
| `VIGIE_RESEAUX` | `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16` | blocs locaux (appartenance d'une IP) ; les cartes « Réseaux » sont les sous-réseaux des interfaces hors WAN dans ces blocs |
| `VIGIE_DHCP` | aucune (le module les déduit de `services.dnsmasq.settings.dhcp-range`) | plages DHCP `nom,début,fin`, séparées par des espaces |
| `VIGIE_SONDES` | `1.1.1.1` | cibles de ping pour la latence Internet |
| `VIGIE_SERVICES` | `dnsmasq unbound nftables` | unités systemd surveillées |
| `VIGIE_DOMAINES_CONNUS` | domaines NTP courants (`pool.ntp.org`, `time.google.com`…) | suffixes du trafic attendu, séparés par des espaces |
| `VIGIE_NOMS` | aucun (le module les déduit de dnsmasq) | noms de repli `ip=nom`, séparés par des espaces |
| `STATE_DIRECTORY` | `/var/lib/vigie` | dossier d'état (fourni par systemd) |

## Licence

MIT.
