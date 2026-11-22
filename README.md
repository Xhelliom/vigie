# Vigie

Petite page d'état pour un routeur NixOS (testée sur un PC Engines APU2) : débit WAN, appareils connectés,
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
  # reseaux = [ "192.168.1.0/24" ];
};
```

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
| `VIGIE_RESEAUX` | les 4 réseaux privés du module | réseaux locaux, séparés par des espaces |
| `STATE_DIRECTORY` | `/var/lib/vigie` | dossier d'état (fourni par systemd) |

## Licence

MIT.
