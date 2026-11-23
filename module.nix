# Module NixOS : service systemd de la vigie. Reprend à l'identique le service du routeur APU2.
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.vigie;
  # "set:principal,192.168.1.60,192.168.1.98,12h" -> "principal,192.168.1.60,192.168.1.98"
  plageDnsmasq = r:
    let
      p = lib.splitString "," r;
      tag = lib.findFirst (lib.hasPrefix "set:") "set:" p;
      ips = lib.filter (x: builtins.match "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" x != null) p;
    in
    "${lib.removePrefix "set:" tag},${builtins.elemAt ips 0},${builtins.elemAt ips 1}";
  # dhcp-host "mac,ip,nom[,bail]" ou host-record "nom,ip[,ttl]" -> { "ip" = "nom"; } (rien sans nom ni IP)
  estIp = x: builtins.match "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" x != null;
  pasUnNom = x: x == "" || estIp x
    || builtins.match "([0-9]+[smhdw]?|infinite|ignore|(set|tag|id):.*|([0-9a-fA-F*]{1,2}[:-]){5}[0-9a-fA-F*]{1,2}|\\[.*)" x != null;
  nomDnsmasq = h:
    let
      p = lib.splitString "," h;
      ips = lib.filter estIp p;
      noms = lib.filter (x: !pasUnNom x) p;
    in
    lib.optionalAttrs (ips != [ ] && noms != [ ]) { ${lib.head ips} = lib.head noms; };
  reglages = config.services.dnsmasq.settings;
  nomsAuto = lib.foldl' (acc: h: acc // nomDnsmasq h) { }
    (lib.toList (reglages.dhcp-host or [ ]) ++ lib.toList (reglages.host-record or [ ]));
in
{
  options.services.vigie = {
    enable = lib.mkEnableOption "la vigie (page d'état du routeur)";
    wan = lib.mkOption { type = lib.types.str; description = "Interface WAN (débit, état du lien)."; };
    ecoute = lib.mkOption { type = lib.types.str; default = "0.0.0.0:8080"; description = "Adresse:port d'écoute HTTP."; };
    listes = lib.mkOption { type = lib.types.str; default = "/var/lib/listes"; description = "Dossier des listes de blocage (menaces.hosts, pub.hosts, ip.txt)."; };
    reseaux = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "192.168.1.0/24" "10.20.0.0/24" "10.30.0.0/24" "10.99.99.0/24" ];
      description = "Réseaux considérés comme locaux.";
    };
    dhcp = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = map plageDnsmasq (lib.toList (config.services.dnsmasq.settings.dhcp-range or [ ]));
      defaultText = lib.literalExpression "plages déduites de services.dnsmasq.settings.dhcp-range";
      description = "Plages DHCP affichées, au format nom,début,fin.";
    };
    sondes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "1.1.1.1" ];
      description = "Cibles pingées toutes les 30 s pour mesurer la latence Internet (la passerelle WAN l'est toujours).";
    };
    services = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "dnsmasq" "unbound" "nftables" ];
      description = "Unités systemd dont l'état est affiché.";
    };
    domainesConnus = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "pool.ntp.org" "time.cloudflare.com" "time.google.com" "time.apple.com" "time.windows.com" "time.nist.gov" "ntp.ubuntu.com" ];
      example = [ "pool.ntp.org" "cache.nixos.org" "github.com" "maison.example" ];
      description = "Suffixes du trafic attendu (sous-domaines compris), mis à part du classement des domaines.";
    };
    noms = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = { "192.0.2.10" = "nas"; };
      description = ''
        Noms affichés par IP (sans espace), en plus de ceux déduits de services.dnsmasq.settings.dhcp-host
        ("mac,ip,nom") et host-record ("nom,ip"). Servent quand le bail DHCP ne donne pas de nom.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.vigie = {
      description = "Vigie : état du routeur et du réseau";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "dnsmasq.service" ];
      path = with pkgs; [ vnstat nftables iproute2 iputils systemd ];
      environment = {
        VIGIE_WAN = cfg.wan;
        VIGIE_ECOUTE = cfg.ecoute;
        VIGIE_LISTES = cfg.listes;
        VIGIE_RESEAUX = lib.concatStringsSep " " cfg.reseaux;
        VIGIE_DHCP = lib.concatStringsSep " " cfg.dhcp;
        VIGIE_SONDES = lib.concatStringsSep " " cfg.sondes;
        VIGIE_SERVICES = lib.concatStringsSep " " cfg.services;
        VIGIE_DOMAINES_CONNUS = lib.concatStringsSep " " cfg.domainesConnus;
        VIGIE_NOMS = lib.concatStringsSep " " (lib.mapAttrsToList (ip: nom: "${ip}=${nom}") (nomsAuto // cfg.noms));
      };
      serviceConfig = {
        ExecStart = "${self.packages.${pkgs.system}.default}/bin/vigie";
        StateDirectory = "vigie";
        Restart = "always";
        # Lit /proc/net/nf_conntrack et vide le journal DNS de dnsmasq : root, mais confiné
        ProtectSystem = "strict";
        ReadWritePaths = [ "-/run/dnsmasq" ];
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        MemoryMax = "96M";
      };
    };
  };
}
