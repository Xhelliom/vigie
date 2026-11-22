# Module NixOS : service systemd de la vigie. Reprend à l'identique le service du routeur APU2.
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.vigie;
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
  };

  config = lib.mkIf cfg.enable {
    systemd.services.vigie = {
      description = "Vigie : état du routeur et du réseau";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "dnsmasq.service" ];
      path = with pkgs; [ vnstat nftables ];
      environment = {
        VIGIE_WAN = cfg.wan;
        VIGIE_ECOUTE = cfg.ecoute;
        VIGIE_LISTES = cfg.listes;
        VIGIE_RESEAUX = lib.concatStringsSep " " cfg.reseaux;
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
