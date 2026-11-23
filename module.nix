# NixOS module: systemd service for vigie (router status page).
self: { config, lib, pkgs, ... }:
let
  cfg = config.services.vigie;
  # "set:lan,192.168.1.100,192.168.1.199,12h" -> "lan,192.168.1.100,192.168.1.199"
  dnsmasqRange = r:
    let
      p = lib.splitString "," r;
      tag = lib.findFirst (lib.hasPrefix "set:") "set:" p;
      ips = lib.filter (x: builtins.match "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" x != null) p;
    in
    "${lib.removePrefix "set:" tag},${builtins.elemAt ips 0},${builtins.elemAt ips 1}";
  # dhcp-host "mac,ip,name[,lease]" or host-record "name,ip[,ttl]" -> { "ip" = "name"; } (nothing without a name or IP)
  isIp = x: builtins.match "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" x != null;
  notAName = x: x == "" || isIp x
    || builtins.match "([0-9]+[smhdw]?|infinite|ignore|(set|tag|id):.*|([0-9a-fA-F*]{1,2}[:-]){5}[0-9a-fA-F*]{1,2}|\\[.*)" x != null;
  dnsmasqName = h:
    let
      p = lib.splitString "," h;
      ips = lib.filter isIp p;
      names = lib.filter (x: !notAName x) p;
    in
    lib.optionalAttrs (ips != [ ] && names != [ ]) { ${lib.head ips} = lib.head names; };
  dnsmasqSettings = config.services.dnsmasq.settings;
  autoNames = lib.foldl' (acc: h: acc // dnsmasqName h) { }
    (lib.toList (dnsmasqSettings.dhcp-host or [ ]) ++ lib.toList (dnsmasqSettings.host-record or [ ]));
in
{
  options.services.vigie = {
    enable = lib.mkEnableOption "vigie (router status page)";
    wan = lib.mkOption { type = lib.types.str; description = "WAN interface (throughput, link state)."; };
    listen = lib.mkOption { type = lib.types.str; default = "0.0.0.0:8080"; description = "HTTP listen address:port."; };
    lists = lib.mkOption { type = lib.types.str; default = "/var/lib/listes"; description = "Directory of the blocklists (threats.hosts, ads.hosts, ip.txt)."; };
    networks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "fe80::/10" "fc00::/7" ];
      description = ''
        Blocks considered local (IPv4 or IPv6 CIDRs). The page shows the IPv4 subnets of the interfaces (except WAN) found in them.
        The IPv6 prefixes of the non-WAN interfaces (e.g. a delegated /64) are always local and shown, whatever is listed here.
      '';
    };
    dhcp = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = map dnsmasqRange (lib.toList (config.services.dnsmasq.settings.dhcp-range or [ ]));
      defaultText = lib.literalExpression "ranges derived from services.dnsmasq.settings.dhcp-range";
      description = "DHCP ranges shown, as name,start,end.";
    };
    probes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "1.1.1.1" ];
      description = "Targets pinged every 30 s to measure Internet latency (the WAN gateway always is).";
    };
    services = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "dnsmasq" "unbound" "nftables" ];
      description = "systemd units whose state is shown.";
    };
    knownDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "pool.ntp.org" "time.cloudflare.com" "time.google.com" "time.apple.com" "time.windows.com" "time.nist.gov" "ntp.ubuntu.com" ];
      example = [ "pool.ntp.org" "cache.nixos.org" "github.com" "home.example" ];
      description = "Suffixes of expected traffic (subdomains included), kept apart from the domain ranking.";
    };
    names = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = { "192.0.2.10" = "nas"; };
      description = ''
        Names shown per IP (no spaces), in addition to those derived from services.dnsmasq.settings.dhcp-host
        ("mac,ip,name") and host-record ("name,ip"). Used when the DHCP lease gives no name.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.vigie = {
      description = "Vigie: router and network status";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" "dnsmasq.service" ];
      path = with pkgs; [ vnstat nftables iproute2 iputils systemd ];
      environment = {
        VIGIE_WAN = cfg.wan;
        VIGIE_LISTEN = cfg.listen;
        VIGIE_LISTS = cfg.lists;
        VIGIE_NETWORKS = lib.concatStringsSep " " cfg.networks;
        VIGIE_DHCP = lib.concatStringsSep " " cfg.dhcp;
        VIGIE_PROBES = lib.concatStringsSep " " cfg.probes;
        VIGIE_SERVICES = lib.concatStringsSep " " cfg.services;
        VIGIE_KNOWN_DOMAINS = lib.concatStringsSep " " cfg.knownDomains;
        VIGIE_NAMES = lib.concatStringsSep " " (lib.mapAttrsToList (ip: name: "${ip}=${name}") (autoNames // cfg.names));
      };
      serviceConfig = {
        ExecStart = "${self.packages.${pkgs.system}.default}/bin/vigie";
        StateDirectory = "vigie";
        Restart = "always";
        # Reads /proc/net/nf_conntrack and truncates dnsmasq's DNS log: root, but confined
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
