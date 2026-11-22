{
  description = "Vigie : page d'état d'un routeur NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systemes = [ "x86_64-linux" "aarch64-linux" ];
      pour = f: nixpkgs.lib.genAttrs systemes (s: f nixpkgs.legacyPackages.${s});
    in
    {
      # Un script Python (bibliothèque standard seulement) + une page HTML, sans dépendance
      packages = pour (pkgs: {
        default = pkgs.runCommand "vigie" { } ''
          mkdir -p $out/bin $out/share/vigie
          cp ${./index.html} $out/share/vigie/index.html
          substitute ${./vigie.py} $out/bin/vigie \
            --replace-fail "@python@" "${pkgs.python3}/bin/python3" \
            --replace-fail "@share@" "$out/share/vigie"
          chmod +x $out/bin/vigie
        '';
      });

      nixosModules.default = import ./module.nix self;
    };
}
