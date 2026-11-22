{
  description = "Vigie : page d'état d'un routeur NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systemes = [ "x86_64-linux" "aarch64-linux" ];
      pour = f: nixpkgs.lib.genAttrs systemes (s: f nixpkgs.legacyPackages.${s});
    in
    {
      # Un seul binaire Rust (page HTML embarquée)
      packages = pour (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "vigie";
          version = (pkgs.lib.importTOML ./Cargo.toml).package.version;
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./index.html ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          meta.mainProgram = "vigie";
        };
      });

      nixosModules.default = import ./module.nix self;
    };
}
