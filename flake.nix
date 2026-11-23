{
  description = "Vigie: status page for a NixOS router";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      # A single Rust binary (HTML page embedded)
      packages = forAll (pkgs: {
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
