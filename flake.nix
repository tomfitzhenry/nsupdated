{
  description = "RFC 2136 dynamic updates and AXFR over a Unix socket, backed by any DNSControl provider";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      vendorHash = "sha256-jc1lzIAj+/mfRIXZVbBq6cysmHg9tk7aEmt40z1kZOs=";
    in {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = (pkgs.buildGoModule.override { go = pkgs.go_1_27; }) {
            pname = "nsupdated";
            version = "0.1.0";
            src = ./.;
            inherit vendorHash;
          };
        });

      checks = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = (pkgs.buildGoModule.override { go = pkgs.go_1_27; }) {
            pname = "nsupdated";
            version = "0.1.0";
            src = ./.;
            inherit vendorHash;
            # Run vet and the test suite instead of building the binary.
            buildPhase = "true";
            installPhase = "mkdir -p $out";
            checkPhase = ''
              go vet ./...
              go test ./...
            '';
          };

          # End-to-end: nsupdate(1) updates a zone through nsupdated backed by
          # the AXFRDDNS provider, against a local Knot DNS primary.
          integration = pkgs.testers.runNixOSTest (
            import ./vm-tests/axfrddns.nix {
              inherit pkgs;
              nsupdated = self.packages.${system}.default;
            }
          );
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go_1_27
              bind # nsupdate, dig
            ];
          };
        });
    };
}
