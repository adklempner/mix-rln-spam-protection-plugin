{
  description = "mix-rln-spam-protection-plugin: RLN SpamProtection + cbind-rln";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [
      "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    libp2p_mix = {
      url = "git+file:///Users/arseniy/Waku/Logos/nim-libp2p-mix?ref=feat/on-demand-roots";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    logos_rln_gifter = {
      url = "git+file:///Users/arseniy/Waku/Logos/logos-rln-gifter?ref=master";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, libp2p_mix, logos_rln_gifter }:
    let
      systems = [
        "x86_64-linux" "aarch64-linux"
        "x86_64-darwin" "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          cbind-rln = import ./nix/cbind-rln.nix {
            inherit pkgs;
            src = ./.;
            libp2pMix = libp2p_mix;
            gifter = logos_rln_gifter;
          };
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            nativeBuildInputs = [ pkgs.nim-2_2 pkgs.git ];
          };
        }
      );
    };
}
