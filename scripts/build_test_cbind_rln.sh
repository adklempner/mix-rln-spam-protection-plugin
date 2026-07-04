#!/usr/bin/env bash
set -uo pipefail
MIX=~/Waku/Logos/nim-libp2p-mix
PLUGIN=~/Waku/Logos/mix-rln-spam-protection-plugin
LIBRLN=${LIBRLN:-~/Waku/Logos/logos-chat/build/librln_mix_v2.0.0.a}

cd "$MIX"
PATHS=$(nix eval --raw --impure --no-accept-flake-config --expr '
  let
    flake = builtins.getFlake (toString ./.);
    pkgs = import flake.inputs.nixpkgs { system = "aarch64-darwin"; };
    deps = import ./nix/deps.nix { inherit pkgs; };
    cbindDeps = import ./nix/cbind-deps.nix { inherit pkgs; };
  in
    builtins.concatStringsSep " " (map (p: "--path:" + toString p) (builtins.attrValues (deps // cbindDeps)))
    + " --path:" + toString deps.dnsclient + "/src"
')

cd "$PLUGIN"
nim c \
  --noNimblePath --path:. --path:src --path:"$MIX" $PATHS \
  --threads:on --mm:refc --skipUserCfg --verbosity:0 --hints:off \
  -d:libp2p_mix_experimental_exit_is_dest \
  --passL:"$LIBRLN" --passL:-lm \
  -o:/tmp/test_cbind_rln \
  "$@" \
  tests/test_cbind_rln.nim
echo "COMPILE_RC=$?"
