#!/usr/bin/env bash
set -uo pipefail
MIX=~/Waku/Logos/nim-libp2p-mix
PLUGIN=~/Waku/Logos/mix-rln-spam-protection-plugin
LIBRLN=${LIBRLN:-~/Waku/Logos/logos-chat/vendor/logos-lez-rln/logos-delivery/build/librln_mix_v2.0.0.a}

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
mkdir -p build
nim c \
  --out:build/libp2p.dylib \
  --threads:on --app:lib --opt:size --noMain --mm:refc --header \
  --undef:metrics --nimMainPrefix:libp2p --nimcache:nimcache_rln \
  --noNimblePath \
  --path:"$MIX" --path:"$MIX/cbind" --path:src --path:. $PATHS \
  --skipUserCfg --verbosity:0 --hints:off \
  -d:libp2p_mix_experimental_exit_is_dest \
  --passL:"$LIBRLN" --passL:-lm \
  "$@" \
  cbind/cbind_rln.nim
echo "BUILD_RC=$?"
