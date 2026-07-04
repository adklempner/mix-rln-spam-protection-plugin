# Combined cbind-rln library: nim-libp2p-mix cbind + RLN spam-protection C
# surface, linked against the vendored librln (zerokit mix fork). Emits a
# superset libp2p.{so,dylib,a} + both headers. Mirrors nim-libp2p-mix/nix/cbind.nix.
{ pkgs, src, libp2pMix, gifter }:

let
  deps = import "${libp2pMix}/nix/deps.nix" { inherit pkgs; };
  cbindDeps = import "${libp2pMix}/nix/cbind-deps.nix" { inherit pkgs; };

  pathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues (deps // cbindDeps)));

  libExt =
    if pkgs.stdenv.hostPlatform.isWindows then "dll"
    else if pkgs.stdenv.hostPlatform.isDarwin then "dylib"
    else "so";
in
pkgs.stdenv.mkDerivation {
  pname = "mix-rln-spam-protection-cbind-rln";
  version = "dev";

  inherit src;

  nativeBuildInputs = [
    pkgs.nim-2_2
    pkgs.git
  ];

  buildPhase = ''
    export HOME=$TMPDIR
    export XDG_CACHE_HOME=$TMPDIR/.cache
    export NIMCACHE=$TMPDIR/nimcache

    mkdir -p build $NIMCACHE

    common_args="--noNimblePath \
      ${pathArgs} \
      --path:${deps.dnsclient}/src \
      --path:${libp2pMix} \
      --path:${libp2pMix}/cbind \
      --path:${gifter}/src \
      --path:${gifter}/cbind \
      --path:. \
      --path:src \
      --threads:on \
      --opt:size \
      --noMain \
      --mm:refc \
      --header \
      --undef:metrics \
      --nimMainPrefix:libp2p \
      --nimcache:$NIMCACHE \
      -d:libp2p_mix_experimental_exit_is_dest \
      --passL:$src/vendor/librln_mix_v2.0.0.a \
      --passL:-lm"

    echo "== Building cbind-rln (dynamic/shared) =="
    nim c $common_args \
      --out:build/libp2p.${libExt} \
      --app:lib \
      cbind/cbind_rln.nim

    echo "== Building cbind-rln (static) =="
    nim c $common_args \
      --out:build/libp2p.a \
      --app:staticlib \
      cbind/cbind_rln.nim
  '';

  installPhase = ''
    mkdir -p $out/lib $out/include
    cp build/libp2p.${libExt} $out/lib
    cp build/libp2p.a         $out/lib
    cp ${libp2pMix}/cbind/libp2p.h $out/include
    cp cbind/libp2p_mix_rln.h      $out/include
    cp ${gifter}/cbind/libp2p_gifter.h $out/include
  '';
}
