# Package
version = "0.1.0"
author = "vacp2p"
description = "RLN-based spam protection plugin for libp2p mix networks"
license = "MIT OR Apache-2.0"
srcDir = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "results >= 0.4.0"
requires "stew >= 0.4.2"
requires "chronicles >= 0.11.0"
requires "chronos >= 4.2.2"
requires "nimcrypto >= 0.6.0"
requires "secp256k1 >= 0.5.0"
requires "json_serialization >= 0.2.0"

# nim-libp2p — used for protobuf/minprotobuf/varint AND mix code (pre-extraction
# bundled layout at libp2p/protocols/mix/*). Pinned to match logos-delivery's
# nim-libp2p pin so liblogosdelivery and this plugin compile against the same
# libp2p version (avoids "Two SpamProtection candidates" symbol conflicts).
requires "https://github.com/vacp2p/nim-libp2p.git#ff8d51857b4b79a68468e7bcc27b2026cca02996"

# Tasks
task test, "Run tests":
  # Requires librln.a in current directory or set LIBRLN_PATH env var
  let librlnPath = getEnv("LIBRLN_PATH", "librln.a")
  exec "nim c -r --passL:" & librlnPath & " --passL:-lm tests/test_all.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --outdir:docs src/mix_rln_spam_protection.nim"
