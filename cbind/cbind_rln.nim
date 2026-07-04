# Combined cbind-rln entry: libp2p_mix cbind + RLN spam-protection C surface
# FEATURE: cbind-rln combined dynamic/static library

## Single compilation unit that exports the mix cbind surface (libp2p_*,
## libp2p_mix_*) from nim-libp2p-mix, the RLN control surface
## (libp2p_mix_rln_*) from this plugin, AND the RLN membership gifter surface
## (libp2p_gifter_*) from logos-rln-gifter — all linked against librln.
## Importing the modules pulls their {.exportc.} procs into the one library;
## the resulting libp2p.{so,dylib,a} is a superset the host links as its
## single libp2p input.

import cbind/cbind as libp2p_cbind
import mix_rln_spam_protection/cbind as rln_cbind
import cbind_gifter as gifter_cbind

# Keep the imports referenced so they are not pruned.
export libp2p_cbind, rln_cbind, gifter_cbind
