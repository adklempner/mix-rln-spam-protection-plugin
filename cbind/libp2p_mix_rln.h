// RLN-on-LEZ spam protection C surface for the mix cbind.
// Companion to libp2p.h (from nim-libp2p-mix cbind); both are emitted by the
// combined cbind-rln library. No RLN type crosses this boundary.
#ifndef LIBP2P_MIX_RLN_H
#define LIBP2P_MIX_RLN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback the host invokes to deliver a fetcher result back to the cbind.
// callerRet == 0 means success and (msg,len) is the JSON response; non-zero
// means error and (msg,len) is the error string. Copy out before returning.
typedef void (*Libp2pMixRlnFetchCallback)(int callerRet, const char *msg,
                                          size_t len, void *callbackData);

// Host-provided fetcher. The cbind calls this from the libp2p thread to fetch
// LEZ data (methodName is "get_valid_roots" or "get_merkle_proofs"; params is
// the config-account id, optionally ",<index>"). The host must deliver the
// result by invoking `callback(... , callbackData)` before returning, and
// return 0 on success. fetcherData is the opaque pointer registered alongside.
typedef int (*Libp2pMixRlnFetcherFunc)(const char *methodName,
                                       const char *params,
                                       Libp2pMixRlnFetchCallback callback,
                                       void *callbackData, void *fetcherData);

// Parse config JSON and register the RLN SpamProtection factory into the mix
// protocol. MUST be called BEFORE libp2p_new (the factory is read once when
// the mix protocol mounts). Returns 0 on success.
//
// config JSON keys (all optional except as noted by your deployment):
//   rlnIdentifier        : array<int> (<=32 bytes), network-wide constant
//   epochDurationSeconds : number   (default 10)
//   userMessageLimit     : int      (default 100)
//   useOnchainLEZ        : bool      (default true)
//   keystorePath         : string
//   keystorePassword     : string
//   configAccount        : string   (LEZ config-account id for fetches)
int libp2p_mix_rln_enable(const char *config_json);

// Install the host fetcher used for LEZ get_valid_roots / get_merkle_proofs.
// Returns 0 on success.
int libp2p_mix_rln_set_fetcher(Libp2pMixRlnFetcherFunc fn, void *user_data);

// Set the RLN credential (idSecretHash used directly, 32 bytes) and the
// on-chain membership leaf index. Call after registration confirms on-chain.
// Returns 0 on success.
int libp2p_mix_rln_set_identity(const uint8_t *id_secret_hash, size_t len,
                                int64_t leaf_index);

// Push a single merkle-proof JSON object (element [0] of get_merkle_proofs'
// array) directly into the group manager's cached proof + root tracker. Lets
// the host fetch the proof on its own (Qt) thread and avoid the libp2p-thread
// cross-module deadlock. Returns 0 on success, 1 on failure (incl. empty/
// unparseable proof — caller retries until the membership lands in the tree).
int libp2p_mix_rln_set_cached_proof(const char *proof_json);

// Host callback invoked FROM THE LIBP2P THREAD when proof verification
// misses the valid-roots window and requests a fresh on-chain read. It must
// ONLY set a host-side flag and return — any blocking or cross-module call
// here stalls the chronos loop (and QtRO calls deadlock). The host performs
// the read on its own thread and answers via libp2p_mix_rln_set_valid_roots.
typedef void (*Libp2pMixRlnRefreshRequester)(void *user_data);

// Install the refresh requester. Returns 0 on success.
int libp2p_mix_rln_set_refresh_requester(Libp2pMixRlnRefreshRequester fn,
                                         void *user_data);

// Push a fresh valid-roots read (JSON array of 32-byte hex strings, newest
// first — get_valid_roots output verbatim) into the root tracker. Call from
// the host's own (Qt) thread. Returns 0 on success, 1 on failure (unparseable
// or empty — transient failures are fine, the verifier re-requests after its
// throttle interval).
int libp2p_mix_rln_set_valid_roots(const char *roots_json);

// 1 if the group manager can generate proofs (membership confirmed and a
// merkle proof cached), else 0.
int libp2p_mix_rln_is_ready(void);

// Start the LEZ poll loop. Call AFTER the node is started. Returns 0 on success.
// LEGACY/dormant path: calling this from a host whose fetch callbacks do
// synchronous cross-module (QtRO) calls reintroduces the libp2p-thread deadlock
// that the host-driven proof push (libp2p_mix_rln_set_cached_proof) replaced.
// See the autostartSpamProtection rationale in cbind.nim.
int libp2p_mix_rln_start_polling(void);

#ifdef __cplusplus
}
#endif

#endif // LIBP2P_MIX_RLN_H
