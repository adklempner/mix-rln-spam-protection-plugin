# Unit tests for the RLN cbind C surface
# FEATURE: cbind-rln tests with a mocked C fetcher

## Drives the libp2p_mix_rln_* C surface with a stub C fetcher (no real LSSA
## sequencer): trampoline round-trip, JSON parse, factory registration,
## identity attach, and the readiness gate transitioning once a poll cycle
## caches a proof from the stub.

import std/[options, unittest]
import chronos
import results

import ../src/mix_rln_spam_protection/cbind
import ../src/mix_rln_spam_protection/spam_protection
import ../src/mix_rln_spam_protection/onchain_group_manager
import ../src/mix_rln_spam_protection/types

import pkg/libp2p_mix/spam_protection_factory

const
  Root0 = "1111111111111111111111111111111111111111111111111111111111111111"
  Root1 = "2222222222222222222222222222222222222222222222222222222222222222"
  PathElem = "3333333333333333333333333333333333333333333333333333333333333333"

  RootsJson = "[\"" & Root0 & "\",\"" & Root1 & "\"]"
  ProofJson =
    "{\"root\":\"" & Root0 & "\"," &
    "\"path_elements\":[\"" & PathElem & "\"]," &
    "\"path_indices\":[0]," &
    "\"valid_roots\":[\"" & Root0 & "\",\"" & Root1 & "\"]}"

# Stub C fetcher: answers get_valid_roots / get_merkle_proofs from the canned
# JSON above, delivering the result via the callback exactly like the host would.
proc stubFetcher(
    methodName: cstring,
    params: cstring,
    callback: RlnFetchCallback,
    callbackData: pointer,
    fetcherData: pointer,
): cint {.cdecl, gcsafe, raises: [].} =
  let m = $methodName
  var resp = ""
  if m == "get_valid_roots":
    resp = RootsJson
  elif m == "get_merkle_proofs":
    resp = ProofJson
  else:
    callback(1, nil, 0, callbackData)
    return 1
  callback(0, cast[ptr cchar](addr resp[0]), csize_t(resp.len), callbackData)
  return 0

proc enableConfig(): cstring =
  cstring(
    "{\"useOnchainLEZ\":true,\"userMessageLimit\":100," &
    "\"epochDurationSeconds\":10.0,\"configAccount\":\"testacct\"}"
  )

var requesterHits = 0

# Stub refresh requester: like the host trampoline, it only flips state — no
# blocking work on the (simulated) libp2p thread.
proc stubRequester(userData: pointer) {.cdecl, gcsafe, raises: [].} =
  inc requesterHits

suite "mix-rln cbind C surface":
  test "set_fetcher + callFetcher trampoline round-trip":
    check libp2p_mix_rln_set_fetcher(stubFetcher, nil) == 0
    let roots = callFetcher("get_valid_roots", "testacct")
    check roots.isOk
    check roots.get() == RootsJson
    let proof = callFetcher("get_merkle_proofs", "testacct,0")
    check proof.isOk
    check proof.get() == ProofJson

  test "parseRoots / parseProof decode canned LEZ JSON":
    let roots = parseRoots(RootsJson)
    check roots.isOk
    check roots.get().len == 2
    let proof = parseProof(ProofJson)
    check proof.isOk
    check proof.get().validRoots.len == 2
    check proof.get().pathElements.len == 32
    check proof.get().identityPathIndex == @[byte(0)]

  test "enable registers a SpamProtection factory":
    check libp2p_mix_rln_enable(enableConfig()) == 0
    let sp = makeSpamProtection()
    check sp.isSome

  test "set_identity attaches credentials; readiness gate flips after a poll":
    check libp2p_mix_rln_set_fetcher(stubFetcher, nil) == 0
    check libp2p_mix_rln_enable(enableConfig()) == 0

    let spOpt = makeSpamProtection()
    check spOpt.isSome
    let gm = OnchainLEZGroupManager(MixRlnSpamProtection(spOpt.get()).groupManager)

    # No proof cached yet -> not ready for generation.
    check libp2p_mix_rln_is_ready() == 0

    var secret: array[32, byte]
    for i in 0 ..< 32: secret[i] = byte(i + 1)
    check libp2p_mix_rln_set_identity(addr secret[0], 32, 0'i64) == 0
    check gm.credentials.isSome
    check gm.membershipIndex == some(MembershipIndex(0))

    # Still not ready: credentials set but no cached proof.
    check libp2p_mix_rln_is_ready() == 0

    # Drive one poll cycle: the loop's first iteration runs immediately,
    # fetching the proof from the stub and caching it -> ready flips to 1.
    check (waitFor gm.init()).isOk
    check (waitFor gm.start()).isOk
    check libp2p_mix_rln_start_polling() == 0
    waitFor sleepAsync(400.milliseconds)
    check libp2p_mix_rln_is_ready() == 1

  test "set_valid_roots lands a host roots push in the tracker":
    check libp2p_mix_rln_enable(enableConfig()) == 0
    let spOpt = makeSpamProtection()
    check spOpt.isSome
    let gm = OnchainLEZGroupManager(MixRlnSpamProtection(spOpt.get()).groupManager)

    check libp2p_mix_rln_set_valid_roots(cstring(RootsJson)) == 0
    let expected = parseRoots(RootsJson).get()
    check gm.rootTracker.containsRoot(expected[0])
    check gm.rootTracker.containsRoot(expected[1])

  test "refresh requester fires on a root miss; set_valid_roots recovers it":
    check libp2p_mix_rln_enable(enableConfig()) == 0
    check libp2p_mix_rln_set_refresh_requester(stubRequester, nil) == 0
    requesterHits = 0

    # Local async scope so the closures capture locals, not test-body globals.
    proc missScenario(): Future[(bool, int)] {.async.} =
      let spOpt = makeSpamProtection()
      if spOpt.isNone:
        return (false, -1)
      let gm = OnchainLEZGroupManager(MixRlnSpamProtection(spOpt.get()).groupManager)

      const missingJson = "[\"" & PathElem & "\"]"
      let missing = parseRoots(missingJson).get()[0]

      proc hostAnswers() {.async.} =
        await sleepAsync(150.milliseconds)
        discard libp2p_mix_rln_set_valid_roots(cstring(missingJson))

      asyncSpawn hostAnswers()
      let recovered = await gm.awaitRootRefresh(missing)
      return (recovered, requesterHits)

    let (recovered, hits) = waitFor missScenario()
    check recovered
    check hits == 1

when isMainModule:
  discard
