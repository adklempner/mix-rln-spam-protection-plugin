{.push raises: [].}

## On-chain LEZ group manager for mix RLN spam protection.
##
## Fetches Merkle roots and proofs from the LSSA sequencer via the logos-core
## RLN module's callback bridge. Does NOT maintain a local tree — proof
## generation uses external witnesses from LEZ directly.

import std/[options]
import chronos
import results
import chronicles

import ./types
import ./constants
import ./rln_interface
import ./group_manager

export group_manager

logScope:
  topics = "mix-rln-onchain-lez"

type
  FetchRootsCallback* = proc(): Future[RlnResult[seq[MerkleNode]]] {.gcsafe, raises: [].}
  FetchProofCallback* = proc(index: MembershipIndex): Future[RlnResult[ExternalMerkleProof]] {.gcsafe, raises: [].}

  ExternalMerkleProof* = object
    pathElements*: seq[byte]
    identityPathIndex*: seq[byte]
    root*: MerkleNode

  OnchainLEZGroupManager* = ref object of GroupManager
    fetchRoots: FetchRootsCallback
    fetchProof: FetchProofCallback
    pollInterval: Duration
    cachedProof: Option[ExternalMerkleProof]

proc new*(
    T: typedesc[OnchainLEZGroupManager],
    rlnInstance: RLNInstance,
    userMessageLimit: uint64 = UserMessageLimit,
    pollInterval: Duration = seconds(5),
): T =
  T(
    rlnInstance: rlnInstance,
    userMessageLimit: userMessageLimit,
    rootTracker: newMerkleRootTracker(),
    pollInterval: pollInterval,
    isInitialized: false,
    isSynced: false,
  )

proc setFetchCallbacks*(
    gm: OnchainLEZGroupManager,
    fetchRoots: FetchRootsCallback,
    fetchProof: FetchProofCallback,
) =
  gm.fetchRoots = fetchRoots
  gm.fetchProof = fetchProof

proc pollLoop(gm: OnchainLEZGroupManager) {.async.}
  # forward declaration

method init*(gm: OnchainLEZGroupManager): Future[RlnResult[void]] {.async.} =
  if gm.isInitialized:
    return ok()
  gm.isInitialized = true
  info "OnchainLEZGroupManager initialized"
  ok()

method start*(gm: OnchainLEZGroupManager): Future[RlnResult[void]] {.async.} =
  if not gm.isInitialized:
    return err("Not initialized")
  if gm.fetchRoots.isNil or gm.fetchProof.isNil:
    return err("Fetch callbacks not set")

  gm.isSynced = true
  info "OnchainLEZGroupManager started polling",
    intervalSeconds = gm.pollInterval.seconds

  # Start background poll loop (non-blocking)
  asyncSpawn gm.pollLoop()
  ok()

method stop*(gm: OnchainLEZGroupManager): Future[void] {.async.} =
  gm.isSynced = false

method register*(
    gm: OnchainLEZGroupManager, commitment: IDCommitment
): Future[RlnResult[MembershipIndex]] {.async.} =
  return err("External registration not supported — use selfRegisterRln via delivery_module")

method register*(
    gm: OnchainLEZGroupManager, credentials: IdentityCredential
): Future[RlnResult[MembershipIndex]] {.async.} =
  return err("Self-registration not supported — use selfRegisterRln via delivery_module")

method withdraw*(
    gm: OnchainLEZGroupManager, index: MembershipIndex
): Future[RlnResult[void]] {.async.} =
  return err("Withdrawal not supported for on-chain LEZ group manager")

{.push raises: [], gcsafe.}

method isReady*(gm: OnchainLEZGroupManager): bool =
  gm.isInitialized and gm.isSynced and
    gm.credentials.isSome and gm.membershipIndex.isSome and
    gm.cachedProof.isSome

method generateProof*(
    gm: OnchainLEZGroupManager,
    signal: openArray[byte],
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    messageId: uint = 0,
): RlnResult[RateLimitProof] =
  if not gm.isReady():
    return err("OnchainLEZ group manager not ready")

  let creds = gm.credentials.get()
  let proof = gm.cachedProof.get()

  trace "Generating proof with external LEZ witness",
    membershipIndex = gm.membershipIndex.get(),
    pathElementsLen = proof.pathElements.len,
    pathIndexLen = proof.identityPathIndex.len

  gm.rlnInstance.generateRlnProofWithExternalWitness(
    proof.pathElements,
    proof.identityPathIndex,
    creds,
    epoch,
    rlnIdentifier,
    signal,
    messageId,
    gm.userMessageLimit,
  )

{.pop.}

proc pollLoop(gm: OnchainLEZGroupManager) {.async.} =
  while gm.isSynced:
    # Fetch roots from LEZ
    try:
      let rootsResult = await gm.fetchRoots()
      if rootsResult.isOk:
        let roots = rootsResult.get()
        for root in roots:
          gm.rootTracker.addRoot(root)
        trace "Polled valid roots from LEZ", count = roots.len
      else:
        debug "Failed to fetch roots from LEZ", error = rootsResult.error
    except CatchableError as e:
      debug "Exception fetching roots", error = e.msg

    # Fetch merkle proof for our membership index
    if gm.membershipIndex.isSome:
      try:
        let proofResult = await gm.fetchProof(gm.membershipIndex.get())
        if proofResult.isOk:
          gm.cachedProof = some(proofResult.get())
          trace "Cached merkle proof from LEZ",
            pathElementsLen = proofResult.get().pathElements.len
        else:
          debug "Failed to fetch merkle proof from LEZ", error = proofResult.error
      except CatchableError as e:
        debug "Exception fetching proof", error = e.msg

    await sleepAsync(gm.pollInterval)
