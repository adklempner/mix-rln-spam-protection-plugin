{.push raises: [].}

## On-chain LEZ group manager for mix RLN spam protection.
##
## Fetches Merkle roots and proofs from the LSSA sequencer via the logos-core
## RLN module's callback bridge. Does NOT maintain a local tree — proof
## generation uses external witnesses from LEZ directly.

import std/[options, locks]
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
  HostRefreshRequester* = proc() {.gcsafe, raises: [].}

  ExternalMerkleProof* = object
    pathElements*: seq[byte]
    identityPathIndex*: seq[byte]
    root*: MerkleNode
    # Roots window read atomically with `root` from the same on-chain account,
    # so consumers can refresh rootTracker without a separate get_valid_roots
    # call that could race a fresh registration tx.
    validRoots*: seq[MerkleNode]

  OnchainLEZGroupManager* = ref object of GroupManager
    fetchRoots: FetchRootsCallback
    fetchProof: FetchProofCallback
    pollInterval: Duration
    cachedProof: Option[ExternalMerkleProof]
    # Set once the gifter status watcher confirms our registration tx has
    # landed on-chain. Used by the pre-publish gate to wait a post-confirm
    # cushion so peers have time to poll the new root before we ship a
    # proof that references it.
    membershipConfirmedAt: Option[Moment]
    # Guards against spawning the poll loop more than once (the mix-mount
    # factory autostarts it; a later libp2p_mix_rln_start_polling is a no-op).
    isPolling: bool
    # Guards cachedProof/credentials/membershipIndex against the cross-thread
    # race: the host writes them from the Qt thread (setCachedProof /
    # setCredential) while the libp2p thread reads them in isReady/generateProof.
    # The rootTracker has its own lock; setCachedProof nests them (stateLock
    # outer) so (cachedProof, rootTracker) update atomically together.
    stateLock: Lock
    # On-demand roots refresh state. Touched only from the libp2p thread
    # (chronos is single-threaded there), so no lock: awaitRootRefresh
    # throttles/coalesces via these, and the requester itself must only set a
    # host-side flag — the actual fetch happens on the host's own thread.
    lastRefreshRequest: Moment
    refreshInFlight: bool
    hostRefreshRequester: HostRefreshRequester

proc new*(
    T: typedesc[OnchainLEZGroupManager],
    rlnInstance: RLNInstance,
    userMessageLimit: uint64 = UserMessageLimit,
    pollInterval: Duration = seconds(10),
): T =
  result = T(
    rlnInstance: rlnInstance,
    userMessageLimit: userMessageLimit,
    rootTracker: newMerkleRootTracker(),
    pollInterval: pollInterval,
    isInitialized: false,
    isSynced: false,
  )
  result.stateLock.initLock()

proc setFetchCallbacks*(
    gm: OnchainLEZGroupManager,
    fetchRoots: FetchRootsCallback,
    fetchProof: FetchProofCallback,
) =
  gm.fetchRoots = fetchRoots
  gm.fetchProof = fetchProof

proc setHostRefreshRequester*(
    gm: OnchainLEZGroupManager, requester: HostRefreshRequester
) =
  gm.hostRefreshRequester = requester

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
  info "OnchainLEZGroupManager started (poll loop deferred)",
    intervalSeconds = gm.pollInterval.seconds
  ok()

proc startPolling*(gm: OnchainLEZGroupManager) =
  ## Start the background poll loop. Call AFTER the node is fully started
  ## to avoid interfering with switch.start(). Idempotent.
  if gm.isSynced and gm.fetchRoots != nil and not gm.isPolling:
    gm.isPolling = true
    asyncSpawn gm.pollLoop()

proc setCachedProof*(gm: OnchainLEZGroupManager, p: ExternalMerkleProof) =
  ## Push a merkle proof fetched by the host (on its own thread) directly into
  ## the GM, mirroring the poll loop's caching. Avoids the libp2p-thread
  ## cross-module fetch deadlock — the host fetches on the Qt thread and pushes.
  ## Held under stateLock (cachedProof) with rootTracker.rebuildRoots nested so
  ## a concurrent libp2p-thread reader never sees a half-applied (proof, roots).
  withLock gm.stateLock:
    gm.cachedProof = some(p)
    gm.rootTracker.rebuildRoots(p.validRoots, p.root)

proc applyHostRoots*(
    gm: OnchainLEZGroupManager, rootsNewestFirst: openArray[MerkleNode]
) =
  ## Replace the root window with a fresh on-chain roots read pushed by the
  ## host (Qt thread) in response to a refresh request. get_valid_roots
  ## returns newest-first (current root, then history newest-at-[0]) —
  ## reversed here so any over-capacity eviction in rebuildRoots drops the
  ## actual oldest. ensureRoot pins our own cachedProof root so a rebuild can
  ## never invalidate self-verification of our next generated proof.
  if rootsNewestFirst.len == 0:
    return
  var oldestFirst = newSeq[MerkleNode](rootsNewestFirst.len)
  for i in 0 ..< rootsNewestFirst.len:
    oldestFirst[rootsNewestFirst.len - 1 - i] = rootsNewestFirst[i]
  withLock gm.stateLock:
    let ensure =
      if gm.cachedProof.isSome:
        gm.cachedProof.get().root
      else:
        rootsNewestFirst[0]
    gm.rootTracker.rebuildRoots(oldestFirst, ensure)

proc setCredential*(
    gm: OnchainLEZGroupManager, idSecretHash: IDSecretHash, leaf: int64
) =
  ## Set the RLN credential + membership leaf from the host (Qt thread). Guarded
  ## so the libp2p-thread readiness/proof readers never observe a torn write.
  withLock gm.stateLock:
    var cred = IdentityCredential()
    cred.idSecretHash = idSecretHash
    gm.credentials = some(cred)
    if leaf >= 0:
      gm.membershipIndex = some(MembershipIndex(leaf))

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

method awaitRootRefresh*(
    gm: OnchainLEZGroupManager, root: MerkleNode
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Root-window miss recovery: ask the host for a fresh valid-roots read
  ## (throttled, coalesced) and wait for `root` to enter the window. Only the
  ## initiator stamps the throttle and clears the in-flight flag; concurrent
  ## verifiers join the same wait instead of issuing another request.
  if gm.rootTracker.containsRoot(root):
    return true
  if gm.hostRefreshRequester.isNil:
    return false

  var initiator = false
  if not gm.refreshInFlight:
    let now = Moment.now()
    if now - gm.lastRefreshRequest < RootsRefreshMinInterval:
      debug "Root refresh throttled",
        sinceLastRequestMs = (now - gm.lastRefreshRequest).milliseconds
      return false
    gm.lastRefreshRequest = now
    gm.refreshInFlight = true
    initiator = true
    gm.hostRefreshRequester()

  try:
    let deadline = Moment.now() + RootsRefreshAwaitTimeout
    while Moment.now() < deadline:
      await sleepAsync(RootsRefreshPollInterval)
      if gm.rootTracker.containsRoot(root):
        return true
    return false
  finally:
    if initiator:
      gm.refreshInFlight = false

{.push raises: [], gcsafe.}

method isReady*(gm: OnchainLEZGroupManager): bool =
  ## Ready for proof GENERATION (needs credentials + cached proof from LEZ).
  withLock gm.stateLock:
    result =
      gm.isInitialized and gm.isSynced and gm.credentials.isSome and
      gm.membershipIndex.isSome and gm.cachedProof.isSome

method isReadyForVerification*(gm: OnchainLEZGroupManager): bool =
  ## Ready for proof VERIFICATION (only needs to be initialized and synced).
  ## Does NOT require local credentials or cached proofs.
  gm.isInitialized and gm.isSynced

method generateProof*(
    gm: OnchainLEZGroupManager,
    signal: openArray[byte],
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    messageId: uint = 0,
): RlnResult[RateLimitProof] =
  # Snapshot the credential + proof under the lock (the readiness check is
  # inlined here rather than calling isReady() to avoid re-acquiring the
  # non-reentrant stateLock), then do the RLN math outside the lock.
  var creds: IdentityCredential
  var proof: ExternalMerkleProof
  var mIndex: MembershipIndex
  withLock gm.stateLock:
    if not (
      gm.isInitialized and gm.isSynced and gm.credentials.isSome and
      gm.membershipIndex.isSome and gm.cachedProof.isSome
    ):
      return err("OnchainLEZ group manager not ready")
    creds = gm.credentials.get()
    proof = gm.cachedProof.get()
    mIndex = gm.membershipIndex.get()

  trace "Generating proof with external LEZ witness",
    membershipIndex = mIndex,
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

proc proofRoot*(gm: OnchainLEZGroupManager): Option[MerkleNode] =
  ## Root our next-generated proof will reference. None until first poll lands.
  withLock gm.stateLock:
    if gm.cachedProof.isSome:
      result = some(gm.cachedProof.get().root)
    else:
      result = none(MerkleNode)

proc getPollInterval*(gm: OnchainLEZGroupManager): Duration =
  gm.pollInterval

proc markMembershipConfirmed*(gm: OnchainLEZGroupManager) =
  ## Record the time the registration tx confirmed on-chain. Idempotent —
  ## later calls don't move the timestamp.
  if gm.membershipConfirmedAt.isNone:
    gm.membershipConfirmedAt = some(Moment.now())

proc membershipConfirmedAt*(gm: OnchainLEZGroupManager): Option[Moment] =
  gm.membershipConfirmedAt

{.pop.}

proc pollLoop(gm: OnchainLEZGroupManager) {.async.} =
  while gm.isSynced:
    # Fetch the most recent valid roots from LEZ. When this node has a
    # membership we don't apply them yet — (cachedProof, validRoots) must
    # come from a single atomic LEZ read below, otherwise the tracker races
    # ahead of cachedProof and self-verify rejects our just-generated proof
    # with "Expected one of the provided roots" (the testnet flake).
    let rootsResult = await gm.fetchRoots()
    if rootsResult.isOk:
      let roots = rootsResult.get()
      if gm.membershipIndex.isNone:
        for root in roots:
          gm.rootTracker.addRoot(root)
      if roots.len > 0:
        debug "Polled valid roots from LEZ",
          count = roots.len,
          firstRoot = roots[0].toHex(),
          appliedToTracker = gm.membershipIndex.isNone
    else:
      debug "Failed to fetch roots from LEZ", error = rootsResult.error

    # For nodes WITH a membership: refresh (cachedProof, rootTracker) from
    # the same LEZ read so the proof root is guaranteed to be in the
    # validRoots window. On fetchProof failure, leave both at their previous
    # (consistent) values rather than rolling the tracker forward alone.
    if gm.membershipIndex.isSome:
      let proofResult = await gm.fetchProof(gm.membershipIndex.get())
      if proofResult.isOk:
        let p = proofResult.get()
        # Same atomic (cachedProof, rootTracker) update as setCachedProof so a
        # concurrent reader never sees a half-rebuilt window.
        withLock gm.stateLock:
          gm.cachedProof = some(p)
          gm.rootTracker.rebuildRoots(p.validRoots, p.root)
        trace "Cached merkle proof from LEZ",
          pathElementsLen = p.pathElements.len,
          unifiedRootsCount = p.validRoots.len
      else:
        debug "Failed to fetch merkle proof from LEZ", error = proofResult.error

    await sleepAsync(gm.pollInterval)
