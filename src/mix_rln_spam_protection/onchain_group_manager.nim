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
    # Roots window read atomically with `root` from the same on-chain account,
    # so consumers can refresh rootTracker without a separate get_valid_roots
    # call that could race a fresh registration tx.
    validRoots*: seq[MerkleNode]

  OnchainLEZGroupManager* = ref object of GroupManager
    fetchRoots: FetchRootsCallback
    fetchProof: FetchProofCallback
    pollInterval: Duration
    cachedProof: Option[ExternalMerkleProof]
    # Stamp set whenever pollLoop's fetchProof leg succeeds and cachedProof
    # is replaced. Used by generateProof to refuse shipping a proof built
    # from a cachedProof older than `2 * pollInterval`: under healthy RPC
    # the next successful poll should always have refreshed within one
    # interval, so >2x means polls have been silently stalling and the
    # cached (cachedProof, rootTracker) pair is stale enough to risk
    # carrying a multi-fetch-race-poisoned snapshot from get_merkle_proofs.
    cachedProofRefreshedAt: Option[Moment]
    # Set once the gifter status watcher confirms our registration tx has
    # landed on-chain. Used by the pre-publish gate to wait a post-confirm
    # cushion so peers have time to poll the new root before we ship a
    # proof that references it.
    membershipConfirmedAt: Option[Moment]

proc new*(
    T: typedesc[OnchainLEZGroupManager],
    rlnInstance: RLNInstance,
    userMessageLimit: uint64 = UserMessageLimit,
    pollInterval: Duration = seconds(10),
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
  info "OnchainLEZGroupManager started (poll loop deferred)",
    intervalSeconds = gm.pollInterval.seconds
  ok()

proc startPolling*(gm: OnchainLEZGroupManager) =
  ## Start the background poll loop. Call AFTER the node is fully started
  ## to avoid interfering with switch.start().
  if gm.isSynced and gm.fetchRoots != nil:
    asyncSpawn gm.pollLoop()

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
  ## Ready for proof GENERATION (needs credentials + cached proof from LEZ).
  gm.isInitialized and gm.isSynced and
    gm.credentials.isSome and gm.membershipIndex.isSome and
    gm.cachedProof.isSome

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
  if not gm.isReady():
    return err("OnchainLEZ group manager not ready")

  # Staleness gate: refuse to ship a proof built from a cachedProof whose
  # last refresh predates `2 * pollInterval`. Under healthy RPC the poll
  # cadence guarantees a refresh every `pollInterval` (~10s default); >2x
  # means polls have stalled, leaving a (cachedProof, rootTracker) pair
  # that may carry a multi-fetch-race poisoned snapshot from a prior
  # get_merkle_proofs response. Better to fail closed and let mix_protocol
  # drop the packet at this hop than to ship a self-verify-failing proof
  # that the next hop will also drop.
  if gm.cachedProofRefreshedAt.isSome:
    let age = Moment.now() - gm.cachedProofRefreshedAt.get()
    let threshold = gm.pollInterval * 2
    if age > threshold:
      warn "OnchainLEZ cachedProof staleness threshold exceeded; refusing",
        ageMs = age.milliseconds, thresholdMs = threshold.milliseconds
      return err(
        "cachedProof stale (>" & $threshold.milliseconds &
        "ms since last successful pollLoop refresh)"
      )

  let creds = gm.credentials.get()
  let proof = gm.cachedProof.get()

  trace "Generating proof with external LEZ witness",
    membershipIndex = gm.membershipIndex.get(),
    pathElementsLen = proof.pathElements.len,
    pathIndexLen = proof.identityPathIndex.len

  let r = gm.rlnInstance.generateRlnProofWithExternalWitness(
    proof.pathElements,
    proof.identityPathIndex,
    creds,
    epoch,
    rlnIdentifier,
    signal,
    messageId,
    gm.userMessageLimit,
  )
  # Diagnostic: cachedProof.root is what LEZ TOLD us the witness anchors to;
  # proof.merkleRoot is what Zerokit COMPUTED from (pathElements, leaf, path).
  # If these differ, the LEZ FFI returned an internally inconsistent
  # (root, pathElements) pair — server-side multi-fetch staleness. Logging at
  # info so it always lands in the .lgx-bundled build's chronicles output.
  if r.isOk:
    let p = r.get()
    if p.merkleRoot != proof.root:
      info "LEZ proof root vs witness-implied root MISMATCH",
        cachedRoot = proof.root.toHex(),
        computedRoot = p.merkleRoot.toHex(),
        pathLen = proof.pathElements.len
    else:
      trace "LEZ proof root matches witness-implied root",
        root = proof.root.toHex()
  r

proc proofRoot*(gm: OnchainLEZGroupManager): Option[MerkleNode] =
  ## Root our next-generated proof will reference. None until first poll lands.
  if gm.cachedProof.isSome:
    some(gm.cachedProof.get().root)
  else:
    none(MerkleNode)

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
        gm.cachedProof = some(p)
        # Stamp the refresh moment so generateProof can gate on staleness.
        gm.cachedProofRefreshedAt = some(Moment.now())
        gm.rootTracker.resetRoots()
        for r in p.validRoots:
          gm.rootTracker.addRoot(r)
        if not gm.rootTracker.containsRoot(p.root):
          # Defensive: same on-chain read should already include `root`,
          # but add it so self-verify accepts proofs we just generated.
          gm.rootTracker.addRoot(p.root)
          # Promote to info so .lgx-bundled chronicles surfaces it: when
          # this fires, the get_merkle_proofs JSON returned `root` and
          # `validRoots` from different chain snapshots — direct evidence
          # of the C++ multi-fetch race in LogosRlnModule::get_merkle_proofs.
          info "Proof root missing from unified validRoots; added defensively",
            proofRoot = p.root.toHex(),
            validRootsCount = p.validRoots.len
        trace "Cached merkle proof from LEZ",
          pathElementsLen = p.pathElements.len,
          unifiedRootsCount = p.validRoots.len
      else:
        debug "Failed to fetch merkle proof from LEZ", error = proofResult.error

    await sleepAsync(gm.pollInterval)
