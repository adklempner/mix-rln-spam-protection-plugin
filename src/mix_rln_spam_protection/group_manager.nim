# Mix RLN Spam Protection Plugin
# Copyright (c) 2025 vacp2p
# Licensed under either of Apache License 2.0 or MIT license.

## Group Manager module for RLN membership management.
##
## The GroupManager obtains Merkle roots and proofs from an external
## service instead of maintaining a local tree. The external service
## is accessed via abstract callbacks (FetchMerkleProofCallback,
## FetchLatestRootsCallback) that the caller provides. This keeps the
## plugin transport-agnostic.
##
## A polling loop periodically fetches the latest root and pre-caches
## our Merkle proof so that generateProof (which is synchronous) can use it.

import std/[tables, deques, options, hashes, sets]
import chronos
import results
import chronicles

import ./types
import ./constants
import ./codec
import ./rln_interface

export types, constants, codec

logScope:
  topics = "mix-rln-group-manager"

type
  # Callback types for group manager events
  OnRegisterCallback* = proc(
    commitment: IDCommitment, index: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}
  OnWithdrawCallback* = proc(
    commitment: IDCommitment, index: MembershipIndex
  ): Future[void] {.gcsafe, raises: [].}

  # Membership entry in the group
  Membership* = object
    commitment*: IDCommitment
    index*: MembershipIndex

  # Root tracker for maintaining valid roots window
  MerkleRootTracker* = ref object
    validRoots: Deque[MerkleNode] # Maintains order for getValidRoots
    rootSet: HashSet[MerkleNode] # O(1) lookup for containsRoot
    windowSize: int

  # Group manager backed by an external Merkle proof service.
  # Does not maintain a local Merkle tree.
  GroupManager* = ref object
    rlnInstance*: RLNInstance
    credentials*: Option[IdentityCredential]
    membershipIndex*: Option[MembershipIndex]
    rootTracker*: MerkleRootTracker
    onRegister: Option[OnRegisterCallback]
    onWithdraw: Option[OnWithdrawCallback]
    isInitialized*: bool
    isSynced*: bool
    userMessageLimit*: uint64 ## Max messages per epoch for this group
    fetchMerkleProof: Option[FetchMerkleProofCallback]
    fetchLatestRoots: Option[FetchLatestRootsCallback]
    pollIntervalSeconds: float
    pollFuture: Future[void]
    # Cached Merkle proof for synchronous generateProof
    cachedProof: Option[ExternalMerkleProof]
    # Lightweight membership tracking (for spam recovery, no local tree)
    membershipByIdCommitment: Table[IDCommitment, MembershipIndex]
    membershipByIndex: Table[MembershipIndex, IDCommitment]

# Hash function for MerkleNode (needed for HashSet)
proc hash*(node: MerkleNode): Hash =
  var h: Hash = 0
  for b in node:
    h = h !& int(b)
  result = !$h

# MerkleRootTracker implementation

proc newMerkleRootTracker*(
    windowSize: int = AcceptableRootWindowSize
): MerkleRootTracker =
  ## Create a new Merkle root tracker.
  MerkleRootTracker(
    validRoots: initDeque[MerkleNode](),
    rootSet: initHashSet[MerkleNode](),
    windowSize: windowSize,
  )

proc addRoot*(tracker: MerkleRootTracker, root: MerkleNode) =
  ## Add a new root to the tracker, removing oldest if at capacity.
  if tracker.validRoots.len >= tracker.windowSize:
    let oldRoot = tracker.validRoots.popFirst()
    tracker.rootSet.excl(oldRoot)
  tracker.validRoots.addLast(root)
  tracker.rootSet.incl(root)

proc containsRoot*(tracker: MerkleRootTracker, root: MerkleNode): bool =
  ## Check if a root is in the valid window. O(1) lookup.
  root in tracker.rootSet

proc getValidRoots*(tracker: MerkleRootTracker): seq[MerkleNode] =
  ## Get all valid roots.
  result = newSeq[MerkleNode](tracker.validRoots.len)
  for i, r in tracker.validRoots:
    result[i] = r

# GroupManager implementation

proc newGroupManager*(
    rlnInstance: RLNInstance,
    pollIntervalSeconds: float = 5.0,
    userMessageLimit: uint64 = UserMessageLimit,
): GroupManager =
  ## Create a new group manager.
  ## Callbacks must be set via setFetchMerkleProof/setFetchLatestRoots before init.
  GroupManager(
    rlnInstance: rlnInstance,
    credentials: none(IdentityCredential),
    membershipIndex: none(MembershipIndex),
    rootTracker: newMerkleRootTracker(),
    onRegister: none(OnRegisterCallback),
    onWithdraw: none(OnWithdrawCallback),
    isInitialized: false,
    isSynced: false,
    userMessageLimit: userMessageLimit,
    fetchMerkleProof: none(FetchMerkleProofCallback),
    fetchLatestRoots: none(FetchLatestRootsCallback),
    pollIntervalSeconds: pollIntervalSeconds,
    pollFuture: nil,
    cachedProof: none(ExternalMerkleProof),
    membershipByIdCommitment: initTable[IDCommitment, MembershipIndex](),
    membershipByIndex: initTable[MembershipIndex, IDCommitment](),
  )

proc setFetchMerkleProof*(
    gm: GroupManager, callback: FetchMerkleProofCallback
) =
  ## Set the callback for fetching Merkle proofs from the external service.
  gm.fetchMerkleProof = some(callback)

proc setFetchLatestRoots*(
    gm: GroupManager, callback: FetchLatestRootsCallback
) =
  ## Set the callback for fetching the latest valid Merkle roots.
  gm.fetchLatestRoots = some(callback)

proc setOnRegister*(gm: GroupManager, callback: OnRegisterCallback) =
  ## Set callback for when new members are registered.
  gm.onRegister = some(callback)

proc setOnWithdraw*(gm: GroupManager, callback: OnWithdrawCallback) =
  ## Set callback for when members are withdrawn.
  gm.onWithdraw = some(callback)

proc pollLoop(gm: GroupManager) {.async.} =
  ## Background loop that periodically fetches the valid roots and
  ## pre-caches our Merkle proof for synchronous generateProof.
  while gm.isSynced:
    # Fetch latest valid roots
    if gm.fetchLatestRoots.isSome:
      let rootsResult = await gm.fetchLatestRoots.get()()
      if rootsResult.isOk:
        let roots = rootsResult.get()
        # Add roots in reverse order (oldest first) so the newest ends up
        # at the tail of the tracker deque
        for i in countdown(roots.high, 0):
          gm.rootTracker.addRoot(roots[i])
        trace "Polled valid roots from service", count = roots.len
      else:
        warn "Failed to fetch valid roots from service", error = rootsResult.error

    # Fetch and cache our Merkle proof
    if gm.fetchMerkleProof.isSome and gm.membershipIndex.isSome:
      let proofResult =
        await gm.fetchMerkleProof.get()(gm.membershipIndex.get())
      if proofResult.isOk:
        gm.cachedProof = some(proofResult.get())
        # The proof's root is also a valid root
        gm.rootTracker.addRoot(proofResult.get().root)
        trace "Cached Merkle proof from service",
          memberIndex = gm.membershipIndex.get()
      else:
        warn "Failed to fetch Merkle proof from service",
          error = proofResult.error

    await sleepAsync(seconds(gm.pollIntervalSeconds.int64))

proc init*(gm: GroupManager): Future[RlnResult[void]] {.async.} =
  ## Initialize the group manager.
  if gm.isInitialized:
    return ok()

  # Fetch initial roots to seed the tracker
  if gm.fetchLatestRoots.isSome:
    let rootsResult = await gm.fetchLatestRoots.get()()
    if rootsResult.isOk:
      let roots = rootsResult.get()
      for i in countdown(roots.high, 0):
        gm.rootTracker.addRoot(roots[i])
      debug "Seeded root tracker from service", rootCount = roots.len
    else:
      warn "Could not fetch initial roots, tracker will be seeded on first poll",
        error = rootsResult.error

  gm.isInitialized = true
  info "Group manager initialized"
  ok()

proc start*(gm: GroupManager): Future[RlnResult[void]] {.async.} =
  ## Start the group manager. Begins polling for roots and proofs.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  gm.isSynced = true

  # Start polling loop
  gm.pollFuture = gm.pollLoop()

  info "Group manager started",
    pollIntervalSeconds = gm.pollIntervalSeconds
  ok()

proc stop*(gm: GroupManager) {.async.} =
  ## Stop the group manager.
  gm.isSynced = false
  if gm.pollFuture != nil and not gm.pollFuture.finished:
    await gm.pollFuture.cancelAndWait()
  info "Group manager stopped"

proc register*(
    gm: GroupManager, commitment: IDCommitment
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register a member in local tracking tables.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  if gm.membershipByIdCommitment.hasKey(commitment):
    return err("Member already registered")

  # Assign the next local index for tracking purposes
  let index = MembershipIndex(gm.membershipByIndex.len)

  gm.membershipByIdCommitment[commitment] = index
  gm.membershipByIndex[index] = commitment

  if gm.onRegister.isSome:
    await gm.onRegister.get()(commitment, index)

  debug "Member registered", index = index
  ok(index)

proc register*(
    gm: GroupManager, credentials: IdentityCredential
): Future[RlnResult[MembershipIndex]] {.async.} =
  ## Register self with credentials.
  if gm.membershipIndex.isSome:
    return ok(gm.membershipIndex.get())

  let indexResult = await gm.register(credentials.idCommitment)
  if indexResult.isErr:
    return err(indexResult.error)

  let index = indexResult.get()
  gm.credentials = some(credentials)
  gm.membershipIndex = some(index)

  debug "Self registered", index = index
  ok(index)

proc withdraw*(
    gm: GroupManager, index: MembershipIndex
): Future[RlnResult[void]] {.async.} =
  ## Remove a member from local tracking.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  if not gm.membershipByIndex.hasKey(index):
    return err("Member not found at index")

  let idCommitment = gm.membershipByIndex[index]
  gm.membershipByIdCommitment.del(idCommitment)
  gm.membershipByIndex.del(index)

  if gm.onWithdraw.isSome:
    await gm.onWithdraw.get()(idCommitment, index)

  if gm.membershipIndex.isSome and gm.membershipIndex.get() == index:
    gm.credentials = none(IdentityCredential)
    gm.membershipIndex = none(MembershipIndex)
    warn "Self membership withdrawn"

  debug "Member withdrawn", index = index
  ok()

{.push raises: [], gcsafe.}

proc isReady*(gm: GroupManager): bool =
  ## Check if the group manager is ready for proof operations.
  gm.isInitialized and gm.isSynced and gm.credentials.isSome and
    gm.membershipIndex.isSome

proc validateRoot*(gm: GroupManager, root: MerkleNode): bool =
  ## Check if a Merkle root is valid (in the acceptable window).
  gm.rootTracker.containsRoot(root)

proc generateProof*(
    gm: GroupManager,
    signal: openArray[byte],
    epoch: Epoch,
    rlnIdentifier: RlnIdentifier,
    messageId: uint = 0,
): RlnResult[RateLimitProof] =
  ## Generate an RLN proof using the cached Merkle proof from the external service.
  if not gm.isReady():
    return err("Group manager not ready")

  if gm.cachedProof.isNone:
    return err("No cached Merkle proof available (service not responding?)")
  let cachedProof = gm.cachedProof.get()

  let creds = gm.credentials.get()

  trace "Generating proof with external witness",
    membershipIndex = gm.membershipIndex.get()

  generateRlnProofFromExternalWitness(
    gm.rlnInstance,
    creds,
    cachedProof.pathElements,
    cachedProof.identityPathIndex,
    epoch,
    rlnIdentifier,
    signal,
    messageId,
    gm.userMessageLimit,
  )

proc verifyProof*(
    gm: GroupManager,
    proof: RateLimitProof,
    signal: openArray[byte],
    rlnIdentifier: RlnIdentifier,
): RlnResult[bool] =
  ## Verify an RLN proof using the valid roots window.
  if not gm.isInitialized:
    return err("Group manager not initialized")

  let validRoots = gm.rootTracker.getValidRoots()
  gm.rlnInstance.verifyRlnProof(proof, rlnIdentifier, signal, validRoots)

proc getMemberCount*(gm: GroupManager): int =
  gm.membershipByIndex.len

proc getMemberIndexByIdCommitment*(
    gm: GroupManager, idCommitment: IDCommitment
): Option[MembershipIndex] =
  try:
    if gm.membershipByIdCommitment.hasKey(idCommitment):
      some(gm.membershipByIdCommitment[idCommitment])
    else:
      none(MembershipIndex)
  except KeyError:
    none(MembershipIndex)

proc hasMemberByIdCommitment*(
    gm: GroupManager, idCommitment: IDCommitment
): bool =
  gm.membershipByIdCommitment.hasKey(idCommitment)

proc getMemberIdCommitment*(
    gm: GroupManager, index: MembershipIndex
): Option[IDCommitment] =
  try:
    if gm.membershipByIndex.hasKey(index):
      some(gm.membershipByIndex[index])
    else:
      none(IDCommitment)
  except KeyError:
    none(IDCommitment)

proc getMemberRateLimit*(
    gm: GroupManager, idCommitment: IDCommitment
): uint64 =
  ## Get the rate limit of a member by idCommitment.
  gm.userMessageLimit

{.pop.}
