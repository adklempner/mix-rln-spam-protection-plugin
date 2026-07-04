# C bindings for the mix RLN spam protection plugin
# FEATURE: cbind-rln C surface registering an RLN SpamProtection factory

## C surface that lets a host (logos-libp2p-module) enable RLN-backed mix spam
## protection without any RLN types crossing the C boundary. It registers a
## SpamProtection factory into libp2p_mix (read at mix mount time on the libp2p
## thread), bridges a C fetcher to the OnchainLEZGroupManager's root/proof
## callbacks, and exposes identity/readiness/polling controls.
##
## Threading: every global below is guarded by `stateLock` and stored as a
## value type or GC-erased `pointer`. The fetcher is invoked FROM the libp2p
## thread (where the chronos loop and group-manager poll loop run) and calls
## back into the host; storing a Nim ref/string in a cross-thread global
## SIGSEGVs under load when the GC collects mid-await (the known
## logos-delivery crash). Cast back to typed refs only under the lock.

{.push raises: [].}

import std/[json, locks, options, strutils]
import chronos
import chronicles
import results

import ./types
import ./spam_protection
import ./onchain_group_manager

import pkg/libp2p_mix/spam_protection as libp2p_spam
import pkg/libp2p_mix/spam_protection_factory

logScope:
  topics = "mix-rln-cbind"

type
  RlnFetchCallback* = proc(
    callerRet: cint, msg: ptr cchar, len: csize_t, userData: pointer
  ) {.cdecl, gcsafe, raises: [].}

  RlnFetcherFunc* = proc(
    methodName: cstring,
    params: cstring,
    callback: RlnFetchCallback,
    callbackData: pointer,
    fetcherData: pointer,
  ): cint {.cdecl, gcsafe, raises: [].}

const ConfigAccountCap = 64
  ## base58 config-account id fits in 44 chars; fixed buffer keeps the
  ## lock-protected global off the GC heap for cross-thread reads.

var
  stateLock: Lock
  fetcher: RlnFetcherFunc = nil
  fetcherData: pointer = nil
  configAccountBuf: array[ConfigAccountCap, char]
  configAccountLen: int = 0
  leafIndex: int64 = -1
  pendingConfig: MixRlnConfig
  haveConfig: bool = false
  groupManager: pointer = nil
    ## OnchainLEZGroupManager erased to pointer (cross-thread global, see top).

stateLock.initLock()

proc setConfigAccount(s: string) =
  let n = min(s.len, ConfigAccountCap)
  for i in 0 ..< n:
    configAccountBuf[i] = s[i]
  configAccountLen = n

proc getConfigAccount(): string =
  result = newString(configAccountLen)
  for i in 0 ..< configAccountLen:
    result[i] = configAccountBuf[i]

# --------------------------------------------------------------------------
# Fetcher trampoline: C fetcher -> Nim Result[string,string].
# Ported from logos-delivery logos_core_client.callRlnFetcher. The C callback
# copies the response into a stack FetchResult; no Nim ref crosses the cdecl.
# --------------------------------------------------------------------------

type FetchResult = object
  json: string
  errMsg: string
  success: bool

proc fetchCb(
    callerRet: cint, msg: ptr cchar, len: csize_t, userData: pointer
) {.cdecl, gcsafe, raises: [].} =
  let res = cast[ptr FetchResult](userData)
  if callerRet == 0 and not msg.isNil and len > 0:
    res[].json = newString(len.int)
    copyMem(addr res[].json[0], msg, len.int)
    res[].success = true
  elif not msg.isNil and len > 0:
    res[].errMsg = newString(len.int)
    copyMem(addr res[].errMsg[0], msg, len.int)
    res[].success = false
  else:
    res[].success = (callerRet == 0)

proc callFetcher*(methodName: string, params: string): Result[string, string] {.gcsafe.} =
  {.gcsafe.}:
    stateLock.acquire()
    let fn = fetcher
    let data = fetcherData
    stateLock.release()

  if fn.isNil:
    return err("RLN fetcher not registered")

  var fr: FetchResult
  let ret = fn(methodName.cstring, params.cstring, fetchCb, addr fr, data)
  if ret != 0 or not fr.success:
    if fr.errMsg.len > 0:
      return err(fr.errMsg)
    return err("RLN fetcher error code: " & $ret)
  if fr.json.len == 0:
    return err("RLN fetcher returned empty response")
  ok(fr.json)

# --------------------------------------------------------------------------
# JSON parsing for LEZ root/proof responses (ported from logos_core_client).
# --------------------------------------------------------------------------

proc hexToBytes32(hex: string): Result[array[32, byte], string] =
  var h = hex
  if h.startsWith("0x") or h.startsWith("0X"):
    h = h[2 .. ^1]
  if h.len != 64:
    return err("expected 64 hex chars, got " & $h.len)
  var output: array[32, byte]
  for i in 0 ..< 32:
    try:
      output[i] = byte(parseHexInt(h[i * 2 .. i * 2 + 1]))
    except ValueError:
      return err("invalid hex at " & $i)
  ok(output)

proc parseRoots*(snapshot: string): Result[seq[MerkleNode], string] =
  if snapshot.len == 0:
    return err("no roots data")
  try:
    let parsed = parseJson(snapshot)
    var roots: seq[MerkleNode]
    for elem in parsed:
      let root = hexToBytes32(elem.getStr()).valueOr:
        return err("invalid root hex: " & error)
      roots.add(MerkleNode(root))
    ok(roots)
  except CatchableError as e:
    err("failed to parse roots: " & e.msg)

proc parseProof*(snapshot: string): Result[ExternalMerkleProof, string] =
  if snapshot.len == 0:
    return err("no merkle proof data")
  try:
    let parsed = parseJson(snapshot)
    let root = hexToBytes32(parsed["root"].getStr()).valueOr:
      return err("invalid root hex: " & error)
    var pathElements: seq[byte]
    for elem in parsed["path_elements"]:
      let elemBytes = hexToBytes32(elem.getStr()).valueOr:
        return err("invalid pathElement hex: " & error)
      for b in elemBytes:
        pathElements.add(b)
    var identityPathIndex: seq[byte]
    for idx in parsed["path_indices"]:
      identityPathIndex.add(byte(idx.getInt()))
    var validRoots: seq[MerkleNode]
    if parsed.hasKey("valid_roots"):
      for r in parsed["valid_roots"]:
        let rb = hexToBytes32(r.getStr()).valueOr:
          continue
        validRoots.add(MerkleNode(rb))
    ok(ExternalMerkleProof(
      pathElements: pathElements,
      identityPathIndex: identityPathIndex,
      root: MerkleNode(root),
      validRoots: validRoots,
    ))
  except CatchableError as e:
    err("failed to parse proof: " & e.msg)

proc makeFetchRoots(): FetchRootsCallback =
  return proc(): Future[RlnResult[seq[MerkleNode]]] {.async, gcsafe, raises: [].} =
    let configAccount = (block:
      stateLock.acquire()
      let s = getConfigAccount()
      stateLock.release()
      s)
    if configAccount.len == 0:
      return err("RLN config account not set")
    let rootsJson = callFetcher("get_valid_roots", configAccount)
    if rootsJson.isErr:
      return err(rootsJson.error)
    parseRoots(rootsJson.get())

proc makeFetchProof(): FetchProofCallback =
  return proc(
      index: MembershipIndex
  ): Future[RlnResult[ExternalMerkleProof]] {.async, gcsafe, raises: [].} =
    let configAccount = (block:
      stateLock.acquire()
      let s = getConfigAccount()
      stateLock.release()
      s)
    if configAccount.len == 0:
      return err("RLN config account not set")
    let params = configAccount & "," & $index
    let proofJson = callFetcher("get_merkle_proofs", params)
    if proofJson.isErr:
      return err(proofJson.error)
    parseProof(proofJson.get())

# Drives the SpamProtection lifecycle (sp.init -> sp.start) on the libp2p thread
# at mix mount. The mix-mount path creates the plugin via the factory but never
# lifecycles it. Lifecycling the GROUP MANAGER alone is NOT enough: sp.state
# stays != Ready, and BOTH generateProof (sender) and verifyProof (every relay
# hop) gate on state==Ready -> proofs are silently skipped and verification
# short-circuits to "allow through". sp.init/sp.start internally lifecycle the GM
# too (gm.init/gm.start -> isInitialized/isSynced) and set state=Ready. We
# deliberately do NOT start the internal poll loop: its fetch callbacks do a
# synchronous cross-module call from the libp2p thread, which deadlocks against
# QtRO owner-thread marshaling. The host fetches the proof on its own (Qt) thread
# and pushes it via libp2p_mix_rln_set_cached_proof.
proc autostartSpamProtection(sp: MixRlnSpamProtection) {.async.} =
  let ir = await sp.init()
  if ir.isErr:
    error "mix-rln cbind: spam protection init failed", err = ir.error
    return
  let sr = await sp.start()
  if sr.isErr:
    error "mix-rln cbind: spam protection start failed", err = sr.error
    return
  info "mix-rln cbind: spam protection autostarted (state=Ready, host-driven proof push)"

# --------------------------------------------------------------------------
# SpamProtection factory: runs on the libp2p thread at mix mount time.
# Builds MixRlnSpamProtection from the stored config, wires the LEZ fetch
# callbacks onto its OnchainLEZGroupManager, and records the GM ref so a later
# set_identity can attach credentials. nimcall (no closure env crosses threads).
# --------------------------------------------------------------------------

proc spamFactory(): Opt[libp2p_spam.SpamProtection] {.gcsafe, nimcall, raises: [].} =
  {.gcsafe.}:
    stateLock.acquire()
    let have = haveConfig
    let cfg = pendingConfig
    stateLock.release()

  if not have:
    return Opt.none(libp2p_spam.SpamProtection)

  let spRes = newMixRlnSpamProtection(cfg)
  if spRes.isErr:
    error "mix-rln cbind: failed to build MixRlnSpamProtection", err = spRes.error
    return Opt.none(libp2p_spam.SpamProtection)
  let sp = spRes.get()

  if cfg.useOnchainLEZ and sp.groupManager of OnchainLEZGroupManager:
    let gm = OnchainLEZGroupManager(sp.groupManager)
    gm.setFetchCallbacks(makeFetchRoots(), makeFetchProof())
    {.gcsafe.}:
      stateLock.acquire()
      groupManager = cast[pointer](gm)
      stateLock.release()
    # Lifecycle the whole plugin on the libp2p thread (we're inside the async
    # mix-mount handler) so sp.state reaches Ready and the GM is init+started.
    asyncSpawn autostartSpamProtection(sp)

  Opt.some(libp2p_spam.SpamProtection(sp))

# --------------------------------------------------------------------------
# Exported C functions.
# --------------------------------------------------------------------------

# The mix cbind (compiled into the same superset library) owns the Nim
# runtime: its C-level initializeLibrary runs NimMain exactly once and
# registers the CALLING thread with the refc GC (setupForeignThreadGc +
# stack bottom). Host threads (Qt) enter this surface directly, so every
# exported proc below must call it first — allocating on an unregistered
# thread crashes the collector (SIGSEGV in collectCT on first GC cycle).
when appType == "lib" or appType == "staticlib":
  proc mixCbindInitializeLibrary() {.importc: "initializeLibrary", cdecl, raises: [].}
else:
  # Executables (unit tests) run NimMain at startup and use Nim-managed
  # threads, so no foreign-thread registration is needed.
  proc mixCbindInitializeLibrary() {.raises: [].} =
    discard

proc libp2p_mix_rln_enable*(
    configJson: cstring
): cint {.dynlib, exportc, cdecl.} =
  ## Parse config JSON, store it, and register the SpamProtection factory.
  ## MUST be called before libp2p_new (the factory is read once at mix mount).
  mixCbindInitializeLibrary()
  if configJson.isNil:
    return 1
  var cfg = MixRlnConfig(
    epochDurationSeconds: 10.0,
    maxEpochGap: 5,
    userMessageLimit: 100,
    membershipContentTopic: "/mix/rln/membership/v1",
    proofMetadataContentTopic: "/mix/rln/metadata/v1",
    useOnchainLEZ: true,
  )
  var configAccount = ""
  try:
    let j = parseJson($configJson)
    if j.hasKey("rlnIdentifier"):
      let idArr = j["rlnIdentifier"]
      for i in 0 ..< min(idArr.len, 32):
        cfg.rlnIdentifier[i] = byte(idArr[i].getInt())
    if j.hasKey("epochDurationSeconds"):
      cfg.epochDurationSeconds = j["epochDurationSeconds"].getFloat()
    if j.hasKey("userMessageLimit"):
      cfg.userMessageLimit = j["userMessageLimit"].getInt()
    if j.hasKey("useOnchainLEZ"):
      cfg.useOnchainLEZ = j["useOnchainLEZ"].getBool()
    if j.hasKey("keystorePath"):
      cfg.keystorePath = j["keystorePath"].getStr()
    if j.hasKey("keystorePassword"):
      cfg.keystorePassword = j["keystorePassword"].getStr()
    if j.hasKey("configAccount"):
      configAccount = j["configAccount"].getStr()
  except CatchableError as e:
    error "mix-rln cbind: bad config json", err = e.msg
    return 1

  {.gcsafe.}:
    stateLock.acquire()
    pendingConfig = cfg
    haveConfig = true
    if configAccount.len > 0:
      setConfigAccount(configAccount)
    stateLock.release()

  registerSpamProtectionFactory(spamFactory)
  return 0

proc libp2p_mix_rln_set_fetcher*(
    fn: RlnFetcherFunc, userData: pointer
): cint {.dynlib, exportc, cdecl.} =
  ## Install the host fetcher used for LEZ get_valid_roots / get_merkle_proofs.
  mixCbindInitializeLibrary()
  {.gcsafe.}:
    stateLock.acquire()
    fetcher = fn
    fetcherData = userData
    stateLock.release()
  return 0

proc libp2p_mix_rln_set_identity*(
    idSecretHash: ptr uint8, len: csize_t, leaf: int64
): cint {.dynlib, exportc, cdecl.} =
  ## Set the RLN credential (idSecretHash used DIRECTLY, never re-derived from
  ## a seed — lez-rln/zerokit seed->credential derivations disagree) and the
  ## on-chain membership leaf index on the group manager.
  mixCbindInitializeLibrary()
  if idSecretHash.isNil or len != 32:
    return 1
  var secret: IDSecretHash
  copyMem(addr secret[0], idSecretHash, 32)

  {.gcsafe.}:
    stateLock.acquire()
    leafIndex = leaf
    let gmPtr = groupManager
    stateLock.release()

  if gmPtr.isNil:
    return 1

  let gm = cast[OnchainLEZGroupManager](gmPtr)
  gm.setCredential(secret, leaf)
  return 0

proc libp2p_mix_rln_set_cached_proof*(
    proofJson: cstring
): cint {.dynlib, exportc, cdecl.} =
  ## Push a single merkle-proof JSON OBJECT (the host extracts element [0] of
  ## get_merkle_proofs' array) directly into the GM's cachedProof + rootTracker.
  ## The host fetches on its own (Qt) thread, avoiding the libp2p-thread
  ## cross-module deadlock. Returns 0 on success, 1 on failure (incl. unparseable
  ## or empty proof — caller retries until the membership is in the tree).
  mixCbindInitializeLibrary()
  if proofJson.isNil:
    return 1
  {.gcsafe.}:
    stateLock.acquire()
    let gmPtr = groupManager
    stateLock.release()
  if gmPtr.isNil:
    return 1
  let parsed = parseProof($proofJson)
  if parsed.isErr:
    return 1
  let gm = cast[OnchainLEZGroupManager](gmPtr)
  gm.setCachedProof(parsed.get())
  return 0

proc libp2p_mix_rln_is_ready*(): cint {.dynlib, exportc, cdecl.} =
  ## 1 if the group manager can generate proofs (membership confirmed and a
  ## merkle proof cached), else 0.
  mixCbindInitializeLibrary()
  {.gcsafe.}:
    stateLock.acquire()
    let gmPtr = groupManager
    stateLock.release()
  if gmPtr.isNil:
    return 0
  let gm = cast[OnchainLEZGroupManager](gmPtr)
  if gm.isReady(): 1 else: 0

proc libp2p_mix_rln_start_polling*(): cint {.dynlib, exportc, cdecl.} =
  ## Start the LEZ poll loop. Call AFTER the node is started.
  ##
  ## LEGACY/dormant path: calling this from a host whose fetch callbacks do
  ## synchronous cross-module (QtRO) calls reintroduces the libp2p-thread
  ## deadlock that the host-driven proof push (libp2p_mix_rln_set_cached_proof)
  ## replaced. See the autostartSpamProtection rationale above for why the
  ## internal poll loop is deliberately not started in the deployed flow.
  mixCbindInitializeLibrary()
  {.gcsafe.}:
    stateLock.acquire()
    let gmPtr = groupManager
    stateLock.release()
  if gmPtr.isNil:
    return 1
  let gm = cast[OnchainLEZGroupManager](gmPtr)
  gm.startPolling()
  return 0

{.pop.}
