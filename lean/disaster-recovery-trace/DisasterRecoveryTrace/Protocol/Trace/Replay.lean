import DisasterRecoveryTrace.Protocol.Trace.Format

namespace DisasterRecoveryTrace.Protocol.Trace

open DisasterRecovery.Protocol.Model

structure Failure where
  prefixLength : Nat
  message : String
  expected : List String
deriving Repr, BEq

structure ObservedSend where
  messageId : String
  source : Location
  description : String
  txid : Option TxID
deriving Repr, BEq

structure PendingEffect where
  node : Location
  effect : Effect
deriving Repr, BEq

structure PendingSendBatch where
  node : Location
  batch : Nat
  phase : Phase
  remaining : List String
deriving Repr, BEq

structure BufferedAttempt where
  node : Location
  attempt : Nat
  events : List TraceEvent
  isOpen : Bool := true
deriving Repr, BEq

structure SendProjection where
  node : Location
  state : NodeState
deriving Repr, BEq

structure SendProof where
  node : Location
  alternatives : List (List (Location × Nat))
deriving Repr, BEq

structure PendingCommit where
  attempt : BufferedAttempt
  txid : TxID
deriving Repr, BEq

structure LocalCommit where
  node : Location
  attempt : Nat
  txid : TxID
deriving Repr, BEq

structure ActiveReplay where
  config : Config
  system : SystemState
  startedNodes : List Location
  sends : List ObservedSend := []
  consumedSendIds : List String := []
  sendProjections : List SendProjection := []
  sendProofs : List SendProof := []
  pendingEffects : List PendingEffect := []
  pendingSendBatches : List PendingSendBatch := []
  completedSendBatches : List (Location × Nat) := []
  terminalNodes : List Location := []
  completedNodes : List Location := []
  committedAttempts : List (Location × Nat) := []
  committedRecords : List PendingCommit := []
  pendingCommits : List PendingCommit := []
deriving Repr, BEq

structure ReplayState where
  active : Option ActiveReplay := none
  attempts : List BufferedAttempt := []
  seenAttempts : List (Location × Nat) := []
  localCommits : List LocalCommit := []
  resolvedTxids : List (Location × TxID) := []
  abortedAttempts : List (Location × Nat) := []
  nextSequence : List (Prod Location Nat) := []
  seenMessageIds : List String := []
deriving Repr, BEq, Inhabited

private def nodeState (system : SystemState) (node : Location) : Option NodeState :=
  (system.nodes.find? fun entry => entry.1 == node).map Prod.snd

private def phaseMatches (expected : Option Phase) (actual : Phase) : Bool :=
  expected == some actual

private def isReceive : Kind -> Bool
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted => true
  | _ => false

private def isSemantic : Kind -> Bool
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted
  | .timeout | .open | .joinRestart | .complete => true
  | _ => false

private def isTransactionSemantic : Kind -> Bool
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted | .timeout => true
  | _ => false

private def isLifecycle : Kind -> Bool
  | .locallyCommitted | .globallyCommitted | .rolledBack | .aborted => true
  | _ => false

private def shapeError (event : TraceEvent) : Option String :=
  if isLifecycle event.kind && (event.pre.isSome || event.post.isSome) then
    some "pre and post are not valid on lifecycle events"
  else if isLifecycle event.kind &&
      (event.messageId.isSome || event.causedBy.isSome ||
        event.source.isSome || event.openKind.isSome || event.send.isSome) then
    some "semantic fields are not valid on lifecycle events"
  else if isLifecycle event.kind && event.attempt.isNone then
    some "attempt is required for lifecycle events"
  else if (event.kind == .locallyCommitted ||
      event.kind == .globallyCommitted || event.kind == .rolledBack) &&
      event.txid.isNone then
    some "view and seqno are required for transaction lifecycle events"
  else if event.kind == .aborted && event.txid.isSome then
    some "view and seqno are not valid for aborted attempts"
  else if isSemantic event.kind && event.attempt.isNone then
    some "attempt is required for speculative semantic events"
  else if (event.kind == .start || event.kind == .send) &&
      event.attempt.isSome then
    some "attempt is not valid for start or send events"
  else if !isLifecycle event.kind &&
      (event.pre.isNone || event.post.isNone) then
    some "pre and post are required"
  else if isReceive event.kind &&
      (event.messageId.isNone || event.causedBy.isNone || event.source.isNone) then
    some "message_id, caused_by, and source are required for receives"
  else if event.kind == .gossipAccepted && event.txid.isNone then
    some "view and seqno are required for gossip"
  else if event.kind == .send &&
      (event.messageId.isNone || event.send.isNone || event.batch.isNone) then
    some "message_id, send, and batch are required for sends"
  else if event.kind != .send && event.batch.isSome then
    some "batch is only valid for send events"
  else if event.kind == .send &&
      (event.send.getD "").startsWith "gossip:" && event.txid.isNone then
    some "view and seqno are required for gossip sends"
  else if event.kind == .open && event.openKind.isNone then
    some "open_kind is required for open"
  else if !isReceive event.kind && event.causedBy.isSome then
    some "caused_by is only valid on receive events"
  else if event.messageId.map String.isEmpty |>.getD false then
    some "message_id must not be empty"
  else if event.causedBy.map String.isEmpty |>.getD false then
    some "caused_by must not be empty"
  else if event.source.map String.isEmpty |>.getD false then
    some "source must not be empty"
  else
    none

private def configError (config : Config) : Option String :=
  if config.instanceId.isEmpty then
    some "instance must not be empty"
  else if config.expectedLocations.isEmpty then
    some "expected_locations must not be empty"
  else if config.expectedLocations.any String.isEmpty then
    some "expected_locations must not contain an empty name"
  else if config.expectedLocations.eraseDups.length !=
      config.expectedLocations.length then
    some "expected_locations must not contain duplicates"
  else
    none

private def expectedSequence (state : ReplayState) (node : Location) : Nat :=
  (state.nextSequence.find? fun entry => entry.1 == node).map Prod.snd |>.getD 0

private def setSequence
    (sequences : List (Prod Location Nat))
    (node : Location)
    (next : Nat) :
    List (Prod Location Nat) :=
  if sequences.any (fun entry => entry.1 == node) then
    sequences.map fun entry => if entry.1 == node then (node, next) else entry
  else
    (node, next) :: sequences

private def effectName : Effect -> Option String
  | .sendGossip destination => some s!"gossip:{destination}"
  | .sendVote destination => some s!"vote:{destination}"
  | .sendIAmOpen destination => some s!"iamopen:{destination}"
  | _ => none

private def sendBatch (config : Config) (state : NodeState) : List String :=
  (step config state .retry).effects.filterMap effectName

private def setPendingSendBatch
    (node : Location)
    (batch : Nat)
    (phase : Phase)
    (remaining : List String)
    (batches : List PendingSendBatch) :
    List PendingSendBatch :=
  let others := batches.filter fun pending =>
    pending.node != node || pending.batch != batch
  if remaining.isEmpty then
    others
  else
    { node, batch, phase, remaining } :: others

private def receiveDescription (event : TraceEvent) : Option String :=
  match event.kind with
  | .gossipAccepted => some s!"gossip:{event.node}"
  | .voteAccepted => some s!"vote:{event.node}"
  | .iAmOpenAccepted => some s!"iamopen:{event.node}"
  | _ => none

private def eventInput (event : TraceEvent) : Option Event :=
  match event.kind, event.source, event.txid with
  | .gossipAccepted, some source, some txid =>
      some (.receiveGossip source txid .accepted)
  | .voteAccepted, some source, _ =>
      some (.receiveVote source .accepted)
  | .iAmOpenAccepted, some source, _ =>
      some (.receiveIAmOpen source .accepted)
  | .timeout, _, _ => some .timeout
  | _, _, _ => none

private def isOneShotEffect : Effect -> Bool
  | .opening _ | .restart _ | .completed => true
  | _ => false

private def addEffects
    (node : Location)
    (effects : List Effect)
    (pending : List PendingEffect) :
    List PendingEffect :=
  pending ++ (effects.filter isOneShotEffect).map fun effect =>
    ({ node := node, effect := effect } : PendingEffect)

private def removeEffect (node : Location) (target : Effect) :
    List PendingEffect -> Option (List PendingEffect)
  | [] => none
  | pending :: rest =>
      if pending.node == node && pending.effect == target then
        some rest
      else
        (removeEffect node target rest).map (fun remaining =>
          pending :: remaining)

private def removeRestart (node : Location) :
    List PendingEffect -> Option (List PendingEffect)
  | [] => none
  | pending :: rest =>
      if pending.node == node then
        match pending.effect with
        | .restart _ => some rest
        | _ => (removeRestart node rest).map (fun remaining =>
            pending :: remaining)
      else
        (removeRestart node rest).map (fun remaining => pending :: remaining)

private def consumeCause
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  let cause := event.causedBy.getD ""
  if active.consumedSendIds.contains cause then
    throw s!"caused_by '{cause}' was already consumed"
  let send <- match active.sends.find? (fun send => send.messageId == cause) with
    | none => throw s!"caused_by '{cause}' has no prior send"
    | some send => pure send
  let source := event.source.getD ""
  let description := receiveDescription event |>.getD ""
  if send.source != source || send.description != description then
    throw s!"caused_by '{cause}' has the wrong source, class, or destination"
  if event.kind == .gossipAccepted && send.txid != event.txid then
    throw s!"caused_by '{cause}' has the wrong gossip TxID"
  pure {
    active with
    consumedSendIds := cause :: active.consumedSendIds
  }

private def validateCause
    (active : ActiveReplay)
    (event : TraceEvent) : Except String Unit := do
  let cause := event.causedBy.getD ""
  let send <- match active.sends.find? (fun send => send.messageId == cause) with
    | none => throw s!"caused_by '{cause}' has no prior send"
    | some send => pure send
  let source := event.source.getD ""
  let description := receiveDescription event |>.getD ""
  if send.source != source || send.description != description then
    throw s!"caused_by '{cause}' has the wrong source, class, or destination"
  if event.kind == .gossipAccepted && send.txid != event.txid then
    throw s!"caused_by '{cause}' has the wrong gossip TxID"

private def applyTransition
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  let before <- match nodeState active.system event.node with
    | none => throw s!"unknown node {event.node}"
    | some state => pure state
  if !phaseMatches event.pre before.phase then
    throw s!"pre phase does not match {phaseName before.phase}"
  let input <- match eventInput event with
    | none => throw "event is not a protocol transition"
    | some input => pure input
  let (system, output) <- match
      systemStep active.config active.system event.node input with
    | none => throw s!"unknown node {event.node}"
    | some result => pure result
  if !output.accepted then
    throw "protocol transition was rejected"
  if !phaseMatches event.post output.state.phase then
    throw s!"post phase does not match {phaseName output.state.phase}"
  pure {
    active with
    system
    pendingEffects :=
      addEffects event.node output.effects active.pendingEffects
  }

private def applyReceive
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  applyTransition (← consumeCause active event) event

private def applySend
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  let batchId := event.batch.getD 0
  let batchKey := (event.node, batchId)
  if active.completedSendBatches.contains batchKey then
    throw s!"send batch {batchId} was already completed"
  let state <- match nodeState active.system event.node with
    | none => throw s!"unknown node {event.node}"
    | some state => pure state
  let pending := active.pendingSendBatches.find?
    (fun batch => batch.node == event.node && batch.batch == batchId)
  let phase := pending.map (fun batch => batch.phase) |>.getD state.phase
  if !phaseMatches event.pre phase || !phaseMatches event.post phase then
    throw s!"send phase does not match {phaseName phase}"
  let description := event.send.getD ""
  let batch := pending.map (fun pending => pending.remaining)
    |>.getD (sendBatch active.config state)
  let expected <- match batch with
    | [] => throw "no retry send batch is enabled"
    | expected :: _ => pure expected
  if description != expected then
    throw s!"expected send '{expected}', got '{description}'"
  pure {
    active with
    sends := {
      messageId := event.messageId.getD ""
      source := event.node
      description
      txid := event.txid
    } :: active.sends
    pendingSendBatches :=
      setPendingSendBatch event.node batchId phase batch.tail
        active.pendingSendBatches
    completedSendBatches := if batch.tail.isEmpty then
      batchKey :: active.completedSendBatches
    else
      active.completedSendBatches
  }

private def applyObservation
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  let state <- match nodeState active.system event.node with
    | none => throw s!"unknown node {event.node}"
    | some state => pure state
  if !phaseMatches event.pre state.phase || !phaseMatches event.post state.phase then
    throw s!"observation phase does not match {phaseName state.phase}"
  match event.kind with
    | .open =>
        if state.phase != .opening || event.openKind != state.openKind then
          throw "open observation does not match state"
        let pendingEffects <- match
            removeEffect event.node (.opening event.openKind.get!) active.pendingEffects with
        | none => throw "open observation has no pending opening effect"
        | some pending => pure pending
        pure { active with pendingEffects }
    | .joinRestart =>
        if state.phase != .joining || !state.restartRequested then
          throw "join_restart observation does not match state"
        let pendingEffects <- match removeRestart event.node active.pendingEffects with
        | none => throw "join_restart has no pending restart effect"
        | some pending => pure pending
        pure {
          active with
          pendingEffects
          terminalNodes := event.node :: active.terminalNodes
        }
    | .complete =>
        if state.phase != .open then
          throw "complete observation does not match state"
        let pendingEffects <- match
            removeEffect event.node .completed active.pendingEffects with
        | none => throw "complete has no pending completion effect"
        | some pending => pure pending
        pure {
          active with
          pendingEffects
          terminalNodes := event.node :: active.terminalNodes
          completedNodes := event.node :: active.completedNodes
        }
    | _ => throw "event is not a protocol observation"

private def expectedEvents (active : ActiveReplay) (node : Location) :
    List String :=
  let phase := nodeState active.system node |>.map
    (fun state => phaseName state.phase) |>.getD "UNKNOWN"
  [s!"state={phase}", "send", "gossip_accepted", "vote_accepted",
    "iamopen_accepted", "timeout", "open", "join_restart", "complete",
    "locally_committed", "globally_committed", "rolled_back", "aborted"]

private def start
    (active : Option ActiveReplay)
    (config : Config)
    (event : TraceEvent) : Except String ActiveReplay := do
  if !config.expectedLocations.contains event.node then
    throw s!"start node {event.node} is not expected"
  let current := active.getD {
    config
    system := initialSystem config
    startedNodes := []
  }
  if current.config != config then
    throw "instance or expected_locations changed"
  if current.startedNodes.contains event.node then
    throw s!"duplicate start event for node {event.node}"
  let state <- match nodeState current.system event.node with
    | none => throw s!"unknown node {event.node}"
    | some state => pure state
  if !phaseMatches event.pre state.phase || !phaseMatches event.post state.phase then
    throw "start pre/post phase does not match GOSSIPING"
  pure {
    current with
    startedNodes := event.node :: current.startedNodes
  }

private def processActive
    (active : ActiveReplay)
    (event : TraceEvent) : Except String ActiveReplay := do
  if active.config.instanceId != event.instanceId ||
      active.config.expectedLocations != event.expectedLocations then
    throw "instance or expected_locations changed"
  if !active.startedNodes.contains event.node then
    throw s!"node {event.node} has no start event"
  match event.kind with
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted =>
      applyReceive active event
  | .timeout => applyTransition active event
  | .send => applySend active event
  | .open | .joinRestart | .complete => applyObservation active event
  | .start => throw "unexpected start event"
  | .locallyCommitted | .globallyCommitted | .rolledBack | .aborted =>
      throw "unexpected lifecycle event"

private def applySemanticEvents
    (active : ActiveReplay)
    (events : List TraceEvent) : Except String ActiveReplay := do
  let mut next := active
  for event in events do
    next <- processActive next event
  pure next

private def applySendProjection
    (active : ActiveReplay)
    (projection : SendProjection) : ActiveReplay :=
  {
    active with
    system := {
      nodes := replaceNode projection.node projection.state active.system.nodes
    }
  }

private structure SpeculativeState where
  active : ActiveReplay
  requiredLocal : List (Location × Nat)

private def speculativeStates
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (node : Location) : List SpeculativeState := Id.run do
  let retained := (active.sendProjections.filter fun projection =>
    projection.node == node).map fun projection => {
      active := applySendProjection active projection
      requiredLocal := []
    }
  let mut candidates := { active, requiredLocal := [] } :: retained
  for buffered in attempts.reverse do
    if buffered.node == node then
      let mut added := []
      for candidate in candidates do
        if let .ok applied :=
            applySemanticEvents candidate.active buffered.events then
          added := {
            active := applied
            requiredLocal :=
              (buffered.node, buffered.attempt) :: candidate.requiredLocal
          } :: added
      candidates := candidates ++ added.reverse
  pure candidates

private def applyImmediateSend
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (locallyCommitted : List (Location × Nat))
    (event : TraceEvent) : Except String ActiveReplay := do
  let remainingProjections := active.sendProjections
  let direct := applySend active event
  if let .ok next := direct then
    return { next with sendProjections := remainingProjections }
  let successful := (speculativeStates active attempts event.node).filterMap
    fun candidate => match applySend candidate.active event with
      | .ok observed => some (observed, candidate.requiredLocal.eraseDups)
      | .error _ => none
  if let some (observed, _) := successful.find? fun candidate =>
      candidate.2.all locallyCommitted.contains then
    return {
      active with
      sends := observed.sends
      sendProjections := remainingProjections
      pendingSendBatches := observed.pendingSendBatches
    }
  if let some (observed, _) := successful.head? then
    let alternatives := successful.map fun candidate =>
      candidate.2.filter fun key => !locallyCommitted.contains key
    return {
      active with
      sends := observed.sends
      sendProjections := remainingProjections
      sendProofs := {
        node := event.node
        alternatives := alternatives.eraseDups
      } :: active.sendProofs
      pendingSendBatches := observed.pendingSendBatches
    }
  direct

private def retainedSendProjections
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (locallyCommitted : List (Location × Nat))
    (node : Location) : List SendProjection :=
  let visibleAttempts := attempts.filter fun buffered =>
    locallyCommitted.contains (buffered.node, buffered.attempt)
  (speculativeStates active visibleAttempts node).filterMap fun candidate => do
    let state <- nodeState candidate.active.system node
    if (sendBatch active.config state).isEmpty then
      none
    else
      some { node, state }

private def addSendProjections
    (active : ActiveReplay)
    (projections : List SendProjection) : ActiveReplay :=
  {
    active with
    sendProjections := projections.foldl (fun retained projection =>
      if retained.contains projection then retained else projection :: retained)
      active.sendProjections
  }

private def localCommitKeys
    (commits : List LocalCommit) : List (Location × Nat) :=
  commits.map fun commit => (commit.node, commit.attempt)

private def attemptTxid
    (commits : List LocalCommit)
    (attempt : BufferedAttempt) : Option TxID :=
  (commits.find? fun commit =>
    commit.node == attempt.node && commit.attempt == attempt.attempt).map
      LocalCommit.txid

private def newestAttemptFirst
    (commits : List LocalCommit)
    (a b : BufferedAttempt) : Bool :=
  if a.node != b.node then
    b.node < a.node
  else
    match attemptTxid commits a, attemptTxid commits b with
    | some aTxid, some bTxid =>
        aTxid.seqno > bTxid.seqno ||
          (aTxid.seqno == bTxid.seqno &&
            (aTxid.view > bTxid.view ||
              (aTxid.view == bTxid.view && a.attempt >= b.attempt)))
    | _, _ => a.attempt >= b.attempt

private def orderAttempts
    (commits : List LocalCommit)
    (attempts : List BufferedAttempt) : List BufferedAttempt :=
  attempts.mergeSort (newestAttemptFirst commits)

private def updateSendProofs
    (active : ActiveReplay)
    (locallyCommitted : List (Location × Nat))
    (aborted : List (Location × Nat)) : Except String ActiveReplay := do
  let mut remaining := []
  for proof in active.sendProofs do
    if proof.alternatives.any fun alternative =>
        alternative.all locallyCommitted.contains then
      continue
    let viable := proof.alternatives.filter fun alternative =>
      !alternative.any aborted.contains
    if viable.isEmpty then
      throw s!"send from {proof.node} depended on an aborted attempt"
    remaining := { proof with alternatives := viable } :: remaining
  pure { active with sendProofs := remaining.reverse }

private def txidLT (a b : TxID) : Bool :=
  a.seqno < b.seqno || (a.seqno == b.seqno && a.view < b.view)

private def pendingCommitLE (a b : PendingCommit) : Bool :=
  a.attempt.node < b.attempt.node ||
    (a.attempt.node == b.attempt.node &&
      (a.txid.seqno < b.txid.seqno ||
        (a.txid.seqno == b.txid.seqno &&
          (a.txid.view < b.txid.view ||
            (a.txid.view == b.txid.view &&
              a.attempt.attempt <= b.attempt.attempt)))))

private def rebuildCommittedState (active : ActiveReplay) : ActiveReplay := Id.run do
  let pending := active.committedRecords.mergeSort pendingCommitLE
  let mut next := {
    active with
    system := initialSystem active.config
    consumedSendIds := []
    pendingEffects := []
    terminalNodes := []
    completedNodes := []
    committedAttempts := []
    pendingCommits := []
  }
  let mut blockedNodes : List Location := []
  let mut remaining := []
  for commit in pending do
    if blockedNodes.contains commit.attempt.node then
      remaining := commit :: remaining
    else
      match applySemanticEvents next commit.attempt.events with
      | .ok applied =>
          next := {
            applied with
            committedAttempts :=
              (commit.attempt.node, commit.attempt.attempt) ::
                applied.committedAttempts
          }
      | .error _ =>
          blockedNodes := commit.attempt.node :: blockedNodes
          remaining := commit :: remaining
  pure {
    next with
    committedRecords := active.committedRecords
    pendingCommits := remaining.reverse
  }

private def validateActiveContext
    (active : ActiveReplay)
    (event : TraceEvent) : Except String Unit := do
  if active.config.instanceId != event.instanceId ||
      active.config.expectedLocations != event.expectedLocations then
    throw "instance or expected_locations changed"
  if !active.startedNodes.contains event.node then
    throw s!"node {event.node} has no start event"

private def closeAttemptGroups
    (node : Location)
    (attempts : List BufferedAttempt) : List BufferedAttempt :=
  attempts.map fun buffered =>
    if buffered.node == node then
      { buffered with isOpen := false }
    else
      buffered

private def bufferSemantic
    (attempts : List BufferedAttempt)
    (seen : List (Location × Nat))
    (event : TraceEvent) :
    Except String (List BufferedAttempt × List (Location × Nat)) := do
  let attempt := event.attempt.getD 0
  let key := (event.node, attempt)
  let current := attempts.find? fun buffered =>
    buffered.node == event.node && buffered.attempt == attempt
  match current with
  | some buffered =>
      if !buffered.isOpen then
        throw s!"duplicate active attempt ({event.node}, {attempt})"
      if isTransactionSemantic event.kind then
        throw s!"duplicate active attempt ({event.node}, {attempt})"
      let next := attempts.map fun candidate =>
        if candidate.node == event.node && candidate.attempt == attempt then
          { candidate with events := candidate.events ++ [event] }
        else if candidate.node == event.node then
          { candidate with isOpen := false }
        else
          candidate
      pure (next, seen)
  | none =>
      if seen.contains key then
        throw s!"duplicate attempt ({event.node}, {attempt})"
      if !isTransactionSemantic event.kind then
        throw s!"correlated event for unknown attempt ({event.node}, {attempt})"
      pure ({
        node := event.node
        attempt
        events := [event]
      } :: closeAttemptGroups event.node attempts, key :: seen)

private def resolveAttempt
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (seen : List (Location × Nat))
    (localCommits : List LocalCommit)
    (event : TraceEvent) :
    Except String (ActiveReplay × List BufferedAttempt) := do
  let attempt := event.attempt.getD 0
  let buffered <- match attempts.find? fun candidate =>
      candidate.node == event.node && candidate.attempt == attempt with
    | some candidate => pure candidate
    | none =>
        let status := if seen.contains (event.node, attempt) then
          "already resolved"
        else
          "unknown"
        throw s!"{status} attempt ({event.node}, {attempt})"
  let pendingAttempts := active.pendingCommits.map
    fun commit => commit.attempt
  let pendingLocals := active.pendingCommits.map fun commit => {
    node := commit.attempt.node
    attempt := commit.attempt.attempt
    txid := commit.txid
  }
  let visibleCommits := localCommits ++ pendingLocals
  let projections := retainedSendProjections active
    (orderAttempts visibleCommits (attempts ++ pendingAttempts))
    (localCommitKeys visibleCommits) event.node
  let mut next := active
  if event.kind == .globallyCommitted then
    next := rebuildCommittedState {
      next with
      committedRecords := {
        attempt := buffered
        txid := event.txid.get!
      } :: next.committedRecords
    }
  next := addSendProjections next projections
  pure (next, attempts.filter fun candidate =>
    candidate.node != event.node || candidate.attempt != attempt)

private def fail
    (index : Nat)
    (message : String)
    (expected : List String := []) :
    Except Failure α :=
  throw { prefixLength := index + 1, message, expected }

private def process
    (index : Nat)
    (state : ReplayState)
    (event : TraceEvent) : Except Failure ReplayState := do
  if let some message := shapeError event then
    fail index message
  let config : Config := {
    instanceId := event.instanceId
    expectedLocations := event.expectedLocations
  }
  if let some message := configError config then
    fail index message
  let expectedSeq := expectedSequence state event.node
  if event.sequence != expectedSeq then
    fail index s!"node {event.node} sequence {event.sequence}, expected {expectedSeq}"
  if let some messageId := event.messageId then
    if state.seenMessageIds.contains messageId then
      fail index s!"message_id '{messageId}' was already used"
    if event.causedBy == some messageId then
      fail index "message_id and caused_by must identify distinct observations"

  let processed : Except String
      (ActiveReplay × List BufferedAttempt × List (Location × Nat) ×
        List LocalCommit × List (Location × TxID) ×
        List (Location × Nat)) := do
    match event.kind with
    | .start =>
        let active <- start state.active config event
        pure (active, closeAttemptGroups event.node state.attempts,
          state.seenAttempts, state.localCommits, state.resolvedTxids,
          state.abortedAttempts)
    | .send =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        let pendingAttempts := active.pendingCommits.map
          fun commit => commit.attempt
        let pendingLocals := active.pendingCommits.map fun commit => {
          node := commit.attempt.node
          attempt := commit.attempt.attempt
          txid := commit.txid
        }
        let visibleCommits := state.localCommits ++ pendingLocals
        let next <- applyImmediateSend active
          (orderAttempts visibleCommits (state.attempts ++ pendingAttempts))
          (localCommitKeys visibleCommits) event
        pure (next, closeAttemptGroups event.node state.attempts,
          state.seenAttempts, state.localCommits, state.resolvedTxids,
          state.abortedAttempts)
    | .gossipAccepted | .voteAccepted | .iAmOpenAccepted
    | .timeout | .open | .joinRestart | .complete =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        if isReceive event.kind then
          validateCause active event
        let (attempts, seen) <-
          bufferSemantic state.attempts state.seenAttempts event
        pure (active, attempts, seen, state.localCommits,
          state.resolvedTxids, state.abortedAttempts)
    | .locallyCommitted =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        let attempts := closeAttemptGroups event.node state.attempts
        let key := (event.node, event.attempt.getD 0)
        if !attempts.any fun candidate =>
            candidate.node == key.1 && candidate.attempt == key.2 then
          throw s!"unknown attempt ({key.1}, {key.2})"
        if state.localCommits.any fun commit =>
            commit.node == key.1 && commit.attempt == key.2 then
          throw s!"duplicate local commit for attempt ({key.1}, {key.2})"
        if state.abortedAttempts.contains key then
          throw s!"aborted attempt ({key.1}, {key.2}) committed locally"
        let txid := event.txid.get!
        let localCommits := { node := event.node, attempt := key.2, txid } ::
          state.localCommits
        let next <- updateSendProofs
          active (localCommitKeys localCommits) state.abortedAttempts
        pure (next, attempts, state.seenAttempts, localCommits,
          state.resolvedTxids, state.abortedAttempts)
    | .globallyCommitted | .rolledBack | .aborted =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        let attempts := closeAttemptGroups event.node state.attempts
        let key := (event.node, event.attempt.getD 0)
        let existingLocal := state.localCommits.find? fun commit =>
          commit.node == key.1 && commit.attempt == key.2
        if event.kind == .aborted && existingLocal.isSome then
          throw s!"locally committed attempt ({key.1}, {key.2}) was aborted"
        let localCommits <-
          if event.kind == .aborted then
            pure state.localCommits
          else
            let txid := event.txid.get!
            match existingLocal with
            | some commit =>
                if commit.txid != txid then
                  throw s!"final TxID does not match local commit for attempt ({key.1}, {key.2})"
                pure state.localCommits
            | none =>
                pure ({
                  node := event.node
                  attempt := key.2
                  txid
                } :: state.localCommits)
        let locallyCommitted := localCommitKeys localCommits
        let aborted :=
          if event.kind == .aborted then key :: state.abortedAttempts
          else state.abortedAttempts
        let active <- updateSendProofs active locallyCommitted aborted
        let (next, remaining) <-
          resolveAttempt active attempts state.seenAttempts localCommits event
        let remainingLocal := if event.kind == .aborted then localCommits else
          localCommits.filter fun commit =>
            commit.node != key.1 || commit.attempt != key.2
        let resolvedTxids := if event.kind == .aborted then state.resolvedTxids
          else (event.node, event.txid.get!) :: state.resolvedTxids
        pure (next, remaining, state.seenAttempts, remainingLocal,
          resolvedTxids, aborted)
  let (nextActive, nextAttempts, nextSeen, nextLocalCommits,
      nextResolvedTxids, nextAborted) <- match processed with
    | .ok result => pure result
    | .error message =>
        let expected := state.active.map
          (fun active => expectedEvents active event.node) |>.getD ["start"]
        fail index message expected

  pure {
    active := some nextActive
    attempts := nextAttempts
    seenAttempts := nextSeen
    localCommits := nextLocalCommits
    resolvedTxids := nextResolvedTxids
    abortedAttempts := nextAborted
    nextSequence :=
      setSequence state.nextSequence event.node (expectedSeq + 1)
    seenMessageIds := event.messageId.toList ++ state.seenMessageIds
  }

def replay (events : List TraceEvent) : Except Failure ReplayState := do
  if events.isEmpty then
    throw {
      prefixLength := 0
      message := "empty trace"
      expected := ["start"]
    }
  let mut state : ReplayState := {}
  for (event, index) in events.zipIdx do
    state <- process index state event
  pure state

def finish (state : ReplayState) (eventCount : Nat) : Except Failure Unit := do
  let active <- match state.active with
    | none =>
        throw {
          prefixLength := eventCount
          message := "trace has no start event"
          expected := ["start"]
        }
    | some active => pure active
  if state.localCommits.any fun commit =>
      state.resolvedTxids.any fun resolved =>
        resolved.1 == commit.node && txidLT commit.txid resolved.2 then
    throw {
      prefixLength := eventCount
      message := "trace omitted the final status of an older local commit"
      expected := ["globally_committed", "rolled_back"]
    }
  if !active.pendingCommits.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace ended with committed attempts awaiting transaction order"
      expected := ["globally_committed", "rolled_back"]
    }
  if !active.pendingEffects.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace ended with unobserved committed effects"
      expected := ["open", "join_restart", "complete"]
    }
  if !active.sendProofs.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace ended with sends not justified by a local commit"
      expected := ["locally_committed", "globally_committed", "rolled_back",
        "aborted"]
    }
  if !active.pendingSendBatches.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace ended with incomplete retry send batches"
      expected := ["send"]
    }
  if !active.startedNodes.all (fun node => active.terminalNodes.contains node) then
    throw {
      prefixLength := eventCount
      message := "trace ended before every participating node terminated"
      expected := ["join_restart", "complete"]
    }
  if active.completedNodes.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace has no completed opener"
      expected := ["complete"]
    }

def validate (events : List TraceEvent) : Except Failure Unit := do
  finish (← replay events) events.length

def renderFailure (failure : Failure) : String :=
  let expected :=
    if failure.expected.isEmpty then ""
    else s!"\nexpected compatible events:\n  {String.intercalate "\n  " failure.expected}"
  s!"shortest failing prefix: {failure.prefixLength}\n{failure.message}{expected}"

end DisasterRecoveryTrace.Protocol.Trace
