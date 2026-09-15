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

structure ActiveReplay where
  config : Config
  system : SystemState
  startedNodes : List Location
  sends : List ObservedSend := []
  consumedSendIds : List String := []
  sendProjections : List SendProjection := []
  pendingEffects : List PendingEffect := []
  pendingSendBatches : List PendingSendBatch := []
  terminalNodes : List Location := []
  completedNodes : List Location := []
  committedAttempts : List (Location × Nat) := []
deriving Repr, BEq

structure ReplayState where
  active : Option ActiveReplay := none
  attempts : List BufferedAttempt := []
  seenAttempts : List (Location × Nat) := []
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
  | .globallyCommitted | .rolledBack | .aborted => true
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
  else if (event.kind == .globallyCommitted || event.kind == .rolledBack) &&
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
      (event.messageId.isNone || event.send.isNone) then
    some "message_id and send are required for sends"
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
    (phase : Phase)
    (remaining : List String)
    (batches : List PendingSendBatch) :
    List PendingSendBatch :=
  let others := batches.filter (fun batch => batch.node != node)
  if remaining.isEmpty then
    others
  else
    { node, phase, remaining } :: others

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
  let state <- match nodeState active.system event.node with
    | none => throw s!"unknown node {event.node}"
    | some state => pure state
  let pending := active.pendingSendBatches.find?
    (fun batch => batch.node == event.node)
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
      setPendingSendBatch event.node phase batch.tail active.pendingSendBatches
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
    "globally_committed", "rolled_back", "aborted"]

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
  | .globallyCommitted | .rolledBack | .aborted =>
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

private def speculativeStates
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (node : Location) : List ActiveReplay := Id.run do
  let retained := (active.sendProjections.filter fun projection =>
    projection.node == node).map (applySendProjection active)
  let mut candidates := active :: retained
  for buffered in attempts.reverse do
    if buffered.node == node then
      let mut added := []
      for candidate in candidates do
        if let .ok applied := applySemanticEvents candidate buffered.events then
          added := applied :: added
      candidates := candidates ++ added.reverse
  pure candidates

private def applyImmediateSend
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (event : TraceEvent) : Except String ActiveReplay := do
  let continuingBatch := active.pendingSendBatches.any fun batch =>
    batch.node == event.node
  let remainingProjections :=
    if continuingBatch then
      active.sendProjections
    else
      active.sendProjections.filter fun projection =>
        projection.node != event.node
  let direct := applySend active event
  if let .ok next := direct then
    return { next with sendProjections := remainingProjections }
  for candidate in speculativeStates active attempts event.node do
    if let .ok observed := applySend candidate event then
      return {
        active with
        sends := observed.sends
        sendProjections := remainingProjections
        pendingSendBatches := observed.pendingSendBatches
      }
  direct

private def retainedSendProjections
    (active : ActiveReplay)
    (attempts : List BufferedAttempt)
    (node : Location) : List SendProjection :=
  (speculativeStates active attempts node).filterMap fun candidate => do
    let state <- nodeState candidate.system node
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
  let projections :=
    if active.pendingSendBatches.any fun batch => batch.node == event.node then
      []
    else
      retainedSendProjections active attempts event.node
  let mut next := active
  if event.kind == .globallyCommitted then
    for semantic in buffered.events do
      next <- processActive next semantic
    next := {
      next with
      committedAttempts :=
        (event.node, attempt) :: next.committedAttempts
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
      (ActiveReplay × List BufferedAttempt × List (Location × Nat)) := do
    match event.kind with
    | .start =>
        let active <- start state.active config event
        pure (active, closeAttemptGroups event.node state.attempts,
          state.seenAttempts)
    | .send =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        let next <- applyImmediateSend active state.attempts event
        pure (next, closeAttemptGroups event.node state.attempts,
          state.seenAttempts)
    | .gossipAccepted | .voteAccepted | .iAmOpenAccepted
    | .timeout | .open | .joinRestart | .complete =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        if isReceive event.kind then
          validateCause active event
        let (attempts, seen) <-
          bufferSemantic state.attempts state.seenAttempts event
        pure (active, attempts, seen)
    | .globallyCommitted | .rolledBack | .aborted =>
        let some active := state.active
          | throw "trace must begin with start"
        validateActiveContext active event
        let attempts := closeAttemptGroups event.node state.attempts
        let (next, remaining) <-
          resolveAttempt active attempts state.seenAttempts event
        pure (next, remaining, state.seenAttempts)
  let (nextActive, nextAttempts, nextSeen) <- match processed with
    | .ok result => pure result
    | .error message =>
        let expected := state.active.map
          (fun active => expectedEvents active event.node) |>.getD ["start"]
        fail index message expected

  pure {
    active := some nextActive
    attempts := nextAttempts
    seenAttempts := nextSeen
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
  if !active.pendingEffects.isEmpty then
    throw {
      prefixLength := eventCount
      message := "trace ended with unobserved committed effects"
      expected := ["open", "join_restart", "complete"]
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
