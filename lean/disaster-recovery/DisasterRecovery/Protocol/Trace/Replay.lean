import DisasterRecovery.Protocol.Trace.Format

namespace DisasterRecovery.Protocol.Trace

structure Failure where
  prefixLength : Nat
  message : String
  expected : List String
deriving Repr, BEq

structure ObservedSend where
  messageId : String
  source : Location
  description : String
deriving Repr, BEq

structure PendingEffect where
  node : Location
  effect : Effect
deriving Repr, BEq

structure PendingSendBatch where
  node : Location
  remaining : List String
deriving Repr, BEq

structure ActiveReplay where
  config : Config
  system : SystemState
  startedNodes : List Location
  sends : List ObservedSend := []
  consumedSendIds : List String := []
  pendingEffects : List PendingEffect := []
  pendingSendBatches : List PendingSendBatch := []
  terminalNodes : List Location := []
  completedNodes : List Location := []
deriving Repr, BEq

structure ReplayState where
  active : Option ActiveReplay := none
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

private def shapeError (event : TraceEvent) : Option String :=
  if event.pre.isNone || event.post.isNone then
    some "pre and post are required"
  else if isReceive event.kind &&
      (event.messageId.isNone || event.causedBy.isNone || event.source.isNone) then
    some "message_id, caused_by, and source are required for receives"
  else if event.kind == .gossipAccepted && event.txid.isNone then
    some "view and seqno are required for gossip"
  else if event.kind == .send &&
      (event.messageId.isNone || event.send.isNone) then
    some "message_id and send are required for sends"
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
    (remaining : List String)
    (batches : List PendingSendBatch) :
    List PendingSendBatch :=
  let others := batches.filter (fun batch => batch.node != node)
  if remaining.isEmpty then
    others
  else
    { node, remaining } :: others

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
  pure {
    active with
    consumedSendIds := cause :: active.consumedSendIds
  }

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
  if !phaseMatches event.pre state.phase || !phaseMatches event.post state.phase then
    throw s!"send phase does not match {phaseName state.phase}"
  let description := event.send.getD ""
  let batch := (active.pendingSendBatches.find?
    (fun batch => batch.node == event.node)).map (fun batch => batch.remaining)
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
    } :: active.sends
    pendingSendBatches :=
      setPendingSendBatch event.node batch.tail active.pendingSendBatches
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
    "iamopen_accepted", "timeout", "open", "join_restart", "complete"]

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
  if event.kind != .send &&
      active.pendingSendBatches.any (fun batch => batch.node == event.node) then
    throw s!"node {event.node} has an incomplete retry send batch"
  match event.kind with
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted =>
      applyReceive active event
  | .timeout => applyTransition active event
  | .send => applySend active event
  | .open | .joinRestart | .complete => applyObservation active event
  | .start => throw "unexpected start event"

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

  let nextActive <- match event.kind with
    | .start =>
        match start state.active config event with
        | .ok active => pure active
        | .error message => fail index message
    | _ =>
        match state.active with
        | none => fail index "trace must begin with start" ["start"]
        | some active =>
            match processActive active event with
            | .ok next => pure next
            | .error message => fail index message (expectedEvents active event.node)

  pure {
    active := some nextActive
    nextSequence :=
      setSequence state.nextSequence event.node (expectedSeq + 1)
    seenMessageIds := event.messageId.toList ++ state.seenMessageIds
  }

def validate (events : List TraceEvent) : Except Failure Unit := do
  if events.isEmpty then
    throw {
      prefixLength := 0
      message := "empty trace"
      expected := ["start"]
    }
  let mut state : ReplayState := {}
  for (event, index) in events.zipIdx do
    state <- process index state event
  let active <- match state.active with
    | none =>
        throw {
          prefixLength := events.length
          message := "trace has no start event"
          expected := ["start"]
        }
    | some active => pure active
  if !active.pendingEffects.isEmpty then
    throw {
      prefixLength := events.length
      message := "trace ended with unobserved committed effects"
      expected := ["open", "join_restart", "complete"]
    }
  if !active.pendingSendBatches.isEmpty then
    throw {
      prefixLength := events.length
      message := "trace ended with incomplete retry send batches"
      expected := ["send"]
    }
  if !active.startedNodes.all (fun node => active.terminalNodes.contains node) then
    throw {
      prefixLength := events.length
      message := "trace ended before every participating node terminated"
      expected := ["join_restart", "complete"]
    }
  if active.completedNodes.isEmpty then
    throw {
      prefixLength := events.length
      message := "trace has no completed opener"
      expected := ["complete"]
    }

def renderFailure (failure : Failure) : String :=
  let expected :=
    if failure.expected.isEmpty then ""
    else s!"\nexpected compatible events:\n  {String.intercalate "\n  " failure.expected}"
  s!"shortest failing prefix: {failure.prefixLength}\n{failure.message}{expected}"

end DisasterRecovery.Protocol.Trace
