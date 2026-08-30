import DisasterRecovery.Protocol.Model
import Lean.Data.Json
import Lean.Data.Json.FromToJson

namespace DisasterRecovery.Protocol.Trace

open Lean

def contractVersion : String :=
  "ccf.recovery_decision_protocol.trace/1"

inductive Kind where
  | start
  | gossipAccepted
  | gossipRejected
  | voteAccepted
  | voteRejected
  | iAmOpenAccepted
  | iAmOpenRejected
  | timeout
  | retry
  | send
  | open
  | joinRestart
  | complete
deriving Repr, BEq, Inhabited

structure TraceEvent where
  version : String
  instanceId : String
  expectedLocations : List Location
  node : Location
  sequence : Nat
  kind : Kind
  messageId : Option String
  causedBy : Option String
  source : Option Location
  txid : Option TxID
  pre : Option Phase
  post : Option Phase
  openKind : Option OpenKind
  send : Option String
deriving Repr, BEq, Inhabited

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

structure HiddenSend where
  source : Location
  description : String
deriving Repr, BEq

structure PendingEffect where
  node : Location
  effect : Effect
deriving Repr, BEq

structure Candidate where
  system : SystemState
  hiddenSends : List HiddenSend := []
  pendingEffects : List PendingEffect := []
deriving Repr, BEq

private def parseKind : String -> Except String Kind
  | "start" => pure .start
  | "gossip_accepted" => pure .gossipAccepted
  | "gossip_rejected" => pure .gossipRejected
  | "vote_accepted" => pure .voteAccepted
  | "vote_rejected" => pure .voteRejected
  | "iamopen_accepted" => pure .iAmOpenAccepted
  | "iamopen_rejected" => pure .iAmOpenRejected
  | "timeout" => pure .timeout
  | "retry" => pure .retry
  | "send" => pure .send
  | "open" => pure .open
  | "join_restart" => pure .joinRestart
  | "complete" => pure .complete
  | value => throw s!"unknown kind '{value}'"

private def parsePhase : String -> Except String Phase
  | "GOSSIPING" => pure .gossiping
  | "VOTING" => pure .voting
  | "OPENING" => pure .opening
  | "JOINING" => pure .joining
  | "OPEN" => pure .open
  | value => throw s!"unknown phase '{value}'"

private def parseOpenKind : String -> Except String OpenKind
  | "QUORUM" => pure .quorum
  | "FAILOVER" => pure .failover
  | value => throw s!"unknown open kind '{value}'"

private def optionalString (json : Json) (key : String) :
    Except String (Option String) :=
  match json.getObjVal? key with
  | .error _ => pure none
  | .ok .null => pure none
  | .ok value => do
      let parsed <- value.getStr?
      pure (some parsed)

private def optionalNat (json : Json) (key : String) :
    Except String (Option Nat) :=
  match json.getObjVal? key with
  | .error _ => pure none
  | .ok .null => pure none
  | .ok value => do
      let parsed <- value.getNat?
      pure (some parsed)

private def optionalPhase (json : Json) (key : String) :
    Except String (Option Phase) := do
  let value <- optionalString json key
  match value with
  | none => pure none
  | some name => do
      let phase <- parsePhase name
      pure (some phase)

private def optionalOpenKind (json : Json) (key : String) :
    Except String (Option OpenKind) := do
  let value <- optionalString json key
  match value with
  | none => pure none
  | some name => do
      let kind <- parseOpenKind name
      pure (some kind)

def parseEvent (line : String) : Except String TraceEvent := do
  let json <- Json.parse line
  let version <- json.getObjValAs? String "version"
  let instanceId <- json.getObjValAs? String "instance"
  let expectedLocations <- json.getObjValAs? (List String) "expected_locations"
  let node <- json.getObjValAs? String "node"
  let sequence <- json.getObjValAs? Nat "sequence"
  let kindName <- json.getObjValAs? String "kind"
  let kind <- parseKind kindName
  let messageId <- optionalString json "message_id"
  let causedBy <- optionalString json "caused_by"
  let source <- optionalString json "source"
  let view <- optionalNat json "view"
  let seqno <- optionalNat json "seqno"
  let txid :=
    match view, seqno with
    | some view, some seqno => some { view, seqno }
    | none, none => none
    | _, _ => none
  let pre <- optionalPhase json "pre"
  let post <- optionalPhase json "post"
  let openKind <- optionalOpenKind json "open_kind"
  let send <- optionalString json "send"
  if version != contractVersion then
    throw s!"unsupported version '{version}'"
  if (view.isSome != seqno.isSome) then
    throw "view and seqno must appear together"
  pure {
    version
    instanceId
    expectedLocations
    node
    sequence
    kind
    messageId
    causedBy
    source
    txid
    pre
    post
    openKind
    send
  }

def parseNDJSON (input : String) : Except String (List TraceEvent) := do
  let lines := (input.splitOn "\n").filter
    (fun line => !line.trimAscii.isEmpty)
  let mut events := []
  for (line, index) in lines.zipIdx do
    match parseEvent line with
    | .ok event => events := event :: events
    | .error message => throw s!"line {index + 1}: {message}"
  pure events.reverse

private def nodeState (system : SystemState) (node : Location) : Option NodeState :=
  (system.nodes.find? fun entry => entry.1 == node).map Prod.snd

private def phaseMatches (expected : Option Phase) (actual : Phase) : Bool :=
  match expected with
  | none => true
  | some phase => phase == actual

private def requiresMessageId : Kind -> Bool
  | .gossipAccepted | .gossipRejected
  | .voteAccepted | .voteRejected
  | .iAmOpenAccepted | .iAmOpenRejected
  | .send => true
  | _ => false

private def requiresSource : Kind -> Bool
  | .gossipAccepted | .gossipRejected
  | .voteAccepted | .voteRejected
  | .iAmOpenAccepted | .iAmOpenRejected => true
  | _ => false

private def missingRequiredFields (event : TraceEvent) : List String :=
  let phases :=
    (if event.pre.isNone then ["pre"] else []) ++
      (if event.post.isNone then ["post"] else [])
  let message :=
    if requiresMessageId event.kind && event.messageId.isNone then
      ["message_id"]
    else
      []
  let source :=
    if requiresSource event.kind && event.source.isNone then ["source"] else []
  let txid :=
    match event.kind with
    | .gossipAccepted | .gossipRejected =>
        if event.txid.isNone then ["view", "seqno"] else []
    | _ => []
  let send :=
    match event.kind with
    | .send => if event.send.isNone then ["send"] else []
    | _ => []
  let openKind :=
    match event.kind with
    | .open => if event.openKind.isNone then ["open_kind"] else []
    | _ => []
  phases ++ message ++ source ++ txid ++ send ++ openKind

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

private def eventInputs (event : TraceEvent) : List Event :=
  let validations : List Validation :=
    match event.kind with
    | .gossipRejected | .voteRejected | .iAmOpenRejected =>
        [Validation.rejected, Validation.accepted]
    | _ => [Validation.accepted]
  match event.kind, event.source, event.txid with
  | .gossipAccepted, some source, some txid =>
      [.receiveGossip source txid .accepted]
  | .gossipRejected, some source, some txid =>
      validations.map fun validation => .receiveGossip source txid validation
  | .voteAccepted, some source, _ =>
      [.receiveVote source .accepted]
  | .voteRejected, some source, _ =>
      validations.map fun validation => .receiveVote source validation
  | .iAmOpenAccepted, some source, _ =>
      [.receiveIAmOpen source .accepted]
  | .iAmOpenRejected, some source, _ =>
      validations.map fun validation => .receiveIAmOpen source validation
  | .timeout, _, _ => [.timeout]
  | .retry, _, _ => [.retry]
  | _, _, _ => []

private def expectsAcceptance : Kind -> Option Bool
  | .gossipAccepted | .voteAccepted | .iAmOpenAccepted => some true
  | .gossipRejected | .voteRejected | .iAmOpenRejected => some false
  | .timeout | .retry => some true
  | _ => none

private def effectName : Effect -> Option String
  | .sendGossip destination => some s!"gossip:{destination}"
  | .sendVote destination => some s!"vote:{destination}"
  | .sendIAmOpen destination => some s!"iamopen:{destination}"
  | _ => none

private def hiddenSendBefore (left right : HiddenSend) : Bool :=
  left.source < right.source ||
    (left.source == right.source && left.description <= right.description)

private def uniqueHiddenSends (sends : List HiddenSend) : List HiddenSend :=
  (sends.foldl (fun result send =>
    if result.contains send then result else send :: result) []).mergeSort
      hiddenSendBefore

private def uniqueCandidates (candidates : List Candidate) : List Candidate :=
  candidates.foldl (fun result candidate =>
    if result.contains candidate then result else candidate :: result) []

private def hiddenSendsAt
    (config : Config)
    (startedNodes : List Location)
    (system : SystemState) : List HiddenSend :=
  startedNodes.flatMap fun source =>
    match nodeState system source with
    | none => []
    | some sender =>
        (step config sender .retry).effects.filterMap fun effect => do
          let description <- effectName effect
          pure { source, description }

def hiddenClosure
    (config : Config)
    (startedNodes : List Location)
    (candidates : List Candidate) : List Candidate :=
  uniqueCandidates (candidates.map fun candidate => {
    candidate with
    hiddenSends := uniqueHiddenSends
      (candidate.hiddenSends ++
        hiddenSendsAt config startedNodes candidate.system)
  })

private def expectedReceiveSend (event : TraceEvent) : Option String :=
  match event.kind with
  | .gossipAccepted | .gossipRejected =>
      some s!"gossip:{event.node}"
  | .voteAccepted | .voteRejected =>
      some s!"vote:{event.node}"
  | .iAmOpenAccepted | .iAmOpenRejected =>
      some s!"iamopen:{event.node}"
  | _ => none

private def observedSendCompatible
    (send : ObservedSend)
    (event : TraceEvent) : Bool :=
  match event.source, expectedReceiveSend event with
  | some source, some expected =>
      send.source == source && send.description == expected
  | _, _ => false

private def hiddenSendCompatible
    (candidate : Candidate)
    (event : TraceEvent) : Bool :=
  match event.source, expectedReceiveSend event with
  | some source, some expected =>
      candidate.hiddenSends.contains {
        source
        description := expected
      }
  | _, _ => false

private def observationCompatible
    (config : Config)
    (system : SystemState)
    (event : TraceEvent) : Bool :=
  match nodeState system event.node with
  | none => false
  | some state =>
      if !phaseMatches event.pre state.phase ||
          !phaseMatches event.post state.phase then
        false
      else
        match event.kind with
        | .send =>
            match event.send with
            | none => false
            | some expected =>
                (step config state .retry).effects.any
                  (fun effect => effectName effect == some expected)
        | .open =>
            state.phase == .opening && event.openKind == state.openKind
        | .joinRestart =>
            state.phase == .joining && state.restartRequested
        | .complete =>
            state.phase == .open
        | _ => false

private def historicalSendCompatible
    (candidate : Candidate)
    (event : TraceEvent) : Bool :=
  match nodeState candidate.system event.node, event.send with
  | some state, some description =>
      phaseMatches event.pre state.phase &&
        phaseMatches event.post state.phase &&
        candidate.hiddenSends.contains {
          source := event.node
          description
        }
  | _, _ => false

private def removePendingEffect (node : Location) (target : Effect) :
    List PendingEffect -> Option (List PendingEffect)
  | [] => none
  | pending :: rest =>
      if pending.node == node && pending.effect == target then
        some rest
      else
        (removePendingEffect node target rest).map (fun remaining =>
          pending :: remaining)

private def removePendingRestart (node : Location) :
    List PendingEffect -> Option (List PendingEffect)
  | [] => none
  | pending :: rest =>
      match pending.effect with
      | .restart _ =>
          if pending.node == node then
            some rest
          else
            (removePendingRestart node rest).map (fun remaining =>
              pending :: remaining)
      | _ =>
          (removePendingRestart node rest).map (fun remaining =>
            pending :: remaining)

private def consumeObservation
    (config : Config)
    (candidate : Candidate)
    (event : TraceEvent) : Option Candidate := do
  match event.kind with
  | .send => do
      guard (
        observationCompatible config candidate.system event ||
          historicalSendCompatible candidate event)
      some candidate
  | .open => do
      guard (observationCompatible config candidate.system event)
      let kind <- event.openKind
      let pendingEffects <- removePendingEffect event.node (.opening kind)
        candidate.pendingEffects
      some { candidate with pendingEffects }
  | .joinRestart => do
      guard (observationCompatible config candidate.system event)
      let pendingEffects <- removePendingRestart event.node
        candidate.pendingEffects
      some { candidate with pendingEffects }
  | .complete => do
      guard (observationCompatible config candidate.system event)
      let pendingEffects <- removePendingEffect event.node .completed
        candidate.pendingEffects
      some { candidate with pendingEffects }
  | _ => none

private def isOneShotEffect : Effect -> Bool
  | .opening _ | .restart _ | .completed => true
  | _ => false

private def transitionCandidates
    (config : Config)
    (system : SystemState)
    (event : TraceEvent) : List (Prod SystemState StepOutput) :=
  match nodeState system event.node with
  | none => []
  | some before =>
      if !phaseMatches event.pre before.phase then []
      else
        (eventInputs event).filterMap fun input => do
          let (nextSystem, output) <- systemStep config system event.node input
          let acceptanceOk :=
            match expectsAcceptance event.kind with
            | none => true
            | some expected => output.accepted == expected
          if acceptanceOk && phaseMatches event.post output.state.phase then
            some (nextSystem, output)
          else
            none

private def expectedEvents (candidates : List Candidate) (node : Location) :
    List String :=
  let phases :=
    candidates.filterMap (fun candidate => nodeState candidate.system node) |>.map
      (fun state => phaseName state.phase)
  let phaseText := String.intercalate "/" phases.eraseDups
  let common := [
    "timeout", "retry", "gossip_accepted|gossip_rejected",
    "vote_accepted|vote_rejected", "iamopen_accepted|iamopen_rejected"
  ]
  let canOpen := candidates.any fun candidate =>
    candidate.pendingEffects.any fun pending =>
      pending.node == node &&
        match pending.effect with
        | .opening _ => true
        | _ => false
  let canRestart := candidates.any fun candidate =>
    candidate.pendingEffects.any fun pending =>
      pending.node == node &&
        match pending.effect with
        | .restart _ => true
        | _ => false
  let canComplete := candidates.any fun candidate =>
    candidate.pendingEffects.any fun pending =>
      pending.node == node && pending.effect == .completed
  let observations :=
    (if canOpen then ["open(open_kind=QUORUM|FAILOVER)"] else []) ++
      (if phases.contains "OPENING" then ["send(iamopen:DEST)"] else []) ++
      (if canRestart then ["join_restart"] else []) ++
      (if canComplete then ["complete"] else [])
  s!"state={phaseText}" :: common ++ observations

structure ValidatorState where
  config : Option Config := none
  candidates : List Candidate := []
  nextSequence : List (Prod Location Nat) := []
  startedNodes : List Location := []
  seenMessageIds : List String := []
  observedSends : List ObservedSend := []
  consumedSendIds : List String := []
deriving Inhabited

private def expectedSequence (state : ValidatorState) (node : Location) : Nat :=
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

private def process
    (index : Nat)
    (state : ValidatorState)
    (event : TraceEvent) :
    Except Failure ValidatorState := do
  let missing := missingRequiredFields event
  if !missing.isEmpty then
    throw {
      prefixLength := index + 1
      message := s!"missing required fields: {String.intercalate ", " missing}"
      expected := []
    }
  if requiresSource event.kind && (event.source.getD "").isEmpty then
    throw {
      prefixLength := index + 1
      message := "source must not be empty"
      expected := []
    }
  if event.messageId.map String.isEmpty |>.getD false then
    throw {
      prefixLength := index + 1
      message := "message_id must not be empty"
      expected := []
    }
  if event.causedBy.map String.isEmpty |>.getD false then
    throw {
      prefixLength := index + 1
      message := "caused_by must not be empty"
      expected := []
    }
  if !requiresSource event.kind && event.causedBy.isSome then
    throw {
      prefixLength := index + 1
      message := "caused_by is only valid on receive events"
      expected := []
    }
  let expectedSeq := expectedSequence state event.node
  if event.sequence != expectedSeq then
    throw {
      prefixLength := index + 1
      message := s!"node {event.node} sequence {event.sequence}, expected {expectedSeq}"
      expected := []
    }
  let config : Config := {
    instanceId := event.instanceId
    expectedLocations := event.expectedLocations
  }
  match configError config with
  | some message =>
      throw {
        prefixLength := index + 1
        message
        expected := []
      }
  | none => pure ()
  match event.messageId with
  | some messageId =>
      if state.seenMessageIds.contains messageId ||
          state.consumedSendIds.contains messageId then
        throw {
          prefixLength := index + 1
          message := s!"message_id '{messageId}' was already used"
          expected := []
        }
  | none => pure ()
  if event.messageId.isSome && event.messageId == event.causedBy then
    throw {
      prefixLength := index + 1
      message := "message_id and caused_by must identify distinct observations"
      expected := []
    }
  match event.kind, state.config with
  | .start, none =>
      if !config.expectedLocations.contains event.node then
        throw {
          prefixLength := index + 1
          message := s!"start node {event.node} is not expected"
          expected := config.expectedLocations
        }
      let system := initialSystem config
      let node := (nodeState system event.node).get!
      if !phaseMatches event.pre node.phase || !phaseMatches event.post node.phase then
        throw {
          prefixLength := index + 1
          message := "start pre/post phase does not match GOSSIPING"
          expected := ["pre=GOSSIPING", "post=GOSSIPING"]
        }
      pure {
        config := some config
        candidates := [{ system }]
        nextSequence := setSequence state.nextSequence event.node (expectedSeq + 1)
        startedNodes := [event.node]
        seenMessageIds := event.messageId.toList
      }
  | .start, some established =>
      if established != config then
        throw {
          prefixLength := index + 1
          message := "instance or expected_locations changed"
          expected := []
        }
      if !config.expectedLocations.contains event.node then
        throw {
          prefixLength := index + 1
          message := s!"start node {event.node} is not expected"
          expected := config.expectedLocations
        }
      if state.startedNodes.contains event.node then
        throw {
          prefixLength := index + 1
          message := s!"duplicate start event for node {event.node}"
          expected := []
        }
      let closure :=
        hiddenClosure config state.startedNodes state.candidates
      let next := closure.filter fun candidate =>
        match nodeState candidate.system event.node with
        | none => false
        | some node =>
            phaseMatches event.pre node.phase &&
              phaseMatches event.post node.phase
      if next.isEmpty then
        throw {
          prefixLength := index + 1
          message := "start pre/post phase does not match GOSSIPING"
          expected := ["pre=GOSSIPING", "post=GOSSIPING"]
        }
      let startedNodes := event.node :: state.startedNodes
      pure {
        state with
        candidates := hiddenClosure config startedNodes next
        nextSequence :=
          setSequence state.nextSequence event.node (expectedSeq + 1)
        startedNodes
        seenMessageIds := event.messageId.toList ++ state.seenMessageIds
      }
  | _, none =>
      throw {
        prefixLength := index + 1
        message := "trace must begin with start"
        expected := ["start"]
      }
  | _, some established =>
      if established != config then
        throw {
          prefixLength := index + 1
          message := "instance or expected_locations changed"
          expected := []
        }
      if !state.startedNodes.contains event.node then
        throw {
          prefixLength := index + 1
          message := s!"node {event.node} has no start event"
          expected := ["start"]
        }
      let closure :=
        hiddenClosure config state.startedNodes state.candidates
      let mustMatchSend :=
        match event.kind with
        | .gossipAccepted | .voteAccepted | .iAmOpenAccepted => true
        | .gossipRejected | .voteRejected | .iAmOpenRejected =>
            event.causedBy.isSome
        | _ => false
      let sourceCandidates :=
        if mustMatchSend &&
            config.expectedLocations.contains (event.source.getD "") then
          closure.filter
            (fun (candidate : Candidate) =>
              hiddenSendCompatible candidate event)
        else
          closure
      let causalCandidates :=
        match event.causedBy with
        | none => sourceCandidates
        | some cause =>
            if state.consumedSendIds.contains cause then
              []
            else
              match state.observedSends.find?
                  (fun (send : ObservedSend) => send.messageId == cause) with
              | some send =>
                  if observedSendCompatible send event then
                    sourceCandidates
                  else
                    []
              | none =>
                  if state.seenMessageIds.contains cause then
                    []
                  else
                    sourceCandidates
      if event.causedBy.isSome && causalCandidates.isEmpty then
        throw {
          prefixLength := index + 1
          message := s!"caused_by '{event.causedBy.getD ""}' has no prior or hidden compatible send"
          expected := expectedEvents closure event.node
        }
      let next :=
        match event.kind with
        | .send | .open | .joinRestart | .complete =>
            causalCandidates.filterMap
              (fun (candidate : Candidate) =>
                consumeObservation config candidate event)
        | _ =>
            causalCandidates.flatMap fun (candidate : Candidate) =>
              (transitionCandidates config candidate.system event).map
                (fun (system, output) => {
                  candidate with
                  system
                  pendingEffects := candidate.pendingEffects ++
                    (output.effects.filter isOneShotEffect).map
                      (fun effect => {
                        node := event.node
                        effect
                      })
                })
      let next := hiddenClosure config state.startedNodes
        (uniqueCandidates next)
      if next.isEmpty then
        throw {
          prefixLength := index + 1
          message := s!"event {repr event.kind} is incompatible"
          expected := expectedEvents closure event.node
        }
      pure {
        config := some config
        candidates := next
        nextSequence :=
          setSequence state.nextSequence event.node (expectedSeq + 1)
        startedNodes := state.startedNodes
        seenMessageIds := event.messageId.toList ++ state.seenMessageIds
        observedSends :=
          match event.kind, event.messageId, event.send with
          | .send, some messageId, some description =>
              {
                messageId
                source := event.node
                description
              } :: state.observedSends
          | _, _, _ => state.observedSends
        consumedSendIds := event.causedBy.toList ++ state.consumedSendIds
      }

def validate (events : List TraceEvent) : Except Failure Nat := do
  let mut state : ValidatorState := {}
  for (event, index) in events.zipIdx do
    state <- process index state event
  if events.isEmpty then
    throw {
      prefixLength := 0
      message := "empty trace"
      expected := ["start"]
    }
  match state.config with
  | none =>
      throw {
        prefixLength := events.length
        message := "trace has no configuration"
        expected := ["start"]
      }
  | some _ => pure ()
  pure state.candidates.length

def renderFailure (failure : Failure) : String :=
  let expected :=
    if failure.expected.isEmpty then ""
    else s!"\nexpected compatible events:\n  {String.intercalate "\n  " failure.expected}"
  s!"shortest failing prefix: {failure.prefixLength}\n{failure.message}{expected}"

end DisasterRecovery.Protocol.Trace
