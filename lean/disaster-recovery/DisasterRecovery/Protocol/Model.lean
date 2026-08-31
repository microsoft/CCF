import Std

namespace DisasterRecovery.Protocol

abbrev Location := String

structure TxID where
  view : Nat
  seqno : Nat
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

inductive Phase where
  | gossiping
  | voting
  | opening
  | joining
  | open
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

inductive OpenKind where
  | quorum
  | failover
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

inductive Validation where
  | accepted
  | rejected
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

structure Config where
  instanceId : String
  expectedLocations : List Location
deriving Repr, BEq, Hashable, Inhabited

def Config.isValid (config : Config) : Bool :=
  !config.instanceId.isEmpty &&
    !config.expectedLocations.isEmpty &&
    !config.expectedLocations.any String.isEmpty &&
    config.expectedLocations.eraseDups.length =
      config.expectedLocations.length

structure NodeState where
  location : Location
  phase : Phase := .gossiping
  timeoutState : Phase := .gossiping
  gossips : List (Prod Location TxID) := []
  votes : List Location := []
  chosen : Option Location := none
  openKind : Option OpenKind := none
  restartRequested : Bool := false
deriving Repr, BEq, Hashable, Inhabited

inductive Event where
  | receiveGossip (source : Location) (txid : TxID) (validation : Validation)
  | receiveVote (source : Location) (validation : Validation)
  | receiveIAmOpen (source : Location) (validation : Validation)
  | timeout
  | retry
deriving Repr, BEq, Hashable

inductive Effect where
  | sendGossip (destination : Location)
  | sendVote (destination : Location)
  | sendIAmOpen (destination : Location)
  | opening (kind : OpenKind)
  | restart (chosen : Location)
  | completed
  | rejected (reason : String)
deriving Repr, BEq, Hashable

structure StepOutput where
  state : NodeState
  effects : List Effect := []
  accepted : Bool := true
deriving Repr, BEq, Inhabited

structure SystemState where
  nodes : List (Prod Location NodeState)
deriving Repr, BEq, Hashable, Inhabited

def phaseName : Phase -> String
  | .gossiping => "GOSSIPING"
  | .voting => "VOTING"
  | .opening => "OPENING"
  | .joining => "JOINING"
  | .open => "OPEN"

def openKindName : OpenKind -> String
  | .quorum => "QUORUM"
  | .failover => "FAILOVER"

def initialNode (location : Location) : NodeState :=
  { location }

def initialSystem (config : Config) : SystemState :=
  { nodes := config.expectedLocations.map fun location =>
      (location, initialNode location) }

def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

private def txScoreGreater
    (leftName : Location)
    (left : TxID)
    (rightName : Location)
    (right : TxID) : Bool :=
  right.view < left.view ||
    (right.view == left.view &&
      (right.seqno < left.seqno ||
        (right.seqno == left.seqno && rightName < leftName)))

def maximumGossip : List (Prod Location TxID) -> Option (Prod Location TxID)
  | [] => none
  | head :: tail =>
      some (tail.foldl (fun current candidate =>
        if txScoreGreater candidate.1 candidate.2 current.1 current.2 then
          candidate
        else
          current) head)

def insertGossip
    (source : Location)
    (txid : TxID)
    (gossips : List (Prod Location TxID)) :
    List (Prod Location TxID) :=
  if gossips.any (fun entry => entry.1 == source) then
    gossips
  else
    ((source, txid) :: gossips).mergeSort (fun left right => left.1 <= right.1)

def insertVote (source : Location) (votes : List Location) : List Location :=
  if votes.contains source then votes
  else (source :: votes).mergeSort (fun left right => left <= right)

def advanceTimeoutState : Phase -> Phase
  | .gossiping => .voting
  | .voting => .opening
  | state => state

def advanceTimeoutLane (state : NodeState) (timeout : Bool) : NodeState :=
  if timeout then
    { state with timeoutState := advanceTimeoutState state.timeoutState }
  else
    state

def advance (config : Config) (state : NodeState) (timeout : Bool) :
    Option StepOutput :=
  let aligned := validTimeout state timeout
  match state.phase with
  | .gossiping =>
      if decide (state.gossips.length >= config.expectedLocations.length) || aligned then
        match maximumGossip state.gossips with
        | none => none
        | some (chosen, _) =>
            let next := { state with phase := .voting, chosen := some chosen }
            some { state := advanceTimeoutLane next timeout }
      else
        some { state := advanceTimeoutLane state timeout }
  | .voting =>
      let sufficient := decide (state.votes.length >= voteQuorum config)
      if sufficient || aligned then
        if aligned && state.votes.isEmpty then
          some { state }
        else
          let kind := if aligned && !sufficient then .failover else .quorum
          let next := {
            state with
            phase := .opening
            openKind := some kind
          }
          some {
            state := advanceTimeoutLane next timeout
            effects := [.opening kind]
          }
      else
        some { state := advanceTimeoutLane state timeout }
  | .joining =>
      match state.chosen with
      | none => none
      | some chosen =>
          some {
            state := advanceTimeoutLane
              { state with restartRequested := true } timeout
            effects := [.restart chosen]
          }
  | .opening =>
      if aligned then
        some {
          state := advanceTimeoutLane { state with phase := .open } timeout
          effects := [.completed]
        }
      else
        some { state := advanceTimeoutLane state timeout }
  | .open =>
      some { state := advanceTimeoutLane state timeout }

def rejected (state : NodeState) (reason : String) : StepOutput :=
  { state, effects := [.rejected reason], accepted := false }

def step (config : Config) (state : NodeState) : Event -> StepOutput
  | .receiveGossip source txid validation =>
      match validation with
      | .rejected => rejected state "quote-or-certificate"
      | .accepted =>
          if state.chosen != none then
            rejected state "gossip-frozen"
          else
            let received := { state with
              gossips := insertGossip source txid state.gossips }
            (advance config received false).getD
              (rejected state "empty-gossip-advance")
  | .receiveVote source validation =>
      match validation with
      | .rejected => rejected state "quote-or-certificate"
      | .accepted =>
          let received := { state with votes := insertVote source state.votes }
          (advance config received false).getD
            (rejected state "vote-advance")
  | .receiveIAmOpen source validation =>
      match validation with
      | .rejected => rejected state "quote-or-certificate"
      | .accepted =>
          match state.phase with
          | .opening | .open =>
              rejected state "already-opening-or-open"
          | _ =>
              let received := {
                state with
                phase := .joining
                chosen := some source
              }
              (advance config received false).getD
                (rejected state "join-without-chosen")
  | .timeout =>
      (advance config state true).getD
        (rejected state "empty-gossip-timeout-aborts")
  | .retry =>
      let effects :=
        match state.phase with
        | .gossiping =>
            config.expectedLocations.map .sendGossip
        | .voting =>
            match state.chosen with
            | none => config.expectedLocations.map .sendGossip
            | some chosen =>
                .sendVote chosen :: config.expectedLocations.map .sendGossip
        | .opening =>
            (config.expectedLocations.filter
              (fun location => location != state.location)).map .sendIAmOpen
        | .joining | .open => []
      { state, effects }

def replaceNode
    (target : Location)
    (next : NodeState)
    (nodes : List (Prod Location NodeState)) :
    List (Prod Location NodeState) :=
  nodes.map fun entry => if entry.1 == target then (target, next) else entry

def systemStep
    (config : Config)
    (state : SystemState)
    (target : Location)
    (event : Event) :
    Option (Prod SystemState StepOutput) := do
  let node <- (state.nodes.find? fun entry => entry.1 == target).map Prod.snd
  let output := step config node event
  pure ({
    nodes := replaceNode target output.state state.nodes
  }, output)

def expectedSource (config : Config) (source : Location) : Bool :=
  config.expectedLocations.contains source

def stateKey (state : NodeState) : String :=
  let gossips := String.intercalate "," (state.gossips.map fun entry =>
    s!"{entry.1}@{entry.2.view}.{entry.2.seqno}")
  let votes := String.intercalate "," state.votes
  let chosen := state.chosen.getD "-"
  let kind := state.openKind.map openKindName |>.getD "-"
  s!"{state.location}|{phaseName state.phase}|{phaseName state.timeoutState}|g={gossips}|v={votes}|c={chosen}|k={kind}|r={state.restartRequested}"

end DisasterRecovery.Protocol
