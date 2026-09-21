import DisasterRecovery.Shared.TransitionSystem
import DisasterRecovery.Shared.Capabilities

namespace DisasterRecovery.Model.Local

open Shared (TransitionSystem Capabilities)

abbrev Location := String

structure TxID where
  view : Nat
  seqno : Nat
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

inductive Phase where
  | gossiping
  | voting
  | opening
  | joining
  | open
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

inductive OpenKind where
  | quorum
  | failover
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

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
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited

inductive Event where
  | receiveGossip (source : Location) (txid : TxID) (validation : Validation)
  | receiveVote (source : Location) (validation : Validation)
  | receiveIAmOpen (source : Location) (validation : Validation)
  | timeout
  | retry
deriving Repr, BEq, Hashable

inductive Message where
  | gossip (txid : TxID)
  | vote
  | iAmOpen
deriving Repr, BEq, ReflBEq, LawfulBEq

def receive (source : Location) : Message -> Event
  | .gossip txid => .receiveGossip source txid .accepted
  | .vote => .receiveVote source .accepted
  | .iAmOpen => .receiveIAmOpen source .accepted

inductive Effect where
  | sendGossip (destination : Location)
  | sendVote (destination : Location)
  | sendIAmOpen (destination : Location)
  | opening (kind : OpenKind)
  | restart (chosen : Location)
  | completed
  | rejected (reason : String)
deriving Repr, BEq, Hashable

structure Result where
  state : NodeState
  effects : List Effect := []
deriving Repr, BEq, Inhabited

def messages (recovered : TxID) (effects : List Effect) : List (Location × Message) :=
  effects.filterMap fun effect =>
    match effect with
    | .sendGossip target => some (target, .gossip recovered)
    | .sendVote target => some (target, .vote)
    | .sendIAmOpen target => some (target, .iAmOpen)
    | _ => none

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

def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

def txScoreGreater
    (leftName : Location)
    (left : TxID)
    (rightName : Location)
    (right : TxID) : Bool :=
  right.view < left.view ||
    (right.view == left.view &&
      (right.seqno < left.seqno ||
        (right.seqno == left.seqno && rightName < leftName)))

def selectMaximum
    (current candidate : Prod Location TxID) :
    Prod Location TxID :=
  if txScoreGreater candidate.1 candidate.2 current.1 current.2 then
    candidate
  else
    current

def maximumGossip : List (Prod Location TxID) -> Option (Prod Location TxID)
  | [] => none
  | head :: tail =>
      some (tail.foldl selectMaximum head)

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
    Option Result :=
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

def rejected (state : NodeState) (reason : String) : Result :=
  { state, effects := [.rejected reason] }

def transition (config : Config) (state : NodeState) : Event -> Option Result
    | .receiveGossip source txid validation =>
        pure <| match validation with
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
        pure <| match validation with
        | .rejected => rejected state "quote-or-certificate"
        | .accepted =>
            let received := { state with votes := insertVote source state.votes }
            (advance config received false).getD (rejected state "vote-advance")
    | .receiveIAmOpen source validation =>
        pure <| match validation with
        | .rejected => rejected state "quote-or-certificate"
        | .accepted =>
            match state.phase with
            | .opening | .open => rejected state "already-opening-or-open"
            | _ =>
                let received := {
                  state with
                  phase := .joining
                  chosen := some source
                }
                (advance config received false).getD
                  (rejected state "join-without-chosen")
    | .timeout =>
        advance config state true
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
        pure { state, effects }

def step (host : Capabilities σ Location Message) (config : Config)
    (recovered : TxID) (state : NodeState) (event : Event) :
    Option (ST σ NodeState) := do
  let output <- transition config state event
  let outgoing := messages recovered output.effects
  match event with
  | .retry => guard (!outgoing.isEmpty)
  | _ => pure ()
  pure do
    for (target, message) in outgoing do
      host.send message target
    return output.state

def transitionSystem (config : Config) (location : Location) :
    TransitionSystem NodeState Event where
  init := fun state => state = initialNode location
  step := fun state event => (transition config state event).map Result.state

def expectedSource (config : Config) (source : Location) : Bool :=
  config.expectedLocations.contains source

def stateKey (state : NodeState) : String :=
  let gossips := String.intercalate "," (state.gossips.map fun entry =>
    s!"{entry.1}@{entry.2.view}.{entry.2.seqno}")
  let votes := String.intercalate "," state.votes
  let chosen := state.chosen.getD "-"
  let kind := state.openKind.map openKindName |>.getD "-"
  s!"{state.location}|{phaseName state.phase}|{phaseName state.timeoutState}|g={gossips}|v={votes}|c={chosen}|k={kind}|r={state.restartRequested}"

end DisasterRecovery.Model.Local
