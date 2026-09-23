import DisasterRecovery.Model

/-!
Proof-only local instrumentation. `Lifting.step_erases` relates these
outputs to `DisasterRecovery.Model.Local.step` results, including rejected receives.
-/

namespace DisasterRecovery.Proofs.Execution.Local

open Shared (TransitionSystem)

export DisasterRecovery.Model.Local (
  Location TxID Phase OpenKind Validation Config NodeState Event
  initialNode voteQuorum validTimeout txScoreGreater
  selectMaximum maximumGossip insertGossip insertVote advanceTimeoutState
  advanceTimeoutLane)

inductive Effect where
  | sendGossip (destination : Location)
  | sendVote (destination : Location)
  | sendIAmOpen (destination : Location)
  | opening (kind : OpenKind)
  | restart (chosen : Location)
  | completed
  | rejected (reason : String)
deriving Repr, BEq, Hashable

def Effect.diagnostic : Effect -> Option Model.Local.Notification
  | .opening kind => some (.opening kind)
  | .restart chosen => some (.restart chosen)
  | .completed => some .completed
  | .rejected reason => some (.rejected reason)
  | _ => none

def messages (source : Location) (recovered : TxID) (effects : List Effect) : List Model.Envelope :=
  effects.filterMap fun effect =>
    match effect with
    | .sendGossip target => some { source, target, payload := .gossip recovered }
    | .sendVote target => some { source, target, payload := .vote }
    | .sendIAmOpen target => some { source, target, payload := .iAmOpen }
    | _ => none

structure StepOutput where
  state : NodeState
  effects : List Effect := []
  accepted : Bool := true
deriving Repr, BEq, Inhabited

structure SystemState where
  nodes : List (Prod Location NodeState)
deriving Repr, BEq, Hashable, Inhabited

def initialSystem (config : Config) : SystemState :=
  { nodes := config.expectedLocations.map fun location =>
      (location, initialNode location) }

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

def transitionSystem (config : Config) (location : Location) :
    TransitionSystem StepOutput Event where
  init := fun current => current = { state := initialNode location }
  step current event :=
    let state := current.state
    match event with
    | .receiveGossip source txid validation => do
        guard (validation = .accepted)
        guard (state.chosen = none)
        let received := { state with
          gossips := insertGossip source txid state.gossips }
        advance config received false
    | .receiveVote source validation => do
        guard (validation = .accepted)
        let received := { state with votes := insertVote source state.votes }
        advance config received false
    | .receiveIAmOpen source validation => do
        guard (validation = .accepted)
        guard (state.phase ≠ .opening ∧ state.phase ≠ .open)
        let received := {
          state with
          phase := .joining
          chosen := some source
        }
        advance config received false
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

def rejectionReason (state : NodeState) : Event -> String
  | .receiveGossip _ _ .rejected
  | .receiveVote _ .rejected
  | .receiveIAmOpen _ .rejected => "quote-or-certificate"
  | .receiveGossip _ _ .accepted =>
      if state.chosen != none then "gossip-frozen" else "empty-gossip-advance"
  | .receiveVote _ .accepted => "vote-advance"
  | .receiveIAmOpen _ .accepted =>
      match state.phase with
      | .opening | .open => "already-opening-or-open"
      | _ => "join-without-chosen"
  | .timeout => "empty-gossip-timeout-aborts"
  | .retry => "retry-disabled"

/-- Preserve rejected receives as stutters for the global delivery model. -/
def step (config : Config) (state : NodeState) (event : Event) : StepOutput :=
  ((transitionSystem config state.location).step { state } event).getD
    (rejected state (rejectionReason state event))

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

end DisasterRecovery.Proofs.Execution.Local
