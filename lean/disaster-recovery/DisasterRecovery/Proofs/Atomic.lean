module

public import DisasterRecovery.Model

@[expose] public section

/-! The serialized protocol used by the safety decoration. It tracks the values
of the six protocol tables, not cell versions, dependencies or queued attempts. -/

namespace DisasterRecovery.Proofs.Atomic

open CCF (Capabilities)
export DisasterRecovery.Model.Local (
  Location Config TxID Phase OpenKind Event Message Notification Validation voteQuorum
  maximumGossip selectMaximum txScoreGreater
)

/-- One node's recovery state, without message queues or execution history. -/
structure NodeState where
  /-- This node's recovery location. -/
  location : Location
  /-- Current protocol phase. -/
  phase : Phase := .gossiping
  /-- Phase reached by the independent timeout lane. -/
  timeoutState : Phase := .gossiping
  /-- The first accepted ledger tip from each gossip source. -/
  gossips : List (Prod Location TxID) := []
  /-- Distinct sources of accepted votes. -/
  votes : List Location := []
  /-- The selected opener, or the node to join after an IAmOpen receive. -/
  chosen : Option Location := none
  /-- The justification recorded when this node starts opening. -/
  openKind : Option OpenKind := none
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited

/-- Starts a node in gossiping with empty gossip and vote collections. -/
def initialNode (location : Location) : NodeState :=
  { location }

/-- A timeout can advance the protocol only when its lane matches the protocol phase. -/
def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

/-- Record a source's first gossip in the order of the committed table. -/
def insertGossip (source : Location) (txid : TxID) (gossips : List (Prod Location TxID))
    : List (Prod Location TxID) :=
  if gossips.any (fun entry => entry.1 == source) then
    gossips
  else
    (source, txid) :: gossips

/-- A put moves its association to the front, without counting the voter twice. -/
def insertVote (source : Location) (votes : List Location) : List Location :=
  source :: votes.erase source

/-- Advances the timeout lane from gossiping to voting, then to opening. -/
def advanceTimeoutState : Phase -> Phase
  | .gossiping => .voting
  | .voting => .opening
  | state => state

/-- Advances the timeout lane only when this step was triggered by a timeout. -/
def advanceTimeoutLane (state : NodeState) (timeout : Bool) : NodeState :=
  if timeout then
    { state with timeoutState := advanceTimeoutState state.timeoutState }
  else
    state

/-- Advances the protocol phase and emits notifications, or disables an impossible advance. -/
def advance (host : Capabilities Location Message Notification)
    (config : Config) (state : NodeState) (timeout : Bool)
    : CCF.Effect Location Message Notification NodeState := do
  let aligned := validTimeout state timeout
  match state.phase with
  | .gossiping =>
      if decide (state.gossips.length >= config.expectedLocations.length) || aligned then
        match maximumGossip state.gossips with
        | none => failure
        | some (chosen, _) =>
            let next := { state with phase := .voting, chosen := some chosen }
            return advanceTimeoutLane next timeout
      else
        return advanceTimeoutLane state timeout
  | .voting =>
      let sufficient := decide (state.votes.length >= voteQuorum config)
      if sufficient || aligned then
        if aligned && state.votes.isEmpty then
          return state
        else
          let kind := if aligned && !sufficient then .failover else .quorum
          let next :=
            {
              state with
                phase := .opening
                openKind := some kind
            }
          host.notify (.opening kind)
          return advanceTimeoutLane next timeout
      else
        return advanceTimeoutLane state timeout
  | .joining =>
      match state.chosen with
      | none => failure
      | some chosen =>
          host.notify (.restart chosen)
          return advanceTimeoutLane state timeout
  | .opening =>
      if aligned then
        host.notify .completed
        return advanceTimeoutLane { state with phase := .open } timeout
      else
        return advanceTimeoutLane state timeout
  | .open =>
      return advanceTimeoutLane state timeout

/-- Emits a rejection diagnostic without changing the local protocol state. -/
def rejected (host : Capabilities Location Message Notification)
    (state : NodeState) (reason : String)
    : CCF.Effect Location Message Notification NodeState := do
  host.notify (.rejected reason)
  return state

/-- Executes one local event using the host's output-only callbacks. -/
def step (host : Capabilities Location Message Notification) (config : Config)
    (recovered : TxID) (state : NodeState) (event : Event)
    : CCF.Effect Location Message Notification NodeState := do
  match event with
  | .receiveGossip source txid validation =>
      match validation with
      | .rejected => rejected host state "quote-or-certificate"
      | .accepted =>
          if state.chosen != none then
            rejected host state "gossip-frozen"
          else
            let received :=
              { state with gossips := insertGossip source txid state.gossips }
            advance host config received false
            <|> rejected host state "empty-gossip-advance"
  | .receiveVote source validation =>
      match validation with
      | .rejected => rejected host state "quote-or-certificate"
      | .accepted =>
          let received := { state with votes := insertVote source state.votes }
          advance host config received false <|> rejected host state "vote-advance"
  | .receiveIAmOpen source validation =>
      match validation with
      | .rejected => rejected host state "quote-or-certificate"
      | .accepted =>
          match state.phase with
          | .opening | .open => rejected host state "already-opening-or-open"
          | _ =>
              let received :=
                {
                  state with
                    phase := .joining
                    chosen := some source
                }
              advance host config received false
              <|> rejected host state "join-without-chosen"
  | .timeout =>
      advance host config state true
  | .retry =>
      match state.phase with
      | .gossiping | .voting =>
          let voteTarget := if state.phase == .voting then state.chosen else none
          guard (voteTarget.isSome || !config.expectedLocations.isEmpty)
          if let some target := voteTarget then
            host.send .vote target
          for target in config.expectedLocations do
            host.send (.gossip recovered) target
          return state
      | .opening =>
          let targets := config.expectedLocations.filter (· != state.location)
          guard (!targets.isEmpty)
          for target in targets do
            host.send .iAmOpen target
          return state
      | .joining | .open => failure

end DisasterRecovery.Proofs.Atomic
