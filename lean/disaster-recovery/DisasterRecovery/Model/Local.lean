import DisasterRecovery.Shared.Capabilities

namespace DisasterRecovery.Model.Local

open Shared (Capabilities)

/-- A node's configured recovery location. -/
abbrev Location := String

/-- The view and sequence number of a recovered ledger's last signed transaction. -/
structure TxID where
  /-- The transaction's Raft view. -/
  view : Nat
  /-- The transaction's sequence number. -/
  seqno : Nat
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The phases of the recovery decision protocol and its timeout lane. -/
inductive Phase where
  | gossiping
  | voting
  | opening
  | joining
  | open
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- Whether opening was justified by a quorum or by the failover timeout. -/
inductive OpenKind where
  | quorum
  | failover
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The host's quote and certificate validation result for a received message. -/
inductive Validation where
  | accepted
  | rejected
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

/-- The recovery instance identifier and expected participants. -/
structure Config where
  /-- Nonempty identifier distinguishing this recovery instance. -/
  instanceId : String
  /-- Distinct, nonempty location names expected to participate in recovery. -/
  expectedLocations : List Location
deriving Repr, BEq, Hashable, Inhabited

/-- Checks that the instance and distinct expected location names are nonempty. -/
def Config.isValid (config : Config) : Bool :=
  !config.instanceId.isEmpty
  && !config.expectedLocations.isEmpty
  && !config.expectedLocations.any String.isEmpty
  && config.expectedLocations.eraseDups.length = config.expectedLocations.length

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
  /-- Whether joining has requested a restart from the chosen node. -/
  restartRequested : Bool := false
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited

/-- A received message and its validation result, or a local timeout or retry. -/
inductive Event where
  | receiveGossip (source : Location) (txid : TxID) (validation : Validation)
  | receiveVote (source : Location) (validation : Validation)
  | receiveIAmOpen (source : Location) (validation : Validation)
  | timeout
  | retry
deriving Repr, BEq, Hashable

/-- Messages emitted by a retry and delivered to another recovery node. -/
inductive Message where
  | gossip (txid : TxID)
  | vote
  | iAmOpen
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Host-visible outcomes of a local recovery step. -/
inductive Notification where
  | opening (kind : OpenKind)
  | restart (chosen : Location)
  | completed
  | rejected (reason : String)
deriving Repr, BEq, Hashable

/-- Starts a node in gossiping with empty gossip and vote collections. -/
def initialNode (location : Location) : NodeState :=
  { location }

/-- The strict-majority vote threshold among expected locations. -/
def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

/-- A timeout can advance the protocol only when its lane matches the protocol phase. -/
def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

/-- Orders gossip candidates by view, sequence number, then location name. -/
def txScoreGreater (leftName : Location) (left : TxID) (rightName : Location)
    (right : TxID)
    : Bool :=
  right.view < left.view
  || (right.view == left.view
      && (right.seqno < left.seqno
          || (right.seqno == left.seqno && rightName < leftName)))

/-- Keeps the greater gossip candidate under the deterministic score ordering. -/
def selectMaximum (current candidate : Prod Location TxID) : Prod Location TxID :=
  if txScoreGreater candidate.1 candidate.2 current.1 current.2 then
    candidate
  else
    current

/-- Selects the highest-scoring gossip, or returns `none` when none has arrived. -/
def maximumGossip : List (Prod Location TxID) -> Option (Prod Location TxID)
  | [] => none
  | head :: tail =>
      some (tail.foldl selectMaximum head)

/-- Records a source's first gossip and keeps the collection sorted by location. -/
def insertGossip (source : Location) (txid : TxID) (gossips : List (Prod Location TxID))
    : List (Prod Location TxID) :=
  if gossips.any (fun entry => entry.1 == source) then
    gossips
  else
    ((source, txid) :: gossips).mergeSort (fun left right => left.1 <= right.1)

/-- Adds a previously unseen voter and keeps votes sorted by location. -/
def insertVote (source : Location) (votes : List Location) : List Location :=
  if votes.contains source then
    votes
  else
    (source :: votes).mergeSort (fun left right => left <= right)

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
    : Option (Shared.Effect Location Message Notification NodeState) :=
  let aligned := validTimeout state timeout
  match state.phase with
  | .gossiping =>
      if decide (state.gossips.length >= config.expectedLocations.length) || aligned then
        match maximumGossip state.gossips with
        | none => none
        | some (chosen, _) =>
            let next := { state with phase := .voting, chosen := some chosen }
            some (pure (advanceTimeoutLane next timeout))
      else
        some (pure (advanceTimeoutLane state timeout))
  | .voting =>
      let sufficient := decide (state.votes.length >= voteQuorum config)
      if sufficient || aligned then
        if aligned && state.votes.isEmpty then
          some (pure state)
        else
          let kind := if aligned && !sufficient then .failover else .quorum
          let next :=
            {
              state with
                phase := .opening
                openKind := some kind
            }
          some do
            host.notify (.opening kind)
            return advanceTimeoutLane next timeout
      else
        some (pure (advanceTimeoutLane state timeout))
  | .joining =>
      match state.chosen with
      | none => none
      | some chosen =>
          some do
            host.notify (.restart chosen)
            return advanceTimeoutLane { state with restartRequested := true } timeout
  | .opening =>
      if aligned then
        some do
          host.notify .completed
          return advanceTimeoutLane { state with phase := .open } timeout
      else
        some (pure (advanceTimeoutLane state timeout))
  | .open =>
      some (pure (advanceTimeoutLane state timeout))

/-- Emits a rejection diagnostic without changing the local protocol state. -/
def rejected (host : Capabilities Location Message Notification)
    (state : NodeState) (reason : String)
    : Shared.Effect Location Message Notification NodeState := do
  host.notify (.rejected reason)
  return state

/-- Executes one local event using the host's output-only callbacks. -/
def step (host : Capabilities Location Message Notification) (config : Config)
    (recovered : TxID) (state : NodeState) (event : Event)
    : Option (Shared.Effect Location Message Notification NodeState) := do
  match event with
  | .receiveGossip source txid validation =>
      match validation with
      | .rejected => pure (rejected host state "quote-or-certificate")
      | .accepted =>
          if state.chosen != none then
            pure (rejected host state "gossip-frozen")
          else
            let received :=
              { state with gossips := insertGossip source txid state.gossips }
            pure
              ((advance host config received false).getD
                (rejected host state "empty-gossip-advance"))
  | .receiveVote source validation =>
      match validation with
      | .rejected => pure (rejected host state "quote-or-certificate")
      | .accepted =>
          let received := { state with votes := insertVote source state.votes }
          pure
            ((advance host config received false).getD
              (rejected host state "vote-advance"))
  | .receiveIAmOpen source validation =>
      match validation with
      | .rejected => pure (rejected host state "quote-or-certificate")
      | .accepted =>
          match state.phase with
          | .opening | .open => pure (rejected host state "already-opening-or-open")
          | _ =>
              let received :=
                {
                  state with
                    phase := .joining
                    chosen := some source
                }
              pure
                ((advance host config received false).getD
                  (rejected host state "join-without-chosen"))
  | .timeout =>
      advance host config state true
  | .retry =>
      match state.phase with
      | .gossiping | .voting =>
          let voteTarget := if state.phase == .voting then state.chosen else none
          guard (voteTarget.isSome || !config.expectedLocations.isEmpty)
          pure do
            if let some target := voteTarget then
              host.send .vote target
            for target in config.expectedLocations do
              host.send (.gossip recovered) target
            return state
      | .opening =>
          let targets := config.expectedLocations.filter (· != state.location)
          guard (!targets.isEmpty)
          pure do
            for target in targets do
              host.send .iAmOpen target
            return state
      | .joining | .open => none

end DisasterRecovery.Model.Local
