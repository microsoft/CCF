import DisasterRecovery.Shared.Capabilities

namespace DisasterRecovery.Model.Local

open Shared (Capabilities)

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
  !config.instanceId.isEmpty
  && !config.expectedLocations.isEmpty
  && !config.expectedLocations.any String.isEmpty
  && config.expectedLocations.eraseDups.length = config.expectedLocations.length

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

inductive Notification where
  | opening (kind : OpenKind)
  | restart (chosen : Location)
  | completed
  | rejected (reason : String)
deriving Repr, BEq, Hashable

def initialNode (location : Location) : NodeState :=
  { location }

def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

def txScoreGreater (leftName : Location) (left : TxID) (rightName : Location) (right : TxID)
    : Bool :=
  right.view < left.view
  || (right.view == left.view
      && (right.seqno < left.seqno || (right.seqno == left.seqno && rightName < leftName)))

def selectMaximum (current candidate : Prod Location TxID) : Prod Location TxID :=
  if txScoreGreater candidate.1 candidate.2 current.1 current.2 then
    candidate
  else
    current

def maximumGossip : List (Prod Location TxID) -> Option (Prod Location TxID)
  | [] => none
  | head :: tail =>
      some (tail.foldl selectMaximum head)

def insertGossip (source : Location) (txid : TxID) (gossips : List (Prod Location TxID))
    : List (Prod Location TxID) :=
  if gossips.any (fun entry => entry.1 == source) then
    gossips
  else
    ((source, txid) :: gossips).mergeSort (fun left right => left.1 <= right.1)

def insertVote (source : Location) (votes : List Location) : List Location :=
  if votes.contains source then
    votes
  else
    (source :: votes).mergeSort (fun left right => left <= right)

def advanceTimeoutState : Phase -> Phase
  | .gossiping => .voting
  | .voting => .opening
  | state => state

def advanceTimeoutLane (state : NodeState) (timeout : Bool) : NodeState :=
  if timeout then
    { state with timeoutState := advanceTimeoutState state.timeoutState }
  else
    state

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

def rejected (host : Capabilities Location Message Notification)
    (state : NodeState) (reason : String)
    : Shared.Effect Location Message Notification NodeState := do
  host.notify (.rejected reason)
  return state

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
            let received := { state with gossips := insertGossip source txid state.gossips }
            pure
              ((advance host config received false).getD
                (rejected host state "empty-gossip-advance"))
  | .receiveVote source validation =>
      match validation with
      | .rejected => pure (rejected host state "quote-or-certificate")
      | .accepted =>
          let received := { state with votes := insertVote source state.votes }
          pure ((advance host config received false).getD (rejected host state "vote-advance"))
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
