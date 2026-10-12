import DisasterRecovery.Shared.Capabilities

namespace DisasterRecovery.Model.Local

open Shared (Capabilities)

/-- The stable name of one recovery location. -/
abbrev Location := String

/-- A recovered transaction, ordered by view before sequence number. -/
structure TxID where
  /-- The consensus view in which the transaction was replicated. -/
  view : Nat
  /-- The transaction's position in the ledger. -/
  seqno : Nat
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The local recovery-decision protocol's lifecycle. -/
inductive Phase where
  /-- Collect recovered transaction IDs before choosing a location. -/
  | gossiping
  /-- Vote for the chosen location and collect votes for this location. -/
  | voting
  /-- Announce that this location is opening the recovered service. -/
  | opening
  /-- Restart against the location that announced it is opening. -/
  | joining
  /-- Recovery has completed at this location. -/
  | open
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The evidence that allowed a location to open. -/
inductive OpenKind where
  /-- A strict majority of the configured locations voted for it. -/
  | quorum
  /-- The voting timeout elapsed with some votes but no quorum. -/
  | failover
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The host's authentication result for an incoming protocol message. -/
inductive Validation where
  /-- The message passed quote and certificate validation. -/
  | accepted
  /-- The message failed quote or certificate validation. -/
  | rejected
deriving Repr, BEq, Hashable, Inhabited, DecidableEq

/-- Configuration shared by the locations in one recovery instance. -/
structure Config where
  /-- A nonempty identifier distinguishing this recovery instance. -/
  instanceId : String
  /-- The distinct, nonempty location names expected to participate. -/
  expectedLocations : List Location
deriving Repr, BEq, Hashable, Inhabited

/-- Check the instance ID and the nonempty, duplicate-free participant list. -/
def Config.isValid (config : Config) : Bool :=
  !config.instanceId.isEmpty
  && !config.expectedLocations.isEmpty
  && !config.expectedLocations.any String.isEmpty
  && config.expectedLocations.eraseDups.length = config.expectedLocations.length

/-- Persistent local state of the recovery-decision protocol. -/
structure NodeState where
  /-- The identity of this node's recovery location. -/
  location : Location
  /-- The current protocol phase, advanced by messages and timeouts. -/
  phase : Phase := .gossiping
  /-- The independently advancing phase of the timeout schedule. -/
  timeoutState : Phase := .gossiping
  /-- The first accepted transaction ID from each gossip source. -/
  gossips : List (Prod Location TxID) := []
  /-- Distinct locations from which this node accepted a vote. -/
  votes : List Location := []
  /-- The selected gossip winner, or the location to join. -/
  chosen : Option Location := none
  /-- Why this location began opening, if it did. -/
  openKind : Option OpenKind := none
  /-- Whether the host has been told to restart against the chosen location. -/
  restartRequested : Bool := false
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited

/-- Inputs handled by one execution of the local protocol. -/
inductive Event where
  /-- Receive a source's recovered transaction ID and its validation result. -/
  | receiveGossip (source : Location) (txid : TxID) (validation : Validation)
  /-- Receive a vote for this location and its validation result. -/
  | receiveVote (source : Location) (validation : Validation)
  /-- Receive another location's opening announcement and validation result. -/
  | receiveIAmOpen (source : Location) (validation : Validation)
  /-- Advance the timeout schedule and, when aligned, the protocol phase. -/
  | timeout
  /-- Resend the messages appropriate to the current phase. -/
  | retry
deriving Repr, BEq, Hashable

/-- Payloads exchanged between recovery locations. -/
inductive Message where
  /-- Advertise the sender's recovered transaction ID. -/
  | gossip (txid : TxID)
  /-- Vote for the recipient as the recovery location. -/
  | vote
  /-- Announce that the sender is opening the recovered service. -/
  | iAmOpen
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Effects reported to the host rather than sent to other locations. -/
inductive Notification where
  /-- Begin opening the service with the given kind of evidence. -/
  | opening (kind : OpenKind)
  /-- Restart the node to join the chosen recovery location. -/
  | restart (chosen : Location)
  /-- The opening timeout has elapsed and recovery is complete. -/
  | completed
  /-- An incoming message was rejected without changing the local state. -/
  | rejected (reason : String)
deriving Repr, BEq, Hashable

/-- Begin gossiping with no received messages or recovery decision. -/
def initialNode (location : Location) : NodeState :=
  { location }

/-- The strict majority required for quorum opening. -/
def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

/-- Whether this execution is a timeout aligned with the protocol phase. -/
def validTimeout (state : NodeState) (timeout : Bool) : Bool :=
  timeout && decide (state.phase = state.timeoutState)

/-- Compare view, sequence number, then location name, breaking ties deterministically. -/
def txScoreGreater (leftName : Location) (left : TxID) (rightName : Location)
    (right : TxID)
    : Bool :=
  right.view < left.view
  || (right.view == left.view
      && (right.seqno < left.seqno
          || (right.seqno == left.seqno && rightName < leftName)))

/-- Keep the gossip with the greater transaction score and location tie-breaker. -/
def selectMaximum (current candidate : Prod Location TxID) : Prod Location TxID :=
  if txScoreGreater candidate.1 candidate.2 current.1 current.2 then
    candidate
  else
    current

/-- Select the winning gossip, or `none` when no gossip has been accepted. -/
def maximumGossip : List (Prod Location TxID) -> Option (Prod Location TxID)
  | [] => none
  | head :: tail =>
      some (tail.foldl selectMaximum head)

/-- Record only the first gossip per source, keeping sources sorted. -/
def insertGossip (source : Location) (txid : TxID) (gossips : List (Prod Location TxID))
    : List (Prod Location TxID) :=
  if gossips.any (fun entry => entry.1 == source) then
    gossips
  else
    ((source, txid) :: gossips).mergeSort (fun left right => left.1 <= right.1)

/-- Record each voting source once, keeping the list sorted. -/
def insertVote (source : Location) (votes : List Location) : List Location :=
  if votes.contains source then
    votes
  else
    (source :: votes).mergeSort (fun left right => left <= right)

/-- Advance the timeout schedule from gossiping to voting to opening. -/
def advanceTimeoutState : Phase -> Phase
  | .gossiping => .voting
  | .voting => .opening
  | state => state

/-- Advance the timeout schedule only for a timeout execution. -/
def advanceTimeoutLane (state : NodeState) (timeout : Bool) : NodeState :=
  if timeout then
    { state with timeoutState := advanceTimeoutState state.timeoutState }
  else
    state

/-- Advance one protocol phase when its evidence or aligned timeout permits it. -/
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

/-- Notify the host of rejection while preserving the supplied local state. -/
def rejected (host : Capabilities Location Message Notification)
    (state : NodeState) (reason : String)
    : Shared.Effect Location Message Notification NodeState := do
  host.notify (.rejected reason)
  return state

/-- Process a validated receive, timeout, or retry using output-only host capabilities. -/
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
