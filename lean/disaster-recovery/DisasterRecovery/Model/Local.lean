module

public import CCF.Capabilities
public import CCF.OCC
public import CCF.TxID

@[expose] public section

namespace DisasterRecovery.Model.Local

open CCF (Capabilities)
open CCF.OCC (Program)

/-- A node's configured recovery location. -/
abbrev Location := String

export CCF (TxID)

/-- The phases of the recovery decision protocol and its timeout lane. -/
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

/-- Whether opening was justified by a quorum or by the failover timeout. -/
inductive OpenKind where
  /-- A strict majority of the configured locations voted for it. -/
  | quorum
  /-- The voting timeout elapsed with some votes but no quorum. -/
  | failover
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- The host's quote and certificate validation result for a received message. -/
inductive Validation where
  /-- The message passed quote and certificate validation. -/
  | accepted
  /-- The message failed quote or certificate validation. -/
  | rejected
deriving Repr, Hashable, Inhabited, DecidableEq

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

/-- The tables of the node's key-value store that the protocol reads and writes. -/
inductive Table where
  /-- The protocol phase, a single value. -/
  | phase
  /-- The phase reached by the independent timeout lane, a single value. -/
  | timeoutPhase
  /-- The first accepted ledger tip from each gossip source. -/
  | gossips
  /-- The selected opener, or the node to join after an IAmOpen receive, a single value. -/
  | chosen
  /-- The sources of accepted votes. -/
  | votes
  /-- The justification recorded when this node starts opening, a single value. -/
  | openKind
deriving Repr, Hashable, DecidableEq

/-- A location in a table with one entry for each source, or `none` in a table that
holds a single value. -/
abbrev Key := Option Location

/-- The values the tables hold. -/
inductive Value where
  /-- A phase, in `phase` and `timeoutPhase`. -/
  | phase (phase : Phase)
  /-- A recovered ledger tip, in `gossips`. -/
  | txid (txid : TxID)
  /-- A location, in `chosen`. -/
  | location (location : Location)
  /-- An opening justification, in `openKind`. -/
  | openKind (kind : OpenKind)
  /-- Membership, in `votes`. -/
  | present
deriving Repr, Hashable, DecidableEq

/-- The committed state of the node's key-value store. -/
abbrev Store := CCF.OCC.DB Table Key Value

/-- A received message and its validation result, or a local timeout or retry. -/
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
deriving Repr, DecidableEq, Hashable

/-- Messages emitted by a retry and delivered to another recovery node. -/
inductive Message where
  /-- Advertise the sender's recovered transaction ID. -/
  | gossip (txid : TxID)
  /-- Vote for the recipient as the recovery location. -/
  | vote
  /-- Announce that the sender is opening the recovered service. -/
  | iAmOpen
deriving Repr, DecidableEq

/-- Host-visible outcomes of a local recovery step. -/
inductive Notification where
  /-- Begin opening the service with the given kind of evidence. -/
  | opening (kind : OpenKind)
  /-- Restart the node to join the chosen recovery location. -/
  | restart (chosen : Location)
  /-- The opening timeout has elapsed and recovery is complete. -/
  | completed
  /-- An incoming message was rejected without changing the local state. -/
  | rejected (reason : String)
deriving Repr, DecidableEq, Hashable

/-- What a transaction asks of the host. -/
inductive Output where
  /-- Send a message to a location. -/
  | send (message : Message) (target : Location)
  /-- Notify the host. -/
  | notify (notification : Notification)
deriving Repr, DecidableEq

/-- A transaction body over the node's store. -/
abbrev Tx := Program Table Key Value Output

/-- A transaction that has run on a snapshot of the store and has not committed. -/
structure Attempt where
  /-- The event the transaction handles. -/
  event : Event
  /-- Its staged writes, and what it read from its snapshot. -/
  normal : CCF.OCC.Normal Table Key Value
  /-- What it asks of the host. -/
  outputs : List Output
deriving Repr, DecidableEq

/-- The store of a node that starts the protocol: both phases are gossiping. -/
def initialStore : Store :=
  [
    ((.phase, none), { value := .phase .gossiping, version := 0 }),
    ((.timeoutPhase, none), { value := .phase .gossiping, version := 0 })
  ]

/-- One node's recovery state. A transaction's snapshot captures `store`; the rest is
outside any snapshot. -/
structure NodeState where
  /-- This node's recovery location. -/
  location : Location
  /-- The committed key-value store. -/
  store : Store := initialStore
  /-- The version of the latest transaction that wrote to the store. -/
  version : Nat := 0
  /-- Transactions that have run and have not committed, oldest first. -/
  pending : List Attempt := []
deriving Repr, DecidableEq

/-- The single value of `table` in `store`. -/
def single (store : Store) (table : Table) : Option Value :=
  (CCF.OCC.find store (table, none)).map (·.value)

/-- The committed protocol phase. -/
def NodeState.phase (state : NodeState) : Phase :=
  match single state.store .phase with
  | some (.phase phase) => phase
  | _ => .gossiping

/-- The committed phase of the timeout lane. -/
def NodeState.timeoutState (state : NodeState) : Phase :=
  match single state.store .timeoutPhase with
  | some (.phase phase) => phase
  | _ => .gossiping

/-- The committed chosen location. -/
def NodeState.chosen (state : NodeState) : Option Location :=
  match single state.store .chosen with
  | some (.location location) => some location
  | _ => none

/-- The committed opening justification. -/
def NodeState.openKind (state : NodeState) : Option OpenKind :=
  match single state.store .openKind with
  | some (.openKind kind) => some kind
  | _ => none

/-- The gossip entries among the entries of the `gossips` table. -/
def gossipEntries (entries : List (Key × Value)) : List (Location × TxID) :=
  entries.filterMap
    fun
      | (some source, .txid txid) => some (source, txid)
      | _ => none

/-- The vote sources among the entries of the `votes` table. -/
def voteEntries (entries : List (Key × Value)) : List Location :=
  entries.filterMap (·.1)

/-- The committed gossips. -/
def NodeState.gossips (state : NodeState) : List (Location × TxID) :=
  gossipEntries ((CCF.OCC.image state.store .gossips).map fun (key, cell) => (key, cell.value))

/-- The committed votes. -/
def NodeState.votes (state : NodeState) : List Location :=
  voteEntries ((CCF.OCC.image state.store .votes).map fun (key, cell) => (key, cell.value))

/-- Starts a node in gossiping with empty gossip and vote collections. -/
def initialNode (location : Location) : NodeState :=
  { location }

/-- The strict-majority vote threshold among expected locations. -/
def voteQuorum (config : Config) : Nat :=
  config.expectedLocations.length / 2 + 1

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

/-- Reads a phase table, failing if it is unset. -/
def readPhase (table : Table) : Tx Phase := do
  match ← Program.read (table, none) with
  | some (.phase phase) => return phase
  | _ => .fail "state-not-set"

/-- Writes a phase table. -/
def writePhase (table : Table) (phase : Phase) : Tx Unit :=
  Program.write (table, none) (.phase phase)

/-- Reads the chosen location, if one is set. -/
def readChosen : Tx (Option Location) := do
  match ← Program.read (.chosen, none) with
  | some (.location location) => return some location
  | _ => return none

/-- Notifies the host, if the transaction commits. -/
def notify (notification : Notification) : Tx Unit :=
  Program.emit (.notify notification)

/-- Advances the protocol phase, as `advance()` in the C++ does, and then the timeout
lane if this is a timeout. -/
def advance (config : Config) (timeout : Bool) : Tx Unit := do
  let phase ← readPhase .phase
  let lane ← readPhase .timeoutPhase
  -- A timeout can advance the protocol only when its lane matches the protocol phase.
  let aligned := timeout && phase == lane
  let advanceLane ←
    match phase with
    | .gossiping => do
        let gossips := gossipEntries (← Program.entries .gossips)
        if decide (gossips.length >= config.expectedLocations.length) || aligned then
          match maximumGossip gossips with
          | none => .fail "no-gossip"
          | some (chosen, _) =>
              Program.write (.chosen, none) (.location chosen)
              writePhase .phase .voting
              pure true
        else
          pure true
    | .voting => do
        let votes := voteEntries (← Program.entries .votes)
        let sufficient := decide (votes.length >= voteQuorum config)
        if sufficient || aligned then
          if aligned && votes.isEmpty then
            -- A node that voted for another node leaves opening to that node.
            pure false
          else
            let kind := if aligned && !sufficient then OpenKind.failover else .quorum
            Program.write (.openKind, none) (.openKind kind)
            writePhase .phase .opening
            notify (.opening kind)
            pure true
        else
          pure true
    | .joining => do
        match ← readChosen with
        | none => .fail "no-chosen-node"
        | some chosen =>
            notify (.restart chosen)
            pure true
    | .opening => do
        if aligned then
          writePhase .phase .open
          notify .completed
        pure true
    | .open => pure true
  if timeout && advanceLane then
    match lane with
    | .gossiping => writePhase .timeoutPhase .voting
    | .voting => writePhase .timeoutPhase .opening
    | _ => pure ()

/-- The transaction of a receive or a timeout, as its C++ handler reads and writes the
store. A failure is the handler returning an error: nothing is applied. -/
def transaction (config : Config) : Event → Tx Unit
  | .receiveGossip _ _ .rejected
  | .receiveVote _ .rejected
  | .receiveIAmOpen _ .rejected => .fail "quote-or-certificate"
  | .receiveGossip source txid .accepted => do
      if (← readChosen).isSome then
        .fail "gossip-frozen"
      else
        if (← Program.read (.gossips, some source)).isNone then
          Program.write (.gossips, some source) (.txid txid)
        advance config false
  | .receiveVote source .accepted => do
      Program.write (.votes, some source) .present
      advance config false
  | .receiveIAmOpen source .accepted => do
      match ← readPhase .phase with
      | .opening | .open => .fail "already-opening-or-open"
      | _ =>
          writePhase .phase .joining
          Program.write (.chosen, none) (.location source)
          advance config false
  | .timeout => advance config true
  | .retry => .fail "not-a-transaction"

/-- The messages a retry sends in the committed phase. It reads the store and writes
nothing. -/
def retry (config : Config) (location : Location) (recovered : TxID) : Tx Unit := do
  let send (message : Message) (target : Location) : Tx Unit :=
    Program.emit (.send message target)
  match ← readPhase .phase with
  | .gossiping =>
      if config.expectedLocations.isEmpty then
        .fail "nothing-to-send"
      else
        for target in config.expectedLocations do
          send (.gossip recovered) target
  | .voting =>
      match ← readChosen with
      | some chosen =>
          send .vote chosen
          for target in config.expectedLocations do
            send (.gossip recovered) target
      | none =>
          if config.expectedLocations.isEmpty then
            .fail "nothing-to-send"
          else
            for target in config.expectedLocations do
              send (.gossip recovered) target
  | .opening =>
      let targets := config.expectedLocations.filter (· != location)
      if targets.isEmpty then
        .fail "nothing-to-send"
      else
        for target in targets do
          send .iAmOpen target
  | .joining | .open => .fail "nothing-to-send"

/-- How a node executes a local event. A receive or a timeout is a transaction, which
runs and then commits; other transactions can commit in between. -/
inductive Operation where
  /-- Run the transaction of a receive or a timeout on a snapshot of the store. -/
  | run (event : Event)
  /-- Commit the pending transaction at `index`, or run it again if it conflicts. -/
  | commit (index : Nat)
  /-- Resend the messages appropriate to the committed phase, outside any transaction. -/
  | retry
deriving Repr, DecidableEq, Hashable

/-- Passes a transaction's outputs to the host, in order. -/
def release (host : Capabilities Location Message Notification)
    : List Output → CCF.Effect Location Message Notification Unit
  | [] => pure ()
  | .send message target :: rest => do
      host.send message target
      release host rest
  | .notify notification :: rest => do
      host.notify notification
      release host rest

/-- The outputs that the C++ passes to the host while the handler runs, without waiting
for its transaction to commit: its restart requests. -/
def unguarded (outputs : List Output) : List Output :=
  outputs.filter
    fun
      | .notify (.restart _) => true
      | _ => false

/-- Runs the transaction of `event` on a snapshot of the committed store, leaving it
pending. A transaction that fails is rejected at once. -/
def start (host : Capabilities Location Message Notification) (config : Config)
    (state : NodeState) (event : Event)
    : CCF.Effect Location Message Notification NodeState := do
  let ran := (transaction config event).exec state.store
  match ran.result with
  | .error reason =>
      host.notify (.rejected reason)
      return state
  | .ok () =>
      release host (unguarded ran.outputs)
      let attempt := { event, normal := ran.normal, outputs := ran.outputs }
      return { state with pending := state.pending ++ [attempt] }

/-- Runs or commits a transaction, or retries.
A commit applies the transaction's writes at the next version and passes its outputs to
the host, unless the transaction conflicts: something it read was written since its
snapshot. It is then rolled back and run again on the committed store. -/
def perform (host : Capabilities Location Message Notification) (config : Config)
    (recovered : TxID) (state : NodeState)
    : Operation → CCF.Effect Location Message Notification NodeState
  | .run .retry => failure
  | .run event => start host config state event
  | .commit index => do
      let some attempt := state.pending[index]?
        | failure
      let state := { state with pending := state.pending.eraseIdx index }
      if attempt.normal.writes.isEmpty then
        release host attempt.outputs
        return state
      else if CCF.OCC.validates state.store attempt.normal.deps then
        release host attempt.outputs
        let version := state.version + 1
        return {
          state with
            store := CCF.OCC.publish state.store version attempt.normal.writes
            version
        }
      else
        start host config state attempt.event
  | .retry => do
      let ran := (retry config state.location recovered).exec state.store
      match ran.result with
      | .error _ => failure
      | .ok () =>
          release host ran.outputs
          return state

end DisasterRecovery.Model.Local
