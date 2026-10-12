import DisasterRecovery.Proofs.Execution

/-! Safety predicates and committed-prefix assumptions for decorated executions. -/

namespace DisasterRecovery.Proofs.Predicates

open Execution.Local hiding Config
open Execution.Global

/-! ## Well-formedness and message provenance -/

/-- Every recorded host notification came from an active location. -/
structure HistoriesActive (state : State) : Prop where
  /-- Only active locations have recorded opening notifications. -/
  openings : forall opening, opening ∈ state.openings -> opening.node ∈ state.active
  /-- Only active locations have recorded restart notifications. -/
  restarts : forall node, node ∈ state.restarts -> node ∈ state.active
  /-- Only active locations have recorded completion notifications. -/
  completed : forall node, node ∈ state.completed -> node ∈ state.active

/-- Node-table consistency and provenance invariants of an instrumented global state. -/
structure WellFormed (config : Config) (state : State) : Prop where
  /-- The node-table keys exactly match the configured locations, in order. -/
  nodeKeys : state.system.nodes.map Prod.fst = config.protocol.expectedLocations
  /-- Each location has at most one node-table entry. -/
  nodeKeysNodup : (state.system.nodes.map Prod.fst).Nodup
  /-- Every local state's location agrees with its node-table key. -/
  nodeLocations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1
  /-- The active-location list has no duplicates. -/
  activeNodup : state.active.Nodup
  /-- Every active location is configured. -/
  activeConfigured
    : forall node, node ∈ state.active -> node ∈ config.protocol.expectedLocations
  /-- Every recorded send has valid local-step evidence. -/
  sentValid : forall envelope, envelope ∈ state.sent -> envelope.Valid config
  /-- Only active locations have sent messages. -/
  sentSourceActive
    : forall envelope, envelope ∈ state.sent -> envelope.source ∈ state.active
  /-- Every queued envelope has a corresponding recorded send. -/
  networkSent : forall envelope, envelope ∈ state.network -> envelope ∈ state.sent
  /-- Host-notification histories refer only to active locations. -/
  historiesActive : HistoriesActive state

/-! ## Votes, quorums, and openings -/

/-- The send history contains a vote from `voter` to `target`. -/
def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent
    /\ envelope.source = voter
    /\ envelope.target = target
    /\ envelope.payload = .vote

/-- No node counts the same voting location more than once. -/
def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes -> entry.2.votes.Nodup

/-- Every vote counted by a node has a matching send to that node. -/
def NodeVotesSent (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall voter, voter ∈ entry.2.votes -> SentVote state voter entry.1

/-- Each voting location has sent votes to at most one target. -/
def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first -> SentVote state voter second -> first = second

/-- A past voter cannot return to gossiping or change its choice while voting. -/
def SentVoteStable (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> forall entry,
        entry ∈ state.system.nodes
        -> entry.1 = envelope.source
        -> entry.2.phase ≠ .gossiping
            /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target)

/-- The node's chosen location is the winner of its accepted gossips. -/
def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\ maximumGossip state.gossips = some (target, txid)

/-- Every currently voting node chose its gossip winner. -/
def VotingSelectionsValid (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes -> entry.2.phase = .voting -> NodeVotingSelection entry.2

/-- The source-state snapshot of every sent vote records a valid gossip selection. -/
def SentVotesSelected (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> NodeVotingSelection envelope.sourceState

/-- A recorded opening agrees with its local state and has justified, distinct votes. -/
structure Opening.Valid (config : Config) (globalState : State) (opening : Opening)
    : Prop where
  /-- The opening snapshot belongs to the notifying location. -/
  location : opening.state.location = opening.node
  /-- The snapshot records the opening phase. -/
  phase : opening.state.phase = .opening
  /-- The snapshot and notification agree on the opening evidence. -/
  kind : opening.state.openKind = some opening.kind
  /-- The snapshot does not count duplicate voters. -/
  votesNodup : opening.state.votes.Nodup
  /-- A quorum opening has at least the configured majority threshold. -/
  quorum
    : opening.kind = .quorum -> voteQuorum config.protocol <= opening.state.votes.length
  /-- Every counted vote was actually sent to the opening location. -/
  votesSent
    : forall voter, voter ∈ opening.state.votes -> SentVote globalState voter opening.node

/-- Every opening notification in the history has a valid supporting snapshot. -/
def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings -> Opening.Valid config state opening

/-- The vote and opening invariants used to prove uniqueness of quorum opening. -/
structure QuorumInvariant (config : Config) (state : State) : Prop where
  /-- Counted votes contain no duplicate sources. -/
  votesNodup : NodeVotesNodup state
  /-- Counted votes are backed by the send history. -/
  votesSent : NodeVotesSent state
  /-- Past voters retain their voting choice until leaving voting. -/
  sentVoteStable : SentVoteStable state
  /-- A source never votes for two different locations. -/
  sentVotesFunctional : SentVotesFunctional state
  /-- Current voting choices are justified by the nodes' gossips. -/
  votingSelections : VotingSelectionsValid state
  /-- Historical votes have snapshots with justified gossip choices. -/
  sentVotesSelected : SentVotesSelected state
  /-- Historical openings have valid evidence and snapshots. -/
  openingsValid : OpeningsValid config state

/-- Extract the source only when the event is an accepted vote. -/
def acceptedVoteSource : Event -> Option Location
  | .receiveVote source .accepted => some source
  | _ => none

/-- The history contains a quorum-opening notification from `node`. -/
def QuorumOpened (state : State) (node : Location) : Prop :=
  exists opening,
    opening ∈ state.openings /\ opening.node = node /\ opening.kind = .quorum

/-! ## Committed-prefix ordering and assumptions -/

namespace TxID

/-- The non-strict transaction freshness order, comparing view before sequence number. -/
def EarlierThan (left right : TxID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end TxID

/-- Some vote for the opener was selected from all configured recovered transaction IDs. -/
def FullGossipSelection (config : Config) (state : State) (opener : Location) : Prop :=
  exists vote,
    vote ∈ state.sent
    /\ vote.payload = .vote
    /\ vote.target = opener
    /\ forall gossip, gossip ∈ vote.sourceState.gossips <-> gossip ∈ config.recovered

/-- At least one recovered transaction ID is as fresh as the committed transaction. -/
def DurableCommit (config : Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\ TxID.EarlierThan committed txid

end DisasterRecovery.Proofs.Predicates
