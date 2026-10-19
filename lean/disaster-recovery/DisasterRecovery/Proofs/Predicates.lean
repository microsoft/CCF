module

public import DisasterRecovery.Proofs.Execution

@[expose] public section

/-! Safety predicates and committed-prefix assumptions for decorated executions. -/

namespace DisasterRecovery.Proofs.Predicates

open Execution.Local hiding Config
open Execution.Global

/-! ## Well-formedness and message provenance -/

/-- Only configured nodes appear in terminal-notification histories. -/
structure HistoriesConfigured (config : Config) (state : State) : Prop where
  /-- Only configured locations have recorded opening notifications. -/
  openings
    : forall opening,
        opening ∈ state.openings -> opening.node ∈ config.protocol.expectedLocations
  /-- Only configured locations have recorded restart notifications. -/
  restarts
    : forall node, node ∈ state.restarts -> node ∈ config.protocol.expectedLocations
  /-- Only configured locations have recorded completion notifications. -/
  completed
    : forall node, node ∈ state.completed -> node ∈ config.protocol.expectedLocations

/-- Node identities, recovered ledger membership, and message provenance are consistent. -/
structure WellFormed (config : Config) (state : State) : Prop where
  /-- Every configured location has a node-table entry; unused nodes may also exist. -/
  nodeKeys
    : forall node,
        node ∈ config.protocol.expectedLocations -> node ∈ state.system.nodes.map Prod.fst
  /-- Each location has at most one node-table entry. -/
  nodeKeysNodup : (state.system.nodes.map Prod.fst).Nodup
  /-- Every local state's location agrees with its node-table key. -/
  nodeLocations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1
  /-- Recovered ledgers belong exactly to the configured locations. -/
  recoveredKeys : config.recovered.map Prod.fst = config.protocol.expectedLocations
  /-- Every recorded send has valid local-step evidence. -/
  sentValid : forall envelope, envelope ∈ state.sent -> envelope.Valid config
  /-- Only configured locations have sent messages. -/
  sentSourceConfigured
    : forall envelope,
        envelope ∈ state.sent -> envelope.source ∈ config.protocol.expectedLocations
  /-- Every queued envelope has a corresponding recorded send. -/
  networkSent : forall envelope, envelope ∈ state.network -> envelope ∈ state.sent
  /-- Host-notification histories refer only to configured locations. -/
  historiesConfigured : HistoriesConfigured config state

/-! ## Votes, quorums, and openings -/

/-- A vote from `voter` to `target` appears in the send history. -/
def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent
    /\ envelope.source = voter
    /\ envelope.target = target
    /\ envelope.payload = .vote

/-- Every node's received-vote collection contains distinct voters. -/
def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes -> entry.2.votes.Nodup

/-- Every received vote has a corresponding vote in the send history. -/
def NodeVotesSent (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall voter, voter ∈ entry.2.votes -> SentVote state voter entry.1

/-- Each voter has sent votes to at most one target. -/
def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first -> SentVote state voter second -> first = second

/-- A sent vote's source no longer gossips and keeps its chosen target while voting. -/
def SentVoteStable (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> forall entry,
        entry ∈ state.system.nodes
        -> entry.1 = envelope.source
        -> entry.2.phase ≠ .gossiping
            /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target)

/-- The chosen node is the maximum-scoring gossip source. -/
def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\ maximumGossip state.gossips = some (target, txid)

/-- Every node in the voting phase has chosen its maximum-scoring gossip source. -/
def VotingSelectionsValid (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes -> entry.2.phase = .voting -> NodeVotingSelection entry.2

/-- Every sent vote's snapshot records a maximum-scoring gossip selection. -/
def SentVotesSelected (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> NodeVotingSelection envelope.sourceState

/-- A recorded opening preserves node identity, vote provenance, and its quorum threshold. -/
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

/-- Every recorded opening satisfies its identity and vote-provenance invariants. -/
def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings -> Opening.Valid config state opening

/-- Vote uniqueness, provenance, stable selection, and validity of recorded openings. -/
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

/-- Extracts the source of an accepted vote receive, ignoring other events. -/
def acceptedVoteSource : Event -> Option Location
  | .receiveVote source .accepted => some source
  | _ => none

/-- The history records a quorum opening by the given node. -/
def QuorumOpened (state : State) (node : Location) : Prop :=
  exists opening,
    opening ∈ state.openings /\ opening.node = node /\ opening.kind = .quorum

/-! ## Committed-prefix ordering and assumptions -/

namespace TxID

/-- Non-strict lexicographic TxID ordering by view and then sequence number. -/
def EarlierThan (left right : TxID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end TxID

/-- A vote for the opener was sent from a snapshot containing all recovered ledger tips. -/
def FullGossipSelection (config : Config) (state : State) (opener : Location) : Prop :=
  exists vote,
    vote ∈ state.sent
    /\ vote.payload = .vote
    /\ vote.target = opener
    /\ forall gossip, gossip ∈ vote.sourceState.gossips <-> gossip ∈ config.recovered

/-- Some recovered ledger tip is at least the supplied committed TxID. -/
def DurableCommit (config : Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\ TxID.EarlierThan committed txid

end DisasterRecovery.Proofs.Predicates
