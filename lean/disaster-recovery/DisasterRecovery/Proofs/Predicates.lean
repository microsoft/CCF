import DisasterRecovery.Proofs.Execution

/-! Safety predicates and committed-prefix assumptions for decorated executions. -/

namespace DisasterRecovery.Proofs.Predicates

open Execution.Local hiding Config
open Execution.Global

/-! ## Well-formedness and message provenance -/

/-- Only active nodes appear in terminal-notification histories. -/
structure HistoriesActive (state : State) : Prop where
  openings : forall opening, opening ∈ state.openings -> opening.node ∈ state.active
  restarts : forall node, node ∈ state.restarts -> node ∈ state.active
  completed : forall node, node ∈ state.completed -> node ∈ state.active

/-- Node identities, active membership, and message provenance are consistent. -/
structure WellFormed (config : Config) (state : State) : Prop where
  nodeKeys : state.system.nodes.map Prod.fst = config.protocol.expectedLocations
  nodeKeysNodup : (state.system.nodes.map Prod.fst).Nodup
  nodeLocations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1
  activeNodup : state.active.Nodup
  activeConfigured
    : forall node, node ∈ state.active -> node ∈ config.protocol.expectedLocations
  sentValid : forall envelope, envelope ∈ state.sent -> envelope.Valid config
  sentSourceActive
    : forall envelope, envelope ∈ state.sent -> envelope.source ∈ state.active
  networkSent : forall envelope, envelope ∈ state.network -> envelope ∈ state.sent
  historiesActive : HistoriesActive state

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
  location : opening.state.location = opening.node
  phase : opening.state.phase = .opening
  kind : opening.state.openKind = some opening.kind
  votesNodup : opening.state.votes.Nodup
  quorum
    : opening.kind = .quorum -> voteQuorum config.protocol <= opening.state.votes.length
  votesSent
    : forall voter, voter ∈ opening.state.votes -> SentVote globalState voter opening.node

/-- Every recorded opening satisfies its identity and vote-provenance invariants. -/
def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings -> Opening.Valid config state opening

/-- Vote uniqueness, provenance, stable selection, and validity of recorded openings. -/
structure QuorumInvariant (config : Config) (state : State) : Prop where
  votesNodup : NodeVotesNodup state
  votesSent : NodeVotesSent state
  sentVoteStable : SentVoteStable state
  sentVotesFunctional : SentVotesFunctional state
  votingSelections : VotingSelectionsValid state
  sentVotesSelected : SentVotesSelected state
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
