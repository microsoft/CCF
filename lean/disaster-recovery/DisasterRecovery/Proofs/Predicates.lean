import DisasterRecovery.Proofs.Execution

/-! Safety predicates and committed-prefix assumptions for decorated executions. -/

namespace DisasterRecovery.Proofs.Predicates

open Execution.Local hiding Config
open Execution.Global

/-! ## Well-formedness and message provenance -/

structure HistoriesActive (state : State) : Prop where
  openings : forall opening, opening ∈ state.openings -> opening.node ∈ state.active
  restarts : forall node, node ∈ state.restarts -> node ∈ state.active
  completed : forall node, node ∈ state.completed -> node ∈ state.active

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

def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent
    /\ envelope.source = voter
    /\ envelope.target = target
    /\ envelope.payload = .vote

def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes -> entry.2.votes.Nodup

def NodeVotesSent (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall voter, voter ∈ entry.2.votes -> SentVote state voter entry.1

def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first -> SentVote state voter second -> first = second

def SentVoteStable (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> forall entry,
        entry ∈ state.system.nodes
        -> entry.1 = envelope.source
        -> entry.2.phase ≠ .gossiping
            /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target)

def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\ maximumGossip state.gossips = some (target, txid)

def VotingSelectionsValid (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes -> entry.2.phase = .voting -> NodeVotingSelection entry.2

def SentVotesSelected (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> NodeVotingSelection envelope.sourceState

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

def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings -> Opening.Valid config state opening

structure QuorumInvariant (config : Config) (state : State) : Prop where
  votesNodup : NodeVotesNodup state
  votesSent : NodeVotesSent state
  sentVoteStable : SentVoteStable state
  sentVotesFunctional : SentVotesFunctional state
  votingSelections : VotingSelectionsValid state
  sentVotesSelected : SentVotesSelected state
  openingsValid : OpeningsValid config state

def acceptedVoteSource : Event -> Option Location
  | .receiveVote source .accepted => some source
  | _ => none

def QuorumOpened (state : State) (node : Location) : Prop :=
  exists opening,
    opening ∈ state.openings /\ opening.node = node /\ opening.kind = .quorum

/-! ## Committed-prefix ordering and assumptions -/

namespace TxID

def EarlierThan (left right : TxID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end TxID

def FullGossipSelection (config : Config) (state : State) (opener : Location) : Prop :=
  exists vote,
    vote ∈ state.sent
    /\ vote.payload = .vote
    /\ vote.target = opener
    /\ forall gossip, gossip ∈ vote.sourceState.gossips <-> gossip ∈ config.recovered

def DurableCommit (config : Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\ TxID.EarlierThan committed txid

end DisasterRecovery.Proofs.Predicates
