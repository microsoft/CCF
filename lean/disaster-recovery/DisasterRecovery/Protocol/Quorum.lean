import DisasterRecovery.Protocol.Invariants

/-! Human-reviewed vote provenance, quorum and opening predicates. -/

namespace DisasterRecovery.Protocol.Quorum

open Model hiding Config
open Global

def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.source = voter /\
      envelope.target = target /\
      envelope.payload = .vote

def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.votes.Nodup

def NodeVotesSent (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    forall voter, voter ∈ entry.2.votes ->
      SentVote state voter entry.1

def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first ->
    SentVote state voter second ->
    first = second

def SentVoteStable (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .vote ->
    forall entry, entry ∈ state.system.nodes ->
      entry.1 = envelope.source ->
      entry.2.phase ≠ .gossiping /\
        (entry.2.phase = .voting ->
          entry.2.chosen = some envelope.target)

def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\
      maximumGossip state.gossips = some (target, txid)

def VotingSelectionsValid (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .voting ->
      NodeVotingSelection entry.2

def SentVotesSelected (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .vote ->
      NodeVotingSelection envelope.sourceState

structure Opening.Valid
    (config : Config)
    (globalState : State)
    (opening : Opening) : Prop where
  location : opening.state.location = opening.node
  phase : opening.state.phase = .opening
  kind : opening.state.openKind = some opening.kind
  votesNodup : opening.state.votes.Nodup
  quorum :
    opening.kind = .quorum ->
      voteQuorum config.protocol <= opening.state.votes.length
  votesSent :
    forall voter, voter ∈ opening.state.votes ->
      SentVote globalState voter opening.node

def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings ->
    Opening.Valid config state opening

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
    opening ∈ state.openings /\
      opening.node = node /\
      opening.kind = .quorum

end DisasterRecovery.Protocol.Quorum
