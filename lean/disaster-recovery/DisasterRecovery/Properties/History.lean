import DisasterRecovery.Model
import DisasterRecovery.Shared.Execution

namespace DisasterRecovery.Properties.History

open Model.Local

abbrev Transition := Shared.Execution.Transition Model.State Model.Action

structure History (config : Model.Config) (state : Model.State) where
  initial : Model.State
  steps : List Transition
  initialized : (Model.transitionSystem config).init initial
  valid : Shared.Execution.Trace (Model.transitionSystem config) initial steps state

def actor : Model.Action -> Location
  | .local node _ => node
  | .deliver envelope => envelope.target

def event : Model.Action -> Event
  | .local _ .retry => .retry
  | .local _ .timeout => .timeout
  | .deliver envelope => receive envelope.source envelope.payload

def OutputAt (config : Model.Config) (edge : Transition) (output : Result) : Prop :=
  exists before,
    Model.nodeState edge.before (actor edge.action) = some before /\
      transition config.protocol before (event edge.action) = some output

def SentAt (config : Model.Config) (edge : Transition)
    (sourceState : NodeState) (envelope : Model.Envelope) : Prop :=
  edge.action = .local envelope.source .retry /\
    Model.nodeState edge.before envelope.source = some sourceState /\
    exists after messages,
      Shared.Global.runStep (Model.protocol config) envelope.source sourceState .retry =
        some (after, messages) /\
      (envelope.target, envelope.payload) ∈ messages

def Sent {config : Model.Config} {state : Model.State}
    (history : History config state) (sourceState : NodeState)
    (envelope : Model.Envelope) : Prop :=
  exists edge, edge ∈ history.steps /\ SentAt config edge sourceState envelope

def SentVote {config : Model.Config} {state : Model.State}
    (history : History config state) (voter target : Location) : Prop :=
  exists sourceState, Sent history sourceState { source := voter, target, payload := .vote }

def VotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\
      maximumGossip state.gossips = some (target, txid)

structure WellFormed {config : Model.Config} {state : Model.State}
    (history : History config state) : Prop where
  sentLocations :
    forall sourceState envelope, Sent history sourceState envelope ->
      sourceState.location = envelope.source
  sentSourceActive :
    forall sourceState envelope, Sent history sourceState envelope ->
      envelope.source ∈ state.active
  networkSent :
    forall envelope, envelope ∈ state.network ->
      exists sourceState, Sent history sourceState envelope
  actorsActive :
    forall edge, edge ∈ history.steps -> actor edge.action ∈ state.active

structure OpeningValid {config : Model.Config} {state : Model.State}
    (history : History config state) (node : Location)
    (kind : OpenKind) (opened : NodeState) : Prop where
  location : opened.location = node
  phase : opened.phase = .opening
  openKind : opened.openKind = some kind
  votesNodup : opened.votes.Nodup
  quorum : kind = .quorum -> voteQuorum config.protocol <= opened.votes.length
  votesSent : forall voter, voter ∈ opened.votes -> SentVote history voter node

structure QuorumInvariant {config : Model.Config} {state : Model.State}
    (history : History config state) : Prop where
  votesSent :
    forall entry, entry ∈ state.nodes ->
      forall voter, voter ∈ entry.2.votes -> SentVote history voter entry.1
  sentVotesFunctional :
    forall voter first second,
      SentVote history voter first -> SentVote history voter second -> first = second
  sentVoteStable :
    forall sourceState voter target,
      Sent history sourceState { source := voter, target, payload := .vote } ->
      forall entry, entry ∈ state.nodes -> entry.1 = voter ->
        entry.2.phase ≠ .gossiping /\
          (entry.2.phase = .voting -> entry.2.chosen = some target)
  votingSelections :
    forall entry, entry ∈ state.nodes ->
      entry.2.phase = .voting -> VotingSelection entry.2
  sentVotesSelected :
    forall sourceState voter target,
      Sent history sourceState { source := voter, target, payload := .vote } ->
        VotingSelection sourceState
  openingsValid :
    forall edge, edge ∈ history.steps ->
      forall output, OutputAt config edge output ->
        forall kind, .opening kind ∈ output.effects ->
          OpeningValid history (actor edge.action) kind output.state

def QuorumOpened {config : Model.Config} {state : Model.State}
    (history : History config state) (node : Location) : Prop :=
  exists edge, edge ∈ history.steps /\
    actor edge.action = node /\
    exists output, OutputAt config edge output /\ .opening .quorum ∈ output.effects

def FullGossipSelection {config : Model.Config} {state : Model.State}
    (history : History config state) (opener : Location) : Prop :=
  exists voter sourceState,
    Sent history sourceState { source := voter, target := opener, payload := .vote } /\
    forall gossip, gossip ∈ sourceState.gossips <-> gossip ∈ config.recovered

end DisasterRecovery.Properties.History
