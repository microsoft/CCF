import DisasterRecovery.Properties.Helpers

namespace DisasterRecovery.Properties

open Model.Local

def GossipFreezesAfterChoice : Prop :=
  forall (config : Config) (state : NodeState) (source : Location) (txid : TxID),
    state.chosen.isSome = true ->
      transition config state (.receiveGossip source txid .accepted) =
        some (rejected state "gossip-frozen")

def RejectedGossipStutters : Prop :=
  forall (config : Config) (state : NodeState) (source : Location) (txid : TxID),
    transition config state (.receiveGossip source txid .rejected) =
      some (rejected state "quote-or-certificate")

def QuorumAdvanceOpens : Prop :=
  forall (config : Config) (state : NodeState),
    state.phase = .voting ->
    state.votes.length >= voteQuorum config ->
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum]

def AlignedOpeningTimeoutCompletes : Prop :=
  forall (config : Config) (state : NodeState),
    let opening := { state with phase := .opening, timeoutState := .opening }
    transition config opening .timeout =
      some { state := { opening with phase := .open }, effects := [.completed] }

def ReachableWellFormed : Prop :=
  forall {config : Model.Config} {state : Model.State},
    Model.Reachable config state -> Helpers.WellFormed config state

def ReachableQuorumInvariant : Prop :=
  forall {config : Model.Config} {state : Model.State},
    Model.Reachable config state -> Helpers.QuorumInvariant config state

def QuorumOpenerUnique : Prop :=
  forall {config : Model.Config} {state : Model.State} {first second : Location},
    Model.Reachable config state ->
    Helpers.QuorumOpened state first -> Helpers.QuorumOpened state second -> first = second

def QuorumHistoryOpenerUnique : Prop :=
  forall {config : Model.Config} {state : Model.State} {first second : Location}
    (history : History.History config state),
    History.QuorumOpened history first -> History.QuorumOpened history second -> first = second

def FullGossipSelectionPreservesCommit : Prop :=
  forall {config : Model.Config} {state : Model.State} {opener : Location} {committed : TxID}
    (history : History.History config state),
    History.FullGossipSelection history opener -> Helpers.DurableCommit config committed ->
    exists recovered, Model.recoveredTxID config opener = some recovered /\
      Helpers.TxID.EarlierThan committed recovered

def QuorumOpenPreservesCommit : Prop :=
  forall {config : Model.Config} {state : Model.State} {opener : Location} {committed : TxID}
    (history : History.History config state),
    Helpers.QuorumOpened state opener ->
    History.FullGossipSelection history opener -> Helpers.DurableCommit config committed ->
    exists recovered, Model.recoveredTxID config opener = some recovered /\
      Helpers.TxID.EarlierThan committed recovered

end DisasterRecovery.Properties
