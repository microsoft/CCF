import DisasterRecovery.Properties.History

namespace DisasterRecovery.Properties.Helpers

open Model.Local

structure WellFormed (config : Model.Config) (state : Model.State) : Prop where
  nodeKeys : state.nodes.map Prod.fst = config.protocol.expectedLocations
  nodeKeysNodup : (state.nodes.map Prod.fst).Nodup
  nodeLocations : forall entry, entry ∈ state.nodes -> entry.2.location = entry.1
  activeNodup : state.active.Nodup
  activeConfigured :
    forall node, node ∈ state.active -> node ∈ config.protocol.expectedLocations
  networkSourceActive :
    forall envelope, envelope ∈ state.network -> envelope.source ∈ state.active
  history : forall history : History.History config state, History.WellFormed history

structure QuorumInvariant (config : Model.Config) (state : Model.State) : Prop where
  votesNodup : forall entry, entry ∈ state.nodes -> entry.2.votes.Nodup
  votesConfigured :
    forall entry, entry ∈ state.nodes ->
      forall voter, voter ∈ entry.2.votes -> voter ∈ config.protocol.expectedLocations
  quorumThreshold :
    forall entry, entry ∈ state.nodes ->
      entry.2.openKind = some .quorum ->
        voteQuorum config.protocol <= entry.2.votes.length
  history : forall history : History.History config state, History.QuorumInvariant history

def QuorumOpened (state : Model.State) (node : Location) : Prop :=
  exists current,
    (node, current) ∈ state.nodes /\ current.openKind = some .quorum

namespace TxID

def EarlierThan (left right : TxID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end TxID

def DurableCommit (config : Model.Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\ TxID.EarlierThan committed txid

end DisasterRecovery.Properties.Helpers
