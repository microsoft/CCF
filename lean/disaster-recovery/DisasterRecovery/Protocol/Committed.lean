import DisasterRecovery.Protocol.Quorum

/-! Human-reviewed committed-prefix ordering and completeness assumptions. -/

namespace DisasterRecovery.Protocol

namespace TxID

def PrefixOf (left right : TxID) : Prop :=
  left.view < right.view \/
    (left.view = right.view /\ left.seqno <= right.seqno)

end TxID

namespace Global

def FullGossipSelection
    (config : Config)
    (state : State)
    (opener : Location) : Prop :=
  exists vote,
    vote ∈ state.sent /\
      vote.payload = .vote /\
      vote.target = opener /\
      forall gossip,
        gossip ∈ vote.sourceState.gossips <->
          gossip ∈ config.recovered

def DurableCommit (config : Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\
      TxID.PrefixOf committed txid

end Global

end DisasterRecovery.Protocol
