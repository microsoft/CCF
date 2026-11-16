module

public import Consensus.Model

@[expose] public section

namespace Consensus.Properties

open Model.Node

/-- Bootstrapping has completed: some node has committed a signature. -/
def Bootstrapped (state : Model.State) : Prop :=
  exists (node : NodeID) (local_ : NodeState),
    (node, local_) ∈ state.nodes /\ 0 < local_.commitIndex

end Consensus.Properties
