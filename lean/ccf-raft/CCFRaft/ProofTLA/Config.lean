module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes the initial membership as an
explicit `Finset NodeID`; proofs carry it in the `Initial` class to avoid repeating
that value in every supporting lemma.

This file also names node-level configuration views used by the proofs.
`ProofTLA/Ledger.lean` proves that the model's definitions agree with them.
These conveniences do not change the model or its properties.
-/

namespace CCFRaft.ProofTLA

/-- The initial membership the model is instantiated with. -/
class Initial where
  configuration : Finset Model.Node.NodeID

end CCFRaft.ProofTLA

namespace CCFRaft.ProofTLA.Config

open Model.Node

/-- The current configuration and every later configuration in the node's log. -/
def activeConfigurationsOf (state : NodeState) : List Configuration :=
  Model.Node.activeConfigurations state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (state : NodeState) : Finset NodeID :=
  (activeConfigurationsOf state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end CCFRaft.ProofTLA.Config
