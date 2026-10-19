module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes an explicit `Model.ModelConfig`
value; proofs use instance inference to avoid repeating that value in every
supporting lemma.

This file also names node-level configuration views used by the proofs.
`ProofTLA/Ledger.lean` proves that the model's definitions agree with them.
These conveniences do not change the model or its properties.
-/

attribute [class] CCFRaft.Model.ModelConfig

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
