module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.Node

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes an explicit `InitialConfig`
value; proofs use instance inference to avoid repeating that value in every
supporting lemma.

This file also names node-level configuration views used by the proofs.
`ProofTLA/Ledger.lean` proves that the model's definitions agree with them.
These conveniences do not change the model or its properties.
-/

attribute [class] CCFRaft.Model.Node.InitialConfig

namespace CCFRaft.ProofTLA.Config

open Model.Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

/-- The current configuration and every later configuration in the node's log. -/
def activeConfigurationsOf (config : InitialConfig Node) (state : NodeState Node TxId)
    : List (Configuration Node) :=
  Model.Node.activeConfigurations config state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  (activeConfigurationsOf config state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end CCFRaft.ProofTLA.Config
