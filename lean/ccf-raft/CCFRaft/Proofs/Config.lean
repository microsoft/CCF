module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.Node

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes an explicit `InitialConfig`
value; proofs use instance inference to avoid repeating that value in every
supporting lemma.

This file also gives recursive, proof-friendly forms of the model's
configuration helpers. `Proofs/Ledger.lean` proves that the model's definitions
agree with them. These conveniences do not change the
model or its properties.
-/

attribute [class] CCFRaft.Model.Node.InitialConfig

namespace CCFRaft.Proofs.Config

open Model.Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

section Initial

variable [config : InitialConfig Node]

abbrev INITIAL_LEADER : Node := config.leader

abbrev INITIAL_CONFIGURATION : Finset Node := config.configuration

abbrev INITIAL_PRE_VOTE_STATUS : Node -> PreVoteStatus := config.preVoteStatus

end Initial

/-- The bootstrap configuration at index 0, which has no log entry. -/
def implicitConfiguration (config : InitialConfig Node) : Configuration Node where
  index := 0
  nodes := config.configuration

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
def configurationsInLogFrom : Nat -> List (Entry Node TxId) -> List (Configuration Node)
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      (entry.content.metadata.configuration.map fun nodes => { index, nodes }).toList
      ++ remaining

/-- All configurations in a log, from reconfiguration entries only. -/
def configurationsInLog (log : List (Entry Node TxId)) : List (Configuration Node) :=
  configurationsInLogFrom 1 log

/-- All configurations of a log, including the bootstrap configuration. -/
def allConfigurations (config : InitialConfig Node) (log : List (Entry Node TxId))
    : List (Configuration Node) :=
  implicitConfiguration config :: configurationsInLog log

/-- The current configuration and every later configuration in the node's log. -/
def activeConfigurationsOf (config : InitialConfig Node) (state : NodeState Node TxId)
    : List (Configuration Node) :=
  Model.Node.activeConfigurations config state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  (activeConfigurationsOf config state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end CCFRaft.Proofs.Config
