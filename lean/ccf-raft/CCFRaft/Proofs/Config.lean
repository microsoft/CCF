module

public import CCFRaft.Model

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes the initial membership at
initialization only; proofs wrap it in a class so instance inference avoids
repeating that value in every supporting lemma about histories.

This file also gives recursive, proof-friendly forms of the model's
configuration helpers. `Proofs/Ledger.lean` proves that the model's definitions
agree with them. These conveniences do not change the
model or its properties.
-/

namespace CCFRaft.Proofs.Config

open Model.Node

/-- The initial membership passed to the model, possibly empty. -/
class InitialConfiguration where
  configuration : Finset NodeID

section Initial

variable [config : InitialConfiguration]

abbrev INITIAL_CONFIGURATION : Finset NodeID := config.configuration

/-- The smallest initial member, which the model makes the bootstrap primary.
Meaningful only for a nonempty initial membership. -/
abbrev INITIAL_PRIMARY : NodeID := INITIAL_CONFIGURATION.min.untopD 0

theorem initial_primary_iff (nonempty : INITIAL_CONFIGURATION.Nonempty) {node : NodeID}
    : INITIAL_CONFIGURATION.min = (node : WithTop NodeID) <-> node = INITIAL_PRIMARY := by
  rw [INITIAL_PRIMARY, ← Finset.coe_min' nonempty, WithTop.untopD_coe, WithTop.coe_inj]
  exact eq_comm

theorem INITIAL_PRIMARY_mem (nonempty : INITIAL_CONFIGURATION.Nonempty)
    : INITIAL_PRIMARY ∈ INITIAL_CONFIGURATION := by
  rw [INITIAL_PRIMARY, ← Finset.coe_min' nonempty, WithTop.untopD_coe]
  exact Finset.min'_mem _ _

/-- The unsigned bootstrap configuration transaction of the initial primary. -/
abbrev GENESIS : Entry :=
  {
    term := Model.BOOTSTRAP_TERM
    content := .transaction 0 { configuration := some INITIAL_CONFIGURATION }
  }

theorem GENESIS_configured : GENESIS.content.metadata.configuration.isSome := by
  simp [EntryContent.metadata]

end Initial

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
def configurationsInLogFrom : Nat -> List Entry -> List Configuration
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      (entry.content.metadata.configuration.map fun nodes => { index, nodes }).toList
      ++ remaining

/-- All configurations in a log, from reconfiguration entries only. -/
def configurationsInLog (log : List Entry) : List Configuration :=
  configurationsInLogFrom 1 log

/-- The current configuration and every later configuration in the node's log. -/
def activeConfigurationsOf (state : NodeState) : List Configuration :=
  Model.Node.activeConfigurations state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (state : NodeState) : Finset NodeID :=
  (activeConfigurationsOf state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end CCFRaft.Proofs.Config
