module

public import CCFRaft.Proofs.Leadership.AnchorKeep

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Configurations by entry

A configuration in a log's configuration history is a configuration entry at its
index.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety

/-! ## Configurations by entry -/

/-- A configuration of a log is a configuration entry at its index. -/
theorem mem_history_iff {log : List Entry} {configuration : Configuration}
    : configuration ∈ configurationHistory log
      <-> exists i entry,
            log[i]? = some entry
            /\ entry.content.metadata.configuration = some configuration.nodes
            /\ configuration.index = i + 1 := by
  unfold configurationHistory
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨⟨entry, index⟩, member, eq⟩
    obtain ⟨nodes, some, rfl⟩ := Option.map_eq_some_iff.mp eq
    obtain ⟨le, get⟩ := List.mem_zipIdx_iff_le_and_getElem?_sub.mp member
    refine ⟨index - 1, entry, by simpa using get, some, ?_⟩
    dsimp only at le ⊢
    omega
  · rintro ⟨i, entry, get, some, indexEq⟩
    refine ⟨(entry, i + 1),
      List.mem_zipIdx_iff_le_and_getElem?_sub.mpr ⟨by omega, by simpa using get⟩, ?_⟩
    obtain ⟨index, nodes⟩ := configuration
    dsimp only at some indexEq ⊢
    rw [some, indexEq]
    rfl

/-! ## Where a step's entries come from -/

section Handlers

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

end Handlers

variable [Config.InitialConfiguration]

end CCFRaft.Proofs.Leadership
