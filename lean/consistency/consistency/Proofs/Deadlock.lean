module

public import consistency.Model

@[expose] public section

namespace consistency.Proofs

theorem deadlock_free : Model.transitionSystem.DeadlockFree := by
  intro state _
  exact ⟨.request .rw, _, rfl⟩

theorem deadlock_free_witness : exists state, Model.transitionSystem.Reachable state :=
  ⟨Model.initialState, .initial rfl⟩

end consistency.Proofs
