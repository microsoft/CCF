module

public import consistency.Model

import Mathlib.Tactic.Lemma

@[expose] public section

namespace consistency.Proofs

theorem deadlock_free : Model.transitionSystem.DeadlockFree := by
  intro state _
  exact ⟨.request .rw, _, rfl⟩

lemma deadlock_free_witness : exists state, Model.transitionSystem.Reachable state :=
  ⟨Model.initialState, .initial rfl⟩

end consistency.Proofs
