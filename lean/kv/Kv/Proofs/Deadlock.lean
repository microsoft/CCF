-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model

@[expose] public section

namespace Kv.Proofs.Deadlock

open Kv.Model

theorem deadlock_free : transitionSystem.DeadlockFree := by
  intro state _
  cases h : find state.stores 0 with
  | none =>
      refine ⟨.storeCreate 0 0, { state with stores := set state.stores 0 {} }, ?_⟩
      simp [step, execute, h]
  | some store =>
      refine ⟨
        .compact 0 0,
        { state with stores := set state.stores 0 (compactStore store 0) },
        ?_
      ⟩
      simp [step, execute, h]

theorem deadlock_free_witness : ∃ state, transitionSystem.Reachable state :=
  ⟨{}, .initial rfl⟩

end Kv.Proofs.Deadlock
