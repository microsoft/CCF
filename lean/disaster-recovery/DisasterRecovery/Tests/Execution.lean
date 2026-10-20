module

public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Tests.Execution

open CCF
open CCF.Execution

private def counter : TransitionSystem Nat Bool where
  init state := state = 0
  step state increment := if increment then some (state + 1) else some state

private def infiniteCounting : Trace Nat := { states := id }

private theorem infiniteCounting_valid : infiniteCounting.Valid counter := by
  refine ⟨rfl, ?_⟩
  intro index
  exact ⟨true, rfl⟩

example (index : Nat) : counter.Reachable index :=
  infiniteCounting_valid.reachable ⟨index, rfl⟩

-- Stutters are allowed: each adjacent pair needs only some enabled action.
example : (⟨fun _ => 0⟩ : Trace Nat).Valid counter := by
  exact ⟨rfl, fun _ => ⟨false, rfl⟩⟩

-- The first state must be initial.
example : ¬ (⟨fun index => index + 1⟩ : Trace Nat).Valid counter := by
  intro valid
  have initial := valid.1
  change 1 = 0 at initial
  contradiction

-- Adjacent states must be related by an enabled action.
example : ¬ (⟨fun index => index * 2⟩ : Trace Nat).Valid counter := by
  intro valid
  obtain ⟨action, step⟩ := valid.2 0
  cases action <;> simp [counter] at step

example
    : ¬ (⟨fun _ => 0⟩ : Trace Nat).Valid
          ({ init := fun state => state = 0, step := fun _ _ => none }
            : TransitionSystem Nat Unit) := by
  intro valid
  obtain ⟨_, step⟩ := valid.2 0
  cases step

end DisasterRecovery.Tests.Execution
