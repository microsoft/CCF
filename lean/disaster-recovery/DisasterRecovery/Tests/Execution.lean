import DisasterRecovery.Shared.Execution

namespace DisasterRecovery.Tests.Execution

open Shared
open Shared.Execution

private def counter : TransitionSystem Nat Bool where
  init state := state = 0
  step state increment := if increment then some (state + 1) else some state

-- Stutters are allowed: each adjacent pair needs only some enabled action.
private def counting : Trace Nat := { states := [0, 0, 1, 2] }

private theorem counting_valid : counting.Valid counter := by
  refine ⟨⟨0, rfl, rfl⟩, ?_⟩
  intro i before after first second
  rcases i with _ | _ | _ | i <;> simp [counting] at first second <;> subst_vars
  · exact ⟨false, by simp [counter]⟩
  · exact ⟨true, by simp [counter]⟩
  · exact ⟨true, by simp [counter]⟩

example : counter.Reachable 2 := counting_valid.reachable (by simp [counting])

example (state : Nat) :
    counter.Reachable state <->
      exists trace : Trace Nat, trace.Valid counter /\ state ∈ trace.states :=
  reachable_iff_trace

-- An empty trace has no initial state.
example : ¬ (⟨[]⟩ : Trace Nat).Valid counter := by
  rintro ⟨⟨_, first, _⟩, _⟩
  simp at first

example : ¬ (⟨[1]⟩ : Trace Nat).Valid counter := by
  rintro ⟨⟨initial, first, initialized⟩, _⟩
  simp at first
  subst first
  simp [counter] at initialized

-- Adjacent states must be related by an enabled action.
example : ¬ (⟨[0, 2]⟩ : Trace Nat).Valid counter := by
  rintro ⟨_, steps⟩
  obtain ⟨action, step⟩ := steps 0 0 2 rfl rfl
  cases action <;> simp [counter] at step

example :
    ¬ (⟨[0, 0]⟩ : Trace Nat).Valid
      ({ init := fun state => state = 0, step := fun _ _ => none } : TransitionSystem Nat Unit) := by
  rintro ⟨_, steps⟩
  obtain ⟨_, step⟩ := steps 0 0 0 rfl rfl
  cases step

end DisasterRecovery.Tests.Execution
