module

public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Tests.Execution

open CCF
open CCF.Execution

private abbrev counter : TransitionSystem where
  State := Nat
  Action := Bool
  init state := state = 0
  step state increment := if increment then some (state + 1) else some state

example : counter.State = Nat := rfl

example : counter.Action = Bool := rfl

-- Generic executions use only the types carried by the system.
example (system : TransitionSystem) (state : system.State) : Run system state [] state :=
  .nil state

example : Run counter 0 [true, false, true] 2 :=
  .cons rfl (.cons rfl (.cons rfl (.nil (system := counter) 2)))

-- Stutters are allowed: each adjacent pair needs only some enabled action.
private def counting : Trace Nat := Stream'.Seq.ofList [0, 0, 1, 2]

private theorem counting_valid : counting.Valid counter := by
  refine ⟨⟨0, rfl, rfl⟩, ?_⟩
  intro i before after first second
  rcases i with _ | _ | _ | i <;> simp [counting] at first second <;> subst_vars
  · exact ⟨false, by simp [counter]⟩
  · exact ⟨true, by simp [counter]⟩
  · exact ⟨true, by simp [counter]⟩

example : counter.Reachable 2 :=
  counting_valid.reachable (Stream'.Seq.get?_mem (n := 3) rfl)

example (state : Nat)
    : counter.Reachable state
      <-> exists trace : Trace Nat, trace.Valid counter /\ state ∈ trace :=
  reachable_iff_trace

-- An empty trace has no initial state.
example : ¬ Trace.Valid counter (Stream'.Seq.ofList []) := by
  rintro ⟨⟨_, first, _⟩, _⟩
  simp at first

example : ¬ Trace.Valid counter (Stream'.Seq.ofList [1]) := by
  rintro ⟨⟨initial, first, initialized⟩, _⟩
  simp at first
  subst first
  simp at initialized

-- Adjacent states must be related by an enabled action.
example : ¬ Trace.Valid counter (Stream'.Seq.ofList [0, 2]) := by
  rintro ⟨_, steps⟩
  obtain ⟨action, step⟩ := steps 0 0 2 rfl rfl
  cases action <;> simp [counter] at step

example
    : ¬ Trace.Valid
          ({
              State := Nat,
              Action := Unit,
              init := fun state => state = 0,
              step := fun _ _ => none
            }
            : TransitionSystem)
          (Stream'.Seq.ofList [0, 0]) := by
  rintro ⟨_, steps⟩
  obtain ⟨_, step⟩ := steps 0 0 0 rfl rfl
  cases step

end DisasterRecovery.Tests.Execution
