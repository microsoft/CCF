module

public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Tests.Execution

open CCF
open CCF.Execution

@[expose] private abbrev counter : TransitionSystem where
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

-- Stutters are allowed when the recorded action is enabled.
private def counting : Trace Nat Bool := Trace.run counter 0 [false, true, true]

private theorem counting_valid : counting.Valid counter := Trace.run_valid rfl

example : counter.Reachable 2 :=
  counting_valid.reachable (Trace.mem_of_stateAt (index := 3) rfl)

example (state : Nat)
    : counter.Reachable state
      <-> exists trace : Trace Nat Bool, trace.Valid counter /\ state ∈ trace :=
  reachable_iff_trace

-- A trace with no steps still contains its initial state.
example : (Trace.run counter 0 []).Valid counter := Trace.run_valid rfl

example : ¬ (Trace.run counter 1 []).Valid counter := by
  rintro ⟨initialized, _⟩
  simp [Trace.run] at initialized

-- Adjacent states must be related by an enabled action.
example
    : ¬ Trace.Valid counter
          (Trace.ofStream (fun i => if i = 0 then 0 else 2) (fun _ => true)) := by
  intro valid
  obtain ⟨action, step⟩ := valid.exists_action (index := 0) (before := 0) (after := 2) rfl rfl
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
          (Trace.ofStream (fun _ => 0) (fun _ => ())) := by
  intro valid
  obtain ⟨_, step⟩ := valid.exists_action (index := 0) (before := 0) (after := 0) rfl rfl
  cases step

example : counting.stepAt 0 = some { before := 0, action := false, after := 0 } := rfl

example : counting.stateAt 3 = some 2 := rfl

example : counting.stateAt 4 = none := rfl

-- An enabled action between these states does not validate a different recorded action.
example : ¬ (Trace.ofStream (fun i => i) (fun _ => false)).Valid counter := by
  intro valid
  have step := valid.enabled (index := 0)
    (step := { before := 0, action := false, after := 1 }) rfl
  simp [counter] at step

@[expose] private abbrev stoppingCounter : TransitionSystem where
  State := Nat
  Action := Bool
  init state := state = 0
  step state increment := if increment then some (state + 1) else none

private def stopped : Trace Nat Bool := Trace.run stoppingCounter 0 [true, false, true]

-- A disabled action ends the trace before the action and its suffix.
example : stopped.stateAt 1 = some 1 := rfl

example : stopped.stateAt 2 = none := rfl

example : stopped.stepAt 1 = none := rfl

example : stopped.Valid stoppingCounter := Trace.run_valid rfl

end DisasterRecovery.Tests.Execution
