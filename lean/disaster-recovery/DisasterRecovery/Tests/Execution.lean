module

public import CCF.Execution

@[expose] public section

namespace DisasterRecovery.Tests.Execution

open CCF
open CCF.Execution

/-- A counter with increment and stutter actions. -/
abbrev counter : TransitionSystem where
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

-- Stutters are recorded as enabled actions, not inserted implicitly.
private def counting : Trace counter where
  states := Stream'.Seq.ofList [0, 0, 1, 2]
  actions := Stream'.Seq.ofList [false, true, true]
  valid_init := ⟨0, rfl, rfl⟩
  valid_domains := by
    intro n
    simp only [Stream'.Seq.ofList_get?, isSome_getElem?, List.length_cons, List.length_nil]
    omega
  valid_step := by
    intro n before action first chosen
    rcases n with _ | _ | _ | n <;>
      simp only [Stream'.Seq.ofList_get?, List.getElem?_cons_zero,
        List.getElem?_cons_succ, List.getElem?_nil, Option.some.injEq] at first chosen ⊢
    all_goals subst_vars
    all_goals first | rfl | cases chosen

example : counter.Reachable 2 :=
  counting.reachable (Trace.stateAt_mem (n := 3) rfl)

example (state : Nat)
    : counter.Reachable state <-> exists trace : Trace counter, state ∈ trace :=
  reachable_iff_trace

example : counting.stateAt 3 = some 2 := rfl
example : counting.actionAt 0 = some false := rfl
example : counting.actionAt 2 = some true := rfl
example : counting.stateAt 4 = none := rfl
example : counting.actionAt 3 = none := rfl
example : 2 ∈ counting := Trace.stateAt_mem (n := 3) rfl
example : 2 ∈ counting.states := Stream'.Seq.get?_mem (n := 3) rfl
example : false ∈ counting.actions := Stream'.Seq.get?_mem (n := 0) rfl

private def initialOnly : Trace counter where
  states := Stream'.Seq.ofList [0]
  actions := Stream'.Seq.nil
  valid_init := ⟨0, rfl, rfl⟩
  valid_domains := by intro n; simp
  valid_step := by intro n before action _ chosen; simp at chosen

example : initialOnly.stateAt 0 = some 0 := rfl
example : initialOnly.stateAt 1 = none := rfl
example : initialOnly.actionAt 0 = none := rfl

private def infinite : Trace counter where
  states := Stream'.Seq.ofStream id
  actions := Stream'.Seq.ofStream (fun _ => true)
  valid_init := ⟨0, rfl, rfl⟩
  valid_step := by
    intro n before action first chosen
    cases first
    cases chosen
    rfl
  valid_domains := fun _ => Iff.rfl

example (n : Nat) : infinite.stateAt n = some n := rfl
example (n : Nat) : infinite.actionAt n = some true := rfl
example (n : Nat) : n ∈ infinite := Trace.stateAt_mem (n := n) rfl

-- A final state has no outgoing action, but each transition has one.
example (trace : Trace counter)
    (states : trace.states = Stream'.Seq.ofList [0, 1])
    (actions : trace.actions = Stream'.Seq.ofList [])
    : False := by
  have domains := trace.valid_domains 0
  simp [states, actions] at domains

example (trace : Trace counter)
    (states : trace.states = Stream'.Seq.ofList [0])
    (actions : trace.actions = Stream'.Seq.ofList [true])
    : False := by
  have domains := trace.valid_domains 0
  simp [states, actions] at domains

-- An enabled action that reaches the wrong successor is not a recorded step.
example (trace : Trace counter)
    (states : trace.states = Stream'.Seq.ofList [0, 1])
    (actions : trace.actions = Stream'.Seq.ofList [false])
    : False := by
  have stepped := trace.valid_step 0 0 false (by simp [states]) (by simp [actions])
  simp [counter, states] at stepped

-- An empty trace has no initial state.
example (trace : Trace counter) (states : trace.states = Stream'.Seq.ofList [])
    : False := by
  obtain ⟨_, first, _⟩ := trace.valid_init
  simp [states] at first

example (trace : Trace counter) (states : trace.states = Stream'.Seq.ofList [1])
    : False := by
  obtain ⟨initial, first, initialized⟩ := trace.valid_init
  simp [states] at first
  subst first
  simp at initialized

-- Adjacent states must be related by an enabled action.
example (trace : Trace counter) (states : trace.states = Stream'.Seq.ofList [0, 2])
    : False := by
  obtain ⟨action, step⟩ := trace.step 0 0 2 (by simp [Trace.stateAt, states])
    (by simp [Trace.stateAt, states])
  cases action <;> simp [counter] at step

example
    (trace
      : Trace
          ({
              State := Nat,
              Action := Unit,
              init := fun state => state = 0,
              step := fun _ _ => none
            }
            : TransitionSystem))
    (states : trace.states = Stream'.Seq.ofList [0, 0])
    : False := by
  obtain ⟨_, step⟩ := trace.step 0 0 0 (by simp [Trace.stateAt, states])
    (by simp [Trace.stateAt, states])
  cases step

end DisasterRecovery.Tests.Execution
