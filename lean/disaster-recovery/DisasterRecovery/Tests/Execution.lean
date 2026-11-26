module

public import CCF.Proofs.Execution

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
private def counting : Behaviour counter :=
  ⟨
    { init := 0, steps := CCF.Seq.ofList [(false, 0), (true, 1), (true, 2)] },
    rfl,
    by
      intro n before action first chosen
      rcases n with _ | _ | _ | n <;>
        simp only [CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ,
          CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_cons_zero,
          List.getElem?_cons_succ, List.getElem?_nil, Option.map_some, Option.map_none,
          Option.some.injEq] at first chosen ⊢
      all_goals subst_vars
      all_goals first | rfl | cases chosen
  ⟩

example : counter.Reachable 2 :=
  counting.reachable (Behaviour.stateAt_mem (n := 3) rfl)

example (state : Nat)
    : counter.Reachable state
      <-> exists behaviour : Behaviour counter, state ∈ behaviour :=
  reachable_iff_behaviour

example : counting.stateAt 3 = some 2 := rfl
example : counting.actionAt 0 = some false := rfl
example : counting.actionAt 2 = some true := rfl
example : counting.stateAt 4 = none := rfl
example : counting.actionAt 3 = none := rfl
example : 2 ∈ counting := Behaviour.stateAt_mem (n := 3) rfl
example : 2 ∈ counting.states := CCF.Seq.get?_mem (n := 3) rfl
example : false ∈ counting.actions := CCF.Seq.get?_mem (n := 0) rfl

private def initialOnly : Behaviour counter :=
  ⟨
    { init := 0, steps := CCF.Seq.nil },
    rfl,
    by intro n before action _ chosen; simp at chosen
  ⟩

example : initialOnly.stateAt 0 = some 0 := rfl
example : initialOnly.stateAt 1 = none := rfl
example : initialOnly.actionAt 0 = none := rfl

private def infinite : Behaviour counter :=
  ⟨
    { init := 0, steps := CCF.Seq.ofStream (fun n => (true, n + 1)) },
    rfl,
    by
      intro n before action first chosen
      cases n <;> cases first <;> cases chosen <;> rfl
  ⟩

example (n : Nat) : infinite.stateAt n = some n := by cases n <;> rfl
example (n : Nat) : infinite.actionAt n = some true := rfl

example (n : Nat) : n ∈ infinite :=
  Behaviour.stateAt_mem (n := n) (by cases n <;> rfl)

-- Actions and states may share a type, so behaviour membership remains state-only.
example
    (behaviour
      : Behaviour
          ({
              State := Nat,
              Action := Nat,
              init := fun state => state = 0,
              step := fun state action => some (state + action)
            }
            : TransitionSystem))
    (state : Nat)
    : state ∈ behaviour ↔ state ∈ behaviour.states :=
  Iff.rfl

-- A final state has no outgoing action, but each transition has one.
example (behaviour : Behaviour counter)
    (states : behaviour.states = CCF.Seq.ofList [0, 1])
    (actions : behaviour.actions = CCF.Seq.ofList [])
    : False := by
  have domains := behaviour.valid_domains 0
  simp [states, actions] at domains

example (behaviour : Behaviour counter)
    (states : behaviour.states = CCF.Seq.ofList [0])
    (actions : behaviour.actions = CCF.Seq.ofList [true])
    : False := by
  have domains := behaviour.valid_domains 0
  simp [states, actions] at domains

-- An enabled action that reaches the wrong successor is not a recorded step.
example (behaviour : Behaviour counter)
    (states : behaviour.states = CCF.Seq.ofList [0, 1])
    (actions : behaviour.actions = CCF.Seq.ofList [false])
    : False := by
  have stepped := behaviour.valid_step 0 0 false (by simp [states]) (by simp [actions])
  simp [counter, states] at stepped

-- An empty behaviour has no initial state.
example (behaviour : Behaviour counter) (states : behaviour.states = CCF.Seq.ofList [])
    : False := by
  obtain ⟨_, first, _⟩ := behaviour.valid_init
  simp [states] at first

example (behaviour : Behaviour counter) (states : behaviour.states = CCF.Seq.ofList [1])
    : False := by
  obtain ⟨initial, first, initialized⟩ := behaviour.valid_init
  simp [states] at first
  subst first
  simp at initialized

-- Adjacent states must be related by an enabled action.
example (behaviour : Behaviour counter)
    (states : behaviour.states = CCF.Seq.ofList [0, 2])
    : False := by
  obtain ⟨action, step⟩ := behaviour.step 0 0 2 (by simp [Behaviour.stateAt, states])
    (by simp [Behaviour.stateAt, states])
  cases action <;> simp [counter] at step

example
    (behaviour
      : Behaviour
          ({
              State := Nat,
              Action := Unit,
              init := fun state => state = 0,
              step := fun _ _ => none
            }
            : TransitionSystem))
    (states : behaviour.states = CCF.Seq.ofList [0, 0])
    : False := by
  obtain ⟨_, step⟩ := behaviour.step 0 0 0 (by simp [Behaviour.stateAt, states])
    (by simp [Behaviour.stateAt, states])
  cases step

end DisasterRecovery.Tests.Execution
