module

public import CCF.Execution
public import CCF.Proofs.Seq

import Std.Tactic.BVDecide.Normalize.Prop

@[expose] public section

namespace CCF.Execution

/-!
Theorems about executions: the states of a behaviour are connected by transitions
and reachable, and behaviours cover exactly the reachable states.
-/

namespace Behaviour

/-- The first state exists and is initial. -/
theorem valid_init {system : TransitionSystem} (behaviour : Behaviour system)
    : exists initial, behaviour.stateAt 0 = some initial /\ system.init initial :=
  ⟨behaviour.val.init, CCF.Seq.get?_cons_zero _ _, behaviour.property.1⟩

/-- Each recorded action executes the corresponding transition. -/
theorem valid_step {system : TransitionSystem} (behaviour : Behaviour system) (n : Nat)
    (before : system.State) (action : system.Action)
    (first : behaviour.stateAt n = some before)
    (chosen : behaviour.actionAt n = some action)
    : system.step before action = behaviour.stateAt (n + 1) :=
  behaviour.property.2 n before action first chosen

/-- Actions exist exactly where a successor state exists, by construction. -/
theorem valid_domains {system : TransitionSystem} (behaviour : Behaviour system) (n : Nat)
    : (behaviour.actions.get? n).isSome <-> (behaviour.states.get? (n + 1)).isSome := by
  simp [actions, states]

/-- State membership is membership in the recorded state sequence. -/
@[simp]
theorem mem_states {system : TransitionSystem} {behaviour : Behaviour system}
    {state : system.State}
    : state ∈ behaviour.states <-> state ∈ behaviour :=
  Iff.rfl

/-- A state in a behaviour is present at some index. -/
theorem mem_iff_exists_stateAt {system : TransitionSystem} {behaviour : Behaviour system}
    {state : system.State}
    : state ∈ behaviour <-> exists n, some state = behaviour.stateAt n :=
  CCF.Seq.mem_iff_exists_get?

/-- A state found at an index belongs to the behaviour. -/
theorem stateAt_mem {system : TransitionSystem} {behaviour : Behaviour system}
    {n : Nat} {state : system.State} (found : behaviour.stateAt n = some state)
    : state ∈ behaviour :=
  CCF.Seq.get?_mem found

/-- Adjacent states are connected by the action recorded at their shared step. -/
theorem step {system : TransitionSystem} (behaviour : Behaviour system) (n : Nat)
    (before after : system.State) (first : behaviour.stateAt n = some before)
    (next : behaviour.stateAt (n + 1) = some after)
    : exists action, system.step before action = some after := by
  have present : (behaviour.actions.get? n).isSome := (behaviour.valid_domains n).mpr
    (by change (behaviour.stateAt (n + 1)).isSome; rw [next]; rfl)
  obtain ⟨action, found⟩ := Option.isSome_iff_exists.mp present
  exact ⟨action, (behaviour.valid_step n before action first found).trans next⟩

/-- Every state in a behaviour is reachable. -/
theorem reachable {system : TransitionSystem} (behaviour : Behaviour system)
    {state : system.State} (member : state ∈ behaviour)
    : system.Reachable state := by
  obtain ⟨index, found⟩ := mem_iff_exists_stateAt.mp member
  clear member
  induction index generalizing state with
  | zero =>
      obtain ⟨initial, first, initialized⟩ := behaviour.valid_init
      rw [first] at found
      cases found
      exact .initial initialized
  | succ index ih =>
      cases previous : behaviour.stateAt index with
      | none =>
          have absent := behaviour.states.le_stable (Nat.le_succ index) previous
          change behaviour.stateAt (index + 1) = none at absent
          rw [absent] at found
          cases found
      | some before =>
          obtain ⟨action, stepped⟩ := behaviour.step index before state previous found.symm
          exact .step (ih previous.symm) stepped

end Behaviour

/-- Behaviours cover exactly the reachable states. Every reachable state is the
last state of some finite behaviour. -/
theorem reachable_iff_behaviour {system : TransitionSystem} {state : system.State}
    : system.Reachable state
      <-> exists behaviour : Behaviour system, state ∈ behaviour := by
  constructor
  · intro reachable
    suffices finite : exists (initial : system.State) (steps : List (system.Action × system.State)),
        system.init initial
        /\ (initial :: steps.map Prod.snd)[steps.length]? = some state
        /\ forall i : Fin steps.length,
          system.step ((initial :: steps.map Prod.snd)[i.val]'(by simp; omega))
            steps[i.val].1 = some steps[i.val].2 by
      obtain ⟨initial, steps, initialized, last, enabled⟩ := finite
      have indexed (n : Nat)
          : (CCF.Seq.cons initial ((CCF.Seq.ofList steps).map Prod.snd)).get? n
              = (initial :: steps.map Prod.snd)[n]? := by
        cases n <;> simp
      refine ⟨⟨{
        init := initial
        steps := CCF.Seq.ofList steps
      }, initialized, ?_⟩, ?_⟩
      · intro n before action first chosen
        change (steps[n]?).map Prod.fst = some action at chosen
        obtain ⟨pair, present, actionEq⟩ := Option.map_eq_some_iff.mp chosen
        obtain ⟨bound, pairEq⟩ := List.getElem?_eq_some_iff.mp present
        have firstEq : (initial :: steps.map Prod.snd)[n]? = some before :=
          (indexed n).symm.trans first
        obtain ⟨_, beforeEq⟩ := List.getElem?_eq_some_iff.mp firstEq
        change system.step before action = (steps[n]?).map Prod.snd
        rw [present]
        simpa only [← beforeEq, ← actionEq, ← pairEq, Option.map_some] using enabled ⟨n, bound⟩
      · apply Behaviour.stateAt_mem (n := steps.length)
        exact (indexed steps.length).trans last
    induction reachable with
    | initial initialized =>
        exact ⟨_, [], initialized, rfl, fun i => Fin.elim0 i⟩
    | @step before after action _ step ih =>
        obtain ⟨initial, steps, initialized, last, enabled⟩ := ih
        refine ⟨initial, steps ++ [(action, after)], initialized, ?_, ?_⟩
        · simp [List.map_append]
        · intro ⟨index, bounded⟩
          simp only [List.map_append, List.map_cons, List.map_nil]
          simp only [← List.cons_append]
          by_cases inside : index < steps.length
          · rw [List.getElem_append_left
                (as := initial :: steps.map Prod.snd) (i := index) (by simp; omega),
              List.getElem_append_left inside]
            exact enabled ⟨index, inside⟩
          · have lastIndex : index = steps.length := by simp at bounded; omega
            subst index
            have beforeEq := (List.getElem?_eq_some_iff.mp last).2
            rw [List.getElem_append_left
              (as := initial :: steps.map Prod.snd) (i := steps.length) (by simp)]
            simpa [← beforeEq] using step
  · rintro ⟨behaviour, member⟩
    exact behaviour.reachable member

/-- Each recorded action leads from the previous state to the state paired with it. -/
def StepsFrom (system : TransitionSystem)
    : system.State -> List (system.Action × system.State) -> Prop
  | _, [] => True
  | before, (action, after) :: rest =>
      system.step before action = some after /\ StepsFrom system after rest

/-- Indexed transitions in a valid list of recorded steps. -/
theorem stepsFrom_getElem? {system : TransitionSystem}
    : forall (initial : system.State) (steps : List (system.Action × system.State)),
        StepsFrom system initial steps
        -> forall (n : Nat) (before : system.State) (action : system.Action),
            (initial :: steps.map Prod.snd)[n]? = some before
            -> (steps.map Prod.fst)[n]? = some action
            -> system.step before action = (steps.map Prod.snd)[n]?
  | _, [], _, _, _, _, _, chosen => by simp at chosen
  | _, (_, _) :: _, ⟨step, _⟩, 0, _, _, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_zero, Option.some.injEq] at first chosen ⊢
      subst first chosen
      exact step
  | _, (_, after) :: rest, ⟨_, valid⟩, n + 1, before, action, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_succ] at first chosen ⊢
      exact stepsFrom_getElem? after rest valid n before action first chosen

/-- The finite behaviour that starts at `initial` and records `steps`. -/
def ofSteps {system : TransitionSystem} (initial : system.State)
    (steps : List (system.Action × system.State)) (initialized : system.init initial)
    (valid : StepsFrom system initial steps)
    : Behaviour system :=
  ⟨
    { init := initial, steps := CCF.Seq.ofList steps },
    initialized,
    by
      intro n before action first chosen
      simp only [CCF.Seq.map_get?, CCF.Seq.ofList_get?] at chosen ⊢
      rw [← List.getElem?_map] at chosen ⊢
      refine stepsFrom_getElem? initial steps valid n before action ?_ chosen
      cases n <;>
        simpa only [CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ,
          CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_cons_zero,
          List.getElem?_cons_succ, List.getElem?_map] using first
  ⟩

/-- The states of a finite behaviour, indexed from its initial state. -/
theorem ofSteps_stateAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).stateAt n
      = (initial :: steps.map Prod.snd)[n]? := by
  cases n <;>
    simp only [ofSteps, Behaviour.stateAt, Behaviour.states,
      CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ, CCF.Seq.map_get?,
      CCF.Seq.ofList_get?, List.getElem?_cons_zero, List.getElem?_cons_succ,
      List.getElem?_map]

/-- The actions of a finite behaviour. -/
theorem ofSteps_actionAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).actionAt n
      = (steps.map Prod.fst)[n]? := by
  simp only [ofSteps, Behaviour.actionAt, Behaviour.actions,
    CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_map]

/-- Membership in a finite behaviour is membership in its list of states. -/
theorem mem_ofSteps {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} {state : system.State}
    : state ∈ ofSteps initial steps initialized valid
      <-> state ∈ initial :: steps.map Prod.snd := by
  rw [Behaviour.mem_iff_exists_stateAt]
  simp only [ofSteps_stateAt]
  constructor
  · rintro ⟨n, found⟩
    exact List.mem_of_getElem? found.symm
  · intro member
    obtain ⟨n, bound, rfl⟩ := List.getElem_of_mem member
    exact ⟨n, (List.getElem?_eq_getElem bound).symm⟩

/-- Append an enabled transition at the end of a valid list of recorded steps. -/
theorem steps_snoc {system : TransitionSystem} (start before after : system.State)
    (steps : List (system.Action × system.State)) (action : system.Action)
    (valid : StepsFrom system start steps)
    (last : (start :: steps.map Prod.snd)[steps.length]? = some before)
    (enabled : system.step before action = some after)
    : StepsFrom system start (steps ++ [(action, after)]) := by
  induction steps generalizing start with
  | nil =>
      simp only [List.map_nil, List.length_nil, List.getElem?_cons_zero,
        Option.some.injEq] at last
      subst start
      exact ⟨enabled, trivial⟩
  | cons pair rest ih =>
      obtain ⟨first, valid⟩ := valid
      refine ⟨first, ih pair.2 valid ?_⟩
      simpa using last

end CCF.Execution
