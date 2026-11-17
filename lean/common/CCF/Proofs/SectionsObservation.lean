module

public import CCF.Proofs.Sections
public import CCF.Observation

@[expose] public section

namespace CCF.Sections

/-!
From the lifting step to observation-point refinement: every observation list accepted
by the event-granular network is explained by one trace of the guarded clean network,
and therefore of any specification whose initial states and steps include the guarded
network's. At each lock-taking event, the node's clean state is related by `R` to the
observed declared state.
-/

open MultiNodeTransitionSystem (nodeState)
open Execution (Run StepsFrom)
open ObservationRefinement (Observation)

section Lists

variable {system : TransitionSystem}

theorem stepsFrom_append
    : forall (start middle : system.State)
              (first second : List (system.Action × system.State)),
        (start :: first.map Prod.snd)[first.length]? = some middle
        -> StepsFrom system start first
        -> StepsFrom system middle second
        -> StepsFrom system start (first ++ second)
  | start, middle, [], second, last, _, valid => by
      simp only [List.map_nil, List.length_nil, List.getElem?_cons_zero,
        Option.some.injEq] at last
      subst last
      exact valid
  | _, middle, (_, after) :: rest, second, last, ⟨step, valid⟩, tail =>
      ⟨step, stepsFrom_append after middle rest second (by simpa using last) valid tail⟩

theorem run_stepsFrom {start finish : system.State} {actions : List system.Action}
    (run : Run system start actions finish)
    : exists steps : List (system.Action × system.State),
        StepsFrom system start steps
        /\ (start :: steps.map Prod.snd)[steps.length]? = some finish := by
  induction run with
  | nil => exact ⟨[], trivial, by simp⟩
  | @cons _ middle _ action _ step _ ih =>
      obtain ⟨steps, valid, last⟩ := ih
      exact ⟨(action, middle) :: steps, ⟨step, valid⟩, by simpa using last⟩

theorem getElem?_shift
    : forall (start middle : system.State)
              (first second : List (system.Action × system.State)) (position : Nat),
        (start :: first.map Prod.snd)[first.length]? = some middle
        -> (start :: (first ++ second).map Prod.snd)[first.length + position]?
            = (middle :: second.map Prod.snd)[position]?
  | start, middle, [], second, position, last => by
      simp only [List.map_nil, List.length_nil, List.getElem?_cons_zero,
        Option.some.injEq] at last
      subst last
      simp
  | _, middle, (_, after) :: rest, second, position, last => by
      simp only [List.cons_append, List.map_cons, List.length_cons,
        List.getElem?_cons_succ] at last ⊢
      rw [show rest.length + 1 + position = (rest.length + position) + 1 by omega,
        List.getElem?_cons_succ]
      exact getElem?_shift after middle rest second position last

end Lists

variable
  {Node Message LocalState Event CleanState LocalAction Notification Input Declared
    : Type}
  [BEq Node] [BEq Message]
  {machine : Machine Node Message LocalState Event}
  {protocol
    : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message Notification
        Input}
  {admit : List (Node × CleanState) -> Node -> Input -> Bool}

/-- Recorded guarded steps are recorded steps of any system that includes them. -/
theorem stepsFrom_embed
    {specInit : MultiNodeTransitionSystem.State Node CleanState Message -> Prop}
    {specStep
      : MultiNodeTransitionSystem.State Node CleanState Message
        -> MultiNodeTransitionSystem.Action Node Message Input
        -> Option (MultiNodeTransitionSystem.State Node CleanState Message)}
    (embeds
      : forall clean action clean',
          guardedNext protocol admit clean action = some clean'
          -> specStep clean action = some clean')
    : forall clean
              (steps
                : List
                    ((guarded protocol admit).Action × (guarded protocol admit).State)),
        StepsFrom (guarded protocol admit) clean steps
        -> StepsFrom ⟨_, _, specInit, specStep⟩ clean steps
  | _, [], _ => trivial
  | clean, (action, after) :: rest, ⟨step, valid⟩ =>
      ⟨embeds clean action after step, stepsFrom_embed embeds after rest valid⟩

variable [LawfulBEq Node] [LawfulBEq Message]

/-- The core induction: emitted observations are read off one guarded clean run. -/
theorem emits_sim (refinement : Refinement machine protocol admit)
    (declare : LocalState -> Declared) (R : Node -> CleanState -> Declared -> Prop)
    (factors
      : forall node clean local_,
          refinement.rel node clean local_
          -> machine.idle local_ = true
          -> R node clean (declare local_))
    (frame
      : forall node local_ received event local',
          machine.idle local_ = true
          -> machine.step node local_ received event = some local'
          -> machine.opens event = true
          -> forall clean, R node clean (declare local_) -> R node clean (declare local'))
    {start finish : State Node Message LocalState}
    {actions : List (Action Node Message Event)}
    {observations : List (Observation Node Event Declared)}
    (emits : Emits machine declare start actions finish observations)
    : forall clean,
        Sim machine refinement.rel refinement.msgInv clean start
        -> exists (steps
                    : List
                        ((guarded protocol admit).Action
                          × (guarded protocol admit).State)) (index : Nat -> Nat),
            StepsFrom (guarded protocol admit) clean steps
            /\ (forall i j, i <= j -> index i <= index j)
            /\ forall (i : Nat) (observation : Observation Node Event Declared),
                observations[i]? = some observation
                -> machine.opens observation.event = true
                -> exists state cleanLocal,
                    (clean :: steps.map Prod.snd)[index i]? = some state
                    /\ nodeState state observation.node = some cleanLocal
                    /\ R observation.node cleanLocal observation.declared := by
  induction emits with
  | nil =>
      intro clean _
      exact ⟨[], fun _ => 0, trivial, fun _ _ _ => Nat.le_refl _, by simp⟩
  | @event before middle _ node event slot _ _ step found _ ih =>
      intro clean sim
      obtain ⟨steps, index, valid, monotone, points⟩ := ih clean (event_sim sim step)
      refine ⟨steps, fun i => if i = 0 then 0 else index (i - 1), valid, ?_, ?_⟩
      · intro i j ordered
        by_cases zero : i = 0
        · simp [zero]
        · have : j ≠ 0 := by omega
          simp only [zero, this, ite_false]
          exact monotone _ _ (by omega)
      · intro i observation found' opens
        cases i with
        | zero =>
            simp only [List.getElem?_cons_zero, Option.some.injEq] at found'
            subst found'
            obtain ⟨slot0, current, found0, allowed, ran, rfl⟩ := next_event_inv step
            obtain ⟨cleanLocal, cleanFound, related, holds⟩ := sim.lookup found0
            have free : slot0.entry = none := by
              simp only at opens
              simpa [opens] using allowed
            have same := (nodeState_setNode found0).symm.trans found
            simp only [Option.some.injEq] at same
            subst same
            have hidle : machine.idle slot0.current = true := by
              unfold SlotInv at holds; rw [free] at holds; exact holds.2
            refine ⟨clean, cleanLocal, by simp, cleanFound, ?_⟩
            show R node cleanLocal (declare current)
            have : slot0.base = slot0.current := by simp [Slot.base, free]
            exact frame node _ none event current hidle ran opens _
              (factors _ _ _ (this ▸ related) hidle)
        | succ i =>
            simp only [List.getElem?_cons_succ] at found'
            simp only [Nat.add_one_ne_zero, ite_false, Nat.add_sub_cancel]
            exact points i observation found' opens
  | @deliver before middle _ envelope event slot _ _ step found _ ih =>
      intro clean sim
      obtain ⟨steps, index, valid, monotone, points⟩ := ih clean (deliver_sim sim step)
      refine ⟨steps, fun i => if i = 0 then 0 else index (i - 1), valid, ?_, ?_⟩
      · intro i j ordered
        by_cases zero : i = 0
        · simp [zero]
        · have : j ≠ 0 := by omega
          simp only [zero, this, ite_false]
          exact monotone _ _ (by omega)
      · intro i observation found' opens
        cases i with
        | zero =>
            simp only [List.getElem?_cons_zero, Option.some.injEq] at found'
            subst found'
            obtain ⟨_, slot0, current, found0, free, ran, rfl⟩ := next_deliver_inv step
            obtain ⟨cleanLocal, cleanFound, related, holds⟩ := sim.lookup found0
            have same := (nodeState_setNode found0).symm.trans found
            simp only [Option.some.injEq] at same
            subst same
            have hidle : machine.idle slot0.current = true := by
              unfold SlotInv at holds; rw [free] at holds; exact holds.2
            refine ⟨clean, cleanLocal, by simp, cleanFound, ?_⟩
            show R envelope.target cleanLocal (declare current)
            have : slot0.base = slot0.current := by simp [Slot.base, free]
            exact frame _ _ _ event current hidle ran opens _
              (factors _ _ _ (this ▸ related) hidle)
        | succ i =>
            simp only [List.getElem?_cons_succ] at found'
            simp only [Nat.add_one_ne_zero, ite_false, Nat.add_sub_cancel]
            exact points i observation found' opens
  | @release before middle _ node _ _ step _ ih =>
      intro clean sim
      obtain ⟨chunk, clean', run, sim'⟩ := release_sim refinement sim step
      obtain ⟨first, valid, last⟩ := run_stepsFrom run
      obtain ⟨second, index, valid', monotone, points⟩ := ih clean' sim'
      refine ⟨first ++ second, fun i => first.length + index i,
        stepsFrom_append _ _ _ _ last valid valid', ?_, ?_⟩
      · intro i j ordered
        exact Nat.add_le_add_left (monotone _ _ ordered) _
      · intro i observation found' opens
        rw [getElem?_shift (system := guarded protocol admit) _ _ first second _ last]
        exact points i observation found' opens

/--
Observation-point refinement from the lifting step. Given a `Refinement` whose relation
implies `R` of the declared part at idle states, and whose lock-taking events preserve
`R` of the declared part when they open a section, every observation list accepted over
the nodes `keys` is explained by one trace of any specification over the same states
whose initial states include the clean network's initial states over `keys`, and whose
steps include the guarded clean network's steps.
-/
theorem observation_refines (refinement : Refinement machine protocol admit)
    (declare : LocalState -> Declared) (R : Node -> CleanState -> Declared -> Prop)
    (factors
      : forall node clean local_,
          refinement.rel node clean local_
          -> machine.idle local_ = true
          -> R node clean (declare local_))
    (frame
      : forall node local_ received event local',
          machine.idle local_ = true
          -> machine.step node local_ received event = some local'
          -> machine.opens event = true
          -> forall clean, R node clean (declare local_) -> R node clean (declare local'))
    (keys : List Node)
    (specInit : MultiNodeTransitionSystem.State Node CleanState Message -> Prop)
    (specStep
      : MultiNodeTransitionSystem.State Node CleanState Message
        -> MultiNodeTransitionSystem.Action Node Message Input
        -> Option (MultiNodeTransitionSystem.State Node CleanState Message))
    (initEmbeds
      : forall clean,
          (MultiNodeTransitionSystem.lift protocol).init clean
          -> clean.nodes.map Prod.fst = keys
          -> specInit clean)
    (stepEmbeds
      : forall clean action clean',
          guardedNext protocol admit clean action = some clean'
          -> specStep clean action = some clean')
    (observations : List (Observation Node Event Declared))
    (accepted : Accepts machine declare keys observations)
    : ObservationRefinement.Refines ⟨_, _, specInit, specStep⟩ nodeState R machine.opens
        observations := by
  obtain ⟨start, actions, finish, initial, hkeys, emits, _⟩ := accepted
  obtain ⟨distinct, empty, slots⟩ := initial
  obtain ⟨cleanNodes, keyed, inits⟩ := init_sim refinement start.nodes slots
  have sim : Sim machine refinement.rel refinement.msgInv { nodes := cleanNodes, network := [] } start :=
    ⟨⟨empty.symm, by simp [empty]⟩, distinct, keyed⟩
  obtain ⟨steps, index, valid, monotone, points⟩ :=
    emits_sim refinement declare R factors frame emits _ sim
  have cleanKeys : cleanNodes.map Prod.fst = keys := keyed.keys.trans hkeys
  have initialized : specInit { nodes := cleanNodes, network := [] } :=
    initEmbeds _ ⟨by rw [cleanKeys, ← hkeys]; exact distinct, rfl, inits⟩ cleanKeys
  refine ⟨Execution.ofSteps (system := ⟨_, _, specInit, specStep⟩) _ steps initialized
    (stepsFrom_embed stepEmbeds _ steps valid), index, monotone, ?_⟩
  intro i observation found opens
  simpa only [Execution.ofSteps_stateAt] using points i observation found opens

end CCF.Sections
