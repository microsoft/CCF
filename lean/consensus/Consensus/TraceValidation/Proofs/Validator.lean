module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Validator.Validate

@[expose] public section

/-!
# T1: the executable validator decides the acceptance predicate (unreviewed proof)

`certify` replays the scheduled actions with the framework's `next`; whatever the
scheduler did, a successful `validate` is a run of the event-granular network from an
initial state over the stream nodes, emitting the observations, with every lock released.
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections
open CCF.MultiNodeTransitionSystem (nodeState)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Ev)

theorem emitsCheck_sound {env : Env}
    : forall {s : GState} {actions : List GAction} {f : GState} {obs : List Obs},
        emitsCheck env s actions = some (f, obs)
        -> Emits (machine env) declare s actions f obs
  | s, [], f, obs, h => by
      simp only [emitsCheck, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact .nil s
  | s, .event node e :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · rename_i s' step
        split at h
        · cases h
        · rename_i slot found
          split at h
          · cases h
          · rename_i f' os tail
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            exact .event step found (emitsCheck_sound tail)
  | s, .deliver x e :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · rename_i s' step
        split at h
        · cases h
        · rename_i slot found
          split at h
          · cases h
          · rename_i f' os tail
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            exact .deliver step found (emitsCheck_sound tail)
  | s, .release node :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · rename_i s' step
        exact .release step (emitsCheck_sound h)

theorem start_init {env : Env} {keys : List NodeID} {ticking : NodeID -> Bool}
    (distinct : keys.Nodup) (initial : keys.all (initOk env) = true)
    : (lift (machine env)).init (start env keys ticking)
      /\ (start env keys ticking).nodes.map Prod.fst = keys := by
  have hkeys : (start env keys ticking).nodes.map Prod.fst = keys := by
    simp [start, List.map_map, Function.comp_def]
  refine ⟨⟨by rw [hkeys]; exact distinct, rfl, ?_⟩, hkeys⟩
  intro entry member
  simp only [start, List.mem_map] at member
  obtain ⟨k, mem, rfl⟩ := member
  have ok := List.all_eq_true.mp initial k mem
  simp only [initOk, Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true, Bool.not_eq_true',
    decide_eq_false_iff_not] at ok
  refine ⟨rfl, rfl, ok.1, fun member => ?_, ticking k, rfl⟩
  rcases ok.2 with notMember | isMin
  · exact absurd member notMember
  · exact isMin

theorem certify_sound {env : Env} {keys : List NodeID} {ticking : NodeID -> Bool}
    {actions : List GAction} {obs : List Obs}
    (h : certify env keys ticking actions = some obs)
    : Accepts (machine env) declare keys obs
      /\ env.genesis.Nonempty
      /\ (forall o, o ∈ obs -> Exec.consistent o.event o.declared = true) := by
  unfold certify at h
  split at h
  · rename_i guards
    obtain ⟨distinct, initial, nonempty⟩ := guards
    split at h
    · rename_i f os run
      split at h
      · rename_i released
        simp only [Option.some.injEq] at h
        subst h
        simp only [Bool.and_eq_true] at released
        obtain ⟨init, hkeys⟩ := start_init distinct initial
        refine ⟨⟨start env keys ticking, actions, f, init, hkeys, emitsCheck_sound run, ?_⟩, nonempty,
          fun o member => List.all_eq_true.mp released.2 o member⟩
        intro entry member
        have := List.all_eq_true.mp released.1 entry member
        simpa using this
      · cases h
    · cases h
  · cases h

/-! ## The observations are the streams' events -/

/-- The node and event of each action that emits an observation. -/
def actionEvents : List GAction -> List (NodeID × Ev)
  | [] => []
  | .event k e :: as => (k, e) :: actionEvents as
  | .deliver x e :: as => (x.target, e) :: actionEvents as
  | .release _ :: as => actionEvents as

theorem emitsCheck_events {env : Env}
    : forall {s : GState} {actions : List GAction} {f : GState} {obs : List Obs},
        emitsCheck env s actions = some (f, obs)
        -> obs.map (fun o => (o.node, o.event)) = actionEvents actions
  | s, [], f, obs, h => by
      simp only [emitsCheck, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      rfl
  | s, .event node e :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · cases h
          · rename_i f' os tail
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            simp [actionEvents, emitsCheck_events tail]
  | s, .deliver x e :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · cases h
          · rename_i f' os tail
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            simp [actionEvents, emitsCheck_events tail]
  | s, .release node :: rest, f, obs, h => by
      simp only [emitsCheck] at h
      split at h
      · cases h
      · rw [actionEvents]
        exact emitsCheck_events h

theorem certify_events {env : Env} {keys : List NodeID} {ticking : NodeID -> Bool}
    {actions : List GAction} {obs : List Obs}
    (h : certify env keys ticking actions = some obs)
    : keys.Nodup /\ obs.map (fun o => (o.node, o.event)) = actionEvents actions := by
  unfold certify at h
  split at h
  · rename_i guards
    split at h
    · rename_i f os run
      split at h
      · simp only [Option.some.injEq] at h
        subst h
        exact ⟨guards.1, emitsCheck_events run⟩
      · cases h
    · cases h
  · cases h

theorem lookup_mem {k : NodeID} {b : List Ev}
    : forall {rest : List (NodeID × List Ev)},
        rest.lookup k = some b -> k ∈ rest.map Prod.fst
  | [], h => by simp at h
  | (j, evs) :: rest, h => by
      by_cases eq : k = j
      · simp [eq]
      · have ne : (k == j) = false := by simpa using eq
        simp only [List.lookup_cons, ne] at h
        exact List.mem_cons_of_mem _ (lookup_mem h)

theorem lookup_of_mem {k : NodeID} {evs : List Ev}
    : forall {rest : List (NodeID × List Ev)},
        (rest.map Prod.fst).Nodup -> (k, evs) ∈ rest -> rest.lookup k = some evs
  | [], _, h => by simp at h
  | (j, b) :: rest, nodup, h => by
      simp only [List.map_cons, List.nodup_cons] at nodup
      rcases List.mem_cons.mp h with eq | mem
      · simp only [Prod.mk.injEq] at eq
        obtain ⟨rfl, rfl⟩ := eq
        simp
      · have ne : k ≠ j := by
          rintro rfl
          exact nodup.1 (List.mem_map.mpr ⟨_, mem, rfl⟩)
        have ne : (k == j) = false := by simpa using ne
        simp only [List.lookup_cons, ne]
        exact lookup_of_mem nodup.2 mem

theorem lookup_empty {k : NodeID}
    : forall {rest : List (NodeID × List Ev)},
        rest.all (·.2.isEmpty) = true -> (rest.lookup k).getD [] = []
  | [], _ => rfl
  | (j, evs) :: rest, h => by
      simp only [List.all_cons, Bool.and_eq_true, List.isEmpty_iff] at h
      by_cases eq : k = j
      · simp [eq, h.1]
      · have ne : (k == j) = false := by simpa using eq
        simp only [List.lookup_cons, ne]
        exact lookup_empty h.2

theorem popEvent_spec {k : NodeID} {e : Ev}
    : forall {rest rest' : List (NodeID × List Ev)},
        popEvent k rest = some (e, rest')
        -> rest'.map Prod.fst = rest.map Prod.fst
            /\ (rest.lookup k).getD [] = e :: (rest'.lookup k).getD []
            /\ forall j, j ≠ k -> rest'.lookup j = rest.lookup j
  | [], _, h => by simp [popEvent] at h
  | (j, evs) :: rest, rest', h => by
      unfold popEvent at h
      by_cases eq : j = k
      · subst eq
        simp only [beq_self_eq_true, ↓reduceIte] at h
        cases evs with
        | nil => cases h
        | cons e' es =>
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            refine ⟨rfl, by simp, fun i ne => ?_⟩
            have ne : (i == j) = false := by simpa using ne
            simp [List.lookup_cons, ne]
      · simp only [beq_iff_eq, eq, ↓reduceIte, Option.map_eq_some_iff, Prod.exists] at h
        obtain ⟨e', r, popped, he⟩ := h
        simp only [Prod.mk.injEq] at he
        obtain ⟨rfl, rfl⟩ := he
        obtain ⟨keys, here, others⟩ := popEvent_spec popped
        have ne : (k == j) = false := by simpa using fun h => eq h.symm
        refine ⟨by simp [keys], by simpa [List.lookup_cons, ne] using here, fun i ne' => ?_⟩
        by_cases ij : i = j
        · simp [ij]
        · have ij : (i == j) = false := by simpa using ij
          simp [List.lookup_cons, ij, others i ne']

theorem restream_spec
    : forall {rest : List (NodeID × List Ev)} {actions actions' : List GAction},
        restream rest actions = some actions'
        -> (forall p, p ∈ actionEvents actions' -> p.1 ∈ rest.map Prod.fst)
            /\ forall k,
                ((actionEvents actions').filter (·.1 == k)).map Prod.snd
                = (rest.lookup k).getD []
  | rest, [], actions', h => by
      unfold restream at h
      split at h
      · rename_i empty
        simp only [Option.some.injEq] at h
        subst h
        exact ⟨by simp [actionEvents], fun k => by simp [actionEvents, lookup_empty empty]⟩
      · cases h
  | rest, .release k :: as, actions', h => by
      simp only [restream, Option.map_eq_some_iff] at h
      obtain ⟨as', tail, rfl⟩ := h
      rw [actionEvents]
      exact restream_spec tail
  | rest, .event k e :: as, actions', h => by
      simp only [restream] at h
      split at h
      · rename_i e' rest' popped
        split at h
        · simp only [Option.map_eq_some_iff] at h
          obtain ⟨as', tail, rfl⟩ := h
          exact step popped (restream_spec tail)
        · cases h
      · cases h
  | rest, .deliver x e :: as, actions', h => by
      simp only [restream] at h
      split at h
      · rename_i e' rest' popped
        split at h
        · simp only [Option.map_eq_some_iff] at h
          obtain ⟨as', tail, rfl⟩ := h
          exact step popped (restream_spec tail)
        · cases h
      · cases h
where
  step {rest rest' : List (NodeID × List Ev)} {k : NodeID} {e : Ev}
      {evs : List (NodeID × Ev)} (popped : popEvent k rest = some (e, rest'))
      (tail
        : (forall p, p ∈ evs -> p.1 ∈ rest'.map Prod.fst)
          /\ forall k, (evs.filter (·.1 == k)).map Prod.snd = (rest'.lookup k).getD [])
      : (forall p, p ∈ (k, e) :: evs -> p.1 ∈ rest.map Prod.fst)
        /\ forall j,
            (((k, e) :: evs).filter (·.1 == j)).map Prod.snd
            = (rest.lookup j).getD [] := by
    obtain ⟨keys, here, others⟩ := popEvent_spec popped
    refine ⟨fun p mem => ?_, fun j => ?_⟩
    · rcases List.mem_cons.mp mem with eq | mem
      · subst eq
        cases found : rest.lookup k with
        | none => simp [found] at here
        | some b => exact lookup_mem found
      · rw [← keys]
        exact tail.1 p mem
    · by_cases eq : j = k
      · subst eq
        simp [here, tail.2]
      · have ne : (k == j) = false := by simpa using fun h => eq h.symm
        simp [ne, tail.2, others j eq]

theorem conclude_streams {env : Env} {ticking : NodeID -> Bool}
    {streams : List (NodeID × List Ev)} {actions : List GAction} {obs : List Obs}
    {scheduled : List GAction} (restreamed : restream streams scheduled = some actions)
    (certified : certify env (streams.map Prod.fst) ticking actions = some obs)
    : streamsMatch streams obs := by
  obtain ⟨nodup, events⟩ := certify_events certified
  obtain ⟨members, perNode⟩ := restream_spec restreamed
  refine ⟨fun o mem => ?_, fun k evs mem => ?_⟩
  · apply members (o.node, o.event)
    rw [← events]
    exact List.mem_map.mpr ⟨o, mem, rfl⟩
  · have := perNode k
    rw [lookup_of_mem nodup mem, ← events, List.filter_map, List.map_map] at this
    simpa [Function.comp_def] using this

/--
**T1.** If the validator accepts, the acceptance predicate holds of its observations: a
run of M_tv's event-granular network over exactly the stream nodes, from an initial state,
emits them and releases every lock; each node's observed events are its stream, in order;
and the genesis configuration is nonempty.
-/
theorem validate_sound {env : Env} {streams : List (NodeID × List Ev)} {v : Verdict}
    (h : validate env streams = .ok v)
    : Accepts (machine env) declare v.keys v.observations
      /\ v.keys = streams.map Prod.fst
      /\ streamsMatch streams v.observations
      /\ env.genesis.Nonempty
      /\ (forall o, o ∈ v.observations -> Exec.consistent o.event o.declared = true) := by
  unfold validate at h
  dsimp only at h
  split at h
  · cases h
  · rename_i w _
    unfold conclude at h
    dsimp only at h
    split at h
    · cases h
    · rename_i actions restreamed
      split at h
      · cases h
      · rename_i obs certified
        simp only [Except.ok.injEq] at h
        subst h
        obtain ⟨accepts, nonempty, consistent⟩ := certify_sound certified
        exact ⟨accepts, rfl, conclude_streams restreamed certified, nonempty, consistent⟩

end Consensus.TraceValidation.Proofs
