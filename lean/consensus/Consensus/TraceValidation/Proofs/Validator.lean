module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Validator

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
      /\ streamsMatch streams v.observations = true
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
    · rename_i obs certified
      split at h
      · rename_i matches_
        simp only [Except.ok.injEq] at h
        subst h
        obtain ⟨accepts, nonempty, consistent⟩ := certify_sound certified
        exact ⟨accepts, rfl, matches_, nonempty, consistent⟩
      · cases h

end Consensus.TraceValidation.Proofs
