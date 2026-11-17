module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickSend

@[expose] public section

/-!
# The self-vote of an election timeout (not reviewed; `Tick` obligation)
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)
open Life (Tri Pres)

variable {env : Env}

theorem tri_pre_prop {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} {p : Prop} (h : p -> Tri env P x Q)
    : Tri env (fun w o => P w o /\ p) x Q := by
  intro c a c' e q run
  exact h q.2 c a c' e q.1 run

/-- A loop whose body leaves the state and outbox alone is a fold. -/
theorem tri_forIn_pure {α β : Type} {l : List α} {init : β}
    {f : α -> β -> M (ForInStep β)} (g : β -> α -> β) {v : State} {O : Outbox}
    (h
      : forall a b,
          a ∈ l
          -> Tri env (fun w o => w = v /\ o = O) (f a b)
              (fun r w o => w = v /\ o = O /\ r = .yield (g b a)))
    : Tri env (fun w o => w = v /\ o = O) (forIn l init f)
        (fun r w o => w = v /\ o = O /\ r = l.foldl g init) := by
  induction l generalizing init with
  | nil =>
      rw [List.forIn_nil]
      exact Tri.conseq (Tri.pure' (Q := fun r w o => w = v /\ o = O /\ r = init) init)
        (fun _ _ ⟨hw, ho⟩ => ⟨hw, ho, rfl⟩) (fun _ _ _ h => h)
  | cons a rest ih =>
      rw [List.forIn_cons]
      refine Tri.bind (h a init List.mem_cons_self) fun r => ?_
      refine Tri.conseq (P' := fun w o => w = v /\ o = O /\ r = .yield (g init a)) ?_
        (fun _ _ h => h) (fun _ _ _ h => h)
      intro c x c' e ⟨hw, ho, hr⟩ run
      subst hr
      exact ih (fun a' b' m => h a' b' (List.mem_cons_of_mem _ m)) c x c' e ⟨hw, ho⟩ run

/-- One configuration's round of `recordVote`'s loop. -/
def voteStep (self : NodeId) (votes : List (Nat × List NodeId × Nat)) (c : Config)
    : List (Nat × List NodeId × Nat) :=
  if (c.nodes.any fun x => x.fst == self) = true then
    match votes.find? (fun x => x.fst == c.idx) with
    | some _ =>
        votes.map
          fun (i, vs, q) =>
            if (i == c.idx) = true then
              (i, if vs.contains self = true then vs else vs ++ [self], q)
            else
              (i, vs, q)
    | none => (votes ++ [(c.idx, [self], 0)]).mergeSort fun a b => decide (a.fst ≤ b.fst)
  else
    votes

theorem tri_recordVote (self : NodeId) (v : State) (O : Outbox)
    (ne : v.configurations ≠ [])
    : Tri env (fun w o => w = v /\ o = O) (recordVote self)
        (fun b w o =>
          let votes := v.configurations.foldl (voteStep self) v.votesForMe
          w = { v with votesForMe := votes }
          /\ o = O
          /\ b = votes.all fun (_, vs, q) => decide (vs.length ≥ q)) := by
  unfold recordVote
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  simp only [List.isEmpty_iff, ne, ↓reduceIte]
  refine Tri.bind (tri_forIn_pure (voteStep self) fun c b _ => ?_) fun r => ?_
  · unfold voteStep
    split
    · exact Tri.conseq (Tri.pure' _) (fun _ _ h => by obtain ⟨hw, ho⟩ := h; exact ⟨hw, ho, rfl⟩)
        (fun _ _ _ h => h)
    · exact Tri.conseq (Tri.pure' _) (fun _ _ h => by obtain ⟨hw, ho⟩ := h; exact ⟨hw, ho, rfl⟩)
        (fun _ _ _ h => h)
  · refine Tri.conseq (tri_pre_prop (P := fun w o => w = v /\ o = O)
        (p := r = v.configurations.foldl (voteStep self) v.votesForMe) fun hr => ?_)
      (fun _ _ h => by obtain ⟨hw, ho, hr⟩ := h; exact ⟨⟨hw, ho⟩, hr⟩) (fun _ _ _ h => h)
    subst hr
    exact Tri.bind (Tri.setV (Q := fun _ w o =>
        w = { v with votesForMe := v.configurations.foldl (voteStep self) v.votesForMe } /\ o = O)
        fun _ _ h => by obtain ⟨hw, ho⟩ := h; exact ⟨by rw [hw], ho⟩)
      (fun _ => Tri.conseq (Tri.pure' _) (fun _ _ h => by obtain ⟨hw, ho⟩ := h; exact ⟨hw, ho, rfl⟩)
        (fun _ _ _ h => h))

/-- Whether configuration `c` lists `self`. -/
def Lists (self : NodeId) (c : Config) : Prop :=
  (c.nodes.any fun x => x.fst == self) = true

instance (self : NodeId) (c : Config) : Decidable (Lists self c) := by
  unfold Lists; infer_instance

/-- The vote record of `c` once the configurations `S` have recorded `self`'s vote. -/
def voteRec (self : NodeId) (S : List Config) (c : Config) : Nat × List NodeId × Nat :=
  (
    c.idx,
    if (S.any fun c' => c'.idx == c.idx && decide (Lists self c')) then [self] else [],
    State.quorum c.nodes.length
  )

theorem voteStep_rec (self : NodeId) (cs S : List Config) {c : Config} (mem : c ∈ cs)
    : voteStep self (cs.map (voteRec self S)) c = cs.map (voteRec self (S ++ [c])) := by
  unfold voteStep
  by_cases P : Lists self c
  · have P' : (c.nodes.any fun x => x.fst == self) = true := P
    simp only [P', ↓reduceIte]
    cases hf : (cs.map (voteRec self S)).find? (fun x => x.fst == c.idx) with
    | none =>
        have := List.find?_eq_none.mp hf (voteRec self S c) (List.mem_map_of_mem mem)
        simp [voteRec] at this
    | some _ =>
        simp only [List.map_map]
        apply List.map_congr_left
        intro c'' _
        simp only [Function.comp, voteRec, List.any_append, List.any_cons, List.any_nil,
          Bool.or_false]
        by_cases hi : c''.idx = c.idx
        · simp only [hi, BEq.rfl, ↓reduceIte, P, decide_true, Bool.and_true, Bool.or_true]
          split <;> simp
        · have : (c''.idx == c.idx) = false := by simpa using hi
          have h2 : (c.idx == c''.idx) = false := by simpa using Ne.symm hi
          simp [this, h2]
  · have P' : (c.nodes.any fun x => x.fst == self) = false := by
      unfold Lists at P; exact Bool.eq_false_iff.mpr P
    simp only [P', Bool.false_eq_true, ↓reduceIte]
    apply List.map_congr_left
    intro c'' _
    have hP : decide (Lists self c) = false := decide_eq_false P
    simp only [voteRec, List.any_append, List.any_cons, List.any_nil, Bool.or_false, hP,
      Bool.and_false]

theorem foldl_voteStep (self : NodeId) (cs : List Config)
    : forall (S rest : List Config),
        (forall c, c ∈ rest -> c ∈ cs)
        -> rest.foldl (voteStep self) (cs.map (voteRec self S))
            = cs.map (voteRec self (S ++ rest)) := by
  intro S rest
  induction rest generalizing S with
  | nil => intro _; simp
  | cons c rest ih =>
      intro sub
      rw [List.foldl_cons, voteStep_rec self cs S (sub c List.mem_cons_self),
        ih _ fun c' m => sub c' (List.mem_cons_of_mem _ m)]
      simp

theorem idx_inj {cs : List Config} (sorted : cs.Pairwise fun a b => a.idx < b.idx)
    {a b : Config} (ma : a ∈ cs) (mb : b ∈ cs) (h : a.idx = b.idx)
    : a = b := by
  induction cs with
  | nil => cases ma
  | cons x rest ih =>
      obtain ⟨lt, sorted⟩ := List.pairwise_cons.mp sorted
      rcases List.mem_cons.mp ma with ha | ma <;> rcases List.mem_cons.mp mb with hb | mb
      · rw [ha, hb]
      · have := lt b mb; rw [ha] at h; omega
      · have := lt a ma; rw [hb] at h; omega
      · exact ih sorted ma mb

/--
After a reset, `self`'s own vote leaves each configuration's record with `self` alone if it
lists `self` and empty otherwise, provided the configurations have distinct indexes.
-/
theorem selfVote_eq (self : NodeId) (cs : List Config)
    (sorted : cs.Pairwise fun a b => a.idx < b.idx)
    : cs.foldl (voteStep self) (cs.map fun c => (c.idx, [], State.quorum c.nodes.length))
      = cs.map
          fun c =>
            (
              c.idx,
              if Lists self c then [self] else [],
              State.quorum c.nodes.length
            ) := by
  have h0 := foldl_voteStep self cs [] cs (fun _ m => m)
  simp only [List.nil_append] at h0
  have e0 : (cs.map fun c => (c.idx, ([] : List NodeId), State.quorum c.nodes.length))
      = cs.map (voteRec self []) := by
    simp [voteRec]
  rw [e0, h0]
  apply List.map_congr_left
  intro c mem
  simp only [voteRec]
  congr 2
  by_cases P : Lists self c
  · simp only [P, ↓reduceIte]
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
    simp only [ite_eq_left_iff, reduceCtorEq, imp_false, Classical.not_not]
    exact ⟨c, mem, rfl, P⟩
  · simp only [P, ↓reduceIte]
    simp only [ite_eq_right_iff, reduceCtorEq, imp_false, List.any_eq_true, Bool.and_eq_true,
      beq_iff_eq, decide_eq_true_eq, not_exists, not_and]
    intro c' mem' hi P'
    exact P (idx_inj sorted mem' mem hi ▸ P')

/-- The self-vote elects iff every configuration is `self` alone. -/
theorem selfVote_all (self : NodeId) (cs : List Config)
    : ((cs.map
          fun c =>
            (c.idx, if Lists self c then [self] else [], State.quorum c.nodes.length)).all
        fun (_, vs, q) => decide (vs.length ≥ q))
      = decide (forall c, c ∈ cs -> Lists self c /\ c.nodes.length <= 1) := by
  rw [Bool.eq_iff_iff]
  simp only [List.all_map, List.all_eq_true, Function.comp, decide_eq_true_eq, State.quorum]
  apply forall_congr'; intro c; apply imp_congr_right; intro _
  by_cases P : Lists self c <;> simp only [P, ↓reduceIte, List.length_singleton,
    List.length_nil, true_and, false_and]
  · generalize c.nodes.length = n
    constructor
    · intro h; omega
    · intro h; omega
  · generalize c.nodes.length = n
    simp only [iff_false]; omega

end Consensus.TraceValidation.Proofs.Tick
