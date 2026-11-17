module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeLemmas

@[expose] public section

/-!
# `find_highest_possible_match` (not reviewed)

Under `inv`, cft.h's view-history walk `State.highestMatch` computes the clean
`findHighestPossibleMatch` of the abstract log: both are the highest index at or below
`min idx lastIdx` whose term is at most `term`.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- Adjacent order implies pairwise order. -/
theorem pairwise_of_zip_tail
    : forall w : List Nat,
        (w.zip w.tail).all (fun (x, y) => decide (x <= y)) = true -> w.Pairwise (· <= ·)
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: rest, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
        decide_eq_true_eq] at h
      have ih := pairwise_of_zip_tail (b :: rest) (by simpa using h.2)
      refine List.Pairwise.cons ?_ ih
      intro y hy
      rcases List.mem_cons.mp hy with rfl | hy
      · exact h.1
      · exact Nat.le_trans h.1 ((List.pairwise_cons.mp ih).1 y hy)

/-- In a sorted list, the first `count` elements are exactly those at or below `q`. -/
theorem sorted_le_iff
    : forall {w : List Nat},
        w.Pairwise (· <= ·)
        -> forall (q k : Nat) (hk : k < w.length),
            w[k] <= q <-> k < (w.filter (· <= q)).length
  | [], _, _, _, hk => absurd hk (Nat.not_lt_zero _)
  | a :: w, hs, q, k, hk => by
      have hs' := List.pairwise_cons.mp hs
      by_cases ha : a <= q
      · have hf : ((a :: w).filter (· <= q)).length = (w.filter (· <= q)).length + 1 := by
          simp [ha]
        rw [hf]
        cases k with
        | zero => simp [ha]
        | succ k =>
            have := sorted_le_iff hs'.2 q k (by simpa using hk)
            simp only [List.getElem_cons_succ]
            omega
      · have hnil : (a :: w).filter (· <= q) = [] := by
          rw [List.filter_eq_nil_iff]
          intro x hx
          rcases List.mem_cons.mp hx with rfl | hx
          · simpa using ha
          · have := hs'.1 x hx; simp; omega
        rw [hnil]
        cases k with
        | zero => simpa using ha
        | succ k =>
            have := hs'.1 _ (List.getElem_mem (l := w) (n := k) (by simpa using hk))
            simp only [List.getElem_cons_succ, List.length_nil, Nat.not_lt_zero, iff_false]
            omega

/-- `highestMatch`'s answer for `probe`: the highest index at or below it whose view is at most `t`. -/
def IsHM (v : State) (t q x : Nat) : Prop :=
  x <= q /\ v.viewAt x <= t /\ forall c, c <= q -> v.viewAt c <= t -> c <= x

theorem IsHM.unique {v : State} {t q x y : Nat} (hx : IsHM v t q x) (hy : IsHM v t q y)
    : x = y :=
  Nat.le_antisymm (hy.2.2 x hx.1 hx.2.1) (hx.2.2 y hy.1 hy.2.1)

section
variable {v : State}

private theorem viewAt_eq (q : Nat)
    : v.viewAt q = (v.views.toList.filter (· <= q)).length :=
  rfl

theorem viewAt_mono' {i j : Nat} (ij : i <= j) : v.viewAt i <= v.viewAt j := by
  unfold State.viewAt
  simp only [← List.countP_eq_length_filter]
  apply List.countP_mono_left
  intro x _ h
  simp only [decide_eq_true_eq] at h ⊢
  omega

theorem viewAt_le_size' (i : Nat) : v.viewAt i <= v.views.size := by
  unfold State.viewAt
  have := List.length_filter_le (fun x => decide (x <= i)) v.views.toList
  simpa using this

variable (sorted : v.views.toList.Pairwise (· <= ·)) (pos : v.views.all (0 < ·) = true)
include sorted

/-- With `tp = viewAt q` positive, view `tp` starts at or below `q` and `startOfView` finds it. -/
theorem startOfView_viewAt {q : Nat} (tp1 : 1 <= v.viewAt q)
    : exists st,
        v.startOfView (v.viewAt q) = st
        /\ st <= q
        /\ st ∈ v.views
        /\ (forall c, st <= c -> v.viewAt q <= v.viewAt c)
        /\ (0 < st -> v.viewAt (st - 1) < v.viewAt q) := by
  have hsz := viewAt_le_size' (v := v) q
  have hk : v.viewAt q - 1 < v.views.toList.length := by simp; omega
  have hst := (sorted_le_iff sorted q (v.viewAt q - 1) hk).mpr (by rw [← viewAt_eq]; omega)
  refine ⟨v.views.toList[v.viewAt q - 1], ?_, hst, ?_, ?_, ?_⟩
  · unfold State.startOfView
    have c1 : ¬ (v.viewAt q > v.views.size || v.viewAt q == 0) = true := by
      simp; omega
    simp only [c1]
    have e1 : v.views[v.viewAt q - 1]! = v.views.toList[v.viewAt q - 1] := by
      simp [getElem!_pos, show v.viewAt q - 1 < v.views.size by omega]
    rw [e1]
    by_cases hlt : v.viewAt q + 1 <= v.views.size
    · have hk2 : v.viewAt q < v.views.toList.length := by simp; omega
      have hgt := (not_congr (sorted_le_iff sorted q (v.viewAt q) hk2)).mpr
        (by rw [← viewAt_eq]; omega)
      have e2 : v.views[v.viewAt q]! = v.views.toList[v.viewAt q] := by
        simp [getElem!_pos, show v.viewAt q < v.views.size by omega]
      have : (v.views[v.viewAt q]! == v.views.toList[v.viewAt q - 1]) = false := by
        rw [e2]; simp only [beq_eq_false_iff_ne, ne_eq]; omega
      simp only [hlt, this, decide_true, Bool.and_false, Bool.false_eq_true, ite_false]
    · simp [hlt]
  · have := List.getElem_mem hk
    simp
  · intro c hc
    have := (sorted_le_iff sorted c (v.viewAt q - 1) hk).mp hc
    rw [← viewAt_eq] at this
    omega
  · intro hp
    refine Nat.lt_of_not_le fun hge => ?_
    have := (sorted_le_iff sorted (v.views.toList[v.viewAt q - 1] - 1) (v.viewAt q - 1) hk).mpr
      (by rw [← viewAt_eq]; omega)
    omega

include pos

theorem highestMatchGo_spec (t : Nat)
    : forall (f q : Nat),
        v.viewAt q < f -> IsHM v t q (v.highestMatchGo t q (v.viewAt q) f)
  | 0, _, h => absurd h (Nat.not_lt_zero _)
  | f + 1, q, h => by
      unfold State.highestMatchGo
      by_cases ht : v.viewAt q > t
      · simp only [ht, ite_true]
        obtain ⟨st, hst, stq, mem, above, below⟩ := startOfView_viewAt sorted (q := q) (by omega)
        rw [hst]
        have stpos : 0 < st := by
          have := (Array.all_eq_true_iff_forall_mem.mp pos) _ mem
          simpa using this
        simp only [stpos, ite_true]
        have r := highestMatchGo_spec t f (st - 1) (by have := below stpos; omega)
        refine ⟨by have := r.1; omega, r.2.1, fun c hc hct => ?_⟩
        by_cases hcs : st <= c
        · have := above c hcs; omega
        · exact r.2.2 c (by omega) hct
      · simp only [ht, ite_false]
        exact ⟨Nat.le_refl _, by omega, fun c hc _ => hc⟩

theorem highestMatch_spec (t idx : Nat)
    : IsHM v t (min idx v.lastIdx) (v.highestMatch t idx) := by
  unfold State.highestMatch
  exact highestMatchGo_spec sorted pos t _ _
    (by have := viewAt_le_size' (v := v) (min idx v.lastIdx); omega)

end

theorem foldMax_prop_cases (p : Nat -> Prop) [DecidablePred p] (l : List Nat) (b : Nat)
    : l.foldl (fun best i => if p i then max best i else best) b = b
      \/ (p (l.foldl (fun best i => if p i then max best i else best) b)
          /\ l.foldl (fun best i => if p i then max best i else best) b ∈ l) := by
  induction l generalizing b with
  | nil => exact Or.inl rfl
  | cons x xs ih =>
      simp only [List.foldl_cons]
      rcases ih (if p x then max b x else b) with h | h
      · rw [h]
        by_cases hx : p x
        · simp only [hx, ite_true]
          rcases Nat.le_total b x with hb | hb
          · rw [Nat.max_eq_right hb]; exact Or.inr ⟨hx, List.mem_cons_self⟩
          · rw [Nat.max_eq_left hb]; exact Or.inl rfl
        · simp [hx]
      · exact Or.inr ⟨h.1, List.mem_cons_of_mem _ h.2⟩

theorem foldMax_prop_ge (p : Nat -> Prop) [DecidablePred p] (l : List Nat) (b : Nat)
    : b <= l.foldl (fun best i => if p i then max best i else best) b
      /\ forall i,
          i ∈ l
          -> p i
          -> i <= l.foldl (fun best i => if p i then max best i else best) b := by
  induction l generalizing b with
  | nil => exact ⟨Nat.le_refl _, fun _ h => absurd h List.not_mem_nil⟩
  | cons x xs ih =>
      simp only [List.foldl_cons]
      obtain ⟨ih1, ih2⟩ := ih (if p x then max b x else b)
      refine ⟨Nat.le_trans (by split <;> omega) ih1, fun i hi hp => ?_⟩
      rcases List.mem_cons.mp hi with rfl | hi
      · refine Nat.le_trans ?_ ih1
        simp only [hp, ite_true]; omega
      · exact ih2 i hi hp

/-- Under `inv`, cft.h's `find_highest_possible_match` is the clean one. -/
theorem highestMatch_eq {names : Names} {v : State} (h : inv names v = true) (t idx : Nat)
    : v.highestMatch t idx = findHighestPossibleMatch (abs names v).log idx t := by
  have sorted : v.views.toList.Pairwise (· <= ·) := by
    apply pairwise_of_zip_tail
    inv_conj h "views_sorted"
  obtain ⟨h1, -, -, -, h5, -, h7⟩ := inv_parts h
  have hlen : (abs names v).log.length = v.lastIdx := by simp [abs, h1]
  have hterm : forall c, 1 <= c -> c <= v.lastIdx -> termAt (abs names v).log c = v.viewAt c := by
    intro c c1 cL
    simp only [termAt_abs h1, show ¬ c = 0 by omega, ↓reduceIte, h5 c c1 cL]; rfl
  refine IsHM.unique (highestMatch_spec sorted h7 t idx) ?_
  unfold findHighestPossibleMatch
  rw [hlen]
  generalize hF : (List.range (min idx v.lastIdx + 1)).foldl _ 0 = F
  have ge := foldMax_prop_ge (fun c => c > 0 /\ termAt (abs names v).log c <= t)
    (List.range (min idx v.lastIdx + 1)) 0
  rw [hF] at ge
  refine ⟨?_, ?_, fun c hc hct => ?_⟩
  · rcases foldMax_prop_cases (fun c => c > 0 /\ termAt (abs names v).log c <= t)
      (List.range (min idx v.lastIdx + 1)) 0 with e | e <;> rw [hF] at e
    · omega
    · have := List.mem_range.mp e.2; omega
  · rcases foldMax_prop_cases (fun c => c > 0 /\ termAt (abs names v).log c <= t)
      (List.range (min idx v.lastIdx + 1)) 0 with e | e <;> rw [hF] at e
    · subst e; rw [viewAt_zero h7]; omega
    · have := List.mem_range.mp e.2
      rw [← hterm F (by omega) (by omega)]; exact e.1.2
  · by_cases c0 : c = 0
    · omega
    · exact ge.2 c (List.mem_range.mpr (by omega))
        ⟨by omega, by rw [hterm c (by omega) (by omega)]; exact hct⟩

end Consensus.TraceValidation.Proofs.Ae
