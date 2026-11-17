module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeLemmas
public import Consensus.TraceValidation.Proofs.Handlers.ReplUpdateCommit

@[expose] public section

/-!
# The batch range of `send_append_entries` (not reviewed; `Tick` obligation)

`send_append_entries` sends from `start` up to an end chosen in `[start, maxIdx]`, where
`maxIdx` is the end of the view of `start` (or the last index). On a declared state whose
view history is sorted, positive, at most one past the ledger, and assigns every entry its
term (`ViewHyps`, from `inv`), that range is inside the ledger and in one view
(`maxIdx_range`, `viewAt_const`), and from `lastIdx + 1` it is empty (`maxIdx_past`).
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- A list whose adjacent elements are ordered is sorted. -/
theorem pairwise_of_adjacent
    : forall {l : List Nat},
        (l.zip l.tail).all (fun (x, y) => decide (x <= y)) = true -> l.Pairwise (· <= ·)
  | [], _ => .nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
        decide_eq_true_eq] at h
      have rest : (b :: t).Pairwise (· <= ·) := pairwise_of_adjacent (by simpa using h.2)
      refine List.Pairwise.cons ?_ rest
      intro x mem
      rcases List.mem_cons.mp mem with rfl | mem
      · exact h.1
      · exact Nat.le_trans h.1 (List.rel_of_pairwise_cons rest mem)

/-- In a sorted list, the `k`-th element is at most `i` iff more than `k` elements are. -/
theorem lt_length_filter_iff
    : forall {l : List Nat},
        l.Pairwise (· <= ·)
        -> forall {k : Nat} (hk : k < l.length) (i : Nat),
            k < (l.filter fun x => decide (x <= i)).length <-> l[k] <= i
  | [], _, k, hk, _ => by simp at hk
  | a :: t, sorted, k, hk, i => by
      have rest := List.Pairwise.of_cons sorted
      by_cases ai : a <= i
      · rw [List.filter_cons_of_pos (by simpa using ai), List.length_cons]
        cases k with
        | zero => simp [ai]
        | succ k =>
            simp only [List.getElem_cons_succ]
            have := lt_length_filter_iff rest (k := k) (by simpa using hk) i
            omega
      · rw [List.filter_cons_of_neg (by simpa using ai)]
        have none_ : (t.filter fun x => decide (x <= i)) = [] :=
          List.filter_eq_nil_iff.mpr fun y mem => by
            have := List.rel_of_pairwise_cons sorted mem
            simp only [decide_eq_true_eq]
            omega
        rw [none_]
        cases k with
        | zero => simp [ai]
        | succ k =>
            simp only [List.length_nil, Nat.not_lt_zero, false_iff, List.getElem_cons_succ]
            have := List.rel_of_pairwise_cons sorted (List.getElem_mem (l := t)
              (show k < t.length by simpa using hk))
            omega

/-- What the batch range needs of the view history, from `inv`. -/
structure ViewHyps (v : State) : Prop where
  size : v.ledger.size = v.lastIdx
  sorted : v.views.toList.Pairwise (· <= ·)
  positive : forall x, x ∈ v.views.toList -> 0 < x
  leLast : forall x, x ∈ v.views.toList -> x <= v.lastIdx + 1
  terms
    : forall i,
        1 <= i -> i <= v.lastIdx -> v.ledger[i - 1]?.map (·.term) = some (v.viewAt i)
  posTerms : forall e, e ∈ v.ledger.toList -> 0 < e.term

open Consensus.TraceValidation (Names) in
theorem ViewHyps.ofInv {names : Names} {v : State} (h : inv names v = true)
    : ViewHyps v := by
  obtain ⟨size, _, _, _, terms, _, positive⟩ := Ae.inv_parts h
  have sorted : (v.views.toList.zip v.views.toList.tail).all
      (fun (x, y) => decide (x <= y)) = true := by
    inv_conj h "views_sorted"
  have leLast : v.views.all (· <= v.lastIdx + 1) = true := by inv_conj h "views_le_last"
  have posTerms : v.ledger.all (0 < ·.term) = true := by inv_conj h "positive_terms"
  refine ⟨size, pairwise_of_adjacent sorted, ?_, ?_, terms, ?_⟩
  · intro x mem
    have := Array.all_eq_true_iff_forall_mem.mp positive x (by simpa using mem)
    simpa using this
  · intro x mem
    have := Array.all_eq_true_iff_forall_mem.mp leLast x (by simpa using mem)
    simpa using this
  · intro e mem
    have := Array.all_eq_true_iff_forall_mem.mp posTerms e (by simpa using mem)
    simpa using this

/-- `send_append_entries`'s `max_idx` from `start`. -/
def maxIdx (v : State) (start : Nat) : Nat :=
  match v.endOfView (v.viewAt start) with
  | 0 => v.lastIdx
  | e => e

variable {v : State}

theorem viewAt_ge_iff (h : ViewHyps v) {k : Nat} (hk : k < v.views.size) (i : Nat)
    : k < v.viewAt i <-> v.views[k] <= i := by
  unfold State.viewAt
  have := lt_length_filter_iff h.sorted (k := k) (by simpa using hk) i
  simpa using this

theorem viewAt_pos (h : ViewHyps v) {i : Nat} (i1 : 1 <= i) (iL : i <= v.lastIdx)
    : 0 < v.viewAt i := by
  have t := h.terms i i1 iL
  have lt : i - 1 < v.ledger.size := by rw [h.size]; omega
  rw [Array.getElem?_eq_getElem lt] at t
  simp only [Option.map_some, Option.some.injEq] at t
  rw [← t]
  exact h.posTerms _ (by simp)

theorem viewAt_past (h : ViewHyps v) : v.viewAt (v.lastIdx + 1) = v.views.size := by
  unfold State.viewAt
  rw [List.filter_eq_self.mpr (fun x mem => by simpa using h.leLast x mem)]
  simp

/-- The range from `start` within the ledger: it ends in the ledger, in the view of `start`. -/
theorem maxIdx_range (h : ViewHyps v) {start : Nat} (s1 : 1 <= start)
    (sL : start <= v.lastIdx)
    : start <= maxIdx v start
      /\ maxIdx v start <= v.lastIdx
      /\ forall i, start <= i -> i <= maxIdx v start -> v.viewAt i = v.viewAt start := by
  have w1 := viewAt_pos h s1 sL
  have wS := ReplUpdateCommit.viewAt_le_size v start
  generalize hw : v.viewAt start = w at w1 wS
  have prevLe : v.views[w - 1] <= start :=
    (viewAt_ge_iff h (k := w - 1) (by omega) start).mp (by omega)
  have prevPos : 0 < v.views[w - 1] := h.positive _ (by simp)
  by_cases last : w < v.views.size
  · have nextGt : start < v.views[w] := by
      have := viewAt_ge_iff h (k := w) last start
      omega
    have nextLe : v.views[w] <= v.lastIdx + 1 := h.leLast _ (by simp)
    have eov : v.endOfView w = v.views[w] - 1 := by
      have ne : Not (v.views[w] = v.views[w - 1]) := by omega
      simp [State.endOfView, State.startOfView, last, Nat.not_lt.mpr (Nat.le_of_lt last),
        Nat.ne_of_gt w1, ne, Nat.succ_le_of_lt last,
        getElem!_pos v.views (w - 1) (by omega), Nat.ne_of_gt prevPos, Nat.not_le.mpr last]
    have mx : maxIdx v start = v.views[w] - 1 := by
      unfold maxIdx
      rw [hw, eov]
      split
      · omega
      · rfl
    rw [mx]
    refine ⟨by omega, by omega, fun i si im => ?_⟩
    have lo := ReplUpdateCommit.viewAt_mono v si
    have hi : Not (w < v.viewAt i) := fun lt => by
      have := (viewAt_ge_iff h last i).mp lt
      omega
    omega
  · have eq : w = v.views.size := by omega
    have eov : v.endOfView w = 0 := by
      simp [State.endOfView, eq]
    have mx : maxIdx v start = v.lastIdx := by
      unfold maxIdx
      rw [hw, eov]
      rfl
    rw [mx]
    refine ⟨sL, Nat.le_refl _, fun i si _ => ?_⟩
    have lo := ReplUpdateCommit.viewAt_mono v si
    have hi := ReplUpdateCommit.viewAt_le_size v i
    omega

/-- From one past the ledger, the range is empty: it ends at the last index. -/
theorem maxIdx_past (h : ViewHyps v) : maxIdx v (v.lastIdx + 1) = v.lastIdx := by
  unfold maxIdx
  rw [viewAt_past h]
  have eov : v.endOfView v.views.size = 0 := by simp [State.endOfView]
  rw [eov]
  rfl

end Consensus.TraceValidation.Proofs.Tick
