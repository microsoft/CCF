module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespSuccessor

@[expose] public section

/-!
# Updating one peer (not reviewed)

`State.setPeer` erases a peer, appends its new record and sorts by node id. On peers
strictly sorted by id (`inv` conjunct `peers_sorted`) that contain the peer, this replaces
the record in place (`setPeer_eq`), so the clean send and match indexes change at the peer
only (`abs_putPeer_matchIndex`, `abs_putPeer_sentIndex`).
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open Consensus.Model.Node
open Consensus.TraceValidation (Names abs agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (absConfig Named named_inj Hyps)

/-- Replace the record of peer `id`. -/
def putPeer (l : List (Exec.NodeId × Peer)) (id : Exec.NodeId) (p : Peer)
    : List (Exec.NodeId × Peer) :=
  l.map fun q => if q.1 = id then (id, p) else q

theorem putPeer_keys (l : List (Exec.NodeId × Peer)) (id : Exec.NodeId) (p : Peer)
    : (putPeer l id p).map Prod.fst = l.map Prod.fst := by
  unfold putPeer
  rw [List.map_map]
  apply List.map_congr_left
  intro q _
  by_cases h : q.1 = id <;> simp [h]

theorem pairwise_inj {β γ : Type} {r : γ -> γ -> Prop} (irrefl : forall x, ¬ r x x)
    {f : β -> γ} {l : List β}
    (sorted : l.Pairwise fun a b => r (f a) (f b)) {a b : β} (ha : a ∈ l) (hb : b ∈ l)
    (e : f a = f b)
    : a = b := by
  induction l with
  | nil => cases ha
  | cons x l ih =>
      cases List.mem_cons.mp ha with
      | inl ha =>
          cases List.mem_cons.mp hb with
          | inl hb => rw [ha, hb]
          | inr hb =>
              have := List.rel_of_pairwise_cons sorted hb
              rw [← ha, e] at this
              exact absurd this (irrefl _)
      | inr ha =>
          cases List.mem_cons.mp hb with
          | inl hb =>
              have := List.rel_of_pairwise_cons sorted ha
              rw [← hb, e] at this
              exact absurd this (irrefl _)
          | inr hb => exact ih (List.Pairwise.of_cons sorted) ha hb

theorem setPeer_perm {l : List (Exec.NodeId × Peer)} {id : Exec.NodeId} {q p : Peer}
    (sorted : l.Pairwise fun a b => a.1 < b.1) (mem : (id, q) ∈ l)
    : List.Perm (l.filter (·.1 != id) ++ [(id, p)]) (putPeer l id p) := by
  obtain ⟨s, t, rfl⟩ := List.append_of_mem mem
  have sorted' := List.pairwise_append.mp sorted
  have notS : forall x, x ∈ s -> x.1 ≠ id := fun x hx e => by
    have := sorted'.2.2 x hx (id, q) List.mem_cons_self
    rw [e] at this
    exact String.lt_irrefl _ this
  have notT : forall x, x ∈ t -> x.1 ≠ id := fun x hx e => by
    have := List.rel_of_pairwise_cons sorted'.2.1 hx
    rw [e] at this
    exact String.lt_irrefl _ this
  have fs : s.filter (·.1 != id) = s := List.filter_eq_self.mpr fun x hx => by
    simpa using notS x hx
  have ft : t.filter (·.1 != id) = t := List.filter_eq_self.mpr fun x hx => by
    simpa using notT x hx
  have ps : putPeer s id p = s := by
    unfold putPeer
    conv => rhs; rw [← List.map_id s]
    apply List.map_congr_left
    intro x hx
    simp [notS x hx]
  have pt : putPeer t id p = t := by
    unfold putPeer
    conv => rhs; rw [← List.map_id t]
    apply List.map_congr_left
    intro x hx
    simp [notT x hx]
  have split : putPeer (s ++ (id, q) :: t) id p = s ++ (id, p) :: t := by
    have : putPeer (s ++ (id, q) :: t) id p
        = putPeer s id p ++ (id, p) :: putPeer t id p := by
      simp [putPeer]
    rw [this, ps, pt]
  rw [split, List.filter_append, List.filter_cons, fs, ft]
  simp only [bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
  exact List.Perm.append_left s (by simp)

theorem putPeer_sorted {l : List (Exec.NodeId × Peer)} {id : Exec.NodeId} {p : Peer}
    {r : Exec.NodeId -> Exec.NodeId -> Prop} (sorted : l.Pairwise fun a b => r a.1 b.1)
    : (putPeer l id p).Pairwise fun a b => r a.1 b.1 := by
  have := putPeer_keys l id p
  have h : (l.map Prod.fst).Pairwise r := List.pairwise_map.mpr sorted
  rw [← this] at h
  exact List.pairwise_map.mp h

theorem setPeer_eq (v : State) {id : Exec.NodeId} {q p : Peer}
    (sorted : v.allOtherNodes.Pairwise fun a b => a.1 < b.1)
    (mem : (id, q) ∈ v.allOtherNodes)
    : v.setPeer id p = { v with allOtherNodes := putPeer v.allOtherNodes id p } := by
  suffices key : (v.allOtherNodes.filter (·.1 != id) ++ [(id, p)]).mergeSort
      (fun a b => decide (a.1 <= b.1)) = putPeer v.allOtherNodes id p by
    simp only [State.setPeer, key]
  apply List.Perm.eq_of_pairwise (le := fun a b => (decide (a.1 <= b.1)) = true)
  · intro a b ha hb ab ba
    have ha' := (List.mergeSort_perm _ _).trans (setPeer_perm (p := p) sorted mem) |>.mem_iff.mp ha
    have e : a.1 = b.1 := String.le_antisymm (by simpa using ab) (by simpa using ba)
    exact pairwise_inj String.lt_irrefl (f := Prod.fst) (putPeer_sorted sorted) ha' hb e
  · exact List.pairwise_mergeSort
      (fun a b c hab hbc => by simp only [decide_eq_true_eq] at *; exact String.le_trans hab hbc)
      (fun a b => by
        rcases String.le_total a.1 b.1 with h | h <;> simp [h])
      _
  · exact (putPeer_sorted sorted).imp fun lt => by
      simp only [decide_eq_true_eq]
      exact String.not_lt.mp (String.lt_asymm lt)
  · exact (List.mergeSort_perm _ _).trans (setPeer_perm sorted mem)

/-- The `peers_sorted` conjunct as a pairwise relation. -/
theorem pairwise_of_zip_tail {α : Type} {r : α -> α -> Prop} [DecidableRel r]
    (trans : forall {a b c}, r a b -> r b c -> r a c)
    : forall (l : List α),
        ((l.zip l.tail).all fun (x : α × α) => decide (r x.1 x.2)) = true -> l.Pairwise r
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true] at h
      have ih := pairwise_of_zip_tail (r := r) trans (b :: t) h.2
      have hab := of_decide_eq_true h.1
      refine List.Pairwise.cons ?_ ih
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact hab
      · exact trans hab (List.rel_of_pairwise_cons ih hx)

theorem find_putPeer_ne (names : Names) {n : NodeID} {id : Exec.NodeId} (p : Peer)
    (ne : n ≠ names.id id)
    : forall (l : List (Exec.NodeId × Peer)),
        (putPeer l id p).find? (fun (i, _) => names.id i == n)
        = l.find? (fun (i, _) => names.id i == n)
  | [] => rfl
  | x :: l => by
      have ih := find_putPeer_ne names p ne l
      unfold putPeer at ih ⊢
      rw [List.map_cons, List.find?_cons, List.find?_cons, ih]
      by_cases hx : x.1 = id
      · have hne : (names.id id == n) = false := by
          simp only [beq_eq_false_iff_ne]; exact fun e => ne e.symm
        have hne' : (names.id x.1 == n) = false := by rw [hx]; exact hne
        obtain ⟨a, b⟩ := x
        simp only at hx hne'
        simp only [hx, ↓reduceIte, hne]
      · simp only [hx, ↓reduceIte]

theorem find_putPeer_eq (names : Names) {id : Exec.NodeId} (p : Peer)
    : forall (l : List (Exec.NodeId × Peer)),
        (forall x, x ∈ l -> names.id x.1 = names.id id -> x.1 = id)
        -> id ∈ l.map Prod.fst
        -> (putPeer l id p).find? (fun (i, _) => names.id i == names.id id) = some (id, p)
  | [], _, mem => by cases mem
  | x :: l, inj, mem => by
      unfold putPeer
      rw [List.map_cons, List.find?_cons]
      by_cases hx : x.1 = id
      · simp [hx]
      · have hne : (names.id x.1 == names.id id) = false := by
          simp only [beq_eq_false_iff_ne]
          exact fun e => hx (inj x List.mem_cons_self e)
        have mem' : id ∈ l.map Prod.fst := by
          rcases List.mem_cons.mp mem with e | m
          · exact absurd e.symm hx
          · exact m
        have := find_putPeer_eq names p l (fun y hy => inj y (List.mem_cons_of_mem _ hy)) mem'
        unfold putPeer at this
        obtain ⟨a, b⟩ := x
        simp only at hx hne
        simp only [hx, ↓reduceIte, hne, this]

/-- After `putPeer`, the clean send and match indexes change at the peer only. -/
theorem abs_putPeer {names : Names} {v w : State} {id : Exec.NodeId} {p : Peer}
    (hw : w.allOtherNodes = putPeer v.allOtherNodes id p)
    (inj : forall x, x ∈ v.allOtherNodes -> names.id x.1 = names.id id -> x.1 = id)
    (mem : id ∈ v.allOtherNodes.map Prod.fst)
    : (abs names w).matchIndex
        = CCF.Function.update (abs names v).matchIndex (names.id id) p.matchIdx
      /\ (abs names w).sentIndex
          = CCF.Function.update (abs names v).sentIndex (names.id id) p.sentIdx := by
  constructor <;> funext n <;> simp only [abs, CCF.Function.update, hw] <;>
    by_cases e : n = names.id id
  all_goals first
    | (subst e; rw [find_putPeer_eq names p _ inj mem]; simp)
    | (rw [find_putPeer_ne names p e]; simp [e])

theorem update_self {α β : Type} [DecidableEq α] (f : α -> β) (a : α)
    : CCF.Function.update f a (f a) = f := by
  funext x
  by_cases e : x = a <;> simp [CCF.Function.update, e]

end Consensus.TraceValidation.Proofs.AeResp
