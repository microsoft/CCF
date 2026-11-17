module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplSend

@[expose] public section

/-!
# Peer lists and the name table (not reviewed; `Replicate` obligation)

Peer lookups after `setPeer` (as in the `Tick` proof's `TickPeers`), and the name table's
order: when the table is strictly sorted, `names.id` is strictly monotone on the ids in it,
so a sorted list of node ids maps to the sorted list of their clean ids.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees)
open ReplUpdateCommit (Named named_inj)

/-! ## Peer lists -/

theorem lookup_iff_mem {l : List (NodeId × Peer)} (nd : (l.map Prod.fst).Nodup)
    {k : NodeId} {p : Peer}
    : l.lookup k = some p <-> (k, p) ∈ l := by
  induction l with
  | nil => simp
  | cons q l ih =>
      obtain ⟨k', p'⟩ := q
      simp only [List.map_cons, List.nodup_cons] at nd
      by_cases e : k = k'
      · subst e
        simp only [List.lookup_cons_self, Option.some.injEq, List.mem_cons, Prod.mk.injEq,
          true_and]
        constructor
        · intro h
          exact Or.inl h.symm
        · rintro (h | h)
          · exact h.symm
          · exact absurd (List.mem_map_of_mem (f := Prod.fst) h) nd.1
      · have ne : (k == k') = false := by simpa using e
        simp only [List.lookup_cons, ne, List.mem_cons, Prod.mk.injEq, e, false_and, false_or]
        exact ih nd.2

theorem mem_setPeer {v : State} {id k : NodeId} {p q : Peer}
    : (k, q) ∈ (v.setPeer id p).allOtherNodes
      <-> (k = id /\ q = p) \/ (k ≠ id /\ (k, q) ∈ v.allOtherNodes) := by
  simp only [State.setPeer, List.mem_mergeSort, List.mem_append, List.mem_filter,
    List.mem_singleton, Prod.mk.injEq, bne_iff_ne, ne_eq]
  constructor
  · rintro (⟨m, n⟩ | h)
    · exact Or.inr ⟨n, m⟩
    · exact Or.inl h
  · rintro (h | ⟨n, m⟩)
    · exact Or.inr h
    · exact Or.inl ⟨m, n⟩

theorem setPeer_nodup {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup)
    (id : NodeId) (p : Peer)
    : ((v.setPeer id p).allOtherNodes.map Prod.fst).Nodup := by
  simp only [State.setPeer]
  refine (((List.mergeSort_perm _ _).map Prod.fst).nodup_iff).mpr ?_
  rw [List.map_append, List.nodup_append]
  refine ⟨((List.filter_sublist).map Prod.fst).nodup nd, by simp, ?_⟩
  intro a ha b hb
  simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
  subst hb
  obtain ⟨x, mem, rfl⟩ := List.mem_map.mp ha
  have := (List.mem_filter.mp mem).2
  simpa using this

theorem setPeer_lookup {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup)
    (id k : NodeId) (p : Peer)
    : (v.setPeer id p).peer? k = if k = id then some p else v.peer? k := by
  have nd' := setPeer_nodup nd id p
  unfold State.peer?
  split
  · rename_i e
    rw [lookup_iff_mem nd', mem_setPeer]
    exact Or.inl ⟨e, rfl⟩
  · rename_i e
    apply Option.ext
    intro q
    rw [lookup_iff_mem nd', lookup_iff_mem nd, mem_setPeer]
    constructor
    · rintro (⟨h, -⟩ | ⟨-, h⟩)
      · exact absurd h e
      · exact h
    · intro h
      exact Or.inr ⟨e, h⟩

theorem mem_keys {l : List (NodeId × Peer)} {k : NodeId}
    : k ∈ l.map Prod.fst <-> exists q, (k, q) ∈ l := by
  simp

theorem peer_isSome_iff {v : State} {k : NodeId}
    : (v.peer? k).isSome <-> k ∈ v.allOtherNodes.map Prod.fst := by
  unfold State.peer?
  rw [List.lookup_isSome_iff]
  simp only [beq_iff_eq, List.mem_map]
  constructor
  · rintro ⟨q, mem, rfl⟩
    exact ⟨q, mem, rfl⟩
  · rintro ⟨q, mem, rfl⟩
    exact ⟨q, mem, rfl⟩

theorem setPeer_keys {v : State} {id k : NodeId} {p : Peer}
    : k ∈ (v.setPeer id p).allOtherNodes.map Prod.fst
      <-> k = id \/ k ∈ v.allOtherNodes.map Prod.fst := by
  rw [mem_keys, mem_keys]
  constructor
  · rintro ⟨q, mem⟩
    rcases mem_setPeer.mp mem with ⟨rfl, -⟩ | ⟨-, mem⟩
    · exact Or.inl rfl
    · exact Or.inr ⟨q, mem⟩
  · rintro (rfl | ⟨q, mem⟩)
    · exact ⟨p, mem_setPeer.mpr (Or.inl ⟨rfl, rfl⟩)⟩
    · by_cases e : k = id
      · exact ⟨p, mem_setPeer.mpr (Or.inl ⟨e, rfl⟩)⟩
      · exact ⟨q, mem_setPeer.mpr (Or.inr ⟨e, mem⟩)⟩

/-! ## Clean and abstract peer indexes -/

/-- The clean send index of a peer is its declared one. -/
theorem abs_sentIndex {names : Names} {v : State}
    (peersNamed : forall p, p ∈ v.allOtherNodes -> Named names p.1) {id : NodeId}
    (named : Named names id) {p : Peer} (found : v.peer? id = some p)
    : (abs names v).sentIndex (names.id id) = p.sentIdx := by
  simp only [abs]
  unfold State.peer? at found
  generalize v.allOtherNodes = l at peersNamed found
  induction l with
  | nil => simp at found
  | cons q l ih =>
      obtain ⟨k, pk⟩ := q
      by_cases same : id = k
      · subst same
        simp only [List.lookup_cons, beq_self_eq_true, Option.some.injEq] at found
        subst found
        simp
      · have ne : (names.id k == names.id id) = false := by
          simp only [beq_eq_false_iff_ne]
          intro eq
          exact same (named_inj named (peersNamed (k, pk) (by simp)) eq.symm)
        have ne' : (id == k) = false := by simpa using same
        simp only [List.lookup_cons, ne'] at found
        simp only [List.find?_cons, ne]
        exact ih (fun p mem => peersNamed p (List.mem_cons_of_mem _ mem)) found

/-- A clean state that agrees with `d` is `abs d` but for the peer indexes and votes. -/
theorem agrees_eq {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c
      = {
        abs names d with
          sentIndex := c.sentIndex,
          matchIndex := c.matchIndex,
          votesGranted := c.votesGranted,
          preVotesGranted := c.preVotesGranted
      } := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, -⟩, h6⟩, h7⟩, h8⟩, -⟩, -⟩, h11⟩ := h
  cases c
  simp only at h1 h2 h3 h4 h6 h7 h8 h11 ⊢
  rw [h1, h2, h3, h4, h6, h7, h8, h11]

/-! ## The name table's order -/

/-- The name table is strictly sorted. -/
abbrev SortedNames (names : Names) : Prop :=
  (names.known.toList.zip names.known.toList.tail).all (fun (x, y) => decide (x < y))
  = true

theorem string_pairwise_of_adjacent
    : forall {l : List String},
        (l.zip l.tail).all (fun (x, y) => decide (x < y)) = true -> l.Pairwise (· < ·)
  | [], _ => .nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
        decide_eq_true_eq] at h
      have rest : (b :: t).Pairwise (· < ·) := string_pairwise_of_adjacent (by simpa using h.2)
      refine List.Pairwise.cons ?_ rest
      intro x mem
      rcases List.mem_cons.mp mem with rfl | mem
      · exact h.1
      · exact String.lt_trans h.1 (List.rel_of_pairwise_cons rest mem)

theorem known_index {names : Names} {x : NodeId} (h : names.known.contains x = true)
    : exists (lt : names.id x < names.known.size), names.known[names.id x] = x := by
  have mem : x ∈ names.known := by simpa using h
  obtain ⟨i, hi⟩ : exists i, names.known.findIdx? (· == x) = some i := by
    cases e : names.known.findIdx? (· == x) with
    | some i => exact ⟨i, rfl⟩
    | none =>
        rw [Array.findIdx?_eq_none_iff] at e
        exact absurd (e x mem) (by simp)
  obtain ⟨lt, eq, -⟩ := Array.findIdx?_eq_some_iff_getElem.mp hi
  have idx : names.id x = i := by simp [Names.id, hi]
  subst idx
  exact ⟨lt, by simpa using eq⟩

theorem named_of_known {names : Names} {x : NodeId} (h : names.known.contains x = true)
    : Named names x := by
  obtain ⟨lt, eq⟩ := known_index h
  show names.name (names.id x) = x
  simp [Names.name, lt, eq]

theorem id_lt_id {names : Names} (sorted : SortedNames names) {x y : NodeId}
    (hx : names.known.contains x = true) (hy : names.known.contains y = true) (xy : x < y)
    : names.id x < names.id y := by
  obtain ⟨ltx, ex⟩ := known_index hx
  obtain ⟨lty, ey⟩ := known_index hy
  have pw := string_pairwise_of_adjacent sorted
  rcases Nat.lt_trichotomy (names.id x) (names.id y) with h | h | h
  · exact h
  · have : x = y := by
      rw [← ex, ← ey]
      simp only [h]
    subst this
    exact absurd xy (String.lt_irrefl _)
  · have := List.pairwise_iff_getElem.mp pw (names.id y) (names.id x)
      (by simpa using lty) (by simpa using ltx) h
    simp only [Array.getElem_toList, ex, ey] at this
    exact absurd xy (String.lt_asymm this)

/-- A strictly sorted list of ids in the table maps to a strictly sorted list of clean ids. -/
theorem map_id_sorted {names : Names} (sorted : SortedNames names) {l : List NodeId}
    (hl : l.Pairwise (· < ·)) (known : forall x, x ∈ l -> names.known.contains x = true)
    : (l.map names.id).Pairwise (· < ·) := by
  rw [List.pairwise_map]
  exact hl.imp_of_mem fun ha hb lt => id_lt_id sorted (known _ ha) (known _ hb) lt

/-! ## Sorted, duplicate-free node id lists -/

theorem eraseDups_sublist {α : Type} [BEq α] [LawfulBEq α]
    : forall (n : Nat) (l : List α), l.length <= n -> l.eraseDups.Sublist l
  | _, [], _ => by simp
  | 0, _ :: _, h => by simp at h
  | n + 1, a :: as, h => by
      rw [List.eraseDups_cons]
      refine List.Sublist.cons_cons _ ?_
      refine List.Sublist.trans (eraseDups_sublist n _ ?_) List.filter_sublist
      have := List.length_filter_le (fun b => !b == a) as
      simp only [List.length_cons] at h
      omega

theorem pairwise_lt_of_le {l : List String} (sorted : l.Pairwise (· <= ·)) (nd : l.Nodup)
    : l.Pairwise (· < ·) := by
  refine (sorted.and nd).imp fun ⟨le, ne⟩ => ?_
  refine Classical.byContradiction fun h => ne ?_
  exact String.le_antisymm le (String.not_lt.mp h)

/-- `mergeSort` then `eraseDups`: strictly sorted, with the same members. -/
theorem sortDedup_spec (l : List NodeId)
    : ((l.mergeSort (· <= ·)).eraseDups).Pairwise (· < ·)
      /\ forall x, x ∈ (l.mergeSort (· <= ·)).eraseDups <-> x ∈ l := by
  refine ⟨?_, fun x => by rw [List.mem_eraseDups, List.mem_mergeSort]⟩
  have sorted : (l.mergeSort (· <= ·)).Pairwise (fun a b => decide (a <= b) = true) :=
    List.pairwise_mergeSort
      (fun a b c hab hbc => by
        simp only [decide_eq_true_eq] at hab hbc ⊢
        exact String.le_trans hab hbc)
      (fun a b => by
        rcases String.le_total a b with h | h <;> simp [h])
      l
  have sub := eraseDups_sublist _ (l.mergeSort (· <= ·)) (Nat.le_refl _)
  refine pairwise_lt_of_le ?_ (ReplUpdateCommit.nodup_eraseDups _ _ (Nat.le_refl _))
  exact (sorted.sublist sub).imp fun h => by simpa using h

end Consensus.TraceValidation.Proofs.Repl
