module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickVotes

@[expose] public section

/-!
# Vote-request order (not reviewed; `Tick` obligation)

M_tv asks `otherNodesInActiveConfigs` in string order; the clean model asks the sorted clean
ids. They coincide because the name table is sorted and holds every member.
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)

/-- A list whose adjacent elements are related by a transitive relation is sorted by it. -/
theorem pairwise_of_adjacent' {α : Type} {R : α -> α -> Prop} [DecidableRel R]
    (trans : forall {a b c : α}, R a b -> R b c -> R a c)
    : forall {l : List α},
        (l.zip l.tail).all (fun (x, y) => decide (R x y)) = true -> l.Pairwise R
  | [], _ => .nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: t, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true] at h
      have rest : (b :: t).Pairwise R := pairwise_of_adjacent' (R := R) trans h.2
      have hab : R a b := of_decide_eq_true h.1
      refine List.Pairwise.cons ?_ rest
      intro x mem
      rcases List.mem_cons.mp mem with rfl | mem
      · exact hab
      · exact trans hab (List.rel_of_pairwise_cons rest mem)

theorem pairwise_eraseDups {α : Type} [BEq α] [LawfulBEq α] {R : α -> α -> Prop}
    : forall (n : Nat) (l : List α),
        l.length <= n -> l.Pairwise R -> l.eraseDups.Pairwise R
  | _, [], _, _ => by simp
  | 0, _ :: _, h, _ => by simp at h
  | n + 1, a :: as, h, p => by
      rw [List.eraseDups_cons]
      rw [List.pairwise_cons] at p
      refine List.Pairwise.cons (fun x mem => ?_) ?_
      · rw [List.mem_eraseDups, List.mem_filter] at mem
        exact p.1 x mem.1
      · apply pairwise_eraseDups n
        · have := List.length_filter_le (fun b => !b == a) as
          simp only [List.length_cons] at h
          omega
        · exact p.2.filter _

/-- Known ids keep their string order as clean ids. -/
theorem id_lt {names : Names} (sorted : names.known.toList.Pairwise (· < ·))
    {a b : NodeId} (ha : a ∈ names.known) (hb : b ∈ names.known) (lt : a < b)
    : names.id a < names.id b := by
  have find : forall x, x ∈ names.known
      -> exists i, exists h : i < names.known.toList.length,
        names.id x = i /\ names.known.toList[i] = x := by
    intro x mem
    have mem' : x ∈ names.known.toList := Array.mem_toList_iff.mpr mem
    have isSome : (names.known.toList.findIdx? (· == x)).isSome = true := by
      rw [List.findIdx?_isSome, List.any_eq_true]
      exact ⟨x, mem', by simp⟩
    obtain ⟨i, hi⟩ := Option.isSome_iff_exists.mp isSome
    obtain ⟨h, eq, -⟩ := List.findIdx?_eq_some_iff_getElem.mp hi
    refine ⟨i, h, ?_, by simpa using eq⟩
    unfold Names.id
    rw [← Array.toArray_toList (xs := names.known), List.findIdx?_toArray, hi]
    rfl
  obtain ⟨i, hi, ia, eqa⟩ := find a ha
  obtain ⟨j, hj, jb, eqb⟩ := find b hb
  rw [ia, jb]
  rcases Nat.lt_trichotomy i j with ij | ij | ij
  · exact ij
  · subst ij
    rw [eqa] at eqb
    subst eqb
    exact absurd lt (String.lt_irrefl _)
  · have := List.pairwise_iff_getElem.mp sorted j i hj hi ij
    rw [eqa, eqb] at this
    exact absurd (String.lt_trans lt this) (String.lt_irrefl _)

theorem mem_others {v : State} {s : NodeId}
    : s ∈ v.otherNodesInActiveConfigs
      <-> (exists x, x ∈ v.configurations /\ exists a, a ∈ x.nodes /\ a.1 = s)
          /\ s ≠ v.nodeId := by
  simp only [State.otherNodesInActiveConfigs, List.mem_eraseDups, List.mem_mergeSort,
    List.mem_filter, List.mem_flatMap, List.mem_map, bne_iff_ne, ne_eq]

theorem others_sorted {v : State} : v.otherNodesInActiveConfigs.Pairwise (· < ·) := by
  unfold State.otherNodesInActiveConfigs
  have le := List.pairwise_mergeSort (le := fun a b : NodeId => decide (a <= b))
    (fun a b c hab hbc => by
      simp only [decide_eq_true_eq] at hab hbc ⊢
      exact String.le_trans hab hbc)
    (fun a b => by
      simp only [Bool.or_eq_true, decide_eq_true_eq]
      exact String.le_total a b)
    ((v.configurations.flatMap (·.nodes.map Prod.fst)).filter (· != v.nodeId))
  generalize ((v.configurations.flatMap (·.nodes.map Prod.fst)).filter (· != v.nodeId)).mergeSort
    (fun a b => decide (a <= b)) = l at le ⊢
  have p := pairwise_eraseDups (R := fun a b : NodeId => decide (a <= b) = true) l.length l
    (Nat.le_refl _) le
  have nd := ReplUpdateCommit.nodup_eraseDups l.length l (Nat.le_refl _)
  refine (p.and (List.nodup_iff_pairwise_ne.mp nd)).imp fun ⟨h1, h2⟩ => ?_
  simp only [decide_eq_true_eq] at h1
  exact Std.lt_of_le_of_ne h1 h2

/-- The clean ids of the nodes M_tv asks, in its order, are sorted. -/
theorem others_ids_sorted {names : Names} {v : State}
    (sorted : names.known.toList.Pairwise (· < ·))
    (known : forall x, x ∈ v.configurations -> forall a, a ∈ x.nodes -> a.1 ∈ names.known)
    : (v.otherNodesInActiveConfigs.map names.id).Pairwise (· < ·) := by
  rw [List.pairwise_map]
  refine others_sorted.imp_of_mem fun ma mb lt => id_lt sorted ?_ ?_ lt
  · obtain ⟨⟨x, xm, a, am, rfl⟩, -⟩ := mem_others.mp ma
    exact known x xm a am
  · obtain ⟨⟨x, xm, a, am, rfl⟩, -⟩ := mem_others.mp mb
    exact known x xm a am

/-! ## The clean active configurations against the declared ones -/

open ReplUpdateCommit (absConfig Shifted Named named_inj)

theorem mem_configurationMembers_iff {cs : List Configuration} {n : NodeID}
    : n ∈ configurationMembers cs <-> exists x, x ∈ cs /\ n ∈ x.nodes := by
  unfold configurationMembers
  have general : forall (cs : List Configuration) (acc : CCF.Finset NodeID),
      n ∈ cs.foldl (fun nodes configuration => nodes ∪ configuration.nodes) acc
      <-> (n ∈ acc \/ exists x, x ∈ cs /\ n ∈ x.nodes) := by
    intro cs
    induction cs with
    | nil => intro acc; simp
    | cons y ys ih =>
        intro acc
        rw [List.foldl_cons, ih, CCF.Finset.mem_union]
        simp only [List.mem_cons, exists_eq_or_imp]
        constructor
        · rintro ((h | h) | h)
          · exact Or.inl h
          · exact Or.inr (Or.inl h)
          · exact Or.inr (Or.inr h)
        · rintro (h | h | h)
          · exact Or.inl (Or.inl h)
          · exact Or.inl (Or.inr h)
          · exact Or.inr h
  rw [general]
  simp only [CCF.Finset.notMem_empty, false_or]

theorem shifted_mem_rev {ci : Nat} {D E : List Config} (sh : Shifted ci D E) {x : Config}
    (mem : x ∈ D)
    : exists y, y ∈ E /\ y.nodes = x.nodes := by
  rcases sh with rfl | ⟨x', y, rest, rfl, rfl, nodes, _⟩
  · exact ⟨x, mem, rfl⟩
  · rcases List.mem_cons.mp mem with rfl | mem
    · exact ⟨y, List.mem_cons_self, nodes.symm⟩
    · exact ⟨x, List.mem_cons_of_mem _ mem, rfl⟩

theorem shifted_nil {ci : Nat} {D E : List Config} (sh : Shifted ci D E)
    : D = [] <-> E = [] := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, _⟩
  · exact Iff.rfl
  · simp

variable {names : Names}

theorem mem_absConfig {x : Config} {n : NodeID}
    : n ∈ (absConfig names x).nodes <-> exists a, a ∈ x.nodes /\ names.id a.1 = n := by
  simp only [absConfig, Names.set, CCF.Finset.mem_ofList, List.mem_map]
  constructor
  · rintro ⟨s, ⟨a, am, rfl⟩, rfl⟩
    exact ⟨a, am, rfl⟩
  · rintro ⟨a, am, rfl⟩
    exact ⟨a.1, ⟨a, am, rfl⟩, rfl⟩

/-- The clean active members are the declared members' clean ids. -/
theorem active_members_iff {active : List Configuration} {D E : List Config} {ci : Nat}
    (hD : active = D.map (absConfig names)) (sh : Shifted ci D E) {n : NodeID}
    : n ∈ configurationMembers active
      <-> exists y, y ∈ E /\ exists a, a ∈ y.nodes /\ names.id a.1 = n := by
  rw [mem_configurationMembers_iff, hD]
  simp only [List.mem_map]
  constructor
  · rintro ⟨_, ⟨x, xm, rfl⟩, nm⟩
    obtain ⟨y, ym, nodes⟩ := shifted_mem_rev sh xm
    refine ⟨y, ym, ?_⟩
    rw [nodes]
    exact mem_absConfig.mp nm
  · rintro ⟨y, ym, nm⟩
    obtain ⟨x, xm, nodes⟩ := ReplUpdateCommit.shifted_mem sh ym
    refine ⟨absConfig names x, ⟨x, xm, rfl⟩, mem_absConfig.mpr ?_⟩
    rw [nodes]
    exact nm

theorem card_absConfig {x : Config} (named : forall a, a ∈ x.nodes -> Named names a.1)
    (distinct : (x.nodes.map Prod.fst).Nodup)
    : (absConfig names x).nodes.card = x.nodes.length := by
  simp only [absConfig, Names.set]
  rw [CCF.Finset.card_ofList_of_nodup, List.length_map, List.length_map]
  rw [List.Nodup, List.pairwise_map]
  refine distinct.imp_of_mem fun ma mb ne same => ne ?_
  simp only [List.mem_map] at ma mb
  obtain ⟨a, am, rfl⟩ := ma
  obtain ⟨b, bm, rfl⟩ := mb
  exact named_inj (named a am) (named b bm) same

theorem self_mem_absConfig {x : Config} {self : NodeId} (selfNamed : Named names self)
    (named : forall a, a ∈ x.nodes -> Named names a.1)
    : names.id self ∈ (absConfig names x).nodes <-> Lists self x := by
  rw [mem_absConfig]
  simp only [Lists, List.any_eq_true, beq_iff_eq]
  constructor
  · rintro ⟨a, am, same⟩
    exact ⟨a, am, named_inj (named a am) selfNamed same⟩
  · rintro ⟨a, am, rfl⟩
    exact ⟨a, am, rfl⟩

/-- The self-vote is a majority of a configuration iff it is the node alone. -/
theorem majority_self {x : Config} {self : NodeId} (selfNamed : Named names self)
    (named : forall a, a ∈ x.nodes -> Named names a.1)
    (distinct : (x.nodes.map Prod.fst).Nodup)
    : hasConfigurationMajority {names.id self} (absConfig names x)
      <-> Lists self x /\ x.nodes.length <= 1 := by
  unfold hasConfigurationMajority
  rw [card_absConfig named distinct, ← self_mem_absConfig selfNamed named]
  generalize (absConfig names x).nodes = S
  have card : ({names.id self} ∩ S : CCF.Finset NodeID).card
      = if names.id self ∈ S then 1 else 0 := by
    show ([names.id self].filter fun a => decide (a ∈ S)).length = _
    by_cases h : names.id self ∈ S <;> simp [h]
  rw [card]
  by_cases h : names.id self ∈ S
  · rw [ite_eq_left h]
    simp only [h, true_and]
    omega
  · rw [ite_eq_right h]
    simp only [h, false_and, iff_false]
    omega

/-- The clean self-vote wins iff every declared configuration is the node alone. -/
theorem hasQuorum_self {active : List Configuration} {D E : List Config} {ci : Nat}
    (hD : active = D.map (absConfig names)) (sh : Shifted ci D E) {self : NodeId}
    (selfNamed : Named names self)
    (named : forall x, x ∈ E -> forall a, a ∈ x.nodes -> Named names a.1)
    (distinct : forall x, x ∈ E -> (x.nodes.map Prod.fst).Nodup)
    : hasQuorum active {names.id self}
      <-> E ≠ [] /\ forall c, c ∈ E -> Lists self c /\ c.nodes.length <= 1 := by
  subst hD
  unfold hasQuorum
  rw [ne_eq, List.map_eq_nil_iff, shifted_nil sh, List.all_eq_true]
  refine and_congr_right fun _ => ?_
  simp only [List.mem_map, decide_eq_true_eq]
  constructor
  · intro h c cm
    obtain ⟨x, xm, nodes⟩ := ReplUpdateCommit.shifted_mem sh cm
    have := h _ ⟨x, xm, rfl⟩
    have nx : forall a, a ∈ x.nodes -> Named names a.1 := by rw [nodes]; exact named c cm
    have dx : (x.nodes.map Prod.fst).Nodup := by rw [nodes]; exact distinct c cm
    rw [majority_self selfNamed nx dx] at this
    simp only [Lists, nodes] at this
    exact this
  · rintro h _ ⟨x, xm, rfl⟩
    obtain ⟨c, cm, nodes⟩ := shifted_mem_rev sh xm
    have nx : forall a, a ∈ x.nodes -> Named names a.1 := by rw [← nodes]; exact named c cm
    have dx : (x.nodes.map Prod.fst).Nodup := by rw [← nodes]; exact distinct c cm
    rw [majority_self selfNamed nx dx]
    have := h c cm
    simp only [Lists, nodes] at this
    exact this

/-- The self-vote's voters are the node alone. -/
theorem selfVotes_set (cs : List Config) (self : NodeId)
    : names.set
        (self
          :: (cs.map
                fun c =>
                  (
                    c.idx,
                    if Lists self c then [self] else [],
                    State.quorum c.nodes.length
                  )).flatMap
              fun (_, vs, _) => vs)
      = {names.id self} := by
  apply CCF.Finset.ext
  intro n
  simp only [Names.set, CCF.Finset.mem_ofList, CCF.Finset.mem_singleton, List.map_cons,
    List.mem_cons, List.mem_map, List.mem_flatMap]
  constructor
  · rintro (h | ⟨s, ⟨_, ⟨c, _, rfl⟩, sm⟩, rfl⟩)
    · exact h
    · by_cases P : Lists self c <;> simp_all
  · exact Or.inl

end Consensus.TraceValidation.Proofs.Tick
