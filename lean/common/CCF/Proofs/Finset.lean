module

public import CCF.Finset

@[expose] public section

namespace CCF

/-! Lemmas about the operations on `CCF.Finset`. -/

namespace Finset

/-- Duplicate-free lists with the same members have the same length. -/
theorem length_eq_of_nodup_of_mem_iff {α : Type} {l₁ l₂ : List α} (nodup₁ : l₁.Nodup)
    (nodup₂ : l₂.Nodup) (same : forall a, a ∈ l₁ <-> a ∈ l₂)
    : l₁.length = l₂.length :=
  Nat.le_antisymm (nodup₁.length_le_of_subset fun a => (same a).mp)
    (nodup₂.length_le_of_subset fun a => (same a).mpr)

variable {α : Type} [LT α]

/-- The sets share no element. -/
def Disjoint (s t : Finset α) : Prop :=
  forall ⦃a⦄, a ∈ s -> a ∉ t

section Sorted

variable [StrictTotalOrder α]

theorem ne_of_lt {a b : α} (lt : a < b) : a ≠ b := by
  intro same
  subst same
  exact StrictTotalOrder.lt_irrefl a lt

/-- Sorted lists have no duplicates. -/
theorem nodup_of_sorted {l : List α} (sorted : l.Pairwise (· < ·)) : l.Nodup :=
  sorted.imp ne_of_lt

/-- Strictly sorted lists with the same members are equal. -/
theorem eq_of_sorted_of_mem_iff
    : forall {l₁ l₂ : List α},
        l₁.Pairwise (· < ·)
        -> l₂.Pairwise (· < ·)
        -> (forall a, a ∈ l₁ <-> a ∈ l₂)
        -> l₁ = l₂
  | [], [], _, _, _ => rfl
  | [], b :: _, _, _, same => nomatch (same b).mpr List.mem_cons_self
  | a :: _, [], _, _, same => nomatch (same a).mp List.mem_cons_self
  | a :: l₁, b :: l₂, sorted₁, sorted₂, same => by
      rw [List.pairwise_cons] at sorted₁ sorted₂
      have head : a = b := by
        rcases List.mem_cons.mp ((same a).mp List.mem_cons_self) with ab | inL₂
        · exact ab
        rcases List.mem_cons.mp ((same b).mpr List.mem_cons_self) with ba | inL₁
        · exact ba.symm
        exact absurd (StrictTotalOrder.lt_trans (sorted₁.1 b inL₁) (sorted₂.1 a inL₂))
          (StrictTotalOrder.lt_irrefl a)
      subst head
      refine congrArg (a :: ·) (eq_of_sorted_of_mem_iff sorted₁.2 sorted₂.2 fun x => ?_)
      constructor
      · intro inL₁
        rcases List.mem_cons.mp ((same x).mp (List.mem_cons_of_mem a inL₁)) with xa | inL₂
        · exact absurd (xa ▸ sorted₁.1 x inL₁) (StrictTotalOrder.lt_irrefl x)
        · exact inL₂
      · intro inL₂
        rcases List.mem_cons.mp ((same x).mpr (List.mem_cons_of_mem a inL₂)) with xa | inL₁
        · exact absurd (xa ▸ sorted₂.1 x inL₂) (StrictTotalOrder.lt_irrefl x)
        · exact inL₁

end Sorted

theorem mem_def {a : α} {s : Finset α} : a ∈ s <-> a ∈ s.val :=
  Iff.rfl

@[ext]
theorem ext [StrictTotalOrder α] {s t : Finset α} (same : forall a, a ∈ s <-> a ∈ t)
    : s = t := by
  obtain ⟨l₁, sorted₁⟩ := s
  obtain ⟨l₂, sorted₂⟩ := t
  cases eq_of_sorted_of_mem_iff sorted₁ sorted₂ same
  rfl

@[simp]
theorem notMem_empty (a : α) : a ∉ (∅ : Finset α) :=
  List.not_mem_nil

@[simp]
theorem mem_singleton {a b : α} : b ∈ ({a} : Finset α) <-> b = a :=
  List.mem_singleton

@[simp]
theorem mem_insert [DecidableLT α] [StrictTotalOrder α] {a b : α} {s : Finset α}
    : b ∈ insert a s <-> b = a \/ b ∈ s :=
  mem_insertSorted

@[simp]
theorem mem_filter {p : α -> Prop} [DecidablePred p] {s : Finset α} {a : α}
    : a ∈ s.filter p <-> a ∈ s /\ p a := by
  simp [filter, mem_def]

@[simp]
theorem mem_erase [DecidableEq α] {a b : α} {s : Finset α}
    : a ∈ s.erase b <-> a ≠ b /\ a ∈ s := by
  simp [erase, And.comm]

@[simp]
theorem mem_union [DecidableLT α] [StrictTotalOrder α] {a : α} {s t : Finset α}
    : a ∈ s ∪ t <-> a ∈ s \/ a ∈ t := by
  change a ∈ t.val.foldr (fun a acc => insert a acc) s <-> a ∈ s \/ a ∈ t.val
  induction t.val with
  | nil => simp
  | cons x xs ih =>
      simp only [List.foldr_cons, mem_insert, ih, List.mem_cons]
      constructor
      · rintro (ax | inS | inXs)
        · exact Or.inr (Or.inl ax)
        · exact Or.inl inS
        · exact Or.inr (Or.inr inXs)
      · rintro (inS | ax | inXs)
        · exact Or.inr (Or.inl inS)
        · exact Or.inl ax
        · exact Or.inr (Or.inr inXs)

@[simp]
theorem mem_inter [DecidableEq α] {a : α} {s t : Finset α}
    : a ∈ s ∩ t <-> a ∈ s /\ a ∈ t :=
  mem_filter

@[simp]
theorem mem_sdiff [DecidableEq α] {a : α} {s t : Finset α}
    : a ∈ s \ t <-> a ∈ s /\ a ∉ t :=
  mem_filter

theorem subset_iff {s t : Finset α} : s ⊆ t <-> forall ⦃a⦄, a ∈ s -> a ∈ t :=
  Iff.rfl

@[simp]
theorem Subset.refl (s : Finset α) : s ⊆ s :=
  fun _ member => member

theorem Subset.trans {s t u : Finset α} (st : s ⊆ t) (tu : t ⊆ u) : s ⊆ u :=
  fun _ member => tu (st member)

theorem inter_subset_left [DecidableEq α] {s t : Finset α} : s ∩ t ⊆ s :=
  fun _ member => (mem_inter.mp member).1

theorem inter_subset_right [DecidableEq α] {s t : Finset α} : s ∩ t ⊆ t :=
  fun _ member => (mem_inter.mp member).2

theorem disjoint_left {s t : Finset α} : Disjoint s t <-> forall ⦃a⦄, a ∈ s -> a ∉ t :=
  Iff.rfl

@[simp]
theorem mem_sort {s : Finset α} {a : α} : a ∈ s.sort <-> a ∈ s :=
  Iff.rfl

theorem min?_mem {s : Finset α} {a : α} (least : s.min? = some a) : a ∈ s :=
  List.mem_of_head? least

theorem min?_isSome {s : Finset α} (nonempty : s.Nonempty) : s.min?.isSome := by
  obtain ⟨a, member⟩ := nonempty
  match s, member with
  | ⟨_ :: _, _⟩, _ => rfl

@[simp]
theorem card_empty : (∅ : Finset α).card = 0 :=
  rfl

theorem card_le_card [StrictTotalOrder α] {s t : Finset α} (subset : s ⊆ t)
    : s.card <= t.card :=
  (nodup_of_sorted s.sorted).length_le_of_subset fun _ member => subset member

theorem card_union_of_disjoint [DecidableLT α] [StrictTotalOrder α] {s t : Finset α}
    (disjoint : Disjoint s t)
    : (s ∪ t).card = s.card + t.card := by
  rw [card, card, card, ← List.length_append]
  apply length_eq_of_nodup_of_mem_iff (nodup_of_sorted (s ∪ t).sorted)
  · exact List.nodup_append.mpr ⟨nodup_of_sorted s.sorted, nodup_of_sorted t.sorted,
      fun a inS b inT same => disjoint inS (same ▸ inT)⟩
  · intro a
    simpa [mem_def] using (mem_union (s := s) (t := t) (a := a))

theorem union_subset [DecidableLT α] [StrictTotalOrder α] {s t u : Finset α}
    (su : s ⊆ u) (tu : t ⊆ u)
    : s ∪ t ⊆ u := by
  intro a member
  rcases mem_union.mp member with inS | inT
  · exact su inS
  · exact tu inT

/-- Two subsets of `s` whose sizes sum to more than `s`'s size intersect. -/
theorem inter_nonempty_of_card_lt_card_add_card [DecidableEq α] [StrictTotalOrder α]
    {s t u : Finset α} (ts : t ⊆ s) (us : u ⊆ s) (larger : s.card < t.card + u.card)
    : (t ∩ u).Nonempty := by
  classical
  apply Decidable.by_contra
  intro empty
  have disjoint : Disjoint t u := fun a inT inU => empty ⟨a, mem_inter.mpr ⟨inT, inU⟩⟩
  have := card_le_card (union_subset ts us)
  rw [card_union_of_disjoint disjoint] at this
  omega

@[simp]
theorem mem_ofList [DecidableLT α] [StrictTotalOrder α] {a : α} {l : List α}
    : a ∈ ofList l <-> a ∈ l := by
  induction l with
  | nil => simp [ofList]
  | cons x xs ih =>
      simp only [ofList, List.foldr_cons, mem_insert, List.mem_cons] at ih ⊢
      rw [ih]

theorem card_ofList_le [DecidableLT α] [StrictTotalOrder α] (l : List α)
    : (ofList l).card <= l.length :=
  (nodup_of_sorted (ofList l).sorted).length_le_of_subset
    fun _ member =>
      mem_ofList.mp member

theorem card_ofList_of_nodup [DecidableLT α] [StrictTotalOrder α] {l : List α}
    (nodup : l.Nodup)
    : (ofList l).card = l.length :=
  length_eq_of_nodup_of_mem_iff (nodup_of_sorted (ofList l).sorted) nodup
    fun _ =>
      mem_ofList

end Finset

end CCF
