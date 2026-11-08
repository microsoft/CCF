module

@[expose] public section

namespace CCF

/-!
Finite sets, covering the part of Mathlib's `Finset` that the models use.

A set is stored as a strictly increasing list. Equal sets therefore have equal
representations, so equality is decidable, `Finset.ext` holds, and the kernel
can evaluate set operations on concrete values by reducing list functions.
-/

/-- A strict total order, enough to store finite sets as sorted lists. -/
class StrictTotalOrder (α : Type) [LT α] : Prop where
  /-- No element is below itself. -/
  lt_irrefl : forall a : α, Not (a < a)
  /-- The order is transitive. -/
  lt_trans : forall {a b c : α}, a < b -> b < c -> a < c
  /-- Any two elements are ordered or equal. -/
  lt_trichotomy : forall a b : α, a < b \/ a = b \/ b < a

instance : StrictTotalOrder Nat :=
  ⟨Nat.lt_irrefl, Nat.lt_trans, Nat.lt_trichotomy⟩

/-- A finite set of elements, stored in increasing order without duplicates. -/
structure Finset (α : Type) [LT α] where
  /-- The elements in increasing order. -/
  val : List α
  /-- The elements are strictly increasing. -/
  sorted : val.Pairwise (· < ·)

namespace Finset

/-- Duplicate-free lists with the same members have the same length. -/
theorem length_eq_of_nodup_of_mem_iff {α : Type} {l₁ l₂ : List α} (nodup₁ : l₁.Nodup)
    (nodup₂ : l₂.Nodup) (same : forall a, a ∈ l₁ <-> a ∈ l₂)
    : l₁.length = l₂.length :=
  Nat.le_antisymm (nodup₁.length_le_of_subset fun a => (same a).mp)
    (nodup₂.length_le_of_subset fun a => (same a).mpr)

variable {α : Type} [LT α]

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

instance : Membership α (Finset α) :=
  ⟨fun s a => a ∈ s.val⟩

theorem mem_def {a : α} {s : Finset α} : a ∈ s <-> a ∈ s.val :=
  Iff.rfl

instance decidableMem [DecidableEq α] (a : α) (s : Finset α) : Decidable (a ∈ s) :=
  inferInstanceAs (Decidable (a ∈ s.val))

instance [DecidableEq α] : DecidableEq (Finset α)
  | ⟨l₁, _⟩, ⟨l₂, _⟩ =>
      if same : l₁ = l₂ then
        isTrue (by subst same; rfl)
      else
        isFalse fun equal => same (congrArg Finset.val equal)

@[ext]
theorem ext [StrictTotalOrder α] {s t : Finset α} (same : forall a, a ∈ s <-> a ∈ t)
    : s = t := by
  obtain ⟨l₁, sorted₁⟩ := s
  obtain ⟨l₂, sorted₂⟩ := t
  cases eq_of_sorted_of_mem_iff sorted₁ sorted₂ same
  rfl

instance : EmptyCollection (Finset α) :=
  ⟨⟨[], .nil⟩⟩

instance : Singleton α (Finset α) :=
  ⟨fun a => ⟨[a], List.pairwise_singleton _ a⟩⟩

@[simp]
theorem notMem_empty (a : α) : a ∉ (∅ : Finset α) :=
  List.not_mem_nil

@[simp]
theorem mem_singleton {a b : α} : b ∈ ({a} : Finset α) <-> b = a :=
  List.mem_singleton

/-- Insert into a strictly increasing list, keeping it strictly increasing. -/
def insertSorted [DecidableLT α] (a : α) : List α -> List α
  | [] => [a]
  | x :: xs =>
      if a < x then
        a :: x :: xs
      else if x < a then
        x :: insertSorted a xs
      else
        x :: xs

theorem mem_insertSorted [DecidableLT α] [StrictTotalOrder α] {a b : α}
    : forall {l : List α}, b ∈ insertSorted a l <-> b = a \/ b ∈ l
  | [] => by simp [insertSorted]
  | x :: xs => by
      unfold insertSorted
      by_cases ax : a < x
      · simp [ax]
      by_cases xa : x < a
      · simp only [ax, xa, ite_false, ite_true, List.mem_cons, mem_insertSorted]
        constructor
        · rintro (bx | ba | inXs)
          · exact Or.inr (Or.inl bx)
          · exact Or.inl ba
          · exact Or.inr (Or.inr inXs)
        · rintro (ba | bx | inXs)
          · exact Or.inr (Or.inl ba)
          · exact Or.inl bx
          · exact Or.inr (Or.inr inXs)
      have same : a = x := by
        rcases StrictTotalOrder.lt_trichotomy a x with lt | eq | gt
        · exact absurd lt ax
        · exact eq
        · exact absurd gt xa
      subst same
      simp [ax]

theorem sorted_insertSorted [DecidableLT α] [StrictTotalOrder α] (a : α)
    : forall {l : List α}, l.Pairwise (· < ·) -> (insertSorted a l).Pairwise (· < ·)
  | [], _ => List.pairwise_singleton _ a
  | x :: xs, sorted => by
      unfold insertSorted
      by_cases ax : a < x
      · simp only [ax, ite_true]
        refine List.Pairwise.cons (fun y member => ?_) sorted
        rcases List.mem_cons.mp member with same | inXs
        · exact same ▸ ax
        · exact StrictTotalOrder.lt_trans ax ((List.pairwise_cons.mp sorted).1 y inXs)
      by_cases xa : x < a
      · simp only [ax, xa, ite_true, ite_false]
        have tail := List.pairwise_cons.mp sorted
        refine List.Pairwise.cons (fun y member => ?_) (sorted_insertSorted a tail.2)
        rcases mem_insertSorted.mp member with same | inXs
        · exact same ▸ xa
        · exact tail.1 y inXs
      · simpa only [ax, xa, ite_false] using sorted

instance [DecidableLT α] [StrictTotalOrder α] : Insert α (Finset α) :=
  ⟨fun a s => ⟨insertSorted a s.val, sorted_insertSorted a s.sorted⟩⟩

@[simp]
theorem mem_insert [DecidableLT α] [StrictTotalOrder α] {a b : α} {s : Finset α}
    : b ∈ insert a s <-> b = a \/ b ∈ s :=
  mem_insertSorted

/-- The elements satisfying a predicate. -/
def filter (p : α -> Prop) [DecidablePred p] (s : Finset α) : Finset α :=
  ⟨s.val.filter fun a => decide (p a), s.sorted.filter _⟩

@[simp]
theorem mem_filter {p : α -> Prop} [DecidablePred p] {s : Finset α} {a : α}
    : a ∈ s.filter p <-> a ∈ s /\ p a := by
  simp [filter, mem_def]

/-- Remove an element. -/
def erase [DecidableEq α] (s : Finset α) (a : α) : Finset α :=
  s.filter (· ≠ a)

@[simp]
theorem mem_erase [DecidableEq α] {a b : α} {s : Finset α}
    : a ∈ s.erase b <-> a ≠ b /\ a ∈ s := by
  simp [erase, And.comm]

/-- Every element of either set; inserts the right set's elements into the left set. -/
def union [DecidableLT α] [StrictTotalOrder α] (s t : Finset α) : Finset α :=
  t.val.foldr (fun a acc => insert a acc) s

instance [DecidableLT α] [StrictTotalOrder α] : Union (Finset α) :=
  ⟨union⟩

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

instance [DecidableEq α] : Inter (Finset α) :=
  ⟨fun s t => s.filter (· ∈ t)⟩

@[simp]
theorem mem_inter [DecidableEq α] {a : α} {s t : Finset α}
    : a ∈ s ∩ t <-> a ∈ s /\ a ∈ t :=
  mem_filter

instance [DecidableEq α] : SDiff (Finset α) :=
  ⟨fun s t => s.filter (· ∉ t)⟩

@[simp]
theorem mem_sdiff [DecidableEq α] {a : α} {s t : Finset α}
    : a ∈ s \ t <-> a ∈ s /\ a ∉ t :=
  mem_filter

instance : HasSubset (Finset α) :=
  ⟨fun s t => forall ⦃a⦄, a ∈ s -> a ∈ t⟩

theorem subset_iff {s t : Finset α} : s ⊆ t <-> forall ⦃a⦄, a ∈ s -> a ∈ t :=
  Iff.rfl

instance [DecidableEq α] (s t : Finset α) : Decidable (s ⊆ t) :=
  decidable_of_iff (s.val.all fun a => decide (a ∈ t)) (by simp [subset_iff, mem_def])

@[simp]
theorem Subset.refl (s : Finset α) : s ⊆ s :=
  fun _ member => member

theorem Subset.trans {s t u : Finset α} (st : s ⊆ t) (tu : t ⊆ u) : s ⊆ u :=
  fun _ member => tu (st member)

theorem inter_subset_left [DecidableEq α] {s t : Finset α} : s ∩ t ⊆ s :=
  fun _ member => (mem_inter.mp member).1

theorem inter_subset_right [DecidableEq α] {s t : Finset α} : s ∩ t ⊆ t :=
  fun _ member => (mem_inter.mp member).2

/-- The set contains an element. -/
def Nonempty (s : Finset α) : Prop :=
  exists a, a ∈ s

instance decidableNonempty (s : Finset α) : Decidable s.Nonempty :=
  match s with
  | ⟨[], _⟩ => isFalse fun ⟨_, member⟩ => nomatch member
  | ⟨a :: _, _⟩ => isTrue ⟨a, List.mem_cons_self⟩

/-- The sets share no element. -/
def Disjoint (s t : Finset α) : Prop :=
  forall ⦃a⦄, a ∈ s -> a ∉ t

theorem disjoint_left {s t : Finset α} : Disjoint s t <-> forall ⦃a⦄, a ∈ s -> a ∉ t :=
  Iff.rfl

/-- The elements in increasing order. -/
def sort (s : Finset α) : List α :=
  s.val

@[simp]
theorem mem_sort {s : Finset α} {a : α} : a ∈ s.sort <-> a ∈ s :=
  Iff.rfl

/-- The least element, or `none` for the empty set. -/
def min? (s : Finset α) : Option α :=
  s.val.head?

theorem min?_mem {s : Finset α} {a : α} (least : s.min? = some a) : a ∈ s :=
  List.mem_of_head? least

theorem min?_isSome {s : Finset α} (nonempty : s.Nonempty) : s.min?.isSome := by
  obtain ⟨a, member⟩ := nonempty
  match s, member with
  | ⟨_ :: _, _⟩, _ => rfl

/-- The number of elements. -/
def card (s : Finset α) : Nat :=
  s.val.length

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

/-- The set of a list's elements. -/
def ofList [DecidableLT α] [StrictTotalOrder α] (l : List α) : Finset α :=
  l.foldr (fun a acc => insert a acc) ∅

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
