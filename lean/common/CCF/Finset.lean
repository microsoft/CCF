module

@[expose] public section

namespace CCF

/-!
Finite sets, covering the part of Mathlib's `Finset` that the models use.

A set is stored as a strictly increasing list. Equal sets therefore have equal
representations, so equality is decidable, `Finset.ext` holds, and the kernel
can evaluate set operations on concrete values by reducing list functions.

This module holds the definitions and the sortedness proofs they carry; lemmas
about them are in `CCF.Proofs.Finset`.
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

variable {α : Type} [LT α]

instance : Membership α (Finset α) :=
  ⟨fun s a => a ∈ s.val⟩

instance decidableMem [DecidableEq α] (a : α) (s : Finset α) : Decidable (a ∈ s) :=
  inferInstanceAs (Decidable (a ∈ s.val))

instance [DecidableEq α] : DecidableEq (Finset α)
  | ⟨l₁, _⟩, ⟨l₂, _⟩ =>
      if same : l₁ = l₂ then
        isTrue (by subst same; rfl)
      else
        isFalse fun equal => same (congrArg Finset.val equal)

instance : EmptyCollection (Finset α) :=
  ⟨⟨[], .nil⟩⟩

instance : Singleton α (Finset α) :=
  ⟨fun a => ⟨[a], List.pairwise_singleton _ a⟩⟩

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

/-- The elements satisfying a predicate. -/
def filter (p : α -> Prop) [DecidablePred p] (s : Finset α) : Finset α :=
  ⟨s.val.filter fun a => decide (p a), s.sorted.filter _⟩

/-- Remove an element. -/
def erase [DecidableEq α] (s : Finset α) (a : α) : Finset α :=
  s.filter (· ≠ a)

/-- Every element of either set; inserts the right set's elements into the left set. -/
def union [DecidableLT α] [StrictTotalOrder α] (s t : Finset α) : Finset α :=
  t.val.foldr (fun a acc => insert a acc) s

instance [DecidableLT α] [StrictTotalOrder α] : Union (Finset α) :=
  ⟨union⟩

instance [DecidableEq α] : Inter (Finset α) :=
  ⟨fun s t => s.filter (· ∈ t)⟩

instance [DecidableEq α] : SDiff (Finset α) :=
  ⟨fun s t => s.filter (· ∉ t)⟩

instance : HasSubset (Finset α) :=
  ⟨fun s t => forall ⦃a⦄, a ∈ s -> a ∈ t⟩

instance [DecidableEq α] (s t : Finset α) : Decidable (s ⊆ t) :=
  decidable_of_iff (s.val.all fun a => decide (a ∈ t))
    (by simp only [List.all_eq_true, decide_eq_true_eq]; exact Iff.rfl)

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

/-- The elements in increasing order. -/
def sort (s : Finset α) : List α :=
  s.val

/-- The least element, or `none` for the empty set. -/
def min? (s : Finset α) : Option α :=
  s.val.head?

/-- The number of elements. -/
def card (s : Finset α) : Nat :=
  s.val.length

/-- The set of a list's elements. -/
def ofList [DecidableLT α] [StrictTotalOrder α] (l : List α) : Finset α :=
  l.foldr (fun a acc => insert a acc) ∅

end Finset

end CCF
