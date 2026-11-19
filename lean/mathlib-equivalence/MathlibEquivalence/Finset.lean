module

public import CCF.Proofs.Finset
public import Mathlib.Data.Finset.Max
public import Mathlib.Data.Finset.Sort
public import Mathlib.Logic.Equiv.Defs

@[expose] public section

/-!
For a linearly ordered element type, `CCF.Finset` is equivalent to Mathlib's
`Finset`, and the equivalence commutes with every operation that CCF defines.
-/

namespace MathlibEquivalence.Finset

variable {α : Type} [LinearOrder α]

instance : CCF.StrictTotalOrder α :=
  ⟨lt_irrefl, lt_trans, lt_trichotomy⟩

/-- The Mathlib set with the same elements. -/
def toMathlib (s : CCF.Finset α) : _root_.Finset α :=
  ⟨s.val, Multiset.coe_nodup.mpr (s.sorted.imp ne_of_lt)⟩

/-- The CCF set with the same elements. -/
def ofMathlib (s : _root_.Finset α) : CCF.Finset α :=
  ⟨s.sort, (_root_.Finset.sortedLT_sort s).pairwise⟩

@[simp]
theorem mem_toMathlib {a : α} {s : CCF.Finset α} : a ∈ toMathlib s ↔ a ∈ s := by
  simp [toMathlib, CCF.Finset.mem_def]

@[simp]
theorem mem_ofMathlib {a : α} {s : _root_.Finset α} : a ∈ ofMathlib s ↔ a ∈ s := by
  simp [ofMathlib, CCF.Finset.mem_def]

theorem ofMathlib_toMathlib (s : CCF.Finset α) : ofMathlib (toMathlib s) = s :=
  CCF.Finset.ext fun _ => by simp

theorem toMathlib_ofMathlib (s : _root_.Finset α) : toMathlib (ofMathlib s) = s :=
  _root_.Finset.ext fun _ => by simp

/-- `CCF.Finset α` and `Finset α` are equivalent. -/
def equiv : CCF.Finset α ≃ _root_.Finset α where
  toFun := toMathlib
  invFun := ofMathlib
  left_inv := ofMathlib_toMathlib
  right_inv := toMathlib_ofMathlib

theorem toMathlib_empty : toMathlib (∅ : CCF.Finset α) = ∅ :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_singleton (a : α) : toMathlib ({a} : CCF.Finset α) = {a} :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_insert (a : α) (s : CCF.Finset α)
    : toMathlib (insert a s) = insert a (toMathlib s) :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_filter (p : α → Prop) [DecidablePred p] (s : CCF.Finset α)
    : toMathlib (s.filter p) = (toMathlib s).filter p :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_erase (s : CCF.Finset α) (a : α)
    : toMathlib (s.erase a) = (toMathlib s).erase a :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_union (s t : CCF.Finset α)
    : toMathlib (s ∪ t) = toMathlib s ∪ toMathlib t :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_inter (s t : CCF.Finset α)
    : toMathlib (s ∩ t) = toMathlib s ∩ toMathlib t :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_sdiff (s t : CCF.Finset α)
    : toMathlib (s \ t) = toMathlib s \ toMathlib t :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_ofList (l : List α) : toMathlib (CCF.Finset.ofList l) = l.toFinset :=
  _root_.Finset.ext fun _ => by simp

theorem toMathlib_subset {s t : CCF.Finset α} : toMathlib s ⊆ toMathlib t ↔ s ⊆ t := by
  simp [_root_.Finset.subset_iff, CCF.Finset.subset_iff]

theorem toMathlib_nonempty {s : CCF.Finset α} : (toMathlib s).Nonempty ↔ s.Nonempty := by
  simp [_root_.Finset.Nonempty, CCF.Finset.Nonempty]

theorem toMathlib_disjoint {s t : CCF.Finset α}
    : Disjoint (toMathlib s) (toMathlib t) ↔ s.Disjoint t := by
  simp [_root_.Finset.disjoint_left, CCF.Finset.disjoint_left]

theorem card_toMathlib (s : CCF.Finset α) : (toMathlib s).card = s.card := by
  simp [toMathlib, CCF.Finset.card]

theorem sort_toMathlib (s : CCF.Finset α) : (toMathlib s).sort = s.sort :=
  congrArg CCF.Finset.val (ofMathlib_toMathlib s)

theorem min_toMathlib (s : CCF.Finset α) : (toMathlib s).min = s.min?.elim ⊤ (↑) := by
  rcases s with ⟨_ | ⟨x, xs⟩, sorted⟩
  · exact _root_.Finset.min_eq_top.mpr (_root_.Finset.ext fun _ => by simp [toMathlib])
  · have least : ∀ m ∈ toMathlib ⟨x :: xs, sorted⟩, (x : WithTop α) ≤ m := by
      intro m member
      simp only [toMathlib, _root_.Finset.mem_mk, Multiset.mem_coe, List.mem_cons] at member
      rcases member with rfl | later
      · exact le_rfl
      · exact WithTop.coe_le_coe.mpr (le_of_lt ((List.pairwise_cons.mp sorted).1 m later))
    exact le_antisymm
      (_root_.Finset.min_le (by simp [toMathlib]))
      (_root_.Finset.le_min least)

/-- The replaced uses compared `Finset.min` with an element. -/
theorem min_toMathlib_eq_coe {s : CCF.Finset α} {a : α}
    : (toMathlib s).min = a ↔ s.min? = some a := by
  rw [min_toMathlib]
  cases s.min? <;> simp

end MathlibEquivalence.Finset
