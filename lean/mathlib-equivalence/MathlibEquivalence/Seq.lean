module

public import CCF.Proofs.Seq
public import Mathlib.Data.Seq.Basic
public import Mathlib.Logic.Equiv.Defs

@[expose] public section

/-!
`CCF.Seq` is equivalent to Mathlib's `Stream'.Seq`, and the equivalence
commutes with every operation that CCF defines.
-/

namespace MathlibEquivalence.Seq

variable {α β : Type}

/-- The Mathlib sequence with the same elements. -/
def toMathlib (s : CCF.Seq α) : Stream'.Seq α :=
  ⟨s.get?, s.stable⟩

/-- The CCF sequence with the same elements. -/
def ofMathlib (s : Stream'.Seq α) : CCF.Seq α :=
  ⟨s.get?, s.2⟩

/-- `CCF.Seq α` and `Stream'.Seq α` are equivalent. -/
def equiv : CCF.Seq α ≃ Stream'.Seq α where
  toFun := toMathlib
  invFun := ofMathlib
  left_inv _ := rfl
  right_inv _ := rfl

@[simp]
theorem get?_toMathlib (s : CCF.Seq α) (n : Nat) : (toMathlib s).get? n = s.get? n :=
  rfl

theorem toMathlib_nil : toMathlib (CCF.Seq.nil : CCF.Seq α) = Stream'.Seq.nil :=
  Stream'.Seq.ext fun _ => rfl

theorem toMathlib_cons (a : α) (s : CCF.Seq α)
    : toMathlib (CCF.Seq.cons a s) = Stream'.Seq.cons a (toMathlib s) :=
  Stream'.Seq.ext fun n => by cases n <;> rfl

theorem toMathlib_map (f : α → β) (s : CCF.Seq α)
    : toMathlib (s.map f) = Stream'.Seq.map f (toMathlib s) :=
  Stream'.Seq.ext fun n => by simp [Stream'.Seq.map_get?]

theorem toMathlib_ofList (l : List α)
    : toMathlib (CCF.Seq.ofList l) = Stream'.Seq.ofList l :=
  Stream'.Seq.ext fun n => by simp [Stream'.Seq.ofList_get?]

theorem toMathlib_ofStream (f : Nat → α)
    : toMathlib (CCF.Seq.ofStream f) = Stream'.Seq.ofStream f :=
  rfl

theorem mem_toMathlib {a : α} {s : CCF.Seq α} : a ∈ toMathlib s ↔ a ∈ s := by
  rw [Stream'.Seq.mem_iff_exists_get?, CCF.Seq.mem_iff_exists_get?]
  rfl

end MathlibEquivalence.Seq
