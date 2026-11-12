module

@[expose] public section

namespace CCF

/-!
Possibly infinite sequences, covering the part of Mathlib's `Stream'.Seq` that
traces use. A sequence is a function from indices to optional elements which
stays absent once an element is absent.
-/

/-- A finite or infinite sequence. -/
structure Seq (α : Type) where
  /-- Element `n`, or `none` past the end of a finite sequence. -/
  get? : Nat -> Option α
  /-- Once an element is absent, the next one is absent too. -/
  stable : forall {n}, get? n = none -> get? (n + 1) = none

namespace Seq

variable {α β : Type}

/-- The empty sequence. -/
def nil : Seq α :=
  ⟨fun _ => none, fun _ => rfl⟩

/-- Prepend an element. -/
def cons (a : α) (s : Seq α) : Seq α :=
  ⟨
    fun
    | 0 => some a
    | n + 1 => s.get? n,
    fun {n} absent => by
      cases n with
      | zero => cases absent
      | succ n => exact s.stable absent
  ⟩

/-- Apply a function to every element. -/
def map (f : α -> β) (s : Seq α) : Seq β :=
  ⟨
    fun n => (s.get? n).map f,
    fun {n} absent => by
      have : s.get? n = none := Option.map_eq_none_iff.mp absent
      change (s.get? (n + 1)).map f = none
      rw [s.stable this]
      rfl
  ⟩

/-- The finite sequence of a list's elements. -/
def ofList (l : List α) : Seq α :=
  ⟨
    fun n => l[n]?,
    fun {n} absent => by
      simp only [List.getElem?_eq_none_iff] at absent ⊢
      omega
  ⟩

/-- The infinite sequence of a stream's elements. -/
def ofStream (f : Nat -> α) : Seq α :=
  ⟨fun n => some (f n), fun absent => by cases absent⟩

/-- An element is in a sequence when it is present at some index. -/
instance : Membership α (Seq α) :=
  ⟨fun s a => exists n, s.get? n = some a⟩

end Seq

end CCF
