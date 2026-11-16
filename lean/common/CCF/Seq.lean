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

@[simp]
theorem get?_nil (n : Nat) : (nil : Seq α).get? n = none :=
  rfl

@[simp]
theorem get?_cons_zero (a : α) (s : Seq α) : (cons a s).get? 0 = some a :=
  rfl

@[simp]
theorem get?_cons_succ (a : α) (s : Seq α) (n : Nat)
    : (cons a s).get? (n + 1) = s.get? n :=
  rfl

@[simp]
theorem map_get? (f : α -> β) (s : Seq α) (n : Nat)
    : (s.map f).get? n = (s.get? n).map f :=
  rfl

@[simp]
theorem ofList_get? (l : List α) (n : Nat) : (ofList l).get? n = l[n]? :=
  rfl

@[simp]
theorem ofStream_get? (f : Nat -> α) (n : Nat) : (ofStream f).get? n = some (f n) :=
  rfl

/-- Membership is presence at some index. -/
theorem mem_iff_exists_get? {a : α} {s : Seq α} : a ∈ s <-> exists n, some a = s.get? n :=
  ⟨fun ⟨n, found⟩ => ⟨n, found.symm⟩, fun ⟨n, found⟩ => ⟨n, found.symm⟩⟩

/-- An element present at an index is a member. -/
theorem get?_mem {s : Seq α} {n : Nat} {a : α} (found : s.get? n = some a) : a ∈ s :=
  ⟨n, found⟩

/-- Once an element is absent, every later element is absent. -/
theorem le_stable (s : Seq α) {m n : Nat} (le : m <= n) (absent : s.get? m = none)
    : s.get? n = none := by
  induction le with
  | refl => exact absent
  | step _ ih => exact s.stable ih

end Seq

end CCF
