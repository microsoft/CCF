module

public import CCF.Seq

@[expose] public section

namespace CCF.Seq

variable {α β : Type}

/-- The empty sequence has no elements. -/
@[simp]
theorem get?_nil (n : Nat) : (nil : Seq α).get? n = none :=
  rfl

/-- The first element of a nonempty sequence is its head. -/
@[simp]
theorem get?_cons_zero (a : α) (s : Seq α) : (cons a s).get? 0 = some a :=
  rfl

/-- Later elements of a nonempty sequence come from its tail. -/
@[simp]
theorem get?_cons_succ (a : α) (s : Seq α) (n : Nat)
    : (cons a s).get? (n + 1) = s.get? n :=
  rfl

/-- Mapping a sequence maps each optional element. -/
@[simp]
theorem map_get? (f : α -> β) (s : Seq α) (n : Nat)
    : (s.map f).get? n = (s.get? n).map f :=
  rfl

/-- A finite sequence has the same indexed elements as its list. -/
@[simp]
theorem ofList_get? (l : List α) (n : Nat) : (ofList l).get? n = l[n]? :=
  rfl

/-- A stream supplies an element at every index. -/
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

end CCF.Seq
