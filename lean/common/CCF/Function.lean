module

@[expose] public section

namespace CCF.Function

/-!
Point updates of functions, covering the part of Mathlib's `Function.update`
that the models use.
-/

/-- `f` with the value at `a` replaced by `v`. -/
def update {α β : Type} [DecidableEq α] (f : α -> β) (a : α) (v : β) : α -> β :=
  fun x => if x = a then v else f x

end CCF.Function
