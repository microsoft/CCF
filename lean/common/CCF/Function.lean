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

theorem update_apply {α β : Type} [DecidableEq α] (f : α -> β) (a : α) (v : β) (x : α)
    : update f a v x = if x = a then v else f x :=
  rfl

@[simp]
theorem update_self {α β : Type} [DecidableEq α] (a : α) (v : β) (f : α -> β)
    : update f a v a = v := by
  simp [update]

@[simp]
theorem update_of_ne {α β : Type} [DecidableEq α] {a a' : α} (different : a ≠ a') (v : β)
    (f : α -> β)
    : update f a' v a = f a := by
  simp [update, different]

/-- Writing back a function's own value leaves it unchanged. -/
@[simp]
theorem update_eq_self {α β : Type} [DecidableEq α] (a : α) (f : α -> β)
    : update f a (f a) = f := by
  funext x
  by_cases same : x = a <;> simp [update, same]

/-- A second update at the same point overrides the first. -/
@[simp]
theorem update_idem {α β : Type} [DecidableEq α] (a : α) (v w : β) (f : α -> β)
    : update (update f a v) a w = update f a w := by
  funext x
  by_cases same : x = a <;> simp [update, same]

end CCF.Function
