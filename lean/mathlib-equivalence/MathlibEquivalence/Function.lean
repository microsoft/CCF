module

public import CCF.Function
public import Mathlib.Logic.Function.Basic

public section

/-!
`CCF.Function.update` is Mathlib's `Function.update`.
-/

namespace MathlibEquivalence.Function

theorem update_eq {α β : Type} [DecidableEq α] (f : α → β) (a : α) (v : β)
    : CCF.Function.update f a v = Function.update f a v := by
  funext x
  simp [CCF.Function.update_apply, Function.update_apply]

end MathlibEquivalence.Function
