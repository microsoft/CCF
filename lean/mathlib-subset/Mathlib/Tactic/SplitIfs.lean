/-
Copyright (c) 2018 Gabriel Ebner. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Gabriel Ebner, David Renshaw
-/
module

public import Mathlib.Init

/-!
Only the `split_ifs` syntax, which `compareOfLessAndEq_rfl` quotes; the tactic itself is omitted.
-/

public meta section

namespace Mathlib.Tactic

open Lean Elab.Tactic Parser.Tactic Lean.Meta

/-- `split_ifs` splits the main goal in two goals for every if-then-else expression it contains,
by applying excluded middle to the condition. If the goal has the form `g (if p then x else y)`,
`split_ifs` will result in two goals `h✝ : p ⊢ g x` and `h✝ : ¬p ⊢ g y`. If there are multiple
if-then-else expressions, then `split_ifs` will split them all, starting with a top-most one whose
condition does not contain another if-then-else expression.

* `split_ifs with h₁ h₂ h₃` names the introduced hypotheses.
  Note that names are not reused across splits: on a goal of the form
  `⊢ (if p then 1 else 2) + (if q then 3 else 4)`, use `split_ifs with hp hq hq` to name all
  the hypotheses.
* `split_ifs at l` splits the if-then-else expressions at location(s) `l`.
-/
syntax (name := splitIfs) "split_ifs" (location)? (" with" (ppSpace colGt binderIdent)+)? : tactic

end Mathlib.Tactic
