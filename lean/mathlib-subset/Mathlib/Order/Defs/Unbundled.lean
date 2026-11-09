/-
Copyright (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Data.Set.Defs

@[expose] public section
/-- `IsTrans X r` means the binary relation `r` on `X` is transitive. -/
class IsTrans (α : Sort*) (r : α → α → Prop) : Prop where
  trans : ∀ a b c, r a b → r b c → r a c
variable {α : Sort*} {r : α → α → Prop}
