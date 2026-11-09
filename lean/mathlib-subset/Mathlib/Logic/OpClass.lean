/-
Copyright (c) 2014 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public import Mathlib.Init
public section
universe u v
variable {α : Sort u} {β : Sort v}
/-- `LeftCommutative op` where `op : α → β → β` says that `op` is a left-commutative operation,
i.e. `op a₁ (op a₂ b) = op a₂ (op a₁ b)`. -/
class LeftCommutative (op : α → β → β) : Prop where
  /-- A left-commutative operation satisfies `op a₁ (op a₂ b) = op a₂ (op a₁ b)`. -/
  left_comm : (a₁ a₂ : α) → (b : β) → op a₁ (op a₂ b) = op a₂ (op a₁ b)
instance {f : α → α → α} [hc : Std.Commutative f] [ha : Std.Associative f] : LeftCommutative f :=
  ⟨fun a b c ↦ by rw [← ha.assoc, hc.comm a, ha.assoc]⟩
