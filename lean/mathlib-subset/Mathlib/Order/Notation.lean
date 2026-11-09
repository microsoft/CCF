/-
Copyright (c) 2017 Johannes Hölzl. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Johannes Hölzl, Yury Kudryashov, Yaël Dillies
-/
module

public import Mathlib.Init

public section

/--
The supremum/join operation: `x ⊔ y`. It is notation for `max x y`
and should be used when the type is not a linear order.
-/
syntax:68 term:68 " ⊔ " term:69 : term

/--
The infimum/meet operation: `x ⊓ y`. It is notation for `min x y`
and should be used when the type is not a linear order.
-/
syntax:69 term:69 " ⊓ " term:70 : term

macro_rules
| `($a ⊔ $b) => `(Max.max $a $b)
| `($a ⊓ $b) => `(Min.min $a $b)

/-- Typeclass for the `⊤` (`\top`) notation -/
@[ext]
class Top (α : Type*) where
  /-- The top (`⊤`, `\top`) element -/
  top : α

/-- The top (`⊤`, `\top`) element -/
notation "⊤" => Top.top

attribute [match_pattern] Top.top
