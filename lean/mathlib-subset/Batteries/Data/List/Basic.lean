/-
Copyright (c) 2016 Microsoft Corporation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Leonardo de Moura
-/
module

public section
namespace List
/-- Computes the difference of `l₁` and `l₂`, by removing each element in `l₂` from `l₁`. -/
@[expose] protected def diff {α} [BEq α] : List α → List α → List α
  | l, [] => l
  | l₁, a :: l₂ => if l₁.elem a then List.diff (l₁.erase a) l₂ else List.diff l₁ l₂
open Option Nat
/--
Constructs the union of two lists, by inserting the elements of `l₁` in reverse order to `l₂`.
As a result, `l₂` will always be a suffix, but only the last occurrence of each element in `l₁`
will be retained (but order will otherwise be preserved).
-/
@[expose, inline] protected def union [BEq α] (l₁ l₂ : List α) : List α := foldr .insert l₂ l₁

instance [BEq α] : Union (List α) := ⟨List.union⟩
/--
`pwFilter R l` is a maximal sublist of `l` which is `Pairwise R`.
`pwFilter (·≠·)` is the erase duplicates function (cf. `eraseDups`), and `pwFilter (·<·)` finds
a maximal increasing subsequence in `l`. For example,
```
pwFilter (·<·) [0, 1, 5, 2, 6, 3, 4] = [0, 1, 2, 3, 4]
```
-/
@[expose] def pwFilter (R : α → α → Prop) [DecidableRel R] (l : List α) : List α :=
  l.foldr (fun x IH => if ∀ y ∈ IH, R x y then x :: IH else IH) []

