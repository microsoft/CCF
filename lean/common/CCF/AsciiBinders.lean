module

public import Std

/-!
ASCII spellings of Lean's bounded binders, such as `forall x ∈ s, p` and
`exists x ∈ s, p`. Core Lean accepts `forall` and `exists` for plain binders,
but registers bounded binders only for the Unicode tokens.
-/

open Lean in
/-- ASCII spelling of `∀ x ∈ s, p` and other bounded universal binders. -/
syntax "forall " binderIdent binderPred ", " term : term

open Lean in
/-- ASCII spelling of `∃ x ∈ s, p` and other bounded existential binders. -/
syntax "exists " binderIdent binderPred ", " term : term

open Lean in
macro_rules
  | `(forall $x:binderIdent $pred:binderPred, $p) => `(∀ $x:binderIdent $pred:binderPred, $p)
  | `(exists $x:binderIdent $pred:binderPred, $p) => `(∃ $x:binderIdent $pred:binderPred, $p)
