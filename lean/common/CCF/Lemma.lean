module

/-!
`lemma` as a synonym for `theorem`, replacing Mathlib's `Mathlib.Tactic.Lemma`.
The models declare existential witness lemmas with it.
-/

public meta section

open Lean

/-- `lemma` means the same as `theorem`. -/
syntax (name := lemmaCommand) declModifiers
  group("lemma " declId ppIndent(declSig) declVal) : command

/-- Expand `lemma` to `theorem`, keeping the modifiers, signature, and body. -/
@[macro lemmaCommand]
def expandLemma : Macro :=
  fun stx =>
    let decl := stx[1]
    let decl :=
      (decl.setArg 0 (mkAtomFrom decl[0] "theorem")).setKind `Lean.Parser.Command.theorem
    pure ((stx.setArg 1 decl).setKind `Lean.Parser.Command.declaration)

end
