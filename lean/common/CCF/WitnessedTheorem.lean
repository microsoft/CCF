module

public meta import Lean

public section

open Lean Elab Command

/-
leanfmt cannot reliably lay out this custom command and may produce excessive
indentation at call sites. This is a formatter limitation, not meaningful nesting.
Keep this translation straightforward rather than complicating the command to
accommodate the formatter. We still accept its output, without format exclusions.
-/

/-- Declare `forall parameters, P -> Q` and `exists parameters, P` (optionally `P /\ I`). -/
syntax (name := witnessedTheorem)
  (docComment)? "witnessed_theorem " ident
  ppIndent(
    ppLine "for " (ppSpace bracketedExplicitBinders)+
    ppLine "requires " term
    ppLine "ensures " term
    (ppLine "witness_satisfies " term)?
    ppLine "proof" " := " term
    ppLine "witness_proof" " := " term) : command

/-- Elaborate ordinary theorems named `name` and `name_witness` at the same source location. -/
@[command_elab witnessedTheorem]
meta def elabWitnessedTheorem : CommandElab :=
  fun stx => do
    let `(command| $[$doc:docComment]? witnessed_theorem $name:ident
        for $binders:bracketedExplicitBinders*
        requires $pre:term
        ensures $post:term
        $[witness_satisfies $casePredicate:term]?
        proof := $safetyProof:term
        witness_proof := $witnessProof:term) := stx | throwUnsupportedSyntax

    let witnessName := mkIdentFrom name (name.getId.appendAfter "_witness")

    -- The witness condition strengthens only existence, never the universal safety claim.
    -- Without it, retain P itself rather than changing the witness type to P /\ True.
    let witnessBody ←
      match casePredicate with
      | some predicate => `(term| $pre ∧ $predicate)
      | none => pure pre

    -- Exists accepts these standard grouped binders directly, but forall uses a
    -- different binder parser. Expand each group into named universal binders;
    -- build inside-out so their order and dependent-type scopes are preserved.
    let mut safetyType ← `(term| $pre → $post)
    for binder in binders.reverse do
      let `(bracketedExplicitBinders| ($xs:binderIdent* : $type:term)) := binder
      | throwUnsupportedSyntax

      -- The two theorem types are elaborated independently. A placeholder such
      -- as (n : _) could become Int in safety but Nat in the witness, so reject it.
      if let some hole :=
          type.raw.find?
            fun node =>
              node.isOfKind ``Parser.Term.hole
              || node.isOfKind ``Parser.Term.syntheticHole
              || node.isOfKind ``Parser.Level.hole then
        throwErrorAt hole "witnessed_theorem parameter types cannot contain placeholders"

      for x in xs.reverse do
        let `(binderIdent| $x:ident) := x
        | throwErrorAt x "witnessed_theorem parameters must be named"
        safetyType ← `(term| ∀ ($x:ident : $type), $safetyType)

    let witnessType ← `(term| ∃ $binders:bracketedExplicitBinders*, $witnessBody)

    -- Preflight both names before emitting either declaration, so a collision
    -- on the witness does not leave a newly generated safety theorem behind.
    -- Restrict names to the current namespace; ignore macro scopes only when
    -- checking that restriction, retaining hygiene for lookup and elaboration.
    let ns ← getCurrNamespace
    for id in #[name, witnessName] do
      unless id.getId.eraseMacroScopes.isAtomic do
        throwErrorAt id "witnessed_theorem requires a simple declaration name"
      withRef id <| checkNotAlreadyDeclared (ns ++ id.getId)

    -- Ordinary theorem elaboration checks each complete proof and inherits the
    -- enclosing visibility. The author's docstring describes safety; give the
    -- witness its own description rather than copying potentially misleading prose.
    let safetyDecl ←
      `(command|
        $[$doc:docComment]? theorem $name : $safetyType := $safetyProof)
    let witnessDecl ←
      `(command|
        /-- An applicable case for the paired safety theorem. -/
        theorem $witnessName : $witnessType := $witnessProof)

    elabCommand safetyDecl
    elabCommand witnessDecl

    -- Resolve the actual names after elaboration: module-private declarations
    -- have internal names which namespace concatenation would not recover.
    -- Both declarations span this command and select the author's theorem name.
    for id in #[name, witnessName] do
      let declName ← liftCoreM <| realizeGlobalConstNoOverload id
      addDeclarationRangesFromSyntax declName stx name
