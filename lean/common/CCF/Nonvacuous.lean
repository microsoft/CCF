-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public meta import Lean.Elab.SyntheticMVars

public section

/-!
# Non-vacuity statements

`nonvacuous% foo` states that the hypotheses of the theorem `foo` can be satisfied, so that a
witness lemma need not repeat the variables and hypotheses of the theorem it witnesses.
-/

namespace CCF

/-- `nonvacuous% foo /\ extra` is `exists xs, pre /\ extra` when
`foo : forall xs, pre -> post`: the name `foo` stands for the hypotheses of `foo`.
`nonvacuous% foo` is `exists xs, pre`.

`nonvacuous% foo a /\ extra` fixes the leading variable of `foo` to `a`, and binds the rest:
`forall a, nonvacuous% foo a` is `forall a, exists ys, pre`.
Each argument fills the next leading explicit variable; hypotheses cannot be filled.

`xs` are the leading variables of `foo` and are in scope in `extra` under the names `foo` gave
them.
`pre` is every hypothesis of `foo`: `foo : forall xs, a -> b -> post` gives `a /\ b`.
Every variable of `foo` must come before its hypotheses, and `post` must not bind more. -/
syntax "nonvacuous% " term : term

open Lean Elab Term Meta in
elab_rules : term
  | `(nonvacuous% $statement) => do
    let (claim, arguments, extra) ←
      match statement with
      | `($claim:ident $arguments* ∧ $extra) => pure (claim, arguments, some extra)
      | `($claim:ident ∧ $extra) => pure (claim, #[], some extra)
      | `($claim:ident $arguments*) => pure (claim, arguments, none)
      | `($claim:ident) => pure (claim, #[], none)
      | _ => throwErrorAt statement "expected a theorem, optionally followed by `/\\ ..`"
    let claimName ← realizeGlobalConstNoOverloadWithInfo claim
    let mut applied ← inferType (← mkConstWithFreshMVarLevels claimName)
    for argument in arguments do
      let .forallE _ domain body .default := applied
        | throwErrorAt argument "{claim} has no explicit variable for this argument"
      unless body.hasLooseBVar 0 && !(← isProp domain) do
        throwErrorAt argument "{claim} has no variable for this argument"
      applied := body.instantiate1 (← elabTermEnsuringType argument domain)
    synthesizeSyntheticMVarsNoPostponing
    let type ← instantiateMVars applied
    -- A variable is a binder that the rest of the statement mentions; a hypothesis is not.
    let rec variableCount : Expr → Nat
      | .forallE _ _ body _ => if body.hasLooseBVar 0 then variableCount body + 1 else 0
      | _ => 0
    let rec hypotheses : Expr → TermElabM (List Expr)
      | .forallE _ pre body _ => do
        if body.hasLooseBVar 0 then
          throwErrorAt claim "{claim} binds a variable after a hypothesis"
        unless ← isProp pre do
          throwErrorAt claim "{claim} binds an unused variable of type {pre}"
        return pre :: (← hypotheses body)
      | _ => pure []
    -- `(a /\ b)` and `c` give `a /\ b /\ c`.
    let rec andAppend (extra : Expr) : Expr → Expr
      | .app (.app (.const ``And _) left) right => mkAnd left (andAppend extra right)
      | pre => mkAnd pre extra
    let rec conjoin : List Expr → Expr
      | [] => mkConst ``True
      | [last] => last
      | pre :: rest => andAppend (conjoin rest) pre
    let outer ← getLCtx
    forallBoundedTelescope type (some (variableCount type)) fun xs body => do
      if extra.isSome then
        for x in xs do
          let name ← x.fvarId!.getUserName
          if (outer.findFromUserName? name).any (!·.isImplementationDetail) then
            throwErrorAt claim "{claim} binds `{name}`, which would hide the outer `{name}`"
      let hypotheses ← hypotheses body
      if hypotheses.isEmpty then
        throwErrorAt claim "{claim} has no hypothesis to witness"
      let extra ← extra.mapM fun extra => do
        let extra ← elabTermEnsuringType extra (mkSort 0)
        synthesizeSyntheticMVarsNoPostponing
        instantiateMVars extra
      xs.foldrM (fun x statement => do mkAppM ``Exists #[← mkLambdaFVars #[x] statement])
        (conjoin (hypotheses ++ extra.toList))

end CCF
