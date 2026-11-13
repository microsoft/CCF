-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public meta import Lean.Elab.SyntheticMVars
public meta import Lean.Elab.Binders

@[expose] public section

/-!
# Witnessed claims

`witnessed% forall xs, { pre := p, post := q }` states a safety claim `forall xs, p -> q`
together with the witness `exists xs, p` that it is not vacuous, so that the variables and
hypotheses are written once.
-/

namespace CCF

/-- `safetyStatement` holds and `witnessStatement` shows that it is not vacuous. -/
structure Witnessed (safetyStatement witnessStatement : Prop) : Prop where
  /-- The safety statement holds. -/
  safety : safetyStatement
  /-- The witness statement holds. -/
  witness : witnessStatement

/-- The body of a `witnessed% forall`. -/
structure Witnessed.Spec where
  /-- Assumed by the claim, satisfied by the witness. -/
  pre : Prop
  /-- Concluded by the claim. -/
  post : Prop
  /-- Additionally satisfied by the witness, when given. -/
  witness : Option Prop := none

/-- `witnessed% forall xs, { pre := p, post := q, witness := w }` is
`Witnessed (forall xs, p -> q) (exists xs, p /\ w)`, where `p /\ w` is as it reads without
parentheses: `a /\ b` and `w` give `a /\ b /\ w`.
Without `witness`, the witness statement is `exists xs, p`.

The braces are a `Witnessed.Spec`, and `xs` are explicit binders.
The result is a proposition, so it can follow `forall` and `->`:
`forall c, h c -> witnessed% forall xs, spec` states both for every `c` satisfying `h c`. -/
syntax "witnessed% " term : term

open Lean in
macro_rules
  | `(witnessed% forall $xs* : $type, $spec) =>
    let xs : TSyntaxArray `ident := xs.map (⟨·.raw⟩)
    `(witnessed% forall ($xs* : $type), $spec)

open Lean Elab Term Meta in
elab_rules : term
  | `(witnessed% forall $binders*, $spec) =>
    elabBinders binders fun xs => do
      for x in xs do
        unless (← x.fvarId!.getBinderInfo).isExplicit do
          throwError "expected explicit binders, of the form `(x : T)`"
      let specification ← elabTermEnsuringType spec (mkConst ``Witnessed.Spec)
      synthesizeSyntheticMVarsNoPostponing
      let (``Witnessed.Spec.mk, #[pre, post, extra]) :=
        (← whnf (← instantiateMVars specification)).getAppFnArgs
        | throwErrorAt spec "expected the fields of a `Witnessed.Spec`, in braces"
      let rec andAppend (extra : Expr) : Expr → Expr
        | .app (.app (.const ``And _) left) right => mkAnd left (andAppend extra right)
        | pre => mkAnd pre extra
      let nonvacuous ←
        match (← whnf extra).getAppFnArgs with
        | (``Option.some, #[_, extra]) => pure (andAppend extra pre)
        | (``Option.none, _) => pure pre
        | _ => throwErrorAt spec "expected `witness` to be given or omitted"
      let safety ← mkForallFVars xs (← mkArrow pre post)
      let nonvacuous ←
        xs.foldrM (fun x statement => do mkAppM ``Exists #[← mkLambdaFVars #[x] statement])
          nonvacuous
      return mkApp2 (mkConst ``Witnessed) safety nonvacuous
  | `(witnessed% $body) => throwErrorAt body "expected `forall xs, spec`"

end CCF
