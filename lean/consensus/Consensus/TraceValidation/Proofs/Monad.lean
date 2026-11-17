module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Handler

@[expose] public section

/-!
# Reasoning about handler runs (not reviewed)

A handler run (`Exec.run`) threads the declared state, the outbox and the bookkeeping of
the trace points it consumes. `Spec env x P` says: whenever `x` returns `a` from a context
with declared state `v` and outbox `o`, ending with `v'` and `o'`, then `P v o a v' o'`.
The bookkeeping (queue, labels, current action) is forgotten, so a handler's `Spec` is the
relation between declared states and sends that the obligations talk about.

The `Spec` of a handler is built by the `spec` tactic from the rules below: one per monad
primitive and per control construct. Only `look` and the trace-point inputs (`use`) leave
their result unconstrained: they depend on the trace, not on the declared state.

`unfold_run [defs] at h` instead unfolds the monad directly, for handlers small enough to
compute.
-/

set_option linter.unusedSimpArgs false

/-- Unfold the handler monad and its primitives at a hypothesis. -/
syntax "unfold_run" (" [" Lean.Parser.Tactic.simpLemma,* "]")? " at " ident : tactic

macro_rules
  | `(tactic| unfold_run at $h:ident) =>
      `(tactic|
        simp [Consensus.TraceValidation.Exec.run, Consensus.TraceValidation.Exec.trace,
          Consensus.TraceValidation.Exec.yieldAtPoint, Consensus.TraceValidation.Exec.fail,
          Consensus.TraceValidation.Exec.emitStr, Consensus.TraceValidation.Exec.emitNat,
          Consensus.TraceValidation.Exec.emit, Consensus.TraceValidation.Exec.getV,
          Consensus.TraceValidation.Exec.setV, Consensus.TraceValidation.Exec.look,
          Consensus.TraceValidation.Exec.send, Consensus.TraceValidation.Exec.note,
          Consensus.TraceValidation.Exec.names, Consensus.TraceValidation.Exec.use,
          Consensus.TraceValidation.Exec.liftE, Consensus.TraceValidation.Exec.curLoc, bind,
          StateT.bind, StateT.run, get, getThe, MonadStateOf.get, StateT.get, set, StateT.set,
          MonadStateOf.set, modify, modifyGet, MonadStateOf.modifyGet, StateT.modifyGet, pure,
          StateT.pure, Except.pure, throw, throwThe, MonadExceptOf.throw, StateT.lift,
          Except.bind] at $h:ident)
  | `(tactic| unfold_run [$extra,*] at $h:ident) =>
      `(tactic|
        simp [$extra,*, Consensus.TraceValidation.Exec.run, Consensus.TraceValidation.Exec.trace,
          Consensus.TraceValidation.Exec.yieldAtPoint, Consensus.TraceValidation.Exec.fail,
          Consensus.TraceValidation.Exec.emitStr, Consensus.TraceValidation.Exec.emitNat,
          Consensus.TraceValidation.Exec.emit, Consensus.TraceValidation.Exec.getV,
          Consensus.TraceValidation.Exec.setV, Consensus.TraceValidation.Exec.look,
          Consensus.TraceValidation.Exec.send, Consensus.TraceValidation.Exec.note,
          Consensus.TraceValidation.Exec.names, Consensus.TraceValidation.Exec.use,
          Consensus.TraceValidation.Exec.liftE, Consensus.TraceValidation.Exec.curLoc, bind,
          StateT.bind, StateT.run, get, getThe, MonadStateOf.get, StateT.get, set, StateT.set,
          MonadStateOf.set, modify, modifyGet, MonadStateOf.modifyGet, StateT.modifyGet, pure,
          StateT.pure, Except.pure, throw, throwThe, MonadExceptOf.throw, StateT.lift,
          Except.bind] at $h:ident)

namespace Consensus.TraceValidation.Proofs

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- The sends of a hold. -/
abbrev Outbox := List (CCF.Envelope NodeID Message)

/-- What every successful run of `x` does to the declared state and the outbox. -/
def Spec {α : Type} (env : Env) (x : M α)
    (P : State -> Outbox -> α -> State -> Outbox -> Prop)
    : Prop :=
  forall (c : Ctx) (a : α) (c' : Ctx),
    c.env = env
    -> x.run c = .ok (a, c')
    -> c'.env = env /\ P c.vars c.outbox a c'.vars c'.outbox

namespace Spec

variable {env : Env}

theorem run {x : M Unit} {P : State -> Outbox -> Unit -> State -> Outbox -> Prop}
    (spec : Spec env x P) {vars : State} {queue : List Action} {final : Bool} {c : Ctx}
    (h : Exec.run env vars queue final x = .ok c)
    : P vars [] () c.vars c.outbox := by
  unfold Exec.run at h
  split at h
  · rename_i c'' found
    cases h
    exact (spec _ _ _ rfl found).2
  · cases h

theorem pure {α : Type} (a : α)
    : Spec env (Pure.pure a : M α)
        fun v o b v' o' =>
          b = a /\ v' = v /\ o' = o := by
  intro c b c' envOk h
  simp only [Pure.pure, StateT.run, StateT.pure, Except.pure, Except.ok.injEq,
    Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨envOk, rfl, rfl, rfl⟩

theorem bind {α β : Type} {x : M α} {f : α -> M β}
    {P : State -> Outbox -> α -> State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> β -> State -> Outbox -> Prop} (first : Spec env x P)
    (rest : forall a, Spec env (f a) (Q a))
    : Spec env (x >>= f)
        fun v o b v'' o'' =>
          exists a v' o', P v o a v' o' /\ Q a v' o' b v'' o'' := by
  intro c b c'' envOk h
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind] at h
  split at h
  · cases h
  · rename_i r found
    obtain ⟨a, c'⟩ := r
    obtain ⟨envMid, p⟩ := first c a c' envOk found
    obtain ⟨envEnd, q⟩ := rest a c' b c'' envMid h
    exact ⟨envEnd, a, c'.vars, c'.outbox, p, q⟩

theorem ite {α : Type} {b : Prop} [Decidable b] {x y : M α}
    {P Q : State -> Outbox -> α -> State -> Outbox -> Prop}
    (yes : Spec env x P) (no : Spec env y Q)
    : Spec env (if b then x else y)
        fun v o a v' o' =>
          (b -> P v o a v' o') /\ (Not b -> Q v o a v' o') := by
  intro c a c' envOk h
  by_cases holds : b
  · simp only [holds, ite_true] at h
    obtain ⟨envEnd, p⟩ := yes c a c' envOk h
    exact ⟨envEnd, fun _ => p, fun no => absurd holds no⟩
  · simp only [holds, ite_false] at h
    obtain ⟨envEnd, q⟩ := no c a c' envOk h
    exact ⟨envEnd, fun yes => absurd yes holds, fun _ => q⟩

theorem option {α β : Type} {o : Option α} {x : M β} {f : α -> M β}
    {P : State -> Outbox -> β -> State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> β -> State -> Outbox -> Prop}
    (none_ : Spec env x P) (some_ : forall a, Spec env (f a) (Q a))
    : Spec env
        (match o with
          | none => x
          | some a => f a)
        fun v ob r v' ob' =>
          (o = none -> P v ob r v' ob')
          /\ (forall a, o = some a -> Q a v ob r v' ob') := by
  intro c r c' envOk h
  cases o with
  | none =>
      obtain ⟨envEnd, p⟩ := none_ c r c' envOk h
      refine ⟨envEnd, fun _ => p, ?_⟩
      intro _ found
      cases found
  | some a =>
      obtain ⟨envEnd, q⟩ := some_ a c r c' envOk h
      refine ⟨envEnd, ?_, ?_⟩
      · intro found
        cases found
      · intro a' found
        cases found
        exact q

theorem weaken {α : Type} {x : M α}
    {P Q : State -> Outbox -> α -> State -> Outbox -> Prop} (spec : Spec env x P)
    (implies : forall v o a v' o', P v o a v' o' -> Q v o a v' o')
    : Spec env x Q := by
  intro c a c' envOk h
  obtain ⟨envEnd, p⟩ := spec c a c' envOk h
  exact ⟨envEnd, implies _ _ _ _ _ p⟩

theorem throw_ {α : Type} (stop : Stop)
    {P : State -> Outbox -> α -> State -> Outbox -> Prop}
    : Spec env (throw stop : M α) P := by
  intro c a c' _ h
  simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, StateT.run, Bind.bind,
    Except.bind] at h

theorem fail {α : Type} (message : String)
    {P : State -> Outbox -> α -> State -> Outbox -> Prop}
    : Spec env (Exec.fail message : M α) P :=
  throw_ _

theorem list {α β : Type} {l : List α} {x : M β} {f : α -> List α -> M β}
    {P : State -> Outbox -> β -> State -> Outbox -> Prop}
    {Q : α -> List α -> State -> Outbox -> β -> State -> Outbox -> Prop}
    (cons_ : forall a rest, Spec env (f a rest) (Q a rest)) (nil_ : Spec env x P)
    : Spec env
        (match l with
          | a :: rest => f a rest
          | [] => x)
        fun v ob r v' ob' =>
          (l = [] -> P v ob r v' ob')
          /\ (forall a rest, l = a :: rest -> Q a rest v ob r v' ob') := by
  intro c r c' envOk h
  cases l with
  | nil =>
      obtain ⟨envEnd, p⟩ := nil_ c r c' envOk h
      refine ⟨envEnd, fun _ => p, ?_⟩
      intro _ _ found
      cases found
  | cons a rest =>
      obtain ⟨envEnd, q⟩ := cons_ a rest c r c' envOk h
      refine ⟨envEnd, ?_, ?_⟩
      · intro found
        cases found
      · intro a' rest' found
        cases found
        exact q

theorem get
    : Spec env (MonadState.get : M Ctx)
        fun v o a v' o' =>
          a.vars = v /\ a.outbox = o /\ a.env = env /\ v' = v /\ o' = o := by
  intro c a c' envOk h
  simp only [MonadState.get, getThe, MonadStateOf.get, StateT.get, StateT.run, Pure.pure,
    Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨envOk, rfl, rfl, envOk, rfl, rfl⟩

theorem modify_ (f : Ctx -> Ctx) (keepsEnv : forall c, (f c).env = c.env)
    : Spec env (modify f : M Unit)
        fun v o _ v' o' =>
          exists c : Ctx,
            c.vars = v /\ c.outbox = o /\ (f c).vars = v' /\ (f c).outbox = o' := by
  intro c a c' envOk h
  simp only [modify, modifyGet, MonadStateOf.modifyGet, StateT.modifyGet, StateT.run,
    Pure.pure, Except.pure, Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨_, rfl⟩ := h
  exact ⟨(keepsEnv c).trans envOk, c, rfl, rfl, rfl, rfl⟩

/-- Run a primitive on a concrete context: unfold the monad and split its branches. -/
macro "prim_cases" : tactic =>
  `(tactic|
    (try simp only [Bind.bind, StateT.bind, StateT.run, MonadState.get, getThe, MonadStateOf.get,
        StateT.get, MonadStateOf.set, StateT.set, MonadStateOf.modifyGet, StateT.modifyGet,
        Pure.pure, StateT.pure, Except.pure, Function.comp, Except.bind] at *
     repeat' split at *
     all_goals
       first
       | (simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, StateT.bind, Except.bind,
            Bind.bind, Except.pure, StateT.set, StateT.pure, Pure.pure, Exec.fail, Functor.map,
            Except.map] at *; done)
       | (simp only [StateT.set, StateT.pure, Except.ok.injEq, Prod.mk.injEq] at *)
       | skip))

/-- `x` leaves the declared state and the outbox alone. -/
abbrev Keeps {α : Type} (env : Env) (x : M α) : Prop :=
  Spec env x fun v o _ v' o' => v' = v /\ o' = o

theorem Keeps.bind {α β : Type} {x : M α} {f : α -> M β} (hx : Keeps env x)
    (hf : forall a, Keeps env (f a))
    : Keeps env (x >>= f) :=
  weaken (Spec.bind hx hf)
    fun _ _ _ _ _ ⟨_, _, _, ⟨h1, h2⟩, h3, h4⟩ => ⟨h3.trans h1, h4.trans h2⟩

theorem Keeps.pure {α : Type} (a : α) : Keeps env (Pure.pure a : M α) :=
  weaken (Spec.pure a) fun _ _ _ _ _ h => h.2

theorem Keeps.fail {α : Type} (message : String) : Keeps env (Exec.fail message : M α) :=
  Spec.fail message

theorem Keeps.ite {α : Type} {b : Prop} [Decidable b] {x y : M α} (hx : Keeps env x)
    (hy : Keeps env y)
    : Keeps env (if b then x else y) := by
  by_cases hb : b
  · simpa [hb] using hx
  · simpa [hb] using hy

theorem Keeps.get : Keeps env (MonadState.get : M Ctx) :=
  weaken Spec.get fun _ _ _ _ _ h => h.2.2.2

theorem yieldAtPoint : Keeps env Exec.yieldAtPoint := by
  intro c a c' envOk h
  simp only [Exec.yieldAtPoint] at h
  prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩

theorem trace (fn : String) : Keeps env (Exec.trace fn) := by
  refine Keeps.bind yieldAtPoint fun _ => ?_
  intro c a c' envOk h
  prim_cases
  rcases hq : c.queue with _ | ⟨x, rest⟩ <;> simp only [hq] at h <;> prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩

theorem getV : Spec env Exec.getV fun v o a v' o' => a = v /\ v' = v /\ o' = o := by
  intro c a c' envOk h
  simp only [Exec.getV] at h
  prim_cases
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨envOk, rfl, rfl, rfl⟩

theorem setV (f : State -> State)
    : Spec env (Exec.setV f) fun v o _ v' o' => v' = f v /\ o' = o := by
  have rest : Spec env (modify fun c => { c with vars := f c.vars } : M Unit)
      fun v o _ v' o' => v' = f v /\ o' = o := by
    intro c a c' envOk h
    simp only [_root_.modify, modifyGet] at h
    prim_cases
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩
  refine weaken (Spec.bind yieldAtPoint fun _ => rest) ?_
  intro v o _ v' o' ⟨_, _, _, ⟨h1, h2⟩, h3, h4⟩
  subst h1 h2
  exact ⟨h3, h4⟩

theorem emit (k : String) (j : Lean.Json) : Keeps env (Exec.emit k j) := by
  intro c a c' envOk h
  simp only [Exec.emit] at h
  prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩

theorem emitStr (k s : String) : Keeps env (Exec.emitStr k s) := emit _ _

theorem emitNat (k : String) (n : Nat) : Keeps env (Exec.emitNat k n) := emit _ _

theorem look : Keeps env Exec.look := by
  refine Keeps.bind yieldAtPoint fun _ => ?_
  intro c a c' envOk h
  prim_cases
  rcases hq : c.queue with _ | ⟨x, rest⟩ <;> simp only [hq] at h <;> prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩

theorem lookFn : Keeps env Exec.lookFn := by
  refine Keeps.bind look fun _ => ?_
  exact Keeps.pure _

theorem curLoc : Keeps env Exec.curLoc := by
  intro c a c' envOk h
  simp only [Exec.curLoc] at h
  prim_cases
  rcases hq : c.cur with _ | x <;> simp only [hq] at h <;> prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, rfl⟩

theorem liftE {α : Type} (x : Except String α) : Keeps env (Exec.liftE x) := by
  unfold Exec.liftE
  split
  · exact Keeps.pure _
  · exact Keeps.bind curLoc fun _ => Keeps.fail _

theorem use (k : String) : Keeps env (Exec.use k) := by
  intro c a c' envOk h
  simp only [Exec.use] at h
  prim_cases
  generalize c.cur = cur at h
  cases cur with
  | none =>
      simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, Exec.fail, Functor.map, Except.map] at h
  | some act =>
      simp only at h
      generalize List.lookup k act.inputs = found at h
      cases found with
      | none =>
          simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, Exec.fail, Functor.map, Except.map] at h
      | some j =>
          simp only [StateT.pure, Except.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨_, rfl⟩ := h
          exact ⟨envOk, rfl, rfl⟩

theorem inNat (k : String) : Keeps env (Exec.inNat k) :=
  Keeps.bind (use k) fun _ => liftE _

theorem inStr (k : String) : Keeps env (Exec.inStr k) :=
  Keeps.bind (use k) fun _ => liftE _

theorem inBool (k : String) : Keeps env (Exec.inBool k) :=
  Keeps.bind (use k) fun _ => liftE _

theorem note (n : Note) : Keeps env (Exec.note n) := by
  intro c a c' envOk h
  simp only [Exec.note, _root_.modify, modifyGet] at h
  prim_cases
  obtain ⟨_, rfl⟩ := h
  exact ⟨envOk, rfl, rfl⟩

theorem names
    : Spec env Exec.names fun v o a v' o' => a = env.names /\ v' = v /\ o' = o := by
  intro c a c' envOk h
  simp only [Exec.names] at h
  prim_cases
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨envOk, by rw [envOk], rfl, rfl⟩

theorem send (dst : NodeId) (m : Message)
    : Spec env (Exec.send dst m)
        fun v o _ v' o' =>
          v' = v
          /\ o'
              = o ++ [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id dst) m] := by
  intro c a c' envOk h
  simp only [Exec.send, _root_.modify, modifyGet] at h
  prim_cases
  obtain ⟨_, rfl⟩ := h
  subst envOk
  exact ⟨rfl, rfl, rfl⟩

end Spec

end Consensus.TraceValidation.Proofs
