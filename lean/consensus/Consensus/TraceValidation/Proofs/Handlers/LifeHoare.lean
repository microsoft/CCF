module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation
public import Consensus.TraceValidation.Proofs.Monad

@[expose] public section

/-!
# Hoare triples over handler runs (not reviewed; lifecycle obligations)

`Tri env P x Q`: every successful run of `x` from a context whose declared state and outbox
satisfy `P` ends in a declared state and outbox satisfying `Q` of its result. `Pres env I x`
is the invariant form `Tri env I x (fun _ => I)`. The rules mirror `Spec`'s, plus loops
(`forIn` over lists) and the reuse of every `Spec`/`Keeps` lemma of
`Consensus.TraceValidation.Proofs.Monad`.
-/

namespace Consensus.TraceValidation.Proofs.Life

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- A Hoare triple over handler runs. -/
def Tri {α : Type} (env : Env) (P : State -> Outbox -> Prop) (x : M α)
    (Q : α -> State -> Outbox -> Prop)
    : Prop :=
  forall (c : Ctx) (a : α) (c' : Ctx),
    c.env = env
    -> P c.vars c.outbox
    -> x.run c = .ok (a, c')
    -> c'.env = env /\ Q a c'.vars c'.outbox

/-- `x` preserves `I`. -/
abbrev Pres {α : Type} (env : Env) (I : State -> Outbox -> Prop) (x : M α) : Prop :=
  Tri env I x fun _ => I

namespace Tri

variable {env : Env} {α β : Type}

theorem ofSpec {x : M α} {S : State -> Outbox -> α -> State -> Outbox -> Prop}
    {P : State -> Outbox -> Prop} {Q : α -> State -> Outbox -> Prop} (s : Spec env x S)
    (h : forall v o a v' o', P v o -> S v o a v' o' -> Q a v' o')
    : Tri env P x Q := by
  intro c a c' e p r
  obtain ⟨e', s'⟩ := s c a c' e r
  exact ⟨e', h _ _ _ _ _ p s'⟩

theorem keeps {x : M α} {P : State -> Outbox -> Prop} (k : Spec.Keeps env x)
    : Tri env P x fun _ => P :=
  ofSpec k fun _ _ _ _ _ p h => by obtain ⟨rfl, rfl⟩ := h; exact p

theorem bind {x : M α} {f : α -> M β} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} {R : β -> State -> Outbox -> Prop}
    (hx : Tri env P x Q) (hf : forall a, Tri env (Q a) (f a) R)
    : Tri env P (x >>= f) R := by
  intro c b c'' e p h
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind] at h
  split at h
  · cases h
  · rename_i r found
    obtain ⟨a, c'⟩ := r
    obtain ⟨e', q⟩ := hx c a c' e p found
    exact hf a c' b c'' e' q h

theorem pure' (a : α) {Q : α -> State -> Outbox -> Prop}
    : Tri env (Q a) (Pure.pure a : M α) Q :=
  ofSpec (Spec.pure a) fun _ _ _ _ _ p h => by obtain ⟨rfl, rfl, rfl⟩ := h; exact p

theorem conseq {x : M α} {P P' : State -> Outbox -> Prop}
    {Q Q' : α -> State -> Outbox -> Prop} (t : Tri env P' x Q')
    (pre : forall v o, P v o -> P' v o) (post : forall a v o, Q' a v o -> Q a v o)
    : Tri env P x Q := by
  intro c a c' e p r
  obtain ⟨e', q⟩ := t c a c' e (pre _ _ p) r
  exact ⟨e', post _ _ _ q⟩

theorem ite {b : Prop} [Decidable b] {x y : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (hx : b -> Tri env P x Q)
    (hy : Not b -> Tri env P y Q)
    : Tri env P (if b then x else y) Q := by
  by_cases hb : b
  · simpa [hb] using hx hb
  · simpa [hb] using hy hb

theorem throw_ {P : State -> Outbox -> Prop} {Q : α -> State -> Outbox -> Prop}
    (stop : Stop)
    : Tri env P (throw stop : M α) Q :=
  ofSpec (Spec.throw_ (P := fun _ _ _ _ _ => False) stop) fun _ _ _ _ _ _ f => f.elim

theorem fail {P : State -> Outbox -> Prop} {Q : α -> State -> Outbox -> Prop}
    (msg : String)
    : Tri env P (Exec.fail msg : M α) Q :=
  throw_ _

theorem preFalse {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (h : forall v o, P v o -> False)
    : Tri env P x Q := by
  intro c a c' _ p _
  exact (h _ _ p).elim

theorem fail_bind {f : α -> M β} {P : State -> Outbox -> Prop}
    {Q : β -> State -> Outbox -> Prop} (msg : String)
    : Tri env P (Exec.fail msg >>= f) Q :=
  bind (Q := fun _ _ _ => False) (fail msg) fun _ => preFalse fun _ _ f => f

theorem getV_bind {f : State -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop}
    (h : forall v, Tri env (fun w o => P w o /\ w = v) (f v) R)
    : Tri env P (Exec.getV >>= f) R :=
  bind
    (ofSpec (Q := fun a w o => P w o /\ w = a) Spec.getV
      fun _ _ _ _ _ p h => by obtain ⟨rfl, rfl, rfl⟩ := h; exact ⟨p, rfl⟩)
    h

theorem setV {f : State -> State} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (h : forall v o, P v o -> Q () (f v) o)
    : Tri env P (Exec.setV f) Q :=
  ofSpec (Spec.setV f) fun _ _ _ _ _ p e => by obtain ⟨rfl, rfl⟩ := e; exact h _ _ p

theorem send {dst : NodeId} {m : Message} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop}
    (h
      : forall v o,
          P v o
          -> Q () v (o ++ [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id dst) m]))
    : Tri env P (Exec.send dst m) Q :=
  ofSpec (Spec.send dst m) fun _ _ _ _ _ p e => by obtain ⟨rfl, rfl⟩ := e; exact h _ _ p

theorem forIn_list {l : List α} {init : β} {f : α -> β -> M (ForInStep β)}
    {I : State -> Outbox -> Prop} (h : forall a b, a ∈ l -> Pres env I (f a b))
    : Pres env I (forIn l init f) := by
  induction l generalizing init with
  | nil =>
      rw [List.forIn_nil]
      exact pure' (Q := fun _ => I) init
  | cons a rest ih =>
      rw [List.forIn_cons]
      refine bind (h a init (List.mem_cons_self ..)) fun r => ?_
      cases r with
      | done b => exact pure' (Q := fun _ => I) b
      | yield b => exact ih (fun a' b' m => h a' b' (List.mem_cons_of_mem _ m))

theorem map {x : M α} {g : α -> β} {P : State -> Outbox -> Prop}
    {Q : β -> State -> Outbox -> Prop} (t : Tri env P x fun a => Q (g a))
    : Tri env P (g <$> x) Q := by
  rw [map_eq_pure_bind]
  exact bind t fun a => pure' (Q := Q) (g a)

theorem discard {x : M α} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (t : Tri env P x fun _ => Q ())
    : Tri env P (Functor.discard x) Q := by
  simp only [Functor.discard]
  exact map t

end Tri

namespace Pres

variable {env : Env} {α β : Type} {I : State -> Outbox -> Prop}

theorem bind {x : M α} {f : α -> M β} (hx : Pres env I x)
    (hf : forall a, Pres env I (f a))
    : Pres env I (x >>= f) :=
  Tri.bind hx hf

theorem pure (a : α) : Pres env I (Pure.pure a : M α) := Tri.pure' (Q := fun _ => I) a

theorem fail (msg : String) : Pres env I (Exec.fail msg : M α) := Tri.fail msg

theorem ite {b : Prop} [Decidable b] {x y : M α} (hx : b -> Pres env I x)
    (hy : Not b -> Pres env I y)
    : Pres env I (if b then x else y) :=
  Tri.ite hx hy

theorem keeps {x : M α} (k : Spec.Keeps env x) : Pres env I x := Tri.keeps k

theorem setV {f : State -> State} (h : forall v o, I v o -> I (f v) o)
    : Pres env I (Exec.setV f) :=
  Tri.setV h

theorem getV_bind {f : State -> M β} (h : forall v o, I v o -> Pres env I (f v))
    : Pres env I (Exec.getV >>= f) :=
  Tri.getV_bind
    fun v =>
      fun c a c' e ⟨p, eq⟩ r => h v c.outbox (eq ▸ p) c a c' e p r

end Pres

/-- One structural step of a `Pres` proof: control first, then primitives. -/
macro "pres_step" : tactic =>
  `(tactic|
    first
      | with_reducible exact Tri.fail_bind _
      | with_reducible refine Pres.bind ?_ (fun _ => ?_)
      | with_reducible refine Pres.ite (fun _ => ?_) (fun _ => ?_)
      | with_reducible refine Tri.forIn_list (fun _ _ _ => ?_)
      | split
      | with_reducible exact Pres.pure _
      | with_reducible exact Pres.fail _
      | with_reducible exact Pres.keeps (Spec.trace _)
      | with_reducible exact Pres.keeps (Spec.emit _ _)
      | with_reducible exact Pres.keeps (Spec.emitStr _ _)
      | with_reducible exact Pres.keeps (Spec.emitNat _ _)
      | with_reducible exact Pres.keeps Spec.look
      | with_reducible exact Pres.keeps Spec.lookFn
      | with_reducible exact Pres.keeps Spec.curLoc
      | with_reducible exact Pres.keeps (Spec.liftE _)
      | with_reducible exact Pres.keeps (Spec.use _)
      | with_reducible exact Pres.keeps (Spec.inNat _)
      | with_reducible exact Pres.keeps (Spec.inStr _)
      | with_reducible exact Pres.keeps (Spec.inBool _)
      | with_reducible exact Pres.keeps (Spec.note _)
      | with_reducible exact Pres.keeps (Spec.weaken Spec.getV fun _ _ _ _ _ h => h.2)
      | with_reducible exact Pres.keeps (Spec.weaken Spec.names fun _ _ _ _ _ h => h.2))

variable {env : Env}

/-- Any run: what `Tri` says holds of a hold's result. -/
theorem Tri.run {x : M Unit} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (t : Tri env P x Q) {vars : State}
    {queue : List Action} {final : Bool} {c : Ctx} (pre : P vars [])
    (h : Exec.run env vars queue final x = .ok c)
    : Q () c.vars c.outbox := by
  unfold Exec.run at h
  split at h
  · rename_i c'' found
    cases h
    exact (t _ _ _ rfl pre found).2
  · cases h

/-- `highest_committable_idx` reads the state and fails or returns. -/
theorem pres_highest {I : State -> Outbox -> Prop} (first : Nat)
    : Pres env I (highestCommittableIdx first) := by
  unfold highestCommittableIdx
  repeat' (first | pres_step | dsimp only)

theorem pres_otherNodesSorted {I : State -> Outbox -> Prop}
    : Pres env I otherNodesSorted := by
  unfold otherNodesSorted
  repeat' pres_step

end Consensus.TraceValidation.Proofs.Life
