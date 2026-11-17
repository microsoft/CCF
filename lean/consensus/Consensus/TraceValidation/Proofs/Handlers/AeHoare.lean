module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Monad

@[expose] public section

/-!
# Hoare triples over handler runs (not reviewed)

`Hoare env P x Q`: every successful run of `x` from a declared state and outbox satisfying
`P` ends in a state and outbox satisfying `Q` of the result. A thin layer over `Spec` with
the rules the AppendEntries proof needs, including loops (`forIn` over lists).
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

def Hoare {α : Type} (env : Env) (P : State -> Outbox -> Prop) (x : M α)
    (Q : α -> State -> Outbox -> Prop)
    : Prop :=
  forall (c : Ctx) (a : α) (c' : Ctx),
    c.env = env
    -> P c.vars c.outbox
    -> x.run c = .ok (a, c')
    -> c'.env = env /\ Q a c'.vars c'.outbox

namespace Hoare
variable {env : Env}

theorem run {x : M Unit} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (h : Hoare env P x Q) {vars : State}
    {queue : List Action} {final : Bool} {c : Ctx} (hp : P vars [])
    (ran : Exec.run env vars queue final x = .ok c)
    : Q () c.vars c.outbox := by
  unfold Exec.run at ran
  split at ran
  · rename_i c'' found
    cases ran
    exact (h _ _ _ rfl hp found).2
  · cases ran

theorem of_spec {α : Type} {x : M α} {R : State -> Outbox -> α -> State -> Outbox -> Prop}
    (h : Spec env x R) {P : State -> Outbox -> Prop} {Q : α -> State -> Outbox -> Prop}
    (imp : forall v o a v' o', P v o -> R v o a v' o' -> Q a v' o')
    : Hoare env P x Q := by
  intro c a c' envOk p ran
  obtain ⟨e, r⟩ := h c a c' envOk ran
  exact ⟨e, imp _ _ _ _ _ p r⟩

theorem bind {α β : Type} {x : M α} {f : α -> M β} {P : State -> Outbox -> Prop}
    {R : α -> State -> Outbox -> Prop} {Q : β -> State -> Outbox -> Prop}
    (hx : Hoare env P x R) (hf : forall a, Hoare env (R a) (f a) Q)
    : Hoare env P (x >>= f) Q := by
  intro c b c'' envOk p h
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind] at h
  split at h
  · cases h
  · rename_i r found
    obtain ⟨a, c'⟩ := r
    obtain ⟨envMid, q⟩ := hx c a c' envOk p found
    exact hf a c' b c'' envMid q h

theorem pre {α : Type} {x : M α} {P P' : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (h : Hoare env P' x Q)
    (imp : forall v o, P v o -> P' v o)
    : Hoare env P x Q :=
  fun c a c' e p r => h c a c' e (imp _ _ p) r

theorem post {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q Q' : α -> State -> Outbox -> Prop} (h : Hoare env P x Q)
    (imp : forall a v o, Q a v o -> Q' a v o)
    : Hoare env P x Q' :=
  fun c a c' e p r => (h c a c' e p r).imp id (imp _ _ _)

theorem false_pre {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (h : forall v o, Not (P v o))
    : Hoare env P x Q :=
  fun _ _ _ _ p _ => absurd p (h _ _)

/-- Reason from one fixed starting state and outbox. -/
theorem pin {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop}
    (h : forall v0 o0, P v0 o0 -> Hoare env (fun v o => v = v0 /\ o = o0) x Q)
    : Hoare env P x Q :=
  fun c a c' e p r => h c.vars c.outbox p c a c' e ⟨rfl, rfl⟩ r

/-- Move a pure fact out of the precondition. -/
theorem lift {α : Type} {φ : Prop} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (h : φ -> Hoare env P x Q)
    : Hoare env (fun v o => φ /\ P v o) x Q :=
  fun c a c' e p r => h p.1 c a c' e p.2 r

theorem ite {α : Type} {b : Prop} [Decidable b] {x y : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (hx : b -> Hoare env P x Q)
    (hy : Not b -> Hoare env P y Q)
    : Hoare env P (if b then x else y) Q := by
  by_cases hb : b
  · simpa [hb] using hx hb
  · simpa [hb] using hy hb

theorem keeps {α : Type} {x : M α} (h : Spec.Keeps env x) {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (imp : forall v o a, P v o -> Q a v o)
    : Hoare env P x Q :=
  of_spec h
    fun v o a v' o' p e => by
      rw [e.1, e.2]
      exact imp v o a p

theorem pure {α : Type} (a : α) {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (imp : forall v o, P v o -> Q a v o)
    : Hoare env P (Pure.pure a : M α) Q :=
  of_spec (Spec.pure a)
    fun v o b v' o' p e => by
      rw [e.1, e.2.1, e.2.2]
      exact imp v o p

theorem fail {α : Type} (m : String) {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop}
    : Hoare env P (Exec.fail m : M α) Q :=
  of_spec (Spec.fail (P := fun _ _ _ _ _ => False) m) fun _ _ _ _ _ _ f => f.elim

theorem getV {P : State -> Outbox -> Prop} {Q : State -> State -> Outbox -> Prop}
    (imp : forall v o, P v o -> Q v v o)
    : Hoare env P Exec.getV Q :=
  of_spec Spec.getV
    fun v o a v' o' p e => by
      rw [e.1, e.2.1, e.2.2]
      exact imp v o p

theorem getV_bind {β : Type} {k : State -> M β} {P : State -> Outbox -> Prop}
    {Q : β -> State -> Outbox -> Prop}
    (h : forall s, Hoare env (fun v o => P v o /\ v = s) (k s) Q)
    : Hoare env P (Exec.getV >>= k) Q :=
  bind (getV (Q := fun s v o => P v o /\ v = s) fun _ _ p => ⟨p, rfl⟩) h

theorem setV (f : State -> State) {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (imp : forall v o, P v o -> Q () (f v) o)
    : Hoare env P (Exec.setV f) Q :=
  of_spec (Spec.setV f)
    fun v o _ v' o' p e => by
      rw [e.1, e.2]
      exact imp v o p

theorem send (dst : NodeId) (m : Message) {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop}
    (imp
      : forall v o,
          P v o
          -> Q () v (o ++ [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id dst) m]))
    : Hoare env P (Exec.send dst m) Q :=
  of_spec (Spec.send dst m)
    fun v o _ v' o' p e => by
      rw [e.1, e.2]
      exact imp v o p

/-- A loop over a list, with an invariant indexed by the processed prefix. -/
theorem forIn_list {α β : Type} (l : List α) (init : β) (f : α -> β -> M (ForInStep β))
    (I : List α -> β -> State -> Outbox -> Prop) (Q : β -> State -> Outbox -> Prop)
    (step
      : forall pre a rest b,
          l = pre ++ a :: rest
          -> Hoare env (I pre b) (f a b)
              fun r v o =>
                match r with
                | .done b' => Q b' v o
                | .yield b' => I (pre ++ [a]) b' v o)
    (fin : forall b v o, I l b v o -> Q b v o)
    : Hoare env (I [] init) (forIn l init f) Q := by
  suffices h : forall rest pre, l = pre ++ rest -> forall b,
      Hoare env (I pre b) (forIn rest b f) Q from
    h l [] rfl init
  intro rest
  induction rest with
  | nil =>
      intro pre hl b
      simp only [List.append_nil] at hl
      subst hl
      exact pure b fun v o p => fin b v o p
  | cons a rest ih =>
      intro pre hl b
      rw [List.forIn_cons]
      refine bind (step pre a rest b hl) fun r => ?_
      cases r with
      | done b' => exact pure b' fun _ _ q => q
      | yield b' => exact ih (pre ++ [a]) (by simp [hl]) b'

end Hoare

end Consensus.TraceValidation.Proofs.Ae
