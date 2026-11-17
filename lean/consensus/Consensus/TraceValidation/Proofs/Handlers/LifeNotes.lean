module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation
public import Consensus.TraceValidation.Proofs.Monad

@[expose] public section

/-!
# Handler runs that also track the notes (not reviewed; lifecycle obligations)

`TriN env P x Q` is `Life.Tri` with the hold's notes as a third component: a joiner's
release reads its snapshot from them (`snapshotOf`). The rules for primitives are in
strongest-postcondition form, so a straight-line handler is walked by `trin_step` and only
the last `setV` needs its postcondition proved.
-/

namespace Consensus.TraceValidation.Proofs.Life

open Consensus.TraceValidation.Exec

/-- A Hoare triple over handler runs that sees the declared state, outbox and notes. -/
def TriN {α : Type} (env : Env) (P : State -> Outbox -> List Note -> Prop) (x : M α)
    (Q : α -> State -> Outbox -> List Note -> Prop)
    : Prop :=
  forall (c : Ctx) (a : α) (c' : Ctx),
    c.env = env
    -> P c.vars c.outbox c.notes
    -> x.run c = .ok (a, c')
    -> c'.env = env /\ Q a c'.vars c'.outbox c'.notes

/-- `x` leaves the notes alone. -/
def NotesKeep {α : Type} (x : M α) : Prop :=
  forall (c : Ctx) (a : α) (c' : Ctx), x.run c = .ok (a, c') -> c'.notes = c.notes

namespace NotesKeep

theorem bind {α β : Type} {x : M α} {f : α -> M β} (hx : NotesKeep x)
    (hf : forall a, NotesKeep (f a))
    : NotesKeep (x >>= f) := by
  intro c b c'' h
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind] at h
  split at h
  · cases h
  · rename_i r found
    obtain ⟨a, c'⟩ := r
    exact (hf a c' b c'' h).trans (hx c a c' found)

theorem pure {α : Type} (a : α) : NotesKeep (Pure.pure a : M α) := by
  intro c b c' h
  simp only [Pure.pure, StateT.run, StateT.pure, Except.pure, Except.ok.injEq,
    Prod.mk.injEq] at h
  obtain ⟨_, rfl⟩ := h
  rfl

theorem fail {α : Type} (msg : String) : NotesKeep (Exec.fail msg : M α) := by
  intro c a c' h
  simp [Exec.fail, throw, throwThe, MonadExceptOf.throw, StateT.lift, StateT.run,
    Bind.bind, Except.bind] at h

theorem yieldAtPoint : NotesKeep Exec.yieldAtPoint := by
  intro c a c' h
  simp only [Exec.yieldAtPoint] at h
  prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    rfl

theorem trace (fn : String) : NotesKeep (Exec.trace fn) := by
  refine bind yieldAtPoint fun _ => ?_
  intro c a c' h
  prim_cases
  rcases hq : c.queue with _ | ⟨x, rest⟩ <;> simp only [hq] at h <;> prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    rfl

theorem getV : NotesKeep Exec.getV := by
  intro c a c' h
  simp only [Exec.getV] at h
  prim_cases
  obtain ⟨_, rfl⟩ := h
  rfl

theorem setV (f : State -> State) : NotesKeep (Exec.setV f) := by
  refine bind yieldAtPoint fun _ => ?_
  intro c a c' h
  simp only [_root_.modify, modifyGet] at h
  prim_cases
  obtain ⟨_, rfl⟩ := h
  rfl

theorem curLoc : NotesKeep Exec.curLoc := by
  intro c a c' h
  simp only [Exec.curLoc] at h
  prim_cases
  rcases hq : c.cur with _ | x <;> simp only [hq] at h <;> prim_cases
  all_goals
    obtain ⟨_, rfl⟩ := h
    rfl

theorem liftE {α : Type} (x : Except String α) : NotesKeep (Exec.liftE x) := by
  unfold Exec.liftE
  split
  · exact pure _
  · exact bind curLoc fun _ => fail _

theorem use (k : String) : NotesKeep (Exec.use k) := by
  intro c a c' h
  simp only [Exec.use] at h
  prim_cases
  generalize c.cur = cur at h
  cases cur with
  | none =>
      simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, Exec.fail, Functor.map,
        Except.map] at h
  | some act =>
      simp only at h
      generalize List.lookup k act.inputs = found at h
      cases found with
      | none =>
          simp [throw, throwThe, MonadExceptOf.throw, StateT.lift, Exec.fail, Functor.map,
            Except.map] at h
      | some j =>
          simp only [StateT.pure] at h
          obtain ⟨_, rfl⟩ := h
          rfl

theorem inNat (k : String) : NotesKeep (Exec.inNat k) :=
  bind (use k) fun _ => liftE _

end NotesKeep

namespace TriN

variable {env : Env} {α β : Type}

theorem bind {x : M α} {f : α -> M β} {P : State -> Outbox -> List Note -> Prop}
    {Q : α -> State -> Outbox -> List Note -> Prop}
    {R : β -> State -> Outbox -> List Note -> Prop}
    (hx : TriN env P x Q) (hf : forall a, TriN env (Q a) (f a) R)
    : TriN env P (x >>= f) R := by
  intro c b c'' e p h
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind] at h
  split at h
  · cases h
  · rename_i r found
    obtain ⟨a, c'⟩ := r
    obtain ⟨e', q⟩ := hx c a c' e p found
    exact hf a c' b c'' e' q h

/-- A primitive that keeps the declared state, outbox and notes. -/
theorem keeps {x : M α} {P : State -> Outbox -> List Note -> Prop} (k : Spec.Keeps env x)
    (n : NotesKeep x)
    : TriN env P x fun _ => P := by
  intro c a c' e p r
  obtain ⟨e', rv, ro⟩ := k c a c' e r
  refine ⟨e', ?_⟩
  rw [rv, ro, n c a c' r]
  exact p

theorem getV {P : State -> Outbox -> List Note -> Prop}
    : TriN env P Exec.getV fun a v o n => P v o n /\ a = v := by
  intro c a c' e p r
  obtain ⟨e', ra, rv, ro⟩ := Spec.getV c a c' e r
  refine ⟨e', ?_⟩
  rw [rv, ro, NotesKeep.getV c a c' r, ra]
  exact ⟨p, rfl⟩

theorem setV {f : State -> State} {P : State -> Outbox -> List Note -> Prop}
    : TriN env P (Exec.setV f) fun _ v o n => exists w, P w o n /\ v = f w := by
  intro c a c' e p r
  obtain ⟨e', rv, ro⟩ := Spec.setV f c a c' e r
  refine ⟨e', c.vars, ?_, rv⟩
  rw [ro, NotesKeep.setV f c a c' r]
  exact p

/-- The last write of a handler: prove the postcondition. -/
theorem setV_last {f : State -> State} {P : State -> Outbox -> List Note -> Prop}
    {Q : Unit -> State -> Outbox -> List Note -> Prop}
    (h : forall v o n, P v o n -> Q () (f v) o n)
    : TriN env P (Exec.setV f) Q := by
  intro c a c' e p r
  obtain ⟨e', rv, ro⟩ := Spec.setV f c a c' e r
  refine ⟨e', ?_⟩
  rw [rv, ro, NotesKeep.setV f c a c' r]
  exact h _ _ _ p

theorem note (nt : Note) {P : State -> Outbox -> List Note -> Prop}
    : TriN env P (Exec.note nt) fun _ v o n => exists m, P v o m /\ n = m ++ [nt] := by
  intro c a c' e p r
  obtain ⟨e', rv, ro⟩ := Spec.note nt c a c' e r
  refine ⟨e', ?_⟩
  simp only [Exec.note, _root_.modify, modifyGet, MonadStateOf.modifyGet, StateT.modifyGet,
    StateT.run] at r
  obtain ⟨_, rfl⟩ := r
  rw [rv, ro]
  exact ⟨c.notes, p, rfl⟩

theorem fail_bind {f : α -> M β} {P : State -> Outbox -> List Note -> Prop}
    {Q : β -> State -> Outbox -> List Note -> Prop} (msg : String)
    : TriN env P (Exec.fail msg >>= f) Q := by
  intro c a c' _ _ r
  simp [Exec.fail, throw, throwThe, MonadExceptOf.throw, StateT.lift, StateT.run,
    Bind.bind, StateT.bind, Except.bind] at r

theorem ite {b : Prop} [Decidable b] {x y : M α}
    {P : State -> Outbox -> List Note -> Prop}
    {Q : α -> State -> Outbox -> List Note -> Prop} (hx : b -> TriN env P x Q)
    (hy : Not b -> TriN env P y Q)
    : TriN env P (if b then x else y) Q := by
  by_cases hb : b
  · simpa [hb] using hx hb
  · simpa [hb] using hy hb

/-- Any run: what `TriN` says holds of a hold's result. -/
theorem run {x : M Unit} {P : State -> Outbox -> List Note -> Prop}
    {Q : Unit -> State -> Outbox -> List Note -> Prop} (t : TriN env P x Q) {vars : State}
    {queue : List Action} {final : Bool} {c : Ctx} (pre : P vars [] [])
    (h : Exec.run env vars queue final x = .ok c)
    : Q () c.vars c.outbox c.notes := by
  unfold Exec.run at h
  split at h
  · rename_i c'' found
    cases h
    exact (t _ _ _ rfl pre found).2
  · cases h

end TriN

/-- One step of a straight-line `TriN` proof: control, then primitives. -/
macro "trin_step" : tactic =>
  `(tactic|
    first
      | with_reducible exact TriN.fail_bind _
      | with_reducible refine TriN.bind (Q := ?_) ?_ (fun _ => ?_)
      | with_reducible refine TriN.ite (fun _ => ?_) (fun _ => ?_)
      | with_reducible exact TriN.keeps (Spec.trace _) (NotesKeep.trace _)
      | with_reducible exact TriN.keeps (Spec.inNat _) (NotesKeep.inNat _)
      | with_reducible exact TriN.keeps Spec.curLoc NotesKeep.curLoc
      | with_reducible exact TriN.getV
      | with_reducible exact TriN.note _
      | with_reducible exact TriN.setV
      | with_reducible refine TriN.setV_last (fun _ _ _ _ => ?_))

end Consensus.TraceValidation.Proofs.Life
