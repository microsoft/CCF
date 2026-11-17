module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickPeers

@[expose] public section

/-!
# A leader's heartbeat (not reviewed; `Tick` obligation)

Every run of the heartbeat's `send_append_entries` calls extends the ghost clean run by one
clean `sendEntries` per `send_append_entries_range`, keeping `HbRel`.
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)
open Life (Tri Pres)

variable {env : Env} {α β : Type}

/-! ## Triple helpers -/

theorem tri_keeps_bind {x : M α} {f : α -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop} (k : Spec.Keeps env x)
    (hf : forall a, Tri env P (f a) R)
    : Tri env P (x >>= f) R :=
  Tri.bind (Tri.keeps k) hf

theorem tri_pres_bind {x : M α} {f : α -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop} (hx : Pres env P x)
    (hf : forall a, Tri env P (f a) R)
    : Tri env P (x >>= f) R :=
  Tri.bind hx hf

/-- Read the declared state, pinning the state and outbox it was read in. -/
theorem tri_getV {f : State -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop}
    (h : forall v o, P v o -> Tri env (fun w o' => w = v /\ o' = o) (f v) R)
    : Tri env P (getV >>= f) R :=
  Tri.getV_bind fun v c a c' e ⟨p, eq⟩ r => h v c.outbox (eq ▸ p) c a c' e ⟨eq, rfl⟩ r

theorem tri_names {f : Names -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop} (h : Tri env P (f env.names) R)
    : Tri env P (Exec.names >>= f) R := by
  refine Tri.bind (Tri.ofSpec (Q := fun a w o => a = env.names /\ P w o) Spec.names
    fun _ _ _ _ _ p s => by obtain ⟨rfl, rfl, rfl⟩ := s; exact ⟨rfl, p⟩) fun a => ?_
  intro c b c' e ⟨ha, p⟩ r
  subst ha
  exact h c b c' e p r

/-! ## One range -/

variable {node : NodeID} {s0 : State} {clean0 : NodeState}

/-- The heartbeat invariant: the outbox is a ghost clean run reaching `HbRel`. -/
abbrev HbAcc (env : Env) (node : NodeID) (s0 : State) (clean0 : NodeState) (v : State)
    (o : Outbox)
    : Prop :=
  Acc env node clean0 (HbRel env.names s0 clean0) v o

theorem HbAcc.shape {v : State} {o : Outbox} (acc : HbAcc env node s0 clean0 v o)
    : exists L,
        v = { s0 with allOtherNodes := L }
        /\ (L.map Prod.fst).Perm (s0.allOtherNodes.map Prod.fst) := by
  obtain ⟨_, _, _, _, _, L, _, hv, _, perm, _⟩ := acc
  exact ⟨L, hv, perm⟩

theorem tri_range (H : HbHyps env.names node s0 clean0) (to : NodeId) (start endIdx : Nat)
    (ext : Bool)
    : Tri env
        (fun v o =>
          HbAcc env node s0 clean0 v o
          /\ exists p,
              v.peer? to = some p
              /\ p.sentIdx + 1 = start
              /\ p.sentIdx <= endIdx
              /\ endIdx <= s0.lastIdx
              /\ forall i, p.sentIdx < i -> i <= endIdx -> s0.viewAt i = s0.viewAt endIdx)
        (sendAppendEntriesRange to start endIdx ext)
        (fun _ v o =>
          HbAcc env node s0 clean0 v o
          /\ exists p, v.peer? to = some p /\ p.sentIdx = endIdx) := by
  unfold sendAppendEntriesRange
  refine tri_getV fun v o ⟨acc, p, found, ps, e1, eL, same⟩ => ?_
  obtain ⟨L, hv, perm⟩ := acc.shape
  have ndv : (v.allOtherNodes.map Prod.fst).Nodup := by
    subst hv
    exact perm.nodup_iff.mpr H.nodup
  have self : env.names.id v.nodeId = node := by
    subst hv
    exact H.self
  subst ps
  simp only [found]
  refine tri_keeps_bind (Spec.emit _ _) fun _ => ?_
  refine tri_keeps_bind (Spec.emitStr _ _) fun _ => ?_
  refine tri_names ?_
  refine Tri.bind
    (Tri.send
      (Q :=
        fun _ w o' =>
          w = v
          /\ o'
              = o
                ++ [⟨
                      node,
                      env.names.id to,
                      .appendEntriesRequest (aeOf env.names v (p.sentIdx + 1) endIdx)
                    ⟩])
      fun w o' ⟨hw, ho⟩ => ⟨hw, by subst hw ho; rw [self]; rfl⟩)
    fun _ => ?_
  refine tri_keeps_bind (Spec.note _) fun _ => ?_
  refine Tri.setV fun w o' ⟨hw, ho⟩ => ?_
  subst hw ho
  obtain ⟨_, _, _, _, _, r⟩ := id acc
  have step := hb_step H r found e1 eL same
  refine ⟨Acc.extend acc (fun clean r => ?_) ?_, ?_⟩
  · obtain ⟨em, rel, _⟩ := hb_step H r found e1 eL same
    exact ⟨_, _, em, admitted_sendEntries _ _, rel⟩
  · intro e mem
    simp only [List.mem_singleton] at mem
    subst mem
    have := step.2.2
    rw [self] at this
    exact this
  · refine ⟨{ p with sentIdx := endIdx }, ?_, rfl⟩
    rw [setPeer_lookup ndv]
    simp

/-! ## One `send_append_entries` -/

/-- The loop's precondition: the peer's next index is `start`. -/
abbrev HbFrom (env : Env) (node : NodeID) (s0 : State) (clean0 : NodeState) (to : NodeId)
    (start : Nat) (v : State) (o : Outbox)
    : Prop :=
  HbAcc env node s0 clean0 v o
  /\ exists p, v.peer? to = some p /\ p.sentIdx + 1 = start /\ p.sentIdx <= s0.lastIdx

/-- The range end the loop accepts lies in the ledger and in one view. -/
theorem hb_ok (H : HbHyps env.names node s0 clean0) {prev endIdx : Nat}
    (pL : prev <= s0.lastIdx)
    (ok
      : (if prev + 1 > maxIdx s0 (prev + 1) then
            endIdx == maxIdx s0 (prev + 1)
          else
            decide (prev + 1 <= endIdx) && decide (endIdx <= maxIdx s0 (prev + 1)))
        = true)
    : prev <= endIdx
      /\ endIdx <= s0.lastIdx
      /\ forall i, prev < i -> i <= endIdx -> s0.viewAt i = s0.viewAt endIdx := by
  have vh := ViewHyps.ofInv H.inv
  by_cases past : prev = s0.lastIdx
  · subst past
    rw [maxIdx_past vh] at ok
    simp only [Nat.lt_add_one, ↓reduceIte, beq_iff_eq] at ok
    subst ok
    exact ⟨Nat.le_refl _, Nat.le_refl _, fun i lo hi => absurd hi (by omega)⟩
  · obtain ⟨lo, hi, same⟩ := maxIdx_range vh (start := prev + 1) (by omega) (by omega)
    simp only [show Not (prev + 1 > maxIdx s0 (prev + 1)) by omega, ↓reduceIte,
      Bool.and_eq_true, decide_eq_true_eq] at ok
    refine ⟨by omega, by omega, fun i l h => ?_⟩
    rw [same i (by omega) (by omega), same endIdx ok.1 ok.2]

theorem tri_tail (H : HbHyps env.names node s0 clean0) {to : NodeId} {ext : Bool}
    {fuel : Nat}
    (ih
      : forall start batch,
          Tri env (HbFrom env node s0 clean0 to start)
            (sendAppendEntries.loop to ext fuel start batch)
            (fun _ => HbAcc env node s0 clean0))
    {v : State} {o : Outbox} (acc : HbAcc env node s0 clean0 v o) {p : Peer}
    (found : v.peer? to = some p) (pL : p.sentIdx <= s0.lastIdx) {endIdx : Nat}
    {batch : Option Nat}
    (ok
      : (if p.sentIdx + 1 > maxIdx v (p.sentIdx + 1) then
            endIdx == maxIdx v (p.sentIdx + 1)
          else
            decide (p.sentIdx + 1 <= endIdx)
            && decide (endIdx <= maxIdx v (p.sentIdx + 1)))
        = true)
    : Tri env (fun w o' => w = v /\ o' = o)
        (do
          sendAppendEntriesRange to (p.sentIdx + 1) endIdx ext
          let v ← getV
          unless endIdx == v.lastIdx do
            sendAppendEntries.loop to ext fuel (min (endIdx + 1) v.lastIdx) batch)
        (fun _ => HbAcc env node s0 clean0) := by
  obtain ⟨L, hv, _⟩ := acc.shape
  have mx : maxIdx v (p.sentIdx + 1) = maxIdx s0 (p.sentIdx + 1) := by subst hv; rfl
  rw [mx] at ok
  obtain ⟨e1, eL, same⟩ := hb_ok H pL ok
  refine Tri.bind (Tri.conseq (tri_range H to (p.sentIdx + 1) endIdx ext)
    (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact ⟨acc, p, found, rfl, e1, eL, same⟩)
    (fun _ _ _ h => h)) fun _ => ?_
  refine tri_getV fun v' o' ⟨acc', p', found', ps'⟩ => ?_
  obtain ⟨L', hv', _⟩ := acc'.shape
  have last : v'.lastIdx = s0.lastIdx := by subst hv'; rfl
  refine Tri.ite (fun _ => ?_) (fun ne => ?_)
  · exact Tri.conseq (Tri.pure' (Q := fun _ => HbAcc env node s0 clean0) ())
      (fun w o'' ⟨hw, ho⟩ => by subst hw ho; exact acc') (fun _ _ _ h => h)
  · simp only [beq_iff_eq, last] at ne
    exact Tri.conseq (ih _ _)
      (fun w o'' ⟨hw, ho⟩ => by
        subst hw ho
        exact ⟨acc', p', found', by rw [ps', last]; omega, by omega⟩)
      (fun _ _ _ h => h)

theorem tri_loop (H : HbHyps env.names node s0 clean0) (to : NodeId) (ext : Bool)
    (fuel start : Nat) (batch : Option Nat)
    : Tri env (HbFrom env node s0 clean0 to start)
        (sendAppendEntries.loop to ext fuel start batch)
        (fun _ => HbAcc env node s0 clean0) := by
  induction fuel generalizing start batch with
  | zero =>
      unfold sendAppendEntries.loop
      exact tri_keeps_bind Spec.curLoc fun _ => Tri.fail _
  | succ fuel ih =>
      rw [sendAppendEntries.loop]
      dsimp only
      refine tri_getV fun v o ⟨acc, p, found, ps, pL⟩ => ?_
      obtain ⟨L, hv, _⟩ := acc.shape
      have nrc : v.isRetiredCommitted = false := by subst hv; exact H.notRC
      subst ps
      simp only [nrc, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
      repeat'
        first
          | exact Tri.fail_bind _
          | exact Tri.fail _
          | exact tri_tail H ih acc found pL (by assumption)
          | refine tri_keeps_bind Spec.curLoc fun _ => ?_
          | refine Tri.ite (fun _ => ?_) (fun _ => ?_)
          | refine tri_pres_bind (by repeat' pres_step) fun _ => ?_

theorem tri_sendAE (H : HbHyps env.names node s0 clean0) (to : NodeId) (start : Nat)
    (ext : Bool)
    : Tri env (HbFrom env node s0 clean0 to start) (sendAppendEntries to start ext)
        (fun _ => HbAcc env node s0 clean0) := by
  unfold sendAppendEntries
  exact Tri.getV_bind fun _ =>
    Tri.conseq (tri_loop H to ext _ start none) (fun _ _ h => h.1) (fun _ _ _ h => h)

/-- A peer of the heartbeat's declared state has sent no index beyond the ledger. -/
theorem HbAcc.bound {v : State} {o : Outbox} (acc : HbAcc env node s0 clean0 v o)
    {to : NodeId} {p : Peer} (found : v.peer? to = some p)
    : p.sentIdx <= s0.lastIdx := by
  obtain ⟨_, _, _, _, _, L, f, hv, _, _, rel⟩ := acc
  subst hv
  exact (rel to p found).2.2

end Consensus.TraceValidation.Proofs.Tick
