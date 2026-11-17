module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeScan

@[expose] public section

/-!
# The whole AppendEntries handler (not reviewed)

`hoare_recv` runs `recvAppendEntries` from the released state `saved` and lists its ends
(`AeOut`): a stale-term NACK; past the term phase (`aeMid`), a log-mismatch NACK
(`nackOut`); a silent return before the commit index or past the log; a silent conflict; or
the accepting run, with `GN` over the parameters `aePar` and the ACK.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- The declared state after the term phase. -/
def aeMid (r : AppendEntriesRequest) (v : State) : State :=
  if (v.currentView == r.term
        && (v.leadership == .candidate || v.leadership == .preVoteCandidate))
      = true then
    bant r.term v
  else if v.currentView < r.term then
    bant r.term v
  else
    v

/-- The declared state when the request matches the log. -/
def aeU (from_ : NodeId) (r : AppendEntriesRequest) (v : State) : State :=
  { aeMid r v with leaderId := some from_ }

def aerOut (env : Env) (from_ : NodeId) (v : State) (term idx : Nat) (ok : Bool)
    : Outbox :=
  [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id from_)
    (.appendEntriesResponse { term := term, success := ok, lastLogIndex := idx })]

/-- The NACK of a mismatching request. -/
def nackOut (env : Env) (from_ : NodeId) (r : AppendEntriesRequest) (v : State)
    : Outbox :=
  if v.getTerm r.prevLogIndex = 0 then
    aerOut env from_ v v.currentView v.lastIdx false
  else
    aerOut env from_ v (v.getTerm (v.highestMatch r.prevLogTerm r.prevLogIndex))
      (v.highestMatch r.prevLogTerm r.prevLogIndex) false

/-- The ends of the AppendEntries hold. -/
def AeOut (env : Env) (from_ : NodeId) (r : AppendEntriesRequest) (K : Option Nat)
    (saved v : State) (o : Outbox)
    : Prop :=
  saved.currentView > r.term
    /\ v = saved
    /\ o = aerOut env from_ saved saved.currentView saved.lastIdx false
  \/ Not (saved.currentView > r.term)
      /\ (aeMid r saved).leadership ≠ .leader
      /\ ((aeMid r saved).getTerm r.prevLogIndex ≠ r.prevLogTerm
            /\ v = aeMid r saved
            /\ o = nackOut env from_ r (aeMid r saved)
          \/ (aeMid r saved).getTerm r.prevLogIndex = r.prevLogTerm
              /\ ((r.prevLogIndex < saved.commitIdx \/ r.prevLogIndex > saved.lastIdx)
                    /\ v = aeU from_ r saved
                    /\ o = []
                  \/ saved.commitIdx <= r.prevLogIndex
                      /\ r.prevLogIndex <= saved.lastIdx
                      /\ (silentOf (aeU from_ r saved) K
                            /\ v = aeU from_ r saved
                            /\ o = []
                          \/ Not (silentOf (aeU from_ r saved) K)
                              /\ GN
                                  (aePar env.names from_ r
                                    ((r.entries.map (toExecEntry env)).toArray)
                                    (aeU from_ r saved) K)
                                  (aePar env.names from_ r
                                    ((r.entries.map (toExecEntry env)).toArray)
                                    (aeU from_ r saved) K).lx.length
                                  (core v)
                              /\ v.commitIdx
                                  = (aePar env.names from_ r
                                      ((r.entries.map (toExecEntry env)).toArray)
                                      (aeU from_ r saved) K).bd
                              /\ o = ack env from_ r v)))

theorem hoare_nack {env : Env} (from_ : NodeId) (V : State)
    : Hoare env (fun v o => v = V /\ o = []) (nack from_)
        (fun _ v o => v = V /\ o = aerOut env from_ V V.currentView V.lastIdx false) := by
  unfold nack
  refine Hoare.getV_bind fun s => hoare_sendAer _ _ _ _ fun v o ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst hv ho hs
  exact ⟨rfl, rfl⟩

theorem hoare_nackRejected {env : Env} (from_ : NodeId) (V : State) (t i : Nat)
    : Hoare env (fun v o => v = V /\ o = []) (nackRejected from_ t i)
        (fun _ v o =>
          v = V
          /\ o
              = aerOut env from_ V (V.getTerm (V.highestMatch t i))
                  (V.highestMatch t i) false) := by
  unfold nackRejected
  refine Hoare.getV_bind fun s => hoare_sendAer _ _ _ _ fun v o ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst hv ho hs
  exact ⟨rfl, rfl⟩

theorem aeMid_frame (r : AppendEntriesRequest) (v : State)
    : (aeMid r v).lastIdx = v.lastIdx
      /\ (aeMid r v).ledger = v.ledger
      /\ (aeMid r v).views = v.views
      /\ (aeMid r v).commitIdx = v.commitIdx
      /\ (aeMid r v).committable = v.committable
      /\ (aeMid r v).rcEntries = v.rcEntries
      /\ (aeMid r v).nodeId = v.nodeId
      /\ (aeMid r v).retiredCommittedIdx = v.retiredCommittedIdx := by
  unfold aeMid
  split
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
  · split <;> exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem aeMid_view (r : AppendEntriesRequest) (v : State)
    (h : Not (v.currentView > r.term))
    : (aeMid r v).currentView = r.term := by
  unfold aeMid
  split
  · rfl
  · split
    · rfl
    · omega

theorem conflictSpec_congr {U V : State} {P n τ : Nat} {K : Option Nat}
    (h1 : U.lastIdx = V.lastIdx) (h2 : U.views = V.views)
    (h : ConflictSpec V P n τ K)
    : ConflictSpec U P n τ K := by
  have hv : U.viewAt = V.viewAt := by funext i; simp [State.viewAt, h2]
  cases K <;> simpa [ConflictSpec, h1, hv] using h

theorem hoare_match {env : Env} (from_ : NodeId) (r : AppendEntriesRequest)
    (K : Option Nat) (saved : State) (hns : Not (saved.currentView > r.term))
    (hnl : (aeMid r saved).leadership ≠ .leader) (hsz : saved.ledger.size = saved.lastIdx)
    (hcomm : saved.committable = sigsIn saved.ledger saved.commitIdx saved.lastIdx)
    (hviews : saved.views.size <= saved.currentView)
    (hrc : forall x, x ∈ saved.rcEntries -> saved.commitIdx < x.1)
    (hτ
      : forall j (h : j < ((r.entries.map (toExecEntry env)).toArray).size),
          ((r.entries.map (toExecEntry env)).toArray)[j].term = aeTermOfIdx r)
    (hK : ConflictSpec saved r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    (hv2
      : Not (saved.currentView > r.term)
        -> (aeMid r saved).getTerm r.prevLogIndex = r.prevLogTerm
        -> aeTermOfIdx r <= r.term)
    : Hoare env (fun v o => v = aeMid r saved /\ o = [])
        (aeMatch from_ r ((r.entries.map (toExecEntry env)).toArray) (aeMid r saved))
        (fun _ v o => AeOut env from_ r K saved v o) := by
  have ⟨f1, f2, f3, f4, f5, f6, f7, f8⟩ := aeMid_frame r saved
  have hview := aeMid_view r saved hns
  unfold aeMatch
  dsimp only
  refine Hoare.ite (fun hb => ?_) (fun hb => ?_)
  · simp only [bne_iff_ne, ne_eq] at hb
    refine Hoare.post (Q := fun _ v o => v = aeMid r saved /\ o = nackOut env from_ r (aeMid r saved)) ?_
      fun _ v o h => Or.inr ⟨hns, hnl, Or.inl ⟨hb, h⟩⟩
    refine Hoare.ite (fun h0 => ?_) (fun h0 => ?_)
    · simp only [beq_iff_eq] at h0
      refine Hoare.bind (hoare_nack from_ _) fun _ => Hoare.pure _ fun v o ⟨hv, ho⟩ => ⟨hv, ?_⟩
      simp [ho, nackOut, h0]
    · simp only [beq_iff_eq] at h0
      refine Hoare.bind (hoare_nackRejected from_ _ _ _) fun _ =>
        Hoare.pure _ fun v o ⟨hv, ho⟩ => ⟨hv, ?_⟩
      simp [ho, nackOut, h0]
  · simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hb
    refine Hoare.setV _ (Q := fun _ v o => v = aeU from_ r saved /\ o = [])
      (fun v o ⟨hv, ho⟩ => ⟨by rw [hv]; rfl, ho⟩) |>.bind fun _ => ?_
    refine Hoare.getV_bind fun s => Hoare.pin fun v0 o0 ⟨⟨hv, ho⟩, hs⟩ => ?_
    subst hv ho hs
    have u1 : (aeU from_ r saved).commitIdx = saved.commitIdx := f4
    have u2 : (aeU from_ r saved).lastIdx = saved.lastIdx := f1
    refine Hoare.ite (fun h1 => ?_) (fun h1 => ?_)
    · exact Hoare.pure _ fun v o ⟨hv, ho⟩ =>
        Or.inr ⟨hns, hnl, Or.inr ⟨hb, Or.inl ⟨Or.inl (u1 ▸ h1), hv, ho⟩⟩⟩
    refine Hoare.ite (fun h2 => ?_) (fun h2 => ?_)
    · exact Hoare.pure _ fun v o ⟨hv, ho⟩ =>
        Or.inr ⟨hns, hnl, Or.inr ⟨hb, Or.inl ⟨Or.inr (u2 ▸ h2), hv, ho⟩⟩⟩
    have hP : r.prevLogIndex <= saved.lastIdx := by omega
    have hci : saved.commitIdx <= r.prevLogIndex := by omega
    have hU : aeU from_ r saved = { aeMid r saved with leaderId := some from_ } := rfl
    refine Hoare.post (hoare_apply from_ r _ (aeU from_ r saved) K
      (aePar env.names from_ r ((r.entries.map (toExecEntry env)).toArray) (aeU from_ r saved) K)
      (by simp) hτ (u2 ▸ hP) (u1 ▸ hci) hnl
      (conflictSpec_congr f1 f3 hK) (by rw [u2]; exact f2 ▸ hsz)
      (good_cCut _ _ _ _ _ _ (u2 ▸ hP) (u1 ▸ hci) hnl (conflictSpec_congr f1 f3 hK)
        (by rw [u2]; exact f2 ▸ hsz) (by rw [u2, u1]; exact f5.trans (f2 ▸ hcomm))
        (by show (aeMid r saved).views.size <= (aeMid r saved).currentView; rw [f3]; omega)
        (by rw [u1]; exact f6 ▸ hrc) rfl)
      rfl (show (aeMid r saved).commitIdx <= r.prevLogIndex by omega)
      (show r.term <= (aeMid r saved).currentView by omega)
      (show aeTermOfIdx r <= (aeMid r saved).currentView by rw [hview]; exact hv2 hns hb) rfl) ?_
    intro _ v o h
    exact Or.inr ⟨hns, hnl, Or.inr ⟨hb, Or.inr ⟨hci, hP, h⟩⟩⟩

theorem hoare_jp {env : Env} (from_ : NodeId) (r : AppendEntriesRequest) (K : Option Nat)
    (saved : State) (hns : Not (saved.currentView > r.term))
    (hsz : saved.ledger.size = saved.lastIdx)
    (hcomm : saved.committable = sigsIn saved.ledger saved.commitIdx saved.lastIdx)
    (hviews : saved.views.size <= saved.currentView)
    (hrc : forall x, x ∈ saved.rcEntries -> saved.commitIdx < x.1)
    (hτ
      : forall j (h : j < ((r.entries.map (toExecEntry env)).toArray).size),
          ((r.entries.map (toExecEntry env)).toArray)[j].term = aeTermOfIdx r)
    (hK : ConflictSpec saved r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    (hv2
      : Not (saved.currentView > r.term)
        -> (aeMid r saved).getTerm r.prevLogIndex = r.prevLogTerm
        -> aeTermOfIdx r <= r.term)
    : Hoare env (fun v o => v = aeMid r saved /\ o = [])
        (do
          let v ← getV
          let jp : Unit -> M Unit :=
            fun _ => aeMatch from_ r ((r.entries.map (toExecEntry env)).toArray) v
          if (v.leadership == .leader && v.currentView == r.term) = true then do
            let l ← curLoc
            let x ←
              Exec.fail
                (toString l
                  ++ toString ": AppendEntries from "
                  ++ toString from_
                  ++ toString " to a leader in its own view "
                  ++ toString r.term)
            jp x
          else
            jp ())
        (fun _ v o => AeOut env from_ r K saved v o) := by
  refine Hoare.getV_bind fun s => Hoare.pin fun v0 o0 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst hv ho hs
  dsimp only
  refine Hoare.ite (fun hb => ?_) (fun hb => ?_)
  · refine Hoare.bind (Hoare.keeps Spec.curLoc (Q := fun _ _ _ => True) fun _ _ _ _ => trivial)
      fun _ => Hoare.bind (Hoare.fail (Q := fun _ _ _ => False) _) fun _ =>
        Hoare.false_pre fun _ _ f => f
  · have hnl : (aeMid r saved).leadership ≠ .leader := by
      intro h
      simp [h, aeMid_view r saved hns] at hb
    exact hoare_match from_ r K saved hns hnl hsz hcomm hviews hrc hτ hK hv2

theorem hoare_recv {env : Env} (from_ : NodeId) (r : AppendEntriesRequest)
    (K : Option Nat) (saved : State) (hsz : saved.ledger.size = saved.lastIdx)
    (hcomm : saved.committable = sigsIn saved.ledger saved.commitIdx saved.lastIdx)
    (hviews : saved.views.size <= saved.currentView)
    (hrc : forall x, x ∈ saved.rcEntries -> saved.commitIdx < x.1)
    (hτ
      : forall j (h : j < ((r.entries.map (toExecEntry env)).toArray).size),
          ((r.entries.map (toExecEntry env)).toArray)[j].term = aeTermOfIdx r)
    (hK : ConflictSpec saved r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    (hv2
      : Not (saved.currentView > r.term)
        -> (aeMid r saved).getTerm r.prevLogIndex = r.prevLogTerm
        -> aeTermOfIdx r <= r.term)
    : Hoare env (fun v o => v = saved /\ o = []) (recvAppendEntries from_ r)
        (fun _ v o => AeOut env from_ r K saved v o) := by
  rw [recvAppendEntries_eq]
  refine Hoare.bind (Hoare.of_spec (det_traceRecv env _ from_ _)
    (Q := fun _ v o => v = saved /\ o = []) fun v o _ v' o' ⟨hv, ho⟩ ⟨e1, e2⟩ => by
      subst hv ho; simp [e1, e2]) fun _ => ?_
  refine Hoare.bind (Hoare.of_spec Spec.get
    (Q := fun c v o => v = saved /\ o = [] /\ c.env = env)
      fun v o a v' o' ⟨hv, ho⟩ ⟨a1, a2, a3, a4, a5⟩ => ⟨a4.trans hv, a5.trans ho, a3⟩)
    fun c => ?_
  refine Hoare.pin fun v0 o0 ⟨hv, ho, hc⟩ => ?_
  subst hv ho
  rw [hc]
  dsimp only
  refine Hoare.getV_bind fun s => Hoare.pin fun v0 o0 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst hv ho hs
  have jp := fun hns => hoare_jp (env := env) from_ r K v0 hns hsz hcomm hviews hrc hτ hK hv2
  refine Hoare.ite (fun hb => ?_) (fun hb => ?_)
  · have hns : Not (v0.currentView > r.term) := by
      simp only [Bool.and_eq_true, beq_iff_eq] at hb; omega
    have hm : aeMid r v0 = bant r.term v0 := by simp [aeMid, hb]
    refine Hoare.bind (Hoare.of_spec (det_becomeAware env r.term)
      (Q := fun _ v o => v = aeMid r v0 /\ o = []) fun v o _ v' o' ⟨hv, ho⟩ ⟨e1, e2⟩ => by
        subst hv ho; simp [e1, e2, hm]) fun _ => jp hns
  refine Hoare.ite (fun hb' => ?_) (fun hb' => ?_)
  · have hns : Not (v0.currentView > r.term) := by omega
    have hm : aeMid r v0 = bant r.term v0 := by simp [aeMid, hb, hb']
    refine Hoare.bind (Hoare.of_spec (det_becomeAware env r.term)
      (Q := fun _ v o => v = aeMid r v0 /\ o = []) fun v o _ v' o' ⟨hv, ho⟩ ⟨e1, e2⟩ => by
        subst hv ho; simp [e1, e2, hm]) fun _ => jp hns
  refine Hoare.ite (fun hs => ?_) (fun hs => ?_)
  · refine Hoare.bind (hoare_nack from_ v0) fun _ => Hoare.pure _ fun v o ⟨hv, ho⟩ =>
      Or.inl ⟨hs, hv, ho⟩
  · have hm : aeMid r v0 = v0 := by simp [aeMid, hb, hb']
    have := jp hs
    rw [hm] at this
    exact this

end Consensus.TraceValidation.Proofs.Ae
