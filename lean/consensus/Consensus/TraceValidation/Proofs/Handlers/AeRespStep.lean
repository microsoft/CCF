module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespCommit

@[expose] public section

/-!
# The AppendEntries response, step by step (not reviewed)

`recv_append_entries_response` from a declared state in closed form (`handler_spec`, one
disjunct of `Outcome` per path), and the clean receive of the response
(`receive_ineligible`, `receive_notPrimary`, `receive_primary`, `handle_*`, `advance_run`).
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open Consensus.Model.Node
open Consensus.TraceValidation (Names Env abs agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open Consensus.TraceValidation.Proofs.Ae (Hoare)

/-- The peer record after a success response. -/
def ackPeer (node : Peer) (r : AppendEntriesResponse) : Peer :=
  { sentIdx := node.sentIdx, matchIdx := max node.matchIdx r.lastLogIndex }

/-- The peer record after a NACK. -/
def nackPeer (v : State) (node : Peer) (r : AppendEntriesResponse) : Peer :=
  {
    sentIdx :=
      max (min (v.highestMatch r.term r.lastLogIndex) node.sentIdx) node.matchIdx,
    matchIdx := node.matchIdx
  }

/-- What `recv_append_entries_response` does from `saved`. -/
def Outcome (env : Env) (saved : State) (from_ : Exec.NodeId) (r : AppendEntriesResponse)
    (v : State) (o : Outbox)
    : Prop :=
  exists node,
    saved.peer? from_ = some node
    /\ ((saved.leadership ≠ .leader /\ v = saved /\ o = [])
        \/ (saved.leadership = .leader
            /\ saved.currentView < r.term
            /\ v = Ae.bant r.term saved
            /\ o = [])
        \/ (saved.leadership = .leader
            /\ r.term < saved.currentView
            /\ r.success = true
            /\ v = saved
            /\ o = [])
        \/ (saved.leadership = .leader
            /\ r.term = saved.currentView
            /\ r.success = true
            /\ r.lastLogIndex < node.matchIdx
            /\ v = saved
            /\ o = [])
        \/ (saved.leadership = .leader
            /\ r.term <= saved.currentView
            /\ r.success = false
            /\ v = saved.setPeer from_ (nackPeer saved node r)
            /\ o = [])
        \/ (saved.leadership = .leader
            /\ r.term = saved.currentView
            /\ r.success = true
            /\ node.matchIdx <= r.lastLogIndex
            /\ exists res,
                ReplUpdateCommit.updateCommitOf (saved.setPeer from_ (ackPeer node r)) 0
                    none ((saved.setPeer from_ (ackPeer node r)).lastIdx + 2)
                  = .ok res
                /\ ((res.getD saved.commitIdx <= saved.commitIdx
                      /\ v = saved.setPeer from_ (ackPeer node r)
                      /\ o = [])
                    \/ exists i,
                        res = some i
                        /\ saved.commitIdx < i
                        /\ i <= saved.lastIdx
                        /\ RInv env (saved.setPeer from_ (ackPeer node r)) i [] v o)))

/-- The pending retired-committed records up to `i` name no other node `v` keeps. -/
def RcRetired (v : State) (i : Nat) : Prop :=
  forall e,
    e ∈ v.rcEntries
    -> e.1 <= i
    -> forall id,
        id ∈ e.2 -> id ≠ v.nodeId -> ¬ MemIn (Exec.commit.pop e.1 v.configurations) id

theorem handler_spec (env : Env) (saved : State) (from_ : Exec.NodeId)
    (r : AppendEntriesResponse)
    (cover
      : forall node,
          saved.peer? from_ = some node
          -> saved.leadership = .leader
          -> Cover (saved.setPeer from_ (ackPeer node r)))
    (hrc : saved.leadership = .leader -> forall i, RcRetired saved i)
    : Hoare env (fun v o => v = saved /\ o = []) (Exec.recvAppendEntriesResponse from_ r)
        fun _ => Outcome env saved from_ r := by
  unfold Exec.recvAppendEntriesResponse
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := s = saved) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst e
  cases hp : s.peer? from_ with
  | none => exact Hoare.fail _
  | some node =>
      simp only
      refine Hoare.bind (Hoare.of_spec (Ae.det_traceRecv env _ _ _)
        (Q := fun _ v o => v = s /\ o = []) fun v o _ v' o' p q => ?_) fun _ => ?_
      · obtain ⟨⟨e, f⟩, -⟩ := p
        rw [q.1, q.2, e, f]; exact ⟨rfl, rfl⟩
      refine Hoare.getV_bind fun t => ?_
      refine hoare_assume (φ := t = s) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
      subst e
      have pre
          : forall (v : State) (o : Outbox),
              ((v = t /\ o = []) /\ v = t) -> v = t /\ o = [] :=
        fun _ _ p => p.1
      refine Hoare.ite (fun nl => Hoare.pure _ fun v o p => ?_) fun lead => ?_
      · obtain ⟨e, f⟩ := pre v o p
        refine ⟨node, hp, Or.inl ⟨by simpa using nl, e, f⟩⟩
      have lead : t.leadership = .leader := by simpa using lead
      refine Hoare.ite (fun gt => ?_) fun ngt => ?_
      · refine Hoare.bind (Hoare.of_spec (Ae.det_becomeAware env r.term)
          (Q := fun _ v o => v = Ae.bant r.term t /\ o = []) fun v o _ v' o' p q => ?_)
          fun _ => Hoare.pure _ fun v o p => ⟨node, hp, Or.inr (Or.inl ⟨lead, gt, p⟩)⟩
        obtain ⟨e, f⟩ := pre v o p
        rw [q.1, q.2, e, f]; exact ⟨rfl, rfl⟩
      cases hs : r.success
      · simp only [Bool.not_false, ↓reduceIte, Bool.false_eq_true, ite_self]
        refine Hoare.bind (Hoare.setV _
          (Q := fun _ v o => v = t.setPeer from_ (nackPeer t node r) /\ o = []) fun v o p => ?_)
          fun _ => Hoare.pure _ fun v o p =>
            ⟨node, hp, Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨lead, by omega, hs, p⟩))))⟩
        obtain ⟨e, f⟩ := pre v o p
        rw [e, f]
        exact ⟨rfl, rfl⟩
      simp only [Bool.not_true, ↓reduceIte, Bool.false_eq_true]
      by_cases same : t.currentView ≠ r.term
      · simp only [bne_iff_ne, ne_eq, same, not_false_eq_true, ↓reduceIte]
        exact Hoare.pure _ fun v o p => ⟨node, hp, Or.inr (Or.inr (Or.inl
          ⟨lead, by omega, hs, pre v o p⟩))⟩
      replace same : t.currentView = r.term := Decidable.of_not_not same
      simp only [same, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
      refine Hoare.ite
        (fun lt =>
          Hoare.pure _
            fun v o p =>
              ⟨
                node,
                hp,
                Or.inr (Or.inr (Or.inr (Or.inl ⟨lead, same.symm, hs, lt, pre v o p⟩)))
              ⟩)
        fun nlt => ?_
      refine Hoare.bind
        (Hoare.setV _ (Q := fun _ v o => v = t.setPeer from_ (ackPeer node r) /\ o = [])
          fun v o p => ?_)
        fun _ => ?_
      · obtain ⟨e, f⟩ := pre v o p
        rw [e, f]
        exact ⟨rfl, rfl⟩
      unfold Exec.updateCommit
      refine Hoare.getV_bind fun s => ?_
      refine hoare_assume (φ := s = t.setPeer from_ (ackPeer node r))
        (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
      subst e
      have l1 : ((t.setPeer from_ (ackPeer node r)).leadership == .leader) = true := by
        simp [Exec.State.setPeer, lead]
      simp only [l1, ↓reduceIte]
      refine Hoare.bind (Hoare.of_spec (ReplUpdateCommit.updateCommitGo_spec _ _ _)
        (Q := fun res v o => v = t.setPeer from_ (ackPeer node r) /\ o = []
          /\ ReplUpdateCommit.updateCommitOf (t.setPeer from_ (ackPeer node r)) 0 none
              ((t.setPeer from_ (ackPeer node r)).lastIdx + 2) = .ok res)
        fun v o a v' o' p q => ?_) fun res => ?_
      · obtain ⟨⟨e, f⟩, -⟩ := p
        obtain ⟨q1, q2, q3⟩ := q
        rw [q1, q2, e, f]
        exact ⟨rfl, rfl, e ▸ q3⟩
      have out
          : forall (v : State) (o : Outbox),
              (v = t.setPeer from_ (ackPeer node r)
                /\ o = []
                /\ ReplUpdateCommit.updateCommitOf (t.setPeer from_ (ackPeer node r)) 0
                      none ((t.setPeer from_ (ackPeer node r)).lastIdx + 2)
                    = .ok res)
              -> res.getD t.commitIdx <= t.commitIdx
              -> Outcome env t from_ r v o :=
        fun v o p le =>
          ⟨
            node,
            hp,
            Or.inr
              (Or.inr
                (Or.inr
                  (Or.inr
                    (Or.inr
                      ⟨
                        lead,
                        same.symm,
                        hs,
                        by omega,
                        res,
                        p.2.2,
                        Or.inl ⟨le, p.1, p.2.1⟩
                      ⟩))))
          ⟩
      cases res with
      | none => exact Hoare.pure _ fun v o p => out v o p (Nat.le_refl _)
      | some i =>
          simp only
          have v1Last : (t.setPeer from_ (ackPeer node r)).lastIdx = t.lastIdx := rfl
          have v1Commit : (t.setPeer from_ (ackPeer node r)).commitIdx = t.commitIdx :=
            rfl
          by_cases gt : i > t.lastIdx
          · unfold Exec.commit
            refine Hoare.getV_bind fun s => ?_
            refine hoare_assume (φ := s = t.setPeer from_ (ackPeer node r))
              (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
            subst e
            simp only [v1Last, gt, ↓reduceIte]
            exact hoare_curLoc_fail _
          by_cases le : i <= t.commitIdx
          · unfold Exec.commit
            refine Hoare.getV_bind fun s => ?_
            refine hoare_assume (φ := s = t.setPeer from_ (ackPeer node r))
              (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
            subst e
            simp only [v1Last, v1Commit, gt, le, ↓reduceIte]
            exact Hoare.pure _ fun v o p => out v o p.1 le
          refine hoare_assume
            (φ :=
              ReplUpdateCommit.updateCommitOf (t.setPeer from_ (ackPeer node r))
                0 none ((t.setPeer from_ (ackPeer node r)).lastIdx + 2)
              = .ok (some i))
            (fun _ _ p => p.2.2) fun ran => ?_
          refine Hoare.post
            (Hoare.pre
              (commit_spec env (v1 := t.setPeer from_ (ackPeer node r))
                (o0 := []) lead (by omega) (by omega) (cover node hp lead) (hrc lead i))
              fun v o p => ⟨p.1, p.2.1⟩)
            fun _ v o q =>
              ⟨
                node,
                hp,
                Or.inr
                  (Or.inr
                    (Or.inr
                      (Or.inr
                        (Or.inr
                          ⟨
                            lead,
                            same.symm,
                            hs,
                            by omega,
                            some i,
                            ran,
                            Or.inr ⟨i, rfl, by omega, by omega, q⟩
                          ⟩))))
              ⟩

/-- What a primary's clean `nominateSuccessor` sends. -/
def nomSends (node : NodeID) (st : NodeState) : List (CCF.Envelope NodeID Message) :=
  ((findSuccessor st node).map
    fun t =>
      CCF.Envelope.mk node t (Message.proposeRequestVoteRequest st.currentTerm)).toList

theorem advance_run (node : NodeID) (st : NodeState) (primary : st.role = .primary)
    : (advanceCommit (CCF.Capabilities.record node) st node).run {}
      = some
          (
            if highestCommittableIndex st node <= st.commitIndex then
              st
            else
              st.recordCommit node (highestCommittableIndex st node),
            {
              outgoing :=
                if ¬ highestCommittableIndex st node <= st.commitIndex
                    /\ (st.recordCommit node
                          (highestCommittableIndex st node)).isRetiredCommitted
                        node then
                  nomSends node st
                else
                  []
            }
          ) := by
  unfold advanceCommit
  by_cases h : highestCommittableIndex st node <= st.commitIndex
  · simp [h]
  · by_cases r : (st.recordCommit node (highestCommittableIndex st node)).isRetiredCommitted node
    · cases hs : findSuccessor st node <;>
        simp [h, primary, nominateSuccessor, guard, nomSends, hs, CCF.Capabilities.record,
          modify, modifyGet, MonadStateOf.modifyGet, StateT.run] <;> (try split) <;> simp_all <;> rfl
    · simp [h]; split <;> simp_all <;> rfl

abbrev cleanRun (node source : NodeID) (clean : NodeState) (r : AppendEntriesResponse) :=
  (Consensus.Model.Node.step (CCF.Capabilities.record node) node clean
    (.receive source (.appendEntriesResponse r))).run
    {}

theorem receive_ineligible {node source : NodeID} {clean : NodeState}
    (r : AppendEntriesResponse) (h : source ∉ eligiblePeers clean node)
    : cleanRun node source clean r = some (clean, {}) := by
  simp [cleanRun, Consensus.Model.Node.step, Model.Node.receive, h]

theorem receive_notPrimary {node source : NodeID} {clean : NodeState}
    (r : AppendEntriesResponse) (h : clean.role ≠ .primary)
    : cleanRun node source clean r = some (clean, {}) := by
  by_cases e : source ∈ eligiblePeers clean node
  · simp [cleanRun, Consensus.Model.Node.step, Model.Node.receive, e, observeTerm, h,
      handleAppendEntriesResponse]
  · exact receive_ineligible r e

theorem receive_primary {node source : NodeID} {clean : NodeState}
    (r : AppendEntriesResponse) (e : source ∈ eligiblePeers clean node)
    (h : clean.role = .primary)
    : cleanRun node source clean r
      = (handleAppendEntriesResponse (CCF.Capabilities.record node) node
          (updateTerm clean r.term) source r).run
          {} := by
  simp [cleanRun, Consensus.Model.Node.step, Model.Node.receive, e, observeTerm, h]

theorem handle_notPrimary {node source : NodeID} {st : NodeState}
    (r : AppendEntriesResponse) (h : st.role ≠ .primary)
    : (handleAppendEntriesResponse (CCF.Capabilities.record node) node st source r).run {}
      = some (st, {}) := by
  simp [handleAppendEntriesResponse, h]

theorem handle_stale {node source : NodeID} {st : NodeState} (r : AppendEntriesResponse)
    (h : st.role = .primary) (ok : r.success = true) (ne : r.term ≠ st.currentTerm)
    : (handleAppendEntriesResponse (CCF.Capabilities.record node) node st source r).run {}
      = some (st, {}) := by
  simp [handleAppendEntriesResponse, h, ok, ne]

theorem handle_nack {node source : NodeID} {st : NodeState} (r : AppendEntriesResponse)
    (h : st.role = .primary) (nok : r.success = false)
    : (handleAppendEntriesResponse (CCF.Capabilities.record node) node st source r).run {}
      = some
          (
            {
              st with
                sentIndex :=
                  CCF.Function.update st.sentIndex source
                    (max
                      (min (findHighestPossibleMatch st.log r.lastLogIndex r.term)
                        (st.sentIndex source))
                      (st.matchIndex source))
            },
            {}
          ) := by
  simp [handleAppendEntriesResponse, h, nok]

theorem handle_ack {node source : NodeID} {st : NodeState} (r : AppendEntriesResponse)
    (h : st.role = .primary) (ok : r.success = true) (same : r.term = st.currentTerm)
    : (handleAppendEntriesResponse (CCF.Capabilities.record node) node st source r).run {}
      = (advanceCommit (CCF.Capabilities.record node)
          {
            st with
              matchIndex :=
                CCF.Function.update st.matchIndex source
                  (max (st.matchIndex source) r.lastLogIndex)
          } node).run
          {} := by
  simp [handleAppendEntriesResponse, h, ok, same]

end Consensus.TraceValidation.Proofs.AeResp
