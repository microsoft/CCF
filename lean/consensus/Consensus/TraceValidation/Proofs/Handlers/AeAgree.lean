module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRecv

@[expose] public section

/-!
# The clean AppendEntries handler and its agreement with the term phase (not reviewed)

`clean_ae` reduces the clean step to `handleAppendEntriesRequest` after `updateTerm`;
`handle_nack`, `handle_silent` and `handle_accept` give its three ends from `cleanMid`.
`cleanMid_agrees` relates `cleanMid` to the program's `aeMid`, and `ae_msg` unpacks `msgInv`
of the request. `accept_agrees` closes the accepting path: the clean handler, run on the cut
state `cutClean`, answers with the program's ACK and agrees with its end state.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)

/-- The clean state after the term phase of `handleAppendEntriesRequest`. -/
def cleanMid (s : NodeState) (r : AppendEntriesRequest) : NodeState :=
  if r.term = s.currentTerm /\ (s.role = .candidate \/ s.role = .preVoteCandidate) then
    becomeAwareOfNewTerm s r.term
  else
    s

def aerMsg (term idx : Nat) (ok : Bool) : Message :=
  .appendEntriesResponse { term := term, success := ok, lastLogIndex := idx }

theorem clean_ae (node source : NodeID) (clean : NodeState) (r : AppendEntriesRequest)
    : (Consensus.Model.Node.step (CCF.Capabilities.record node) node clean
        (.receive source (.appendEntriesRequest r))).run
        {}
      = (handleAppendEntriesRequest (CCF.Capabilities.record node) node source
          (updateTerm clean r.term) r).run
          {} := by
  simp [Consensus.Model.Node.step, Model.Node.receive, observeTerm, Message.term]

theorem handle_nack (node source : NodeID) (s : NodeState) (r : AppendEntriesRequest)
    (h
      : r.term < (cleanMid s r).currentTerm
        \/ Not (appendEntryMatchesLog (cleanMid s r) r))
    : (handleAppendEntriesRequest (CCF.Capabilities.record node) node source s r).run {}
      = some
          (
            cleanMid s r,
            {
              outgoing :=
                [⟨
                  node,
                  source,
                  if r.term < (cleanMid s r).currentTerm
                      \/ termAt (cleanMid s r).log r.prevLogIndex = 0 then
                    aerMsg (cleanMid s r).currentTerm (cleanMid s r).log.length false
                  else
                    aerMsg
                      (termAt (cleanMid s r).log
                        (findHighestPossibleMatch (cleanMid s r).log r.prevLogIndex
                          r.prevLogTerm))
                      (findHighestPossibleMatch (cleanMid s r).log r.prevLogIndex
                        r.prevLogTerm)
                      false
                ⟩]
            }
          ) := by
  unfold handleAppendEntriesRequest
  rw [show (if r.term = s.currentTerm /\ (s.role = .candidate \/ s.role = .preVoteCandidate) then
    becomeAwareOfNewTerm s r.term else s) = cleanMid s r from rfl]
  generalize cleanMid s r = m at *
  dsimp only
  simp only [h, ↓reduceIte]
  split <;> simp [CCF.Capabilities.record, aerMsg, *]

theorem handle_silent (node source : NodeID) (s : NodeState) (r : AppendEntriesRequest)
    (h1 : Not (r.term < (cleanMid s r).currentTerm))
    (h2 : appendEntryMatchesLog (cleanMid s r) r)
    (h3
      : r.prevLogIndex < (cleanMid s r).commitIndex
        \/ ((firstTermConflictIndex (cleanMid s r) r).isSome
            /\ !(cleanMid s r).isNewFollower))
    : (handleAppendEntriesRequest (CCF.Capabilities.record node) node source s r).run {}
      = some ({ cleanMid s r with primaryKnown := true }, {}) := by
  unfold handleAppendEntriesRequest
  rw [show (if r.term = s.currentTerm /\ (s.role = .candidate \/ s.role = .preVoteCandidate) then
    becomeAwareOfNewTerm s r.term else s) = cleanMid s r from rfl]
  generalize cleanMid s r = m at *
  have hf : firstTermConflictIndex { m with primaryKnown := true } r
      = firstTermConflictIndex m r := rfl
  have hn : Not (r.term < m.currentTerm \/ Not (appendEntryMatchesLog m r)) := by
    simp only [not_or, Decidable.not_not]; exact ⟨h1, h2⟩
  dsimp only
  simp only [hn, ↓reduceIte, hf, h3]
  rfl

/-- The clean state the accept path hands to `handleAppendEntiresFromPrimary`. -/
def cutClean (m : NodeState) (K : Option Nat) : NodeState :=
  match K with
  | none => { m with primaryKnown := true }
  | some index =>
      {
        m with
          primaryKnown := true, log := m.log.take (index - 1), isNewFollower := false
      }

theorem handle_accept (node source : NodeID) (s : NodeState) (r : AppendEntriesRequest)
    (h1 : Not (r.term < (cleanMid s r).currentTerm))
    (h2 : appendEntryMatchesLog (cleanMid s r) r)
    (h3
      : Not
          (r.prevLogIndex < (cleanMid s r).commitIndex
            \/ ((firstTermConflictIndex (cleanMid s r) r).isSome
                /\ !(cleanMid s r).isNewFollower)))
    : (handleAppendEntriesRequest (CCF.Capabilities.record node) node source s r).run {}
      = some
          (
            (handleAppendEntiresFromPrimary node
              (cutClean (cleanMid s r) (firstTermConflictIndex (cleanMid s r) r)) r).1,
            {
              outgoing :=
                [⟨
                  node,
                  source,
                  .appendEntriesResponse
                    (handleAppendEntiresFromPrimary node
                      (cutClean (cleanMid s r) (firstTermConflictIndex (cleanMid s r) r))
                      r).2
                ⟩]
            }
          ) := by
  unfold handleAppendEntriesRequest
  rw [show (if r.term = s.currentTerm /\ (s.role = .candidate \/ s.role = .preVoteCandidate) then
    becomeAwareOfNewTerm s r.term else s) = cleanMid s r from rfl]
  generalize cleanMid s r = m at *
  have hf : firstTermConflictIndex { m with primaryKnown := true } r
      = firstTermConflictIndex m r := rfl
  have hn : Not (r.term < m.currentTerm \/ Not (appendEntryMatchesLog m r)) := by
    simp only [not_or, Decidable.not_not]; exact ⟨h1, h2⟩
  dsimp only
  simp only [hn, ↓reduceIte, hf, h3]
  cases firstTermConflictIndex m r <;> simp [CCF.Capabilities.record, cutClean]

theorem agrees_role {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.role = absRole d.leadership := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  exact h.1.1.1.1.1.1.1.1.1.1

theorem agrees_rci {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.retiredCommittedIndex = d.retiredCommittedIdx
      /\ c.commitIndex = d.commitIdx
      /\ c.isNewFollower = d.isNewFollower := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  exact ⟨h.2, h.1.1.1.1.1.1.1.2, h.1.1.1.1.1.2⟩

theorem aeMid_role (r : AppendEntriesRequest) (v : State)
    (h : Not (v.currentView > r.term))
    : (aeMid r v).leadership ≠ .candidate
      /\ (aeMid r v).leadership ≠ .preVoteCandidate := by
  unfold aeMid
  split
  · exact ⟨by simp [bant], by simp [bant]⟩
  · rename_i hb
    split
    · exact ⟨by simp [bant], by simp [bant]⟩
    · have : v.currentView = r.term := by omega
      simp only [this, beq_self_eq_true, Bool.true_and, Bool.or_eq_true, beq_iff_eq] at hb
      exact ⟨fun e => hb (Or.inl e), fun e => hb (Or.inr e)⟩

theorem cleanMid_agrees {names : Names} {clean : NodeState} {d : State}
    {r : AppendEntriesRequest} (h : agrees names clean d = true)
    (hns : Not (d.currentView > r.term))
    : agrees names (cleanMid (updateTerm clean r.term) r) (aeMid r d) = true := by
  obtain ⟨hterm, -⟩ := agrees_term_log h
  have hrole := agrees_role h
  unfold aeMid
  split
  · rename_i hb
    simp only [Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true] at hb
    have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
    have hc : cleanMid clean r = Model.Node.becomeAwareOfNewTerm clean r.term := by
      have c : r.term = clean.currentTerm
          /\ (clean.role = .candidate \/ clean.role = .preVoteCandidate) := by
        refine ⟨by omega, ?_⟩
        rcases hb.2 with e | e <;> simp [hrole, e, absRole]
      unfold cleanMid
      exact ite_eq_left c
    rw [hu, hc]
    exact agrees_bant _ h
  · rename_i hb
    split
    · have hu : updateTerm clean r.term = Model.Node.becomeAwareOfNewTerm clean r.term :=
        updateTerm_of_lt (by omega)
      have hc : cleanMid (Model.Node.becomeAwareOfNewTerm clean r.term) r
          = Model.Node.becomeAwareOfNewTerm clean r.term := by
        unfold cleanMid
        simp [Model.Node.becomeAwareOfNewTerm]
      rw [hu, hc]
      exact agrees_bant _ h
    · have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
      have hv : d.currentView = r.term := by omega
      have hc : cleanMid clean r = clean := by
        have c : Not (r.term = clean.currentTerm
            /\ (clean.role = .candidate \/ clean.role = .preVoteCandidate)) := by
          simp only [hv, beq_self_eq_true, Bool.true_and, Bool.or_eq_true, beq_iff_eq] at hb
          rw [hrole]
          intro ⟨_, e⟩
          apply hb
          cases hl : d.leadership <;> rw [hl] at e <;> simp [absRole] at e <;> simp
        unfold cleanMid
        simp only [c, ↓reduceIte]
      rw [hu, hc]
      exact h

theorem agrees_known {names : Names} {c : NodeState} {d : State} (x : Exec.NodeId)
    (h : agrees names c d = true)
    : agrees names { c with primaryKnown := true } { d with leaderId := some x }
      = true := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, -⟩, h9⟩, h10⟩, h11⟩ := h
  exact ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, rfl⟩, h9⟩, h10⟩, h11⟩

theorem unmatched_of_role {node : NodeID} {c : NodeState} (h : c.role ≠ .primary)
    : UnnamedUnmatched node c :=
  fun p => absurd p h

theorem absRole_ne_primary {l : Exec.Leadership} (h : l ≠ .leader)
    : absRole l ≠ .primary := by
  cases l <;> simp_all [absRole]

theorem aeMid_getTerm (r : AppendEntriesRequest) (v : State)
    : (aeMid r v).getTerm = v.getTerm := by
  unfold aeMid
  split
  · rfl
  · split <;> rfl

theorem abs_aeMid_log (names : Names) (r : AppendEntriesRequest) (v : State)
    : (abs names (aeMid r v)).log = (abs names v).log := by
  unfold aeMid
  split
  · rfl
  · split <;> rfl

theorem ae_msg {env : Env} {source node : NodeID} {r : AppendEntriesRequest}
    (h : msgInv env.names ⟨source, node, .appendEntriesRequest r⟩ = true)
    : (forall e,
        e ∈ r.entries -> e.term = Exec.aeTermOfIdx r /\ 0 < e.term /\ e.term <= r.term)
      /\ (r.prevLogIndex = 0 \/ 0 < r.prevLogTerm)
      /\ r.entries.map (fun e => absEntry env.names (Exec.toExecEntry env e))
          = r.entries := by
  simp only [msgInv, Bool.and_eq_true, List.all_eq_true] at h
  obtain ⟨⟨⟨-, hn⟩, ht, hp⟩, hq⟩ := h
  refine ⟨fun e he => ?_, ?_, ?_⟩
  · have := ht e he
    simp only [beq_iff_eq, decide_eq_true_eq] at this
    obtain ⟨⟨h1, h2⟩, h3⟩ := this
    refine ⟨?_, h2, h3⟩
    simp only [Exec.aeTermOfIdx, ← h1, Option.getD_some]
  · simpa [Bool.or_eq_true, beq_iff_eq] using hp
  · conv => rhs; rw [← List.map_id r.entries]
    exact List.map_congr_left fun e he => absEntry_toExecEntry env e (hq e he) (List.all_eq_true.mpr (hn e he))

theorem inv_rci {names : Names} {d : State} (h : inv names d = true)
    : d.retiredCommittedIdx = firstConf (names.id d.nodeId) (abs names d).log d.commitIdx
      /\ forall j,
          d.retiredCommittedIdx = some j
          -> (retirementIndexInLog (names.id d.nodeId)
                ((abs names d).log.take j)).isSome := by
  refine ⟨?_, ?_⟩
  · have hc : d.retiredCommittedIdx
        = firstLogIndexAfter ((abs names d).log.take d.commitIdx) 0
            fun c => decide (names.id d.nodeId ∈ c.metadata.retirementConfirmations) := by
      inv_conj h "rci_first"
    exact hc
  · intro j hj
    have hc : d.retiredCommittedIdx.all
        (fun j => (retirementIndexInLog (names.id d.nodeId) ((abs names d).log.take j)).isSome)
        = true := by
      inv_conj h "rci_retired"
    rw [hj] at hc
    simpa using hc

/-! ## The accepting path -/

theorem abs_log_length {names : Names} {d : State} (h : d.ledger.size = d.lastIdx)
    : (abs names d).log.length = d.lastIdx := by
  simp [abs, h]

theorem cutClean_eq (m : NodeState) (U : State) (K : Option Nat)
    (hl : m.log.length = U.lastIdx)
    : (cutClean m K).log = m.log.take (cutOf U K)
      /\ (cutClean m K).isNewFollower = (if K.isSome then false else m.isNewFollower)
      /\ (cutClean m K).role = m.role
      /\ (cutClean m K).currentTerm = m.currentTerm
      /\ (cutClean m K).commitIndex = m.commitIndex
      /\ (cutClean m K).retiredCommittedIndex = m.retiredCommittedIndex
      /\ (cutClean m K).votedFor = m.votedFor
      /\ (cutClean m K).primaryKnown = true := by
  cases K with
  | none => simp [cutClean, cutOf, ← hl]
  | some k => simp [cutClean, cutOf]

theorem firstConf_take {node : NodeID} {L : List Entry} {c k : Nat} (h : c <= k)
    : firstConf node (L.take k) c = firstConf node L c := by
  unfold firstConf
  rw [List.take_take, Nat.min_eq_left h]

theorem accept_agrees (env : Env) (from_ : Exec.NodeId) (r : AppendEntriesRequest)
    (saved vars : State) (K : Option Nat) (cm : NodeState)
    (invSaved : inv env.names saved = true) (invVars : inv env.names vars = true)
    (hcm : agrees env.names { cm with primaryKnown := true } (aeU from_ r saved) = true)
    (hns : Not (saved.currentView > r.term))
    (hP : r.prevLogIndex <= saved.lastIdx) (hci : saved.commitIdx <= r.prevLogIndex)
    (hK
      : ConflictSpec (aeU from_ r saved) r.prevLogIndex r.entries.length
          (Exec.aeTermOfIdx r) K)
    (hrt
      : r.entries.map (fun e => absEntry env.names (Exec.toExecEntry env e)) = r.entries)
    (hg
      : GN
          (aePar env.names from_ r ((r.entries.map (Exec.toExecEntry env)).toArray)
            (aeU from_ r saved) K)
          (aePar env.names from_ r ((r.entries.map (Exec.toExecEntry env)).toArray)
            (aeU from_ r saved) K).lx.length
          (core vars))
    (hbd
      : vars.commitIdx
        = (aePar env.names from_ r ((r.entries.map (Exec.toExecEntry env)).toArray)
            (aeU from_ r saved) K).bd)
    : (handleAppendEntiresFromPrimary (env.names.id saved.nodeId) (cutClean cm K) r).2
        = { term := vars.currentView, success := true, lastLogIndex := Exec.aeIdx r }
      /\ agrees env.names
            (handleAppendEntiresFromPrimary (env.names.id saved.nodeId) (cutClean cm K)
              r).1 vars
          = true := by
  generalize hU : aeU from_ r saved = U at *
  obtain ⟨hlI, hled, -, hciU, -, -, hnid, hrciU⟩ := aeMid_frame r saved
  have hUl : U.lastIdx = saved.lastIdx := by rw [← hU]; exact hlI
  have hUled : U.ledger = saved.ledger := by rw [← hU]; exact hled
  have hUci : U.commitIdx = saved.commitIdx := by rw [← hU]; exact hciU
  have hUnid : U.nodeId = saved.nodeId := by rw [← hU]; exact hnid
  have hUrci : U.retiredCommittedIdx = saved.retiredCommittedIdx := by rw [← hU]; exact hrciU
  have hUabs : (abs env.names U).log = (abs env.names saved).log := by
    rw [← hU]; exact abs_aeMid_log env.names r saved
  obtain ⟨hsz, -⟩ := inv_parts invSaved
  obtain ⟨hterm, hlog⟩ := agrees_term_log hcm
  obtain ⟨hrci, hcci, hnf⟩ := agrees_rci hcm
  simp only at hterm hlog hrci hcci hnf
  rw [hUabs] at hlog
  have hl : cm.log.length = U.lastIdx := by rw [hlog, abs_log_length hsz, hUl]
  obtain ⟨htl, htnf, htrole, htterm, htci, htrci, htvf, htpk⟩ := cutClean_eq cm U K hl
  have ⟨hc1, hc2⟩ := cutOf_le (U := U) (by omega) hK
  generalize hcut : cutOf U K = cut at *
  have htl' : (cutClean cm K).log = (abs env.names saved).log.take cut := by rw [htl, hlog]
  have htlen : (cutClean cm K).log.length = cut := by
    rw [htl', List.length_take, abs_log_length hsz]; omega
  obtain ⟨g, hlen⟩ := hg
  have gnid := g.nodeId
  have gled := g.ledger
  have gview := g.view
  have gnf := g.nf
  have gd := g.d
  have gnl := g.nl
  simp only [core, aePar] at gnid gled gview gnf gd hlen gnl
  rw [hcut] at gled hlen
  have habs : (abs env.names vars).log
      = (cutClean cm K).log ++ r.entries.drop (cut - r.prevLogIndex) := by
    show (vars.ledger.toList.take vars.lastIdx).map _ = _
    rw [gled, hlen, List.take_take, Nat.min_self, List.take_length, List.map_append, htl']
    congr 1
    · have e : U.ledger.toList = saved.ledger.toList := by rw [hUled]
      rw [e]
      show _ = ((saved.ledger.toList.take saved.lastIdx).map _).take cut
      rw [← List.map_take, List.take_take, Nat.min_eq_left (by omega)]
    · conv => rhs; rw [← hrt]
      rw [← List.map_drop, List.map_map, List.map_drop]
      rfl
  have hlx : (abs env.names vars).log
      = (aePar env.names from_ r ((r.entries.map (Exec.toExecEntry env)).toArray) U K).lx.map
          (absEntry env.names) := by
    show (vars.ledger.toList.take vars.lastIdx).map _ = _
    rw [gled, hlen, List.take_take, Nat.min_self, List.take_length]
    simp only [aePar, hcut]
  have hciV : vars.commitIdx = max (cutClean cm K).commitIndex
      (maxCommittableIndexUpTo (abs env.names vars).log
        (min r.primaryCommit (r.prevLogIndex + r.entries.length))) := by
    rw [hbd, hlx, htci, hcci]
    rfl
  obtain ⟨hrV, hrR⟩ := inv_rci invVars
  rw [show vars.nodeId = saved.nodeId by rw [gnid, hUnid]] at hrV hrR
  obtain ⟨hrS, -⟩ := inv_rci invSaved
  have hs : (cutClean cm K).retiredCommittedIndex
      = firstConf (env.names.id saved.nodeId) (cutClean cm K).log (cutClean cm K).commitIndex := by
    rw [htrci, hrci, hUrci, hrS, htl', htci, hcci, hUci, firstConf_take (by omega)]
  have hL : (cutClean cm K).log ++ r.entries.drop ((cutClean cm K).log.length - r.prevLogIndex)
      = (abs env.names vars).log := by rw [habs, htlen]
  rw [fromPrimary_eq _ _ _ hs (by rw [htlen, htci, hcci, hUci]; omega)
    (by rw [hL, ← hciV, ← hrV]; exact hrR), hL, ← hciV]
  refine ⟨by simp only [htterm, hterm, gview, Exec.aeIdx], ?_⟩
  have hvf := (agrees_vote_parts hcm).1
  simp only at hvf
  have hrole := agrees_role hcm
  simp only at hrole
  have hmr := aeMid_role r saved hns
  have hUlead : U.leadership = (aeMid r saved).leadership := by rw [← hU]; rfl
  have htr : (trackedPeers env.names vars) = [] := by
    simp [trackedPeers, gnl]
  have gvf := g.vf
  simp only [core, aePar] at gvf
  have hnfV : (cutClean cm K).isNewFollower = vars.isNewFollower := by
    rw [htnf, gnf]
    cases K <;> simp [cCut, hnf, core]
  have hcand : absRole U.leadership ≠ .candidate /\ absRole U.leadership ≠ .preVoteCandidate := by
    rw [hUlead]
    revert hmr
    cases (aeMid r saved).leadership <;> simp [absRole]
  unfold settle
  rw [← hrV]
  rcases gd with ⟨hr1, hl1, hld1⟩ | ⟨⟨s1, hs1, hr1⟩, hl1, hld1⟩
  · simp only [agrees, abs, htr, hr1, htrci, hrci, hl1, hld1, hUrci, htrole, hrole, htterm, hterm,
      gview, hvf, htvf, htpk, hnfV, gvf]
    cases saved.retiredCommittedIdx <;> simp [hcand]
  · have hsn : saved.retiredCommittedIdx = none := by
      cases hsr : saved.retiredCommittedIdx with
      | none => rfl
      | some x =>
          rw [hsr] at hrS
          have hpre : (abs env.names saved).log.take saved.commitIdx
              <+: (abs env.names vars).log.take vars.commitIdx := by
            have e : (abs env.names saved).log.take saved.commitIdx
                = (cutClean cm K).log.take saved.commitIdx := by
              rw [htl', List.take_take, Nat.min_eq_left (by omega)]
            rw [e, habs]
            exact take_prefix_take (List.prefix_append _ _) (by rw [hciV, htci, hcci, hUci]; omega)
          have h1 := firstConf_mono hrS.symm hpre
          rw [← hrV, hr1] at h1
          have h2 := firstConf_le hrS.symm
          rw [Option.some.injEq] at h1
          rw [hUci] at hs1
          omega
    simp only [agrees, abs, htr, hr1, htrci, hrci, hl1, hld1, hUrci, hsn, htterm, hterm,
      gview, htvf, hvf, gvf, hnfV]
    simp [absRole]

end Consensus.TraceValidation.Proofs.Ae
