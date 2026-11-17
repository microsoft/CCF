module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespMain
public import Consensus.TraceValidation.Proofs.Handlers.Nomination
public import Consensus.TraceValidation.Proofs.Handlers.AeMatch

@[expose] public section

/-!
# Obligation: `append_entries_response` (not reviewed)

The driver's `recv_append_entries_response`. Responses from unknown senders, to non-leaders,
or of a stale term change nothing; a newer term makes the node a follower. A NACK lowers the
sent index to the retry point. An ACK raises the sender's match and sent indices and then runs
`update_commit`: no commit changes nothing more; a commit either keeps the node leader, or
(when the node's own retirement is now committed) steps down after nominating a successor.
Each case is matched by the clean `appendEntriesResponse` run (`AeResp.handler_spec`,
`AeResp.commit_spec`, `AeResp.tvSuccessor_core`).
-/

namespace Consensus.TraceValidation.Proofs.AeResp
open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation (
  Names Env abs absRole agrees trackedPeers inv invChecks msgInv)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)

/-- The state `recordCommit` builds before it may clear the role. -/
abbrev latch (node : NodeID) (st : NodeState) (i : Nat) : NodeState :=
  { st with commitIndex := i, retiredCommittedIndex := Ae.firstConf node st.log i }

theorem recordCommit_clear {node : NodeID} {st : NodeState} {i : Nat}
    (h : st.retiredCommittedIndex = none) (c : (latch node st i).isRetiredCommitted node)
    : st.recordCommit node i
      = { latch node st i with role := .none, primaryKnown := false } := by
  unfold NodeState.recordCommit
  simp only [latch, Ae.firstConf] at c
  simp [h, Ae.firstConf, c]

theorem recordCommit_keep {node : NodeID} {st : NodeState} {i : Nat}
    (h : st.retiredCommittedIndex = none)
    (c : ¬ (latch node st i).isRetiredCommitted node)
    : st.recordCommit node i = latch node st i := by
  unfold NodeState.recordCommit
  simp only [latch, Ae.firstConf] at c
  simp [h, Ae.firstConf, c]

/-- The clean state after a success response, before the commit. -/
abbrev ackState (st : NodeState) (source : NodeID) (idx : Nat) : NodeState :=
  {
    st with
      matchIndex :=
        CCF.Function.update st.matchIndex source (max (st.matchIndex source) idx)
  }

/-- The clean side of a hold, from one clean receive. -/
theorem concl_of {env : Env} {node source : NodeID} {r : AppendEntriesResponse}
    {cleanOthers : List (NodeID × NodeState)} {clean clean' : NodeState} {vars : State}
    {outbox : Outbox} {out : CCF.Outputs NodeID Message Notification}
    (step : cleanRun node source clean r = some (clean', out))
    (sends : out.outgoing = outbox) (agreed : agrees env.names clean' vars = true)
    (unmatched : UnnamedUnmatched node clean')
    (msgs : forall e, e ∈ outbox -> msgInv env.names e = true)
    : exists (inputs : List Input) (clean' : NodeState),
        LocalRun (protocol env) node clean
          (cleanActions env (some (source, .appendEntriesResponse r)) inputs) clean'
          outbox
        /\ agrees env.names clean' vars = true
        /\ UnnamedUnmatched node clean'
        /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
        /\ forall envelope, envelope ∈ outbox -> msgInv env.names envelope = true :=
  ⟨[], clean', sends ▸ localRun_of step, agreed, unmatched, by simp, msgs⟩

end Consensus.TraceValidation.Proofs.AeResp

namespace Consensus.TraceValidation.Proofs
open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation (
  Names Env abs absRole agrees trackedPeers inv invChecks msgInv)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open AeResp

theorem appendEntriesResponseSound (env : Env) : AppendEntriesResponseSound env := by
  intro node source r saved actions c vars others cleanOthers savedName savedId invSaved msgOk _ ran _
    finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have hsrc : env.names.id (env.names.name source) = source :=
    Ae.msgInv_source (msgOk source _ rfl)
  have cover : forall nd, saved.peer? (env.names.name source) = some nd
      -> saved.leadership = .leader
      -> Cover (saved.setPeer (env.names.name source) (ackPeer nd r)) := by
    intro nd hp lead
    have mem := lookup_mem hp
    have L0 := leader_nonempty invSaved lead mem
    exact cover_setPeer (peerCtx invSaved lead L0).sortedStr mem (cover_of_inv invSaved lead L0)
  obtain ⟨nd, hp, outcome⟩ := Ae.Hoare.run
    (handler_spec env saved (env.names.name source) r cover
      fun lead => rcRetired_of_inv invSaved lead) ⟨rfl, rfl⟩ ran
  have mem := lookup_mem hp
  -- Not a leader: nothing changes.
  rcases outcome with ⟨nl, hv, ho⟩ | outcome
  · rw [hv, ho]
    refine ⟨rfl, fun clean _ agreed unmatched => ?_⟩
    have np : clean.role ≠ .primary := by
      rw [(Agrees.of agreed).role]
      cases h : saved.leadership <;> simp_all [absRole]
    exact concl_of (receive_notPrimary r np) rfl agreed unmatched (by simp)
  have lead : saved.leadership = .leader := by
    rcases outcome with ⟨l, _⟩ | ⟨l, _⟩ | ⟨l, _⟩ | ⟨l, _⟩ | ⟨l, _⟩ <;> exact l
  have L0 := leader_nonempty invSaved lead mem
  have pc := peerCtx invSaved lead L0
  have facts : forall clean, agrees env.names clean saved = true
      -> Agrees env.names clean saved /\ clean.role = .primary
        /\ source ∈ eligiblePeers clean node
        /\ clean.matchIndex source = nd.matchIdx /\ clean.sentIndex source = nd.sentIdx := by
    intro clean agreed
    have A := Agrees.of agreed
    have tracked : source ∈ trackedPeers env.names saved := by
      simp only [trackedPeers, lead, beq_self_eq_true, ↓reduceIte, List.mem_map]
      exact ⟨_, mem, hsrc⟩
    refine ⟨A, by rw [A.role, lead]; rfl, ?_, ?_, ?_⟩
    · rw [Ae.eligiblePeers_congr A.log A.commit, ← savedId, pc.eligible_iff]
      exact ⟨_, mem, hsrc⟩
    · rw [A.match_ _ tracked, ← hsrc]
      exact abs_matchIndex_of_sorted pc.sortedId mem
    · rw [A.sent _ tracked, ← hsrc]
      exact abs_sentIndex_of_sorted pc.sortedId mem
  rcases outcome with ⟨_, lt, hv, ho⟩ | ⟨_, lt, ok, hv, ho⟩ | ⟨_, eq, ok, lt, hv, ho⟩
    | ⟨_, le, nok, hv, ho⟩ | ⟨_, eq, ok, le, res, run, branch⟩
  -- A newer term: become a follower.
  · rw [hv, ho]
    refine ⟨rfl, fun clean _ agreed _ => ?_⟩
    obtain ⟨A, primary, elig, -, -⟩ := facts clean agreed
    have step := receive_primary r elig primary
    rw [Ae.updateTerm_of_lt (by rw [A.term]; exact lt),
      handle_notPrimary r (by simp [Model.Node.becomeAwareOfNewTerm])] at step
    exact concl_of step rfl (Ae.agrees_bant r.term agreed)
      (fun h => by simp [Model.Node.becomeAwareOfNewTerm] at h) (by simp)
  -- A stale success: ignored.
  · rw [hv, ho]
    refine ⟨rfl, fun clean _ agreed unmatched => ?_⟩
    obtain ⟨A, primary, elig, -, -⟩ := facts clean agreed
    have step := receive_primary r elig primary
    rw [Ae.updateTerm_of_ge (by rw [A.term]; omega),
      handle_stale r primary ok (by rw [A.term]; omega)] at step
    exact concl_of step rfl agreed unmatched (by simp)
  -- A success below the match index: no change, and the clean commit does not advance.
  · rw [hv, ho]
    refine ⟨rfl, fun clean _ agreed unmatched => ?_⟩
    obtain ⟨A, primary, elig, matched, -⟩ := facts clean agreed
    have step := receive_primary r elig primary
    rw [Ae.updateTerm_of_ge (by rw [A.term]; omega),
      handle_ack r primary ok (by rw [A.term]; exact eq),
      Nat.max_eq_left (by omega : r.lastLogIndex <= clean.matchIndex source), update_self,
      show ({ clean with matchIndex := clean.matchIndex } : NodeState) = clean from rfl,
      advance_run node clean primary] at step
    have maximal : (saved.leadership != .leader
        || decide (highestCommittableIndex (abs env.names saved) (env.names.id saved.nodeId)
          <= saved.commitIdx)) = true := by
      inv_conj invSaved "commit_maximal"
    simp only [lead, bne_self_eq_false, Bool.false_or, decide_eq_true_eq] at maximal
    have hle : highestCommittableIndex clean node <= clean.commitIndex := by
      rw [hc_of_agrees A (fun n e => tracked_of_eligible pc lead A (by rw [savedId]; exact e)),
        A.commit, ← savedId]
      exact maximal
    simp only [hle, ↓reduceIte, not_true_eq_false, false_and] at step
    exact concl_of step rfl agreed unmatched (by simp)
  -- A NACK: the send index moves back.
  · rw [hv, ho]
    refine ⟨rfl, fun clean _ agreed unmatched => ?_⟩
    obtain ⟨A, primary, elig, matched, sent⟩ := facts clean agreed
    have step := receive_primary r elig primary
    rw [Ae.updateTerm_of_ge (by rw [A.term]; omega), handle_nack r primary nok] at step
    refine concl_of step rfl
      (Agrees.to (agrees_setPeer A pc mem rfl rfl rfl rfl rfl rfl rfl rfl ?_ ?_)
        ⟨by simp [State.setPeer, lead], by simp [State.setPeer, lead]⟩) unmatched (by simp)
    · show clean.matchIndex = CCF.Function.update clean.matchIndex (env.names.id (env.names.name source)) nd.matchIdx
      rw [hsrc, ← matched, update_self]
    · show _ = CCF.Function.update clean.sentIndex (env.names.id (env.names.name source))
        (max (min (saved.highestMatch r.term r.lastLogIndex) nd.sentIdx) nd.matchIdx)
      rw [hsrc, matched, sent, Ae.highestMatch_eq invSaved, ← A.log]
  -- A success at or above the match index: the match index moves up and the commit may advance.
  · have hv1 := setPeer_eq saved pc.sortedStr mem (p := ackPeer nd r)
    rw [hv1] at run branch
    generalize hW : ({ saved with
        allOtherNodes := putPeer saved.allOtherNodes (env.names.name source) (ackPeer nd r) }
        : State) = W at run branch
    have wLead : W.leadership = .leader := by rw [← hW]; exact lead
    have wKeys : W.allOtherNodes.map Prod.fst = saved.allOtherNodes.map Prod.fst := by
      rw [← hW]; exact putPeer_keys _ _ _
    have wSorted : W.allOtherNodes.Pairwise fun p q => env.names.id p.1 < env.names.id q.1 := by
      rw [← hW]
      exact putPeer_sorted (r := fun a b => env.names.id a < env.names.id b) pc.sortedId
    have hy0 := ReplUpdateCommit.Hyps.ofInv invSaved
    have hy : ReplUpdateCommit.Hyps env.names W := by
      rw [← hW]
      refine { hy0 with peersNamed := fun p m => ?_ }
      have : p.1 ∈ (putPeer saved.allOtherNodes (env.names.name source) (ackPeer nd r)).map
          Prod.fst := List.mem_map_of_mem m
      rw [putPeer_keys] at this
      obtain ⟨q, mq, e⟩ := List.mem_map.mp this
      rw [← e]
      exact hy0.peersNamed q mq
    have hcW : highestCommittableIndex (abs env.names W) node = res.getD saved.commitIdx := by
      have := ReplUpdateCommit.updateCommit_eq hy run
      rw [← hW] at this ⊢
      rw [← savedId]
      exact this
    have cleanSide : forall clean, agrees env.names clean saved = true
        -> Agrees env.names (ackState clean source r.lastLogIndex) W
          /\ clean.role = .primary /\ source ∈ eligiblePeers clean node
          /\ highestCommittableIndex (ackState clean source r.lastLogIndex) node
            = res.getD saved.commitIdx
          /\ cleanRun node source clean r
            = (advanceCommit (CCF.Capabilities.record node) (ackState clean source r.lastLogIndex)
                node).run {} := by
      intro clean agreed
      obtain ⟨A, primary, elig, matched, sent⟩ := facts clean agreed
      have A1 := agrees_setPeer (clean1 := ackState clean source r.lastLogIndex) (p := ackPeer nd r)
        A pc mem rfl rfl rfl rfl rfl rfl rfl rfl
        (by show CCF.Function.update clean.matchIndex source
                (max (clean.matchIndex source) r.lastLogIndex)
              = CCF.Function.update clean.matchIndex (env.names.id (env.names.name source))
                (max nd.matchIdx r.lastLogIndex)
            rw [hsrc, matched])
        (by show clean.sentIndex = CCF.Function.update clean.sentIndex
              (env.names.id (env.names.name source)) nd.sentIdx
            rw [hsrc, ← sent, update_self])
      rw [hv1, hW] at A1
      have tracked : forall n, n ∈ eligiblePeers (ackState clean source r.lastLogIndex) node
          -> n ∈ trackedPeers env.names W := by
        intro n e
        rw [← hW, trackedPeers_putPeer (names := env.names) (v := saved)
          (w := { saved with
            allOtherNodes := putPeer saved.allOtherNodes (env.names.name source) (ackPeer nd r) })
          rfl rfl]
        rw [Ae.eligiblePeers_congr (a := ackState clean source r.lastLogIndex) (b := clean)
          rfl rfl] at e
        exact tracked_of_eligible pc lead A (by rw [savedId]; exact e)
      refine ⟨A1, primary, elig, (hc_of_agrees A1 tracked).trans hcW, ?_⟩
      rw [receive_primary r elig primary, Ae.updateTerm_of_ge (by rw [A.term]; omega),
        handle_ack r primary ok (by rw [A.term]; exact eq)]
    rcases branch with ⟨hle, hv, ho⟩ | ⟨i, hi, lt, -, R⟩
    -- No commit.
    · refine ⟨by rw [hv, ← hW], fun clean _ agreed unmatched => ?_⟩
      obtain ⟨A1, primary, elig, hc1, step⟩ := cleanSide clean agreed
      rw [advance_run node (ackState clean source r.lastLogIndex) primary] at step
      have h' : highestCommittableIndex (ackState clean source r.lastLogIndex) node
          <= (ackState clean source r.lastLogIndex).commitIndex := by
        rw [hc1]
        show _ <= clean.commitIndex
        rw [(Agrees.of agreed).commit]
        exact hle
      simp only [h', ↓reduceIte, not_true_eq_false, false_and] at step
      rw [hv, ho]
      exact concl_of step rfl (Agrees.to A1 ⟨by rw [wLead]; simp, by rw [wLead]; simp⟩)
        (unmatched_update unmatched rfl rfl (eligible_mem_history elig) rfl) (by simp)
    -- A commit.
    · subst hi
      obtain ⟨⟨kId, kView, kLedger, kLast, kNF, kVoted, kCommit⟩, -, R⟩ := R
      refine ⟨by rw [kId, ← hW], fun clean _ agreed unmatched => ?_⟩
      obtain ⟨A1, primary, elig, hc1, step⟩ := cleanSide clean agreed
      have A := Agrees.of agreed
      simp only [Option.getD_some] at hc1
      have nle : ¬ i <= clean.commitIndex := by
        rw [A.commit]
        omega
      rw [advance_run node (ackState clean source r.lastLogIndex) primary] at step
      simp only [hc1] at step
      simp only [nle, ↓reduceIte, not_false_eq_true, true_and] at step
      have rciNone : (ackState clean source r.lastLogIndex).retiredCommittedIndex = none :=
        A.rci.trans (leader_rci_none invSaved lead)
      have absLog : (abs env.names c.vars).log = clean.log := by
        show (c.vars.ledger.toList.take c.vars.lastIdx).map _ = _
        rw [kLedger, kLast, ← hW]
        exact A.log.symm
      have hIdV : env.names.id c.vars.nodeId = node := by rw [kId, ← hW]; exact savedId
      have rciEq : c.vars.retiredCommittedIdx = Ae.firstConf node clean.log i := by
        have e : (c.vars.retiredCommittedIdx
            == firstLogIndexAfter ((abs env.names c.vars).log.take c.vars.commitIdx) 0
              fun x => decide (env.names.id c.vars.nodeId ∈ x.metadata.retirementConfirmations))
            = true := by
          inv_conj invVars "rci_first"
        rw [absLog, kCommit, hIdV, beq_iff_eq] at e
        exact e
      have rcIff : (latch node (ackState clean source r.lastLogIndex) i).isRetiredCommitted node
          <-> c.vars.isRetiredCommitted = true := by
        have e : (c.vars.isRetiredCommitted
            == decide ((abs env.names c.vars).isRetiredCommitted (env.names.id c.vars.nodeId)))
            = true := by
          inv_conj invVars "retired_committed"
        rw [hIdV, beq_iff_eq] at e
        rw [e, decide_eq_true_iff, Ae.isRetiredCommitted_iff, Ae.isRetiredCommitted_iff, absLog]
        show _ <-> _ /\ c.vars.retiredCommittedIdx.isSome = true
        rw [rciEq]
      have trackedW : forall p, p ∈ W.allOtherNodes -> env.names.id p.1 ∈ trackedPeers env.names W := by
        intro p m
        simp only [trackedPeers, wLead, beq_self_eq_true, ↓reduceIte, List.mem_map]
        exact ⟨p, m, rfl⟩
      rcases R with ⟨vl, vlid, ho, sub, -⟩ | ⟨vl, vlid, vrc, ho⟩
      -- Still leader.
      · have notRC : (c.vars.leadership != .leader || !c.vars.isRetiredCommitted) = true := by
          inv_conj invVars "leader_not_retired_committed"
        simp only [vl, bne_self_eq_false, Bool.false_or, Bool.not_eq_true'] at notRC
        have nrc : ¬ (latch node (ackState clean source r.lastLogIndex) i).isRetiredCommitted node :=
          fun h => by rw [rcIff.mp h] at notRC; cases notRC
        rw [recordCommit_keep rciNone nrc] at step
        simp only [nrc, ↓reduceIte] at step
        have sortedV := (peerCtx invVars vl (by rw [kLast, ← hW]; exact L0)).sortedId
        have trackedV : forall n, n ∈ trackedPeers env.names c.vars
            -> exists p, p ∈ c.vars.allOtherNodes /\ env.names.id p.1 = n := by
          intro n m
          simp only [trackedPeers, vl, beq_self_eq_true, ↓reduceIte, List.mem_map] at m
          exact m
        have agreedV : Agrees env.names (latch node (ackState clean source r.lastLogIndex) i)
            c.vars := by
          refine ⟨?_, ?_, absLog.symm, kCommit.symm, ?_, ?_, ?_, ?_, ?_, ?_⟩
          · show clean.role = _
            rw [primary, vl]
            rfl
          · show clean.currentTerm = c.vars.currentView
            rw [A.term, kView, ← hW]
          · intro n m
            obtain ⟨p, mp, rfl⟩ := trackedV n m
            have mW := sub p mp
            exact ((A1.sent _ (trackedW p mW)).trans (abs_sentIndex_of_sorted wSorted mW)).trans
              (abs_sentIndex_of_sorted sortedV mp).symm
          · intro n m
            obtain ⟨p, mp, rfl⟩ := trackedV n m
            have mW := sub p mp
            exact ((A1.match_ _ (trackedW p mW)).trans (abs_matchIndex_of_sorted wSorted mW)).trans
              (abs_matchIndex_of_sorted sortedV mp).symm
          · show clean.isNewFollower = c.vars.isNewFollower
            rw [A.newFollower, kNF, ← hW]
          · show clean.votedFor = _
            rw [A.voted, kVoted, ← hW]
          · show clean.primaryKnown = c.vars.leaderId.isSome
            rw [A.known, vlid, ← hW]
          · show Ae.firstConf node clean.log i = _
            rw [rciEq]
        rw [ho]
        exact concl_of step rfl (Agrees.to agreedV ⟨by rw [vl]; simp, by rw [vl]; simp⟩)
          (unmatched_update unmatched rfl rfl (eligible_mem_history elig) rfl) (by simp)
      -- Stepped down, having nominated a successor.
      · have yrc := rcIff.mpr vrc
        rw [recordCommit_clear rciNone yrc] at step
        have yrc' : ({ latch node (ackState clean source r.lastLogIndex) i with
            role := .none, primaryKnown := false } : NodeState).isRetiredCommitted node :=
          (Ae.isRetiredCommitted_iff _ _).mpr ((Ae.isRetiredCommitted_iff _ _).mp yrc)
        split at step
        rotate_left
        · exact absurd yrc' ‹_›
        have matchedW : forall p, p ∈ W.allOtherNodes
            -> (ackState clean source r.lastLogIndex).matchIndex (env.names.id p.1) = p.2.matchIdx :=
          fun p m => (A1.match_ _ (trackedW p m)).trans (abs_matchIndex_of_sorted wSorted m)
        have succ := tvSuccessor_core invSaved lead (w := W) (c := ackState clean source r.lastLogIndex)
          A.log A.commit wKeys (by rw [← hW]) matchedW
        rw [savedId] at succ
        have wId : W.nodeId = saved.nodeId := by rw [← hW]
        have wView : W.currentView = saved.currentView := by rw [← hW]
        have sends : nomSends node (ackState clean source r.lastLogIndex)
            = nominationSends env.names W := by
          unfold nomSends nominationSends
          rw [← succ]
          cases tvSuccessor W <;> simp [wLead, wId, savedId, wView, A.term]
        have agreedV : Agrees env.names { latch node (ackState clean source r.lastLogIndex) i with
            role := .none, primaryKnown := false } c.vars := by
          refine ⟨by rw [vl]; rfl, ?_, absLog.symm, kCommit.symm, ?_, ?_, ?_, ?_,
            by rw [vlid]; rfl, ?_⟩
          · show clean.currentTerm = c.vars.currentView
            rw [A.term, kView, ← hW]
          · intro n m
            simp [trackedPeers, vl] at m
          · intro n m
            simp [trackedPeers, vl] at m
          · show clean.isNewFollower = c.vars.isNewFollower
            rw [A.newFollower, kNF, ← hW]
          · show clean.votedFor = _
            rw [A.voted, kVoted, ← hW]
          · show Ae.firstConf node clean.log i = _
            rw [rciEq]
        rw [List.nil_append] at ho
        rw [ho]
        refine concl_of step sends
          (Agrees.to agreedV ⟨by rw [vl]; simp, by rw [vl]; simp⟩)
          (fun h => by simp at h)
          ?_
        have hnode : env.names.id (env.names.name node) = node := by rw [← savedName]; exact savedId
        intro envelope memE
        rw [← sends] at memE
        unfold nomSends at memE
        cases hs : findSuccessor (ackState clean source r.lastLogIndex) node with
        | none => simp [hs] at memE
        | some t =>
            simp only [hs, Option.map_some, Option.toList_some, List.mem_singleton] at memE
            subst memE
            have ne := findSuccessor_ne hs
            simp only [msgInv, hnode, beq_self_eq_true, Bool.true_and, bne_iff_ne, ne_eq,
              Bool.and_true]
            exact fun e => ne e.symm
end Consensus.TraceValidation.Proofs
