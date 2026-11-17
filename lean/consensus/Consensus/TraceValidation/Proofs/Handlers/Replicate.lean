module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplCommit

@[expose] public section

/-!
# Obligation: `replicate` (not reviewed)

A leader replicates a batch of entries (`replicate_entry`, with its hooks, `put_entry` and
flushes), then runs `update_commit` only if no other node was in its active configurations
before the batch. The clean counterpart is one `append` input with the batch's entries, or
none for an empty batch. With other nodes, the clean `advanceCommit` cannot move
(`Mid.stuck`); without them, `update_commit` chooses the clean `highestCommittableIndex`, and
the node cannot step down, as it is not removed (`alone_not_removed`).
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation (Names Env abs agrees inv msgInv UnnamedUnmatched)
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Life

theorem firstLogIndexAfter_isSome {l : List Model.Node.Entry} {p : EntryContent -> Bool}
    : (firstLogIndexAfter l 0 p).isSome
      <-> exists (j : Nat) (x : Model.Node.Entry),
            l[j]? = some x /\ p x.content = true := by
  unfold firstLogIndexAfter
  rw [Option.isSome_map, List.find?_isSome]
  constructor
  · rintro ⟨⟨x, k⟩, mem, hp⟩
    rw [List.mem_zipIdx_iff_le_and_getElem?_sub] at mem
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hp
    exact ⟨k - 1, x, mem.2, hp.2⟩
  · rintro ⟨j, x, hj, hp⟩
    refine ⟨(x, j + 1), ?_, ?_⟩
    · rw [List.mem_zipIdx_iff_le_and_getElem?_sub]
      simpa using hj
    · simp [hp]

variable {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}

/-- What `replicate` leaves, from a leader `v0` and a clean state `cl0`. -/
def Out (env : Env) (node : NodeID) (v0 : State) (cl0 : NodeState) (v : State)
    (o : Outbox)
    : Prop :=
  exists v1 o1,
    Batch env node v0 cl0 v1 o1
    /\ ((v0.otherNodesInActiveConfigs.isEmpty = false /\ v = v1 /\ o = o1)
        \/ (v0.otherNodesInActiveConfigs.isEmpty = true /\ UcOut env v1 o1 v o))

theorem replicate_tri (S : Start env.names node v0 cl0)
    : Tri env (fun v o => v = v0 /\ o = []) Exec.replicate
        fun _ => Out env node v0 cl0 := by
  unfold Exec.replicate
  refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
  refine Tri.getV_bind fun v => ?_
  refine tri_fact (φ := v = v0) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst v
  refine Tri.conseq (P' := fun w o => w = v0 /\ o = []) ?_ (fun _ _ p => p.1)
    fun _ _ _ q => q
  have g : (v0.leadership == .leader && !v0.isRetiredCommitted) = true := by
    simp [S.leader, S.notRC]
  simp only [g, ↓reduceIte]
  refine Tri.bind (Tri.keeps Spec.Keeps.get) fun ctx => ?_
  refine Tri.bind (Tri.conseq (entries_tri S _) (fun v o p => Or.inl p) fun _ _ _ q => q)
    fun _ => ?_
  refine Tri.ite (fun alone => ?_) fun others => ?_
  · refine tri_pin fun v1 o1 L => ?_
    obtain ⟨es, cl, -, M, -⟩ := L.batch S
    have uc := updateCommit_hoare env (v1 := v1) (o1 := o1)
      (M.frame.leadership.trans S.leader) (M.cover S) (M.rcRetired alone)
    exact fun c a c' e p r => by
      obtain ⟨e', q⟩ := uc c a c' e p r
      exact ⟨e', v1, o1, L.batch S, Or.inr ⟨alone, q⟩⟩
  · exact Tri.conseq (Tri.pure' ()) (fun v o L => ⟨v, o, L.batch S,
      Or.inl ⟨Bool.eq_false_iff.mpr others, rfl, rfl⟩⟩) fun _ _ _ q => q

theorem replicate_fails
    (no : Not (v0.leadership = .leader /\ v0.isRetiredCommitted = false))
    : Tri env (fun v o => v = v0 /\ o = []) Exec.replicate fun _ _ _ => False := by
  unfold Exec.replicate
  refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
  refine Tri.getV_bind fun v => ?_
  refine tri_fact (φ := v = v0) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst v
  have g : (v0.leadership == .leader && !v0.isRetiredCommitted) = false := by
    cases h1 : v0.leadership <;> cases h2 : v0.isRetiredCommitted <;> simp_all
  simp only [g, Bool.false_eq_true, ↓reduceIte]
  exact Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _

theorem Out.nodeId {v : State} {o : Outbox} (h : Out env node v0 cl0 v o)
    : v.nodeId = v0.nodeId := by
  obtain ⟨v1, o1, ⟨es, cl, -, M, -⟩, br⟩ := h
  rcases br with ⟨-, rfl, -⟩ | ⟨-, res, -, ⟨-, rfl, -⟩ | ⟨i, -, -, -, K, -⟩⟩
  · exact M.frame.nodeId
  · exact M.frame.nodeId
  · exact K.1.trans M.frame.nodeId

theorem Mid.role (S : Start env.names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid env.names node v0 cl0 cl v)
    : cl.role = .primary := by
  obtain ⟨f, rfl, -⟩ := M.clean
  exact S.role

theorem Mid.rci (S : Start env.names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid env.names node v0 cl0 cl v)
    : cl.retiredCommittedIndex = none := by
  obtain ⟨f, rfl, -⟩ := M.clean
  exact S.cleanRci

theorem emits_nil {cl : NodeState} {o : Outbox}
    (em : Emits (([] : List AppendEntryInput).foldlM (entryStep node) cl0) cl o)
    : cl = cl0 /\ o = [] := by
  have h := emits_run em
  rw [List.foldlM_nil, emits_run (emits_pure cl0)] at h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, h⟩ := h
  exact ⟨rfl, (congrArg CCF.Outputs.outgoing h).symm⟩

theorem emits_advance_le {st : NodeState} (primary : st.role = .primary)
    (le : highestCommittableIndex st node <= st.commitIndex)
    : Emits (advanceCommit (CCF.Capabilities.record node) st node) st [] := by
  have h := emits_advance (node := node) st primary
  rwa [ite_eq_left le, ite_eq_right fun c => c.1 le] at h

theorem emits_advance_keep {st : NodeState} {i : Nat} (primary : st.role = .primary)
    (hi : highestCommittableIndex st node = i) (gt : Not (i <= st.commitIndex))
    (rci : st.retiredCommittedIndex = none)
    (nrc : Not ((AeResp.latch node st i).isRetiredCommitted node))
    : Emits (advanceCommit (CCF.Capabilities.record node) st node)
        (AeResp.latch node st i) [] := by
  have h := emits_advance (node := node) st primary
  rwa [hi, ite_eq_right gt, AeResp.recordCommit_keep rci nrc, ite_eq_right fun c => nrc c.2] at h

open CCF.Sections (LocalRun) in
/-- The clean side, from the batch's clean run and the clean commit after it. -/
theorem conclude (S : Start env.names node v0 cl0)
    {cleanOthers : List (NodeID × NodeState)} {es : List AppendEntryInput}
    {cl cl' : NodeState} {o1 o2 o : Outbox} {v : State}
    (em : Emits (es.foldlM (entryStep node) cl0) cl o1)
    (ha : Emits (advanceCommit (CCF.Capabilities.record node) cl node) cl' o2)
    (still : es = [] -> cl' = cl /\ o2 = []) (out : o = o1 ++ o2)
    (agreed : agrees env.names cl' v = true) (U : UnnamedUnmatched node cl')
    (msgs : forall e, e ∈ o -> msgInv env.names e = true)
    : exists (inputs : List Input) (clean' : NodeState),
        LocalRun (protocol env) node cl0 (cleanActions env none inputs) clean' o
        /\ agrees env.names clean' v = true
        /\ UnnamedUnmatched node clean'
        /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
        /\ forall e, e ∈ o -> msgInv env.names e = true := by
  subst out
  by_cases ne : es = []
  · subst ne
    obtain ⟨rfl, rfl⟩ := emits_nil em
    obtain ⟨rfl, rfl⟩ := still rfl
    refine ⟨[], _, ?_, agreed, U, by simp, msgs⟩
    simpa [cleanActions] using LocalRun.nil (protocol := protocol env) (node := node) _
  · exact ⟨[.append es], cl', localRun_append env
      (emits_appendBatch S.role (not_rc_of_rci S.cleanRci node) ne em ha), agreed, U,
      by simp [admit], msgs⟩

open CCF.Sections (LocalRun) in
open AeResp (Agrees hc_of_agrees) in
/-- The obligation's clean side, from what `replicate` leaves. -/
theorem out_sound (S : Start env.names node v0 cl0)
    {cleanOthers : List (NodeID × NodeState)} {v : State} {o : Outbox}
    (h : Out env node v0 cl0 v o) (invV : inv env.names v = true)
    : exists (inputs : List Input) (clean' : NodeState),
        LocalRun (protocol env) node cl0 (cleanActions env none inputs) clean' o
        /\ agrees env.names clean' v = true
        /\ UnnamedUnmatched node clean'
        /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
        /\ forall e, e ∈ o -> msgInv env.names e = true := by
  obtain ⟨v1, o1, ⟨es, cl, em, M, msgs⟩, br⟩ := h
  have prim := M.role S
  have rci := M.rci S
  have cc := M.cleanCommit S
  obtain ⟨A1b, U⟩ := M.finish S
  have A1 := Agrees.of A1b
  have idle : highestCommittableIndex cl node <= cl.commitIndex
      -> exists (inputs : List Input) (clean' : NodeState),
        LocalRun (protocol env) node cl0 (cleanActions env none inputs) clean' o1
        /\ agrees env.names clean' v1 = true /\ UnnamedUnmatched node clean'
        /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
        /\ forall e, e ∈ o1 -> msgInv env.names e = true :=
    fun le => conclude S em (emits_advance_le prim le) (fun _ => ⟨rfl, rfl⟩)
      (List.append_nil _).symm A1b U msgs
  have hcEq : forall r, ReplUpdateCommit.updateCommitOf v1 0 none (v1.lastIdx + 2) = .ok r
      -> highestCommittableIndex cl node = r.getD v1.commitIdx := by
    intro r run
    rw [hc_of_agrees A1 fun n el => ?_, ← M.self S]
    · exact ReplUpdateCommit.updateCommit_eq M.hy run
    · obtain ⟨k, memK, rfl⟩ := (M.eligible n).mp el
      obtain ⟨p, memP⟩ := mem_keys.mp memK
      exact (tracked_iff (M.leader S)).mpr ⟨k, p, memP, rfl⟩
  rcases br with ⟨others, rfl, rfl⟩ | ⟨alone, res, run, ⟨le, rfl, rfl⟩ | ⟨i, rfl, lt, ile, R⟩⟩
  · exact idle (M.stuck S others)
  · exact idle (by rw [hcEq _ run, cc]; exact le)
  -- A commit.
  obtain ⟨⟨kId, kView, kLedger, kLast, kNF, kVoted, kCommit⟩, -, R⟩ := R
  have hc := hcEq _ run
  simp only [Option.getD_some] at hc
  have nmax : es ≠ [] := by
    rintro rfl
    obtain ⟨rfl, -⟩ := emits_nil em
    have := S.maximal
    omega
  have absLog : (abs env.names v).log = (abs env.names v1).log := by
    show (v.ledger.toList.take v.lastIdx).map _ = (v1.ledger.toList.take v1.lastIdx).map _
    rw [kLedger, kLast]
  have hIdV : env.names.id v.nodeId = node := by rw [kId]; exact M.self S
  have rciEq : v.retiredCommittedIdx = Ae.firstConf node cl.log i := by
    have e : (v.retiredCommittedIdx
        == firstLogIndexAfter ((abs env.names v).log.take v.commitIdx) 0
          fun x => decide (env.names.id v.nodeId ∈ x.metadata.retirementConfirmations))
        = true := by
      inv_conj invV "rci_first"
    rw [absLog, kCommit, hIdV, beq_iff_eq, ← A1.log] at e
    exact e
  have rcIff : (AeResp.latch node cl i).isRetiredCommitted node
      <-> v.isRetiredCommitted = true := by
    have e : (v.isRetiredCommitted
        == decide ((abs env.names v).isRetiredCommitted (env.names.id v.nodeId))) = true := by
      inv_conj invV "retired_committed"
    rw [hIdV, beq_iff_eq] at e
    rw [e, decide_eq_true_iff, Ae.isRetiredCommitted_iff, Ae.isRetiredCommitted_iff, absLog,
      ← A1.log]
    show _ <-> _ /\ v.retiredCommittedIdx.isSome = true
    rw [rciEq]
  rcases R with ⟨vl, vlid, ho, sub, -⟩ | ⟨vl, vlid, vrc, ho⟩
  -- Still leader.
  · have notRC : (v.leadership != .leader || !v.isRetiredCommitted) = true := by
      inv_conj invV "leader_not_retired_committed"
    simp only [vl, bne_self_eq_false, Bool.false_or, Bool.not_eq_true'] at notRC
    have nrc : Not ((AeResp.latch node cl i).isRetiredCommitted node) :=
      fun h => by rw [rcIff.mp h] at notRC; cases notRC
    have ha := emits_advance_keep prim hc (by omega) rci nrc
    obtain ⟨f, -, P⟩ := M.clean
    have sortedV := (AeResp.peerCtx invV vl (by rw [kLast]; omega)).sortedId
    have trackedV : forall n, n ∈ trackedPeers env.names v
        -> exists p, p ∈ v.allOtherNodes /\ env.names.id p.1 = n := by
      intro n m
      simp only [trackedPeers, vl, beq_self_eq_true, ↓reduceIte, List.mem_map] at m
      exact m
    have peerV1 : forall p, p ∈ v1.allOtherNodes
        -> cl.sentIndex (env.names.id p.1) = p.2.sentIdx
          /\ cl.matchIndex (env.names.id p.1) = p.2.matchIdx := by
      intro p mp
      have tr : env.names.id p.1 ∈ trackedPeers env.names v1 :=
        (tracked_iff (M.leader S)).mpr ⟨p.1, p.2, mp, rfl⟩
      have found := (lookup_iff_mem P.nodup).mpr mp
      have named := M.hy.peersNamed _ mp
      exact ⟨(A1.sent _ tr).trans (abs_sentIndex M.hy.peersNamed named found),
        (A1.match_ _ tr).trans (ReplUpdateCommit.abs_matchIndex M.hy.peersNamed named found)⟩
    have agreedV : Agrees env.names (AeResp.latch node cl i) v := by
      refine ⟨?_, ?_, ?_, kCommit.symm, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · show cl.role = _
        rw [prim, vl]
        rfl
      · show cl.currentTerm = v.currentView
        rw [A1.term, kView]
      · show cl.log = _
        rw [absLog]
        exact A1.log
      · intro n m
        obtain ⟨p, mp, rfl⟩ := trackedV n m
        exact (peerV1 p (sub p mp)).1.trans (AeResp.abs_sentIndex_of_sorted sortedV mp).symm
      · intro n m
        obtain ⟨p, mp, rfl⟩ := trackedV n m
        exact (peerV1 p (sub p mp)).2.trans (AeResp.abs_matchIndex_of_sorted sortedV mp).symm
      · show cl.isNewFollower = _
        rw [A1.newFollower, kNF]
      · show cl.votedFor = _
        rw [A1.voted, kVoted]
      · show cl.primaryKnown = _
        rw [A1.known, vlid]
      · show Ae.firstConf node cl.log i = _
        rw [rciEq]
    exact conclude S em ha (fun e => absurd e nmax) (by rw [ho, List.append_nil])
      (Agrees.to agreedV ⟨by rw [vl]; simp, by rw [vl]; simp⟩) U (by rw [ho]; exact msgs)
  -- Stepped down: impossible, as the node was not removed.
  · exfalso
    have some1 := ((Ae.isRetiredCommitted_iff _ _).mp (rcIff.mpr vrc)).2
    change (Ae.firstConf node cl.log i).isSome = true at some1
    rw [Ae.firstConf, firstLogIndexAfter_isSome] at some1
    obtain ⟨j, x, hj, hx⟩ := some1
    rw [List.getElem?_take] at hj
    split at hj
    rotate_left
    · cases hj
    have M0 := Mid.start S
    have ge : v0.commitIdx <= j := by
      refine Nat.le_of_not_lt fun jl => ?_
      have e0 : (v0.retiredCommittedIdx
          == firstLogIndexAfter ((abs env.names v0).log.take v0.commitIdx) 0
            fun x => decide (env.names.id v0.nodeId ∈ x.metadata.retirementConfirmations))
          = true := by
        inv_conj S.inv "rci_first"
      rw [S.rci, S.self, beq_iff_eq] at e0
      have len : j < cl0.log.length := by
        rw [S.log, ReplUpdateCommit.abs_log_length M0.hy.size]
        have := M0.hy.commitLe
        omega
      obtain ⟨T, hT⟩ := M.isPrefix
      have some0 := (firstLogIndexAfter_isSome (l := (abs env.names v0).log.take v0.commitIdx)
        (p := fun x => decide (node ∈ x.metadata.retirementConfirmations))).mpr ⟨j, x, ?_, hx⟩
      · rw [← e0] at some0
        cases some0
      · rw [List.getElem?_take, ite_eq_left jl, ← S.log, ← List.getElem?_append_left len (l₂ := T),
          hT, ← A1.log]
        exact hj
    have mem := M.confRemoved j x ge (by rw [← A1.log]; exact hj) node (of_decide_eq_true hx)
    have e2 : (v0.leadership != .leader
        || !v0.configurations.all (·.nodes.all (·.1 == v0.nodeId))
        || decide (env.names.id v0.nodeId ∉ removedNodes (abs env.names v0).log)) = true := by
      inv_conj S.inv "alone_not_removed"
    have all : v0.configurations.all (·.nodes.all (·.1 == v0.nodeId)) = true := by
      simp only [List.all_eq_true, beq_iff_eq]
      exact (others_empty_iff v0).mp alone
    rw [S.leader, all, S.self] at e2
    simp only [bne_self_eq_false, Bool.not_true, Bool.or_false, Bool.false_or,
      decide_eq_true_eq] at e2
    exact e2 mem

section Witness

variable {names : Names}

theorem agrees_abs (v : State) : agrees names (abs names v) v = true := by
  simp [agrees]

theorem unmatched_abs {v : State} (h : inv names v = true) (lead : v.leadership = .leader)
    : UnnamedUnmatched (names.id v.nodeId) (abs names v) := by
  intro _ n _ nm
  simp only [abs]
  split
  · rename_i k p hf
    exfalso
    have mem := List.mem_of_find?_eq_some hf
    have e := List.find?_some hf
    simp only [beq_iff_eq] at e
    exact nm (AeResp.eligible_mem_history
      ((AeResp.peerCtx h lead (AeResp.leader_nonempty h lead mem)).eligible_iff.mpr ⟨_, mem, e⟩))
  · rfl

end Witness

end Consensus.TraceValidation.Proofs.Repl

namespace Consensus.TraceValidation.Proofs
open Consensus.Model.Node
open Consensus.TraceValidation (abs agrees)
open Repl Life

theorem replicateSound (env : Env) : ReplicateSound env := by
  intro node saved actions c vars others cleanOthers savedName savedId invSaved _ _ ran _
    finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  by_cases able : saved.leadership = .leader /\ saved.isRetiredCommitted = false
  rotate_left
  · exact (Tri.run (replicate_fails able) ⟨rfl, rfl⟩ ran).elim
  obtain ⟨lead, notRC⟩ := able
  have start : forall cl0, agrees env.names cl0 saved = true -> UnnamedUnmatched node cl0
      -> Start env.names node saved cl0 :=
    fun _ a u => ⟨invSaved, a, u, savedId, lead, notRC, AeResp.leader_rci_none invSaved lead⟩
  have out : forall cl0, Start env.names node saved cl0
      -> Out env node saved cl0 c.vars c.outbox :=
    fun _ S => Tri.run (replicate_tri S) ⟨rfl, rfl⟩ ran
  refine ⟨(out _ (start _ (agrees_abs saved)
    (savedId ▸ unmatched_abs invSaved lead))).nodeId, fun clean _ agreed unmatched => ?_⟩
  have S := start clean agreed unmatched
  exact out_sound S (out clean S) invVars

end Consensus.TraceValidation.Proofs
