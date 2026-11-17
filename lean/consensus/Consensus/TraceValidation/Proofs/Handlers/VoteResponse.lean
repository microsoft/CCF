module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteCandidate

@[expose] public section

/-!
# `recv_request_vote_response` against the clean receive (not reviewed)

M_tv ignores a response from a node that is not a peer, adopts a newer view, ignores a stale
or unrequested response and, for a granted (pre-)vote from a member of its configurations,
records it; on a quorum a candidate becomes leader and a pre-vote candidate becomes candidate.
The clean receive does the same: a peer is an eligible peer (`peer_iff_eligible`), the
recorded voters are the clean (pre-)votes granted plus the voter (`voters_record`), and
M_tv's quorum is the clean `hasQuorum` (`quorum_tally`).
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae (Hoare)
open Consensus.TraceValidation (Names)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (Named named_inj absConfig)

/-- A postcondition for every clean state with a property, from one such state. -/
theorem hoare_all {env : Env} {α ι : Type} {H : ι -> Prop} {P : State -> Outbox -> Prop}
    {x : M α} {Q : ι -> α -> State -> Outbox -> Prop} (i0 : ι) (h0 : H i0)
    (h : forall i, H i -> Hoare env P x (Q i))
    : Hoare env P x fun a v o => forall i, H i -> Q i a v o :=
  fun c a c' e p r => ⟨(h i0 h0 c a c' e p r).1, fun i hi => (h i hi c a c' e p r).2⟩

theorem agrees_abs (names : Names) (d : State) : agrees names (abs names d) d = true := by
  simp [agrees]

/-- An initialised node with a peer has a ledger (`inv`'s `empty_ledger_alone`). -/
theorem pos_of_peer {names : Names} {d : State} (h : inv names d = true)
    (init : initialised d = true) (peer : d.allOtherNodes ≠ [])
    : 0 < d.lastIdx := by
  have alone : (d.currentView == 0 && d.leadership == .none) || d.lastIdx != 0
      || d.allOtherNodes.isEmpty := by
    inv_conj h "empty_ledger_alone"
  unfold initialised at init
  simp only [bne_iff_ne, ne_eq, Bool.or_eq_true] at init
  simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq,
    List.isEmpty_iff] at alone
  rcases alone with (⟨a, b⟩ | a) | a
  · rcases init with i | i <;> contradiction
  · omega
  · exact absurd a peer

/-- The (pre-)vote response message. -/
def respMsg (pre : Bool) (r : RequestVoteResponse) : Message :=
  if pre then .requestPreVoteResponse r else .requestVoteResponse r

theorem receive_resp (caps : Caps) (self source : NodeID) (state : NodeState) (pre : Bool)
    (r : RequestVoteResponse)
    : Model.Node.receive caps self source state (respMsg pre r)
      = if source ∉ eligiblePeers state self then
          pure state
        else if pre then
          handleRequestPreVoteResponse caps self (updateTerm state r.term) source r
        else
          handleRequestVoteResponse caps self (updateTerm state r.term) source r := by
  cases pre <;> simp [respMsg, Model.Node.receive, observeTerm, Message.term]

theorem localRun_receive (env : Env) {node source : NodeID} {m : Message}
    {clean clean' : NodeState} {sends : List (CCF.Envelope NodeID Message)}
    (h
      : Emits (Model.Node.receive (CCF.Capabilities.record node) node source clean m)
          clean' sends)
    : CCF.Sections.LocalRun (protocol env) node clean
        (cleanActions env (some (source, m)) []) clean' sends := by
  have run := CCF.Sections.LocalRun.cons (protocol := protocol env) (node := node)
    (state := clean) (action := (protocol env).receive source m) (h {})
    (CCF.Sections.LocalRun.nil _)
  simpa [cleanActions] using run

theorem leaderPre_votes {names : Names} {e : State} (h : inv names e = true)
    (L0 : 0 < e.lastIdx) (cand : e.leadership = .candidate) (X : List VoteRec)
    : LeaderPre names { e with votesForMe := X } := by
  obtain ⟨s1, s2, s3, s4, s5, s6, -⟩ := inv_parts h
  have vle : e.views.all (· <= e.lastIdx + 1) = true := by inv_conj h "views_le_last"
  have vlt : (e.leadership != .candidate || e.views.size < e.currentView) = true := by
    inv_conj h "candidate_views"
  have ret : e.isRetiredCommitted
      = decide ((abs names e).isRetiredCommitted (names.id e.nodeId)) := by
    have hc : (e.isRetiredCommitted
        == decide ((abs names e).isRetiredCommitted (names.id e.nodeId))) = true := by
      inv_conj h "retired_committed"
    simpa using hc
  simp only [cand, bne_self_eq_false, Bool.false_or, decide_eq_true_eq] at vlt
  refine ⟨by simp [cand], vlt, fun x hx => ?_, s1, s2, s3, s4, s5, ret, Or.inr ?_⟩
  · have := Array.all_eq_true_iff_forall_mem.mp vle x (by simpa using hx)
    simpa using this
  · rw [eligiblePeers_congr (a := abs names { e with votesForMe := X }) (b := abs names e) rfl rfl]
    exact peers_of_inv (d := e) h L0

theorem becomeLeader_all (env : Env) {d : State} {o0 : Outbox}
    (pre : LeaderPre env.names d)
    : Hoare env (fun v o => v = d /\ o = o0) Exec.becomeLeader
        (fun b v o =>
          forall c,
            agrees env.names c d = true
            -> (c.isRetiredCommitted (env.names.id d.nodeId)
                  /\ b = false
                  /\ v = d
                  /\ o = o0)
                \/ (Not (c.isRetiredCommitted (env.names.id d.nodeId))
                    /\ b = true
                    /\ exists sends,
                        o = o0 ++ sends
                        /\ v.nodeId = d.nodeId
                        /\ v.currentView = d.currentView
                        /\ v.leadership = .leader
                        /\ (forall x, x ∈ v.configurations -> x ∈ d.configurations)
                        /\ (inv env.names v = true
                            -> Emits
                                  (becomePrimary
                                    (CCF.Capabilities.record (env.names.id d.nodeId))
                                    (env.names.id d.nodeId) c)
                                  (primaryState c) sends
                                /\ agrees env.names (primaryState c) v = true
                                /\ forall e, e ∈ sends -> msgInv env.names e = true))) :=
  hoare_all (abs env.names d) (agrees_abs _ _) fun _ ag => becomeLeader_spec env pre ag

/-- The clean facts `becomeCandidate_spec` needs of `c`. -/
def CandFrame (names : Names) (e : State) (c : NodeState) : Prop :=
  c.currentTerm = e.currentView
  /\ c.log = (abs names e).log
  /\ c.commitIndex = e.commitIdx
  /\ c.isNewFollower = e.isNewFollower
  /\ c.retiredCommittedIndex = e.retiredCommittedIdx
  /\ UnnamedUnmatched (names.id e.nodeId) c

theorem becomeCandidate_all (env : Env) {e : State} {X : List VoteRec} {o0 : Outbox}
    (h : inv env.names e = true) (L0 : 0 < e.lastIdx) (ne : e.configurations ≠ [])
    : Hoare env (fun v o => v = { e with votesForMe := X } /\ o = o0) Exec.becomeCandidate
        (fun _ v o =>
          forall c,
            CandFrame env.names e c
            -> exists sends,
                o = o0 ++ sends
                /\ v.nodeId = e.nodeId
                /\ (inv env.names v = true
                    -> exists c',
                        Emits
                          (Model.Node.becomeCandidate
                            (CCF.Capabilities.record (env.names.id e.nodeId)) c
                            (env.names.id e.nodeId))
                          c' sends
                        /\ agrees env.names c' v = true
                        /\ UnnamedUnmatched (env.names.id e.nodeId) c'
                        /\ forall m, m ∈ sends -> msgInv env.names m = true)) :=
  hoare_all { abs env.names e with role := .follower }
    ⟨rfl, rfl, rfl, rfl, rfl, fun hp => absurd hp (by simp)⟩
    fun _ ⟨ht, hl, hc, hnf, hrc, um⟩ =>
      becomeCandidate_spec env h L0 ne ht hl hc hnf hrc um

/-! ## The clean receive of a response -/

/-- A response the clean handler acts on: a granted (pre-)vote in the current term. -/
def Counted (pre : Bool) (state : NodeState) (r : RequestVoteResponse) : Prop :=
  (if pre then state.role = .preVoteCandidate else state.role = .candidate)
  /\ r.term = state.currentTerm
  /\ r.voteGranted = true

theorem receive_notPeer {caps : Caps} {self source : NodeID} {state : NodeState}
    {pre : Bool} {r : RequestVoteResponse} (np : source ∉ eligiblePeers state self)
    : Model.Node.receive caps self source state (respMsg pre r) = pure state := by
  rw [receive_resp]
  simp [np]

theorem receive_newer {caps : Caps} {self source : NodeID} {state : NodeState}
    {pre : Bool} {r : RequestVoteResponse} (el : source ∈ eligiblePeers state self)
    (lt : state.currentTerm < r.term)
    : Model.Node.receive caps self source state (respMsg pre r)
      = pure (Model.Node.becomeAwareOfNewTerm state r.term) := by
  rw [receive_resp, updateTerm_of_lt lt]
  cases pre <;> simp [el, handleRequestVoteResponse, handleRequestPreVoteResponse,
    Model.Node.becomeAwareOfNewTerm]

theorem receive_ignored {caps : Caps} {self source : NodeID} {state : NodeState}
    {pre : Bool} {r : RequestVoteResponse} (el : source ∈ eligiblePeers state self)
    (ge : ¬ state.currentTerm < r.term) (no : ¬ Counted pre state r)
    : Model.Node.receive caps self source state (respMsg pre r) = pure state := by
  rw [receive_resp, updateTerm_of_ge ge]
  cases pre <;> simp only [Counted, Bool.false_eq_true, ite_true, ite_false] at no <;>
    simp only [el, not_true_eq_false, ite_false, Bool.false_eq_true, ite_true,
      handleRequestVoteResponse, handleRequestPreVoteResponse, no]

theorem receive_vote {caps : Caps} {self source : NodeID} {state : NodeState}
    {r : RequestVoteResponse} (el : source ∈ eligiblePeers state self)
    (yes : Counted false state r)
    : Model.Node.receive caps self source state (respMsg false r)
      = electIfQuorum caps self
          { state with votesGranted := insert source state.votesGranted } := by
  obtain ⟨hr, ht, hg⟩ := yes
  rw [receive_resp, updateTerm_of_ge (by omega)]
  simp at hr
  simp [el, handleRequestVoteResponse, hr, ht, hg]

theorem receive_preVote {caps : Caps} {self source : NodeID} {state : NodeState}
    {r : RequestVoteResponse} (el : source ∈ eligiblePeers state self)
    (yes : Counted true state r)
    : Model.Node.receive caps self source state (respMsg true r)
      = let s := { state with preVotesGranted := insert source state.preVotesGranted }
        if hasQuorum s.activeConfigurations s.preVotesGranted then
          Model.Node.becomeCandidate caps s self
        else
          pure s := by
  obtain ⟨hr, ht, hg⟩ := yes
  rw [receive_resp, updateTerm_of_ge (by omega)]
  simp at hr
  simp [el, handleRequestPreVoteResponse, hr, ht, hg]

theorem set_cons (names : Names) (x : NodeId) (l : List NodeId)
    : names.set (x :: l) = insert (names.id x) (names.set l) :=
  CCF.Finset.ext
    fun a => by simp [Names.set, CCF.Finset.mem_ofList, CCF.Finset.mem_insert]

theorem agrees_role {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.role = absRole d.leadership := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  exact h.1.1.1.1.1.1.1.1.1.1

theorem agrees_votes {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : (d.leadership = .candidate -> c.votesGranted = names.set (voters d))
      /\ (d.leadership = .preVoteCandidate
          -> c.preVotesGranted = names.set (voters d)) := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨-, h9⟩, h10⟩, -⟩ := h
  refine ⟨fun l => ?_, fun l => ?_⟩
  · simpa [abs, absRole, l, voters] using h9
  · simpa [abs, absRole, l, voters] using h10

theorem eligible_agrees {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true) (n : NodeID)
    : eligiblePeers c n = eligiblePeers (abs names d) n := by
  obtain ⟨-, hl, hc, -⟩ := agrees_frame h
  exact eligiblePeers_congr hl hc n

theorem agrees_votesGranted {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true) (cand : d.leadership = .candidate) (X : List VoteRec)
    : agrees names
        { c with votesGranted := names.set (voters { d with votesForMe := X }) }
        { d with votesForMe := X }
      = true := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, -⟩, h10⟩, h11⟩ := h
  simp only [abs, trackedPeers, cand, absRole] at h1 h2 h3 h4 h5 h6 h7 h8 h10 h11 ⊢
  simp_all [voters]

theorem agrees_preVotesGranted {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true) (cand : d.leadership = .preVoteCandidate)
    (X : List VoteRec)
    : agrees names
        { c with preVotesGranted := names.set (voters { d with votesForMe := X }) }
        { d with votesForMe := X }
      = true := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩, -⟩, h11⟩ := h
  simp only [abs, trackedPeers, cand, absRole] at h1 h2 h3 h4 h5 h6 h7 h8 h9 h11 ⊢
  simp_all [voters]

/-- The (pre-)candidate role a counted response needs. -/
def wantRole (pre : Bool) : Leadership := if pre then .preVoteCandidate else .candidate

/-- What the obligation needs of a (pre-)vote response hold that ends in `v` having sent `o`. -/
def RespPost (env : Env) (node source : NodeID) (pre : Bool) (r : RequestVoteResponse)
    (saved : State) (v : State) (o : Outbox)
    : Prop :=
  v.nodeId = saved.nodeId
  /\ forall clean,
      agrees env.names clean saved = true
      -> UnnamedUnmatched node clean
      -> inv env.names v = true
      -> exists clean',
          Emits
            (Model.Node.receive (CCF.Capabilities.record node) node source clean
              (respMsg pre r))
            clean' o
          /\ agrees env.names clean' v = true
          /\ UnnamedUnmatched node clean'
          /\ forall m, m ∈ o -> msgInv env.names m = true

theorem voteResponse_spec (env : Env) {node source : NodeID} (pre : Bool)
    (r : RequestVoteResponse) {saved : State}
    (savedId : env.names.id saved.nodeId = node)
    (hsrc : env.names.id (env.names.name source) = source)
    (h : inv env.names saved = true) (init : initialised saved = true)
    : Hoare env (fun v o => v = saved /\ o = [])
        (Exec.recvRequestVoteResponse (env.names.name source) pre r)
        fun _ v o => RespPost env node source pre r saved v o := by
  unfold Exec.recvRequestVoteResponse
  refine Ae.Hoare.bind
    (Ae.Hoare.of_spec (det_traceRecv env _ _ _)
      (Q := fun _ v o => v = saved /\ o = [])
      fun v o _ v' o' ⟨hv, ho⟩ ⟨h1, h2⟩ => ⟨by rw [h1, hv]; rfl, by rw [h2, ho]; rfl⟩)
    fun _ => ?_
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  dsimp only
  have elig : forall clean, agrees env.names clean saved = true
      -> eligiblePeers clean node = eligiblePeers (abs env.names saved) (env.names.id saved.nodeId) :=
    fun clean ag => by rw [eligible_agrees ag, savedId]
  refine Ae.Hoare.ite (fun np => ?_) fun pp => ?_
  · refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
    subst v o
    refine ⟨rfl, fun clean ag um _ => ⟨clean, ?_, ag, um, by simp⟩⟩
    have np' : source ∉ eligiblePeers clean node := by
      rw [elig clean ag, ← peer_iff_eligible h init hsrc]
      simpa using np
    rw [receive_notPeer np']
    exact emits_pure _
  have el : forall clean, agrees env.names clean saved = true -> source ∈ eligiblePeers clean node :=
    fun clean ag => by
      rw [elig clean ag, ← peer_iff_eligible h init hsrc]
      simpa [Option.isSome_iff_ne_none] using pp
  refine Ae.Hoare.ite (fun lt => ?_) fun ge => ?_
  · refine Ae.Hoare.bind (Ae.Hoare.of_spec (det_becomeAware env r.term)
      (Q := fun _ v o => v = bant r.term saved /\ o = [])
      fun v o _ v' o' ⟨hv, ho⟩ ⟨h1, h2⟩ => ⟨by rw [h1, hv], by rw [h2, ho]; rfl⟩) fun _ => ?_
    refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
    subst v o
    refine ⟨rfl, fun clean ag um _ => ⟨_, ?_, agrees_bant r.term ag, ?_, by simp⟩⟩
    · have lt' : clean.currentTerm < r.term := by rw [(agrees_term_log ag).1]; exact lt
      rw [receive_newer (el clean ag) lt']
      exact emits_pure _
    · have lt' : clean.currentTerm < r.term := by rw [(agrees_term_log ag).1]; exact lt
      have := unmatched_updateTerm r.term um
      rwa [updateTerm_of_lt lt'] at this
  have ign : Not (saved.leadership = wantRole pre /\ r.term = saved.currentView
        /\ r.voteGranted = true)
      -> Hoare env (fun v o => v = saved /\ o = []) (pure ())
        fun _ v o => RespPost env node source pre r saved v o := by
    intro no
    refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
    subst v o
    refine ⟨rfl, fun clean ag um _ => ⟨clean, ?_, ag, um, by simp⟩⟩
    have ge' : Not (clean.currentTerm < r.term) := by rw [(agrees_term_log ag).1]; exact ge
    have no' : Not (Counted pre clean r) := by
      rintro ⟨hr, ht, hg⟩
      refine no ⟨?_, by rw [ht, (agrees_term_log ag).1], hg⟩
      rw [agrees_role ag] at hr
      cases pre <;> cases hl : saved.leadership <;> simp_all [wantRole, absRole]
    rw [receive_ignored (el clean ag) ge' no']
    exact emits_pure _
  refine Ae.Hoare.ite (fun ne => ign ?_) fun eq => ?_
  · rintro ⟨-, ht, -⟩
    simp [ht] at ne
  refine Ae.Hoare.ite (fun c1 => ign ?_) fun c1 => ?_
  · rintro ⟨hl, -⟩
    cases pre <;> simp [hl, wantRole] at c1
  refine Ae.Hoare.ite (fun c2 => ign ?_) fun c2 => ?_
  · rintro ⟨hl, -⟩
    cases pre <;> simp [hl, wantRole] at c2
  refine Ae.Hoare.ite (fun c3 => ign ?_) fun c3 => ?_
  · rintro ⟨hl, -⟩
    cases pre <;> simp [hl, wantRole] at c3
  refine Ae.Hoare.ite (fun c4 => ign ?_) fun c4 => ?_
  · rintro ⟨-, -, hg⟩
    simp [hg] at c4
  refine Ae.Hoare.ite (fun mem => ?_) fun _ => ?_
  rotate_left
  · exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
      Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _) fun _ =>
        Ae.Hoare.false_pre fun _ _ f => f
  have role : saved.leadership = wantRole pre := by
    cases pre <;> cases hl : saved.leadership <;> simp_all [wantRole]
  have ht : r.term = saved.currentView := by simp at eq; omega
  have hg : r.voteGranted = true := by simpa using c4
  have counted : forall clean, agrees env.names clean saved = true -> Counted pre clean r := by
    intro clean ag
    refine ⟨?_, by rw [ht, (agrees_term_log ag).1], hg⟩
    rw [agrees_role ag, role]
    cases pre <;> rfl
  have ge' : forall clean, agrees env.names clean saved = true
      -> Not (clean.currentTerm < r.term) :=
    fun clean ag => by rw [(agrees_term_log ag).1]; exact ge
  have others : saved.allOtherNodes ≠ [] := by
    intro e
    simp [State.peer?, e] at pp
  have L0 := pos_of_peer h init others
  have hy := ReplUpdateCommit.Hyps.ofInv h
  obtain ⟨D, hD, sh⟩ := hy.configs L0
  have sorted := hy.sorted L0
  have cand : saved.leadership = .candidate \/ saved.leadership = .preVoteCandidate := by
    cases pre <;> simp [role, wantRole]
  have t := tally_of_inv h cand
  have member : exists c, c ∈ saved.configurations
      /\ env.names.name source ∈ c.nodes.map Prod.fst := by
    simp only [List.any_eq_true, beq_iff_eq] at mem
    obtain ⟨c, mc, a, ma, e⟩ := mem
    exact ⟨c, mc, List.mem_map.mpr ⟨a, ma, e⟩⟩
  have quorum := quorum_tally (names := env.names) (D := D) (tally_record (env.names.name source) t sorted)
    hy.membersNamed (fun w mw => by
      rcases List.mem_cons.mp mw with rfl | mw
      · obtain ⟨c, mc, ma⟩ := member
        obtain ⟨a, ma2, e⟩ := List.mem_map.mp ma
        rw [← e]
        exact hy.membersNamed c mc a ma2
      · rcases List.mem_cons.mp mw with rfl | mw
        · exact hy.selfNamed
        · obtain ⟨-, c, mc, ma⟩ := (mem_flat_tally t).mp mw
          obtain ⟨a, ma2, e⟩ := List.mem_map.mp ma
          rw [← e]
          exact hy.membersNamed c mc a ma2)
    hy.distinct (shifted_nodes sh)
  have votes : env.names.set (voters { saved with votesForMe := recorded (env.names.name source) saved })
      = insert source (env.names.set (voters saved)) := by
    rw [set_congr (voters_record t sorted member), set_cons, hsrc]
  have active : forall clean, agrees env.names clean saved = true
      -> clean.activeConfigurations = D.map (absConfig env.names) := by
    intro clean ag
    obtain ⟨-, hl, hc, -⟩ := agrees_frame ag
    show activeConfigurations clean.log clean.commitIndex = _
    rw [hl, hc]
    exact hD
  unfold Exec.addVoteForMe
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  refine Ae.Hoare.bind (recordVote_spec env _ saved []) fun b => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨hb, hv, ho⟩ => ?_
  subst v1 o1
  rw [set_cons, hsrc] at quorum
  have qb : b = decide (hasQuorum (D.map (absConfig env.names))
      (insert source (env.names.set (voters saved)))) := by
    rw [hb]
    exact quorum
  have notPrimary : forall clean, agrees env.names clean saved = true -> clean.role ≠ .primary := by
    intro clean ag hp
    rw [agrees_role ag] at hp
    cases pre <;> simp [role, wantRole, absRole] at hp
  have failed : forall {Q : Unit -> State -> Outbox -> Prop} {P : State -> Outbox -> Prop},
      Hoare env P (do
        let l ← curLoc
        fail (toString l ++ toString ": add_vote_for_me() while not a candidate")) Q :=
    Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ => Ae.Hoare.fail _
  cases pre
  · have hcand : saved.leadership = .candidate := role
    have agS : forall clean, agrees env.names clean saved = true
        -> agrees env.names { clean with votesGranted := insert source clean.votesGranted }
          { saved with votesForMe := recorded (env.names.name source) saved } = true := by
      intro clean ag
      have := agrees_votesGranted ag hcand (recorded (env.names.name source) saved)
      rwa [votes, ← (agrees_votes ag).1 hcand] at this
    have unS : forall clean, agrees env.names clean saved = true -> UnnamedUnmatched node clean
        -> UnnamedUnmatched node { clean with votesGranted := insert source clean.votesGranted } :=
      fun clean ag um => unmatched_frame um fun hp => absurd hp (notPrimary clean ag)
    have qS : forall clean, agrees env.names clean saved = true
        -> (hasQuorum { clean with votesGranted := insert source clean.votesGranted }.activeConfigurations
          { clean with votesGranted := insert source clean.votesGranted }.votesGranted
          <-> b = true) := by
      intro clean ag
      rw [qb, decide_eq_true_iff, (agrees_votes ag).1 hcand]
      show hasQuorum clean.activeConfigurations _ <-> _
      rw [active clean ag]
    refine Ae.Hoare.ite (fun yes => ?_) fun no => ?_
    · split
      · rename_i e
        rw [hcand] at e
        cases e
      rotate_left
      · exact failed
      refine hoare_discard (Ae.Hoare.post (becomeLeader_all env (o0 := [])
        (leaderPre_votes h L0 hcand (recorded (env.names.name source) saved)))
        fun _ v o p => ?_)
      have nid : v.nodeId = saved.nodeId := by
        rcases p _ (agrees_abs _ _) with ⟨-, -, hv, -⟩ | ⟨-, -, sends, -, wn, -⟩
        · rw [hv]
        · exact wn
      refine ⟨nid, fun clean ag um hinv => ?_⟩
      rw [receive_vote (el clean ag) (counted clean ag)]
      unfold electIfQuorum
      rcases p _ (agS clean ag) with ⟨hr, -, hv, ho⟩ | ⟨hr, -, sends, ho, wn, -, -, -, cl⟩
      · subst v o
        have no : Not ({ clean with votesGranted := insert source clean.votesGranted }.role = .candidate
            /\ hasQuorum { clean with votesGranted := insert source clean.votesGranted }.activeConfigurations
              { clean with votesGranted := insert source clean.votesGranted }.votesGranted
            /\ Not ({ clean with votesGranted := insert source clean.votesGranted }.isRetiredCommitted node)) :=
          fun ⟨_, _, n⟩ => n (savedId ▸ hr)
        simp only [no, ↓reduceIte]
        exact ⟨_, emits_pure _, agS clean ag, unS clean ag um, by simp⟩
      · obtain ⟨em, ag', mi⟩ := cl hinv
        have yes' : { clean with votesGranted := insert source clean.votesGranted }.role = .candidate
            /\ hasQuorum { clean with votesGranted := insert source clean.votesGranted }.activeConfigurations
              { clean with votesGranted := insert source clean.votesGranted }.votesGranted
            /\ Not ({ clean with votesGranted := insert source clean.votesGranted }.isRetiredCommitted node) :=
          ⟨by rw [agrees_role ag, hcand]; rfl, (qS clean ag).mpr yes, savedId ▸ hr⟩
        rw [ite_eq_left yes']
        rw [savedId] at em
        subst o
        exact ⟨_, em, ag', unmatched_primaryState _ _, mi⟩
    · refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
      subst v o
      refine ⟨rfl, fun clean ag um _ => ?_⟩
      rw [receive_vote (el clean ag) (counted clean ag)]
      unfold electIfQuorum
      have no' : Not ({ clean with votesGranted := insert source clean.votesGranted }.role = .candidate
          /\ hasQuorum { clean with votesGranted := insert source clean.votesGranted }.activeConfigurations
            { clean with votesGranted := insert source clean.votesGranted }.votesGranted
          /\ Not ({ clean with votesGranted := insert source clean.votesGranted }.isRetiredCommitted node)) :=
        fun ⟨_, q, _⟩ => no ((qS clean ag).mp q)
      simp only [no', ↓reduceIte]
      exact ⟨_, emits_pure _, agS clean ag, unS clean ag um, by simp⟩
  · have hpre : saved.leadership = .preVoteCandidate := role
    have ne : saved.configurations ≠ [] := by
      obtain ⟨c, mc, -⟩ := member
      exact List.ne_nil_of_mem mc
    have agS : forall clean, agrees env.names clean saved = true
        -> agrees env.names { clean with preVotesGranted := insert source clean.preVotesGranted }
          { saved with votesForMe := recorded (env.names.name source) saved } = true := by
      intro clean ag
      have := agrees_preVotesGranted ag hpre (recorded (env.names.name source) saved)
      rwa [votes, ← (agrees_votes ag).2 hpre] at this
    have unS : forall clean, agrees env.names clean saved = true -> UnnamedUnmatched node clean
        -> UnnamedUnmatched node { clean with preVotesGranted := insert source clean.preVotesGranted } :=
      fun clean ag um => unmatched_frame um fun hp => absurd hp (notPrimary clean ag)
    have qS : forall clean, agrees env.names clean saved = true
        -> (hasQuorum
            { clean with preVotesGranted := insert source clean.preVotesGranted }.activeConfigurations
            { clean with preVotesGranted := insert source clean.preVotesGranted }.preVotesGranted
          <-> b = true) := by
      intro clean ag
      rw [qb, decide_eq_true_iff, (agrees_votes ag).2 hpre]
      show hasQuorum clean.activeConfigurations _ <-> _
      rw [active clean ag]
    refine Ae.Hoare.ite (fun yes => ?_) fun no => ?_
    · split
      rotate_left
      · rename_i e
        rw [hpre] at e
        cases e
      · exact failed
      refine Ae.Hoare.post (becomeCandidate_all env (o0 := []) h L0 ne) fun _ v o p => ?_
      have nid : v.nodeId = saved.nodeId := by
        obtain ⟨_, _, wn, _⟩ := p { abs env.names saved with role := .follower }
          ⟨rfl, rfl, rfl, rfl, rfl, fun hp => absurd hp (by simp)⟩
        exact wn
      refine ⟨nid, fun clean ag um hinv => ?_⟩
      obtain ⟨ht', hl, hc, hnf, -, hrc⟩ := agrees_frame ag
      obtain ⟨sends, ho, -, cl⟩ := p { clean with preVotesGranted := insert source clean.preVotesGranted }
        ⟨ht', hl, hc, hnf, hrc, by rw [savedId]; exact unS clean ag um⟩
      obtain ⟨c', em, ag', um', mi⟩ := cl hinv
      rw [savedId] at em um'
      rw [receive_preVote (el clean ag) (counted clean ag)]
      dsimp only
      rw [ite_eq_left ((qS clean ag).mpr yes)]
      subst o
      exact ⟨c', em, ag', um', mi⟩
    · refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
      subst v o
      refine ⟨rfl, fun clean ag um _ => ?_⟩
      rw [receive_preVote (el clean ag) (counted clean ag)]
      dsimp only
      have no' : Not (hasQuorum
          { clean with preVotesGranted := insert source clean.preVotesGranted }.activeConfigurations
          { clean with preVotesGranted := insert source clean.preVotesGranted }.preVotesGranted) :=
        fun q => no ((qS clean ag).mp q)
      simp only [no', ↓reduceIte]
      exact ⟨_, emits_pure _, agS clean ag, unS clean ag um, by simp⟩

end Consensus.TraceValidation.Proofs.Vote
