module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteResponse

@[expose] public section

/-!
# `recv_propose_request_vote` against the clean receive (not reviewed)

M_tv starts an election on a proposal in its view when it is ticking and not retired-committed
(its election guard is the clean `canStartElection`); otherwise it ignores the proposal, and the
clean node does not start an election either: the view differs, the node is retired-committed
(`inv`'s `retired_committed`), or the node is not ticking and cannot start one.
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae (Hoare)
open Consensus.TraceValidation (Names)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (Named named_inj absConfig)

theorem receive_propose (caps : Caps) (self source : NodeID) (state : NodeState) (t : Nat)
    : Model.Node.receive caps self source state (.proposeRequestVoteRequest t)
      = handleProposeRequestVoteRequest caps state self t := by
  simp [Model.Node.receive, observeTerm]

theorem canStart_agrees {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true) (n : NodeID)
    : canStartElection c n <-> canStartElection (abs names d) n := by
  have hr : c.role = (abs names d).role := agrees_role h
  obtain ⟨-, hl, hc, -, -, hrc⟩ := agrees_frame h
  have hc' : c.commitIndex = (abs names d).commitIndex := hc
  have hrc' : c.retiredCommittedIndex = (abs names d).retiredCommittedIndex := hrc
  simp only [canStartElection, NodeState.signedActiveConfigurations, NodeState.activeConfigurations,
    NodeState.retirementCompletedNodes, NodeState.committedLog, NodeState.isRetiredCommitted,
    NodeState.retirement, hr, hl, hc', hrc']

theorem history_nil_of_active {log : List Model.Node.Entry} {ci : Nat}
    (h : activeConfigurations log ci = [])
    : configurationHistory log = [] := by
  unfold activeConfigurations at h
  simp only [List.drop_eq_nil_iff] at h
  have := List.length_filter_le (fun x : Configuration => decide (x.index <= ci))
    (configurationHistory log)
  exact List.eq_nil_of_length_eq_zero (by omega)

theorem history_take_nil {log : List Model.Node.Entry} (k : Nat)
    (h : configurationHistory log = [])
    : configurationHistory (log.take k) = [] := by
  rw [← List.take_append_drop k log] at h
  unfold configurationHistory at h ⊢
  rw [List.zipIdx_append, List.filterMap_append, List.append_eq_nil_iff] at h
  exact h.1

/-- A node that can start an election has an active configuration. -/
theorem active_of_canStart {s : NodeState} {n : NodeID} (h : canStartElection s n)
    : s.activeConfigurations ≠ [] := by
  intro hnil
  obtain ⟨-, mem, -⟩ := h
  have hist := history_nil_of_active hnil
  rcases mem with m | m
  · simp [NodeState.signedActiveConfigurations, hnil, configurationMembers] at m
  · have : configurationHistory s.committedLog = [] := history_take_nil _ hist
    simp [NodeState.retirementCompletedNodes, this, configurationMembers] at m

theorem electionGuard_spec (env : Env) {d : State} {o0 : Outbox}
    : Hoare env (fun v o => v = d /\ o = o0) Exec.electionGuard
        fun _ v o =>
          v = d
          /\ o = o0
          /\ canStartElection (abs env.names d) (env.names.id d.nodeId) := by
  unfold Exec.electionGuard
  refine Ae.Hoare.bind (Ae.Hoare.of_spec Spec.names
    (Q := fun a v o => a = env.names /\ v = d /\ o = o0)
    fun v o a v' o' p ⟨ha, hv, ho⟩ => ⟨ha, hv ▸ p.1, ho ▸ p.2⟩) fun nm => ?_
  refine Ae.Hoare.lift fun hn => ?_
  subst hn
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  refine Ae.Hoare.ite (fun yes => Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ =>
    ⟨hv, ho, of_decide_eq_true yes⟩) fun _ => ?_
  exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ => Ae.Hoare.fail _

/-- What the obligation needs of a proposal hold that ends in `v` having sent `o`. -/
def ProposePost (env : Env) (node source : NodeID) (t : Nat) (saved : State) (v : State)
    (o : Outbox)
    : Prop :=
  v.nodeId = saved.nodeId
  /\ forall clean,
      agrees env.names clean saved = true
      -> UnnamedUnmatched node clean
      -> inv env.names v = true
      -> exists clean',
          Emits
            (Model.Node.receive (CCF.Capabilities.record node) node source clean
              (.proposeRequestVoteRequest t))
            clean' o
          /\ agrees env.names clean' v = true
          /\ UnnamedUnmatched node clean'
          /\ forall m, m ∈ o -> msgInv env.names m = true

theorem propose_spec (env : Env) {node source : NodeID} (t : Nat) {saved : State}
    (savedId : env.names.id saved.nodeId = node) (h : inv env.names saved = true)
    : Hoare env (fun v o => v = saved /\ o = [])
        (Exec.recvProposeRequestVote (env.names.name source) t)
        fun _ v o => ProposePost env node source t saved v o := by
  unfold Exec.recvProposeRequestVote
  refine Ae.Hoare.bind
    (Ae.Hoare.of_spec (det_traceRecv env _ _ _)
      (Q := fun _ v o => v = saved /\ o = [])
      fun v o _ v' o' ⟨hv, ho⟩ ⟨h1, h2⟩ => ⟨by rw [h1, hv]; rfl, by rw [h2, ho]; rfl⟩)
    fun _ => ?_
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  have ignored : forall {x : M Unit}, (forall clean, agrees env.names clean saved = true
        -> Not (t = clean.currentTerm /\ canStartElection clean node))
      -> Hoare env (fun v o => v = saved /\ o = []) x (fun _ v o => v = saved /\ o = [])
      -> Hoare env (fun v o => v = saved /\ o = []) x
        fun _ v o => ProposePost env node source t saved v o := by
    intro x no hx
    refine Ae.Hoare.post hx fun _ v o ⟨hv, ho⟩ => ?_
    subst v o
    refine ⟨rfl, fun clean ag um _ => ⟨clean, ?_, ag, um, by simp⟩⟩
    rw [receive_propose, handleProposeRequestVoteRequest]
    simp only [no clean ag, ↓reduceIte]
    exact emits_pure _
  have hy := ReplUpdateCommit.Hyps.ofInv h
  have canStart : forall clean, agrees env.names clean saved = true
      -> (canStartElection clean node
        <-> canStartElection (abs env.names saved) (env.names.id saved.nodeId)) :=
    fun clean ag => by rw [canStart_agrees ag, savedId]
  refine Ae.Hoare.ite (fun c1 => ?_) fun c1 => ?_
  · have c1' := c1
    simp only [Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at c1'
    obtain ⟨-, ht⟩ := c1'
    dsimp only
    refine Ae.Hoare.ite (fun _ => ?_) fun _ => ?_
    · exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
        Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _) fun _ =>
          Ae.Hoare.false_pre fun _ _ f => f
    refine Ae.Hoare.bind (electionGuard_spec env) fun _ => ?_
    refine Ae.Hoare.pin fun v1 o1 ⟨hv, ho, cs⟩ => ?_
    subst v1 o1
    have act := active_of_canStart cs
    have L0 : 0 < saved.lastIdx := by
      refine Nat.pos_of_ne_zero fun z => act ?_
      show activeConfigurations (abs env.names saved).log saved.commitIdx = []
      simp [abs, z, activeConfigurations, configurationHistory]
    have ne : saved.configurations ≠ [] := by
      intro e
      obtain ⟨D, hD, sh⟩ := hy.configs L0
      have := shifted_nodes sh
      rw [e, List.map_nil, List.map_eq_nil_iff] at this
      rw [this, List.map_nil] at hD
      exact act hD
    refine Ae.Hoare.post (Ae.Hoare.pre
      (becomeCandidate_all env (X := saved.votesForMe) (o0 := []) h L0 ne)
      fun v o ⟨hv, ho⟩ => ⟨hv, ho⟩) fun _ v o p => ?_
    have nid : v.nodeId = saved.nodeId := by
      obtain ⟨_, _, wn, _⟩ := p { abs env.names saved with role := .follower }
        ⟨rfl, rfl, rfl, rfl, rfl, fun hp => absurd hp (by simp)⟩
      exact wn
    refine ⟨nid, fun clean ag um hinv => ?_⟩
    obtain ⟨ht', hl, hc, hnf, -, hrc⟩ := agrees_frame ag
    obtain ⟨sends, ho, -, cl⟩ := p clean ⟨ht', hl, hc, hnf, hrc, by rw [savedId]; exact um⟩
    obtain ⟨c', em, ag', um', mi⟩ := cl hinv
    rw [savedId] at em um'
    rw [receive_propose, handleProposeRequestVoteRequest,
      ite_eq_left ⟨ht.trans ht'.symm, (canStart clean ag).mpr cs⟩]
    subst o
    exact ⟨c', em, ag', um', mi⟩
  · refine Ae.Hoare.ite (fun c2 => ?_) fun c2 => ?_
    · refine Ae.Hoare.bind (Ae.Hoare.of_spec Spec.names
        (Q := fun a v o => a = env.names /\ v = saved /\ o = [])
        fun v o a v' o' p ⟨ha, hv, ho⟩ => ⟨ha, hv ▸ p.1, ho ▸ p.2⟩) fun nm => ?_
      refine Ae.Hoare.lift fun hn => ?_
      subst hn
      refine Ae.Hoare.ite (fun _ => ?_) fun no => ?_
      · exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
          Ae.Hoare.fail _
      · refine ignored (fun clean ag ⟨_, cs⟩ => no ?_) (Ae.Hoare.pure _ fun _ _ p => p)
        exact decide_eq_true ((canStart clean ag).mp cs)
    · refine ignored (fun clean ag ⟨ht, cs⟩ => ?_) (Ae.Hoare.pure _ fun _ _ p => p)
      have ht' : t = saved.currentView := ht.trans (agrees_term_log ag).1
      have ret : saved.isRetiredCommitted
          = decide ((abs env.names saved).isRetiredCommitted (env.names.id saved.nodeId)) := by
        have hc : (saved.isRetiredCommitted
            == decide ((abs env.names saved).isRetiredCommitted (env.names.id saved.nodeId)))
            = true := by
          inv_conj h "retired_committed"
        simpa using hc
      obtain ⟨-, -, nr⟩ := (canStart clean ag).mp cs
      cases tk : saved.ticking <;> cases rc : saved.isRetiredCommitted <;>
        simp_all

end Consensus.TraceValidation.Proofs.Vote
