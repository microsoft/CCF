module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickOrder
public import Consensus.TraceValidation.Proofs.Handlers.TickLeader
public import Consensus.TraceValidation.Proofs.Handlers.VoteBecomeLeader

@[expose] public section

/-!
# A non-leader's election timeout (not reviewed; `Tick` obligation)

The election timeout is one clean `timeout .election`: a pre-vote candidate that asks every
other active member, or, if every configuration is the node alone, a candidate, and then a
primary that sends its heartbeats.
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)
open Life (Tri Pres)

variable {env : Env}

/-! ## Vote requests -/

/-- The vote request `sendRequestVote pre` sends from `v`. -/
def rvMsg (pre : Bool) (v : State) : Message :=
  let r : RequestVoteRequest :=
    {
      term := v.currentView,
      lastCommittableTerm := v.getTerm v.lastCommittable,
      lastCommittableIndex := v.lastCommittable
    }
  if pre then .requestPreVoteRequest r else .requestVoteRequest r

theorem tri_sendRequestVote (pre : Bool) (to : NodeId) (v : State) (O : Outbox)
    (h : v.commitIdx <= v.lastCommittable)
    : Tri env (fun w o => w = v /\ o = O) (sendRequestVote pre to)
        (fun _ w o =>
          w = v /\ o = O ++ [⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩]) := by
  unfold sendRequestVote
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  dsimp only
  refine Tri.ite (fun lt => absurd h (Nat.not_le.mpr lt)) fun _ => ?_
  refine tri_keeps_bind (Spec.trace _) fun _ => tri_keeps_bind (Spec.emit _ _) fun _ =>
    tri_keeps_bind (Spec.emitStr _ _) fun _ => Tri.send fun w o ⟨hw, ho⟩ => ?_
  subst w o
  exact ⟨rfl, rfl⟩

theorem tri_rvLoop (pre : Bool) (v : State) (h : v.commitIdx <= v.lastCommittable)
    : forall (l : List NodeId) (O : Outbox),
        Tri env (fun w o => w = v /\ o = O)
          (forIn l PUnit.unit
            fun id _ => do
              sendRequestVote pre id
              pure (ForInStep.yield PUnit.unit))
          (fun _ w o =>
            w = v
            /\ o
                = O
                  ++ l.map
                      fun to => ⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩)
  | [], O => by
      rw [List.forIn_nil]
      exact Tri.conseq (Tri.pure' _) (fun w o ⟨hw, ho⟩ => ⟨hw, by simp [ho]⟩) (fun _ _ _ h => h)
  | to :: rest, O => by
      rw [List.forIn_cons]
      refine Tri.bind (Tri.bind (tri_sendRequestVote pre to v O h) fun _ =>
        Tri.conseq (Tri.pure' (Q := fun r w o => r = ForInStep.yield PUnit.unit /\ w = v
          /\ o = O ++ [⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩]) _)
          (fun _ _ h => ⟨rfl, h⟩) (Q := fun r w o => (w = v
            /\ o = O ++ [⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩])
            /\ r = ForInStep.yield PUnit.unit) (fun _ _ _ h => by
              obtain ⟨a, b, c⟩ := h
              exact ⟨⟨b, c⟩, a⟩)) fun r => ?_
      refine tri_pre_prop fun hr => ?_
      subst hr
      exact Tri.conseq (tri_rvLoop pre v h rest _) (fun _ _ h => h)
        (fun _ _ _ ⟨hw, ho⟩ => ⟨hw, by simp [ho]⟩)

/-! ## The election guard -/

/-- A node that can start an election has a ledger entry. -/
theorem guard_pos {names : Names} {d : State} {n : NodeID}
    (g : canStartElection (abs names d) n)
    : 0 < d.lastIdx := by
  refine Nat.pos_of_ne_zero fun h => ?_
  have hl : (abs names d).log = [] := by simp [abs, h]
  obtain ⟨-, mem, -⟩ := g
  unfold NodeState.signedActiveConfigurations NodeState.activeConfigurations
    NodeState.retirementCompletedNodes NodeState.committedLog at mem
  rw [hl] at mem
  simp [activeConfigurations, configurationHistory, configurationMembers,
    latestConfigurationMembers, retiredCommittedNodes, CCF.Finset.mem_sdiff] at mem

/-! ## The states of the election -/

/-- The vote records once the node voted for itself. -/
def marked (v : State) : List (Nat × List NodeId × Nat) :=
  v.configurations.map
    fun c =>
      (c.idx, if Lists v.nodeId c then [v.nodeId] else [], State.quorum c.nodes.length)

/-- The declared pre-vote candidate once it voted for itself. -/
def pvState (v : State) : State :=
  { v with leadership := .preVoteCandidate, leaderId := none, votesForMe := marked v }

/-- The declared candidate once it voted for itself. -/
def candState (v : State) : State :=
  {
    v with
      leadership := .candidate,
      leaderId := none,
      votedFor := some v.nodeId,
      votesForMe := marked v,
      currentView := v.currentView + 1
  }

/-- The clean pre-vote candidate. -/
def cleanPv (c : NodeState) (node : NodeID) : NodeState :=
  { c with role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {node} }

/-- The clean candidate. -/
def cleanCand (c : NodeState) (node : NodeID) : NodeState :=
  {
    cleanPv c node with
      role := .candidate,
      currentTerm := c.currentTerm + 1,
      votedFor := some node,
      primaryKnown := false,
      votesGranted := {node},
      preVotesGranted := ∅
  }

theorem agrees_pv {names : Names} {c : NodeState} {d : State}
    (ag : agrees names c d = true)
    : agrees names (cleanPv c (names.id d.nodeId)) (pvState d) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := Vote.agrees_frame ag
  have votes := selfVotes_set (names := names) d.configurations d.nodeId
  simp only [agrees, Bool.and_eq_true, beq_iff_eq]
  simp [cleanPv, pvState, abs, trackedPeers, absRole, h1, h2, h3, h4, h5, h6, marked, votes]

theorem agrees_cand {names : Names} {c : NodeState} {d : State}
    (ag : agrees names c d = true)
    : agrees names (cleanCand c (names.id d.nodeId)) (candState d) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := Vote.agrees_frame ag
  have votes := selfVotes_set (names := names) d.configurations d.nodeId
  simp only [agrees, Bool.and_eq_true, beq_iff_eq]
  simp [cleanCand, cleanPv, candState, abs, trackedPeers, absRole, h1, h2, h3, h4, h5, h6, marked,
    votes]

/-! ## The guard on both sides -/

theorem tri_guard (saved : State)
    : Tri env (fun w o => w = saved /\ o = []) electionGuard
        (fun _ w o =>
          (w = saved /\ o = [])
          /\ canStartElection (abs env.names saved) (env.names.id saved.nodeId)) := by
  unfold electionGuard
  refine tri_names (tri_getV fun w o ⟨hw, ho⟩ => ?_)
  subst w o
  refine Tri.ite (fun g => ?_) (fun _ => ?_)
  · exact Tri.conseq (Tri.pure' (Q := fun _ w o => (w = saved /\ o = [])
        /\ canStartElection (abs env.names saved) (env.names.id saved.nodeId)) _)
      (fun _ _ h => ⟨h, of_decide_eq_true g⟩) (fun _ _ _ h => h)
  · exact tri_keeps_bind Spec.curLoc fun _ => Tri.fail _

theorem canStartElection_congr {a b : NodeState} (hr : a.role = b.role)
    (hl : a.log = b.log) (hc : a.commitIndex = b.commitIndex)
    (hrc : a.retiredCommittedIndex = b.retiredCommittedIndex) (n : NodeID)
    (g : canStartElection b n)
    : canStartElection a n := by
  have ret := Vote.retirement_congr hl hc hrc n
  unfold canStartElection NodeState.signedActiveConfigurations NodeState.activeConfigurations
    NodeState.retirementCompletedNodes NodeState.committedLog NodeState.isRetiredCommitted at *
  rw [hr, hl, hc, ret]
  exact g

theorem guard_clean {names : Names} {c : NodeState} {d : State}
    (ag : agrees names c d = true)
    (g : canStartElection (abs names d) (names.id d.nodeId))
    : canStartElection c (names.id d.nodeId) := by
  obtain ⟨-, hl, hc, -, -, hrc⟩ := Vote.agrees_frame ag
  have hr : c.role = (abs names d).role := by
    simp only [agrees, Bool.and_eq_true, beq_iff_eq] at ag
    exact ag.1.1.1.1.1.1.1.1.1.1
  exact canStartElection_congr hr hl hc hrc _ g

/-! ## Facts from the invariant -/

theorem names_sorted_of {names : Names} {d : State} (h : inv names d = true)
    (ne : d.configurations ≠ [])
    : names.known.toList.Pairwise (· < ·) := by
  have hs : (d.configurations.isEmpty && d.allOtherNodes.isEmpty
      || (names.known.toList.zip names.known.toList.tail).all fun (x, y) => decide (x < y))
      = true := by
    inv_conj h "names_sorted"
  have e : d.configurations.isEmpty = false := by simpa using ne
  simp only [e, Bool.false_and, Bool.false_or] at hs
  exact pairwise_of_adjacent' (R := fun x y : NodeId => x < y) String.lt_trans hs

theorem members_known_of {names : Names} {d : State} (h : inv names d = true)
    : forall x, x ∈ d.configurations -> forall a, a ∈ x.nodes -> a.1 ∈ names.known := by
  have hk : ((d.configurations.flatMap (·.nodes.map Prod.fst)).all names.known.contains)
      = true := by
    inv_conj h "members_known"
  intro x xm a am
  simp only [List.all_eq_true, List.mem_flatMap, List.mem_map] at hk
  have := hk a.1 ⟨x, xm, a, am, rfl⟩
  simpa using this

/-! ## The vote requests on both sides -/

open ReplUpdateCommit (absConfig Shifted Named named_inj) in
/-- The clean pre-vote broadcast goes to the nodes M_tv asks, in its order. -/
theorem others_eq {names : Names} {v : State} {active : List Configuration}
    {D : List Config} {ci : Nat} (hD : active = D.map (absConfig names))
    (sh : Shifted ci D v.configurations) (sorted : names.known.toList.Pairwise (· < ·))
    (known : forall x, x ∈ v.configurations -> forall a, a ∈ x.nodes -> a.1 ∈ names.known)
    (selfNamed : Named names v.nodeId)
    (named : forall x, x ∈ v.configurations -> forall a, a ∈ x.nodes -> Named names a.1)
    : ((configurationMembers active).erase (names.id v.nodeId)).sort
      = v.otherNodesInActiveConfigs.map names.id := by
  refine CCF.Finset.eq_of_sorted_of_mem_iff (CCF.Finset.sorted _)
    (others_ids_sorted sorted known) fun n => ?_
  rw [CCF.Finset.mem_sort, CCF.Finset.mem_erase, active_members_iff hD sh, List.mem_map]
  constructor
  · rintro ⟨ne, y, ym, a, am, rfl⟩
    refine ⟨a.1, mem_others.mpr ⟨⟨y, ym, a, am, rfl⟩, fun e => ne (by rw [e])⟩, rfl⟩
  · rintro ⟨s, sm, rfl⟩
    obtain ⟨⟨y, ym, a, am, rfl⟩, ne⟩ := mem_others.mp sm
    exact ⟨fun e => ne (named_inj (named y ym a am) selfNamed e), y, ym, a, am, rfl⟩

theorem msgInv_rv {names : Names} {src tgt : NodeID} (r : RequestVoteRequest) (pre : Bool)
    (hn : names.id (names.name src) = src) (ne : src ≠ tgt)
    : msgInv names
        ⟨src, tgt, if pre then .requestPreVoteRequest r else .requestVoteRequest r⟩
      = true := by
  cases pre <;> simp [msgInv, hn, ne]

/-- M_tv's vote request is the clean one. -/
theorem rvMsg_clean {names : Names} {c : NodeState} {d : State} (h : inv names d = true)
    (ag : agrees names c d = true) (pre : Bool)
    : rvMsg pre d
      = if pre then
          .requestPreVoteRequest (makeRequestVoteRequest c)
        else
          .requestVoteRequest (makeRequestVoteRequest c) := by
  obtain ⟨ht, hl, hc, -⟩ := Vote.agrees_frame ag
  obtain ⟨-, h2, h3, -⟩ := Vote.inv_parts h
  have bounds := Vote.lastCommittable_bounds h2 h3
  have lci : lastCommittableIndex c = d.lastCommittable := by
    unfold lastCommittableIndex
    rw [hl, hc, ← Vote.lastCommittable_eq h]
    exact Nat.max_eq_right bounds.1
  have r : makeRequestVoteRequest c
      = { term := d.currentView, lastCommittableTerm := d.getTerm d.lastCommittable,
          lastCommittableIndex := d.lastCommittable } := by
    simp only [makeRequestVoteRequest, lastCommittableTerm, lci, ht, hl, Vote.getTerm_eq h]
  rw [r]
  rfl

/-! ## The clean election -/

/-- The clean pre-vote broadcast of `node` from `c`. -/
def pvSends (c : NodeState) (node : NodeID) : List (CCF.Envelope NodeID Message) :=
  ((cleanPv c node).activeMembers.erase node).sort.map
    fun p =>
      ⟨node, p, .requestPreVoteRequest (makeRequestVoteRequest (cleanPv c node))⟩

theorem emits_broadcast (node : NodeID) (st : NodeState) (m : Message)
    : Emits (broadcastToOthers (CCF.Capabilities.record node) node st m) ()
        ((st.activeMembers.erase node).sort.map fun p => ⟨node, p, m⟩) := by
  unfold broadcastToOthers
  exact emits_congr (emits_bind (emits_forIn _ fun _ => m) (emits_pure ())) rfl (List.append_nil _)

theorem clean_pv {c : NodeState} {node : NodeID} (g : canStartElection c node)
    (nq : Not (hasQuorum c.activeConfigurations {node}))
    : Emits (act (CCF.Capabilities.record node) node c (.timeout .election))
        (cleanPv c node) (pvSends c node) := by
  show Emits (startElection _ c node) _ _
  unfold startElection
  refine emits_congr (emits_bind (emits_guard g) ?_) rfl (List.nil_append _)
  unfold Model.Node.becomePreVoteCandidate
  have nq' : Not (hasQuorum (cleanPv c node).activeConfigurations (cleanPv c node).preVotesGranted) :=
    nq
  show Emits (if hasQuorum (cleanPv c node).activeConfigurations (cleanPv c node).preVotesGranted
    then _ else _) _ _
  rw [ite_eq_right nq']
  exact emits_congr (emits_bind (emits_broadcast _ _ _) (emits_pure _)) rfl (List.append_nil _)

theorem clean_cand {c : NodeState} {node : NodeID} (g : canStartElection c node)
    (q : hasQuorum c.activeConfigurations {node})
    (alone : ((cleanCand c node).activeMembers.erase node).sort = [])
    {sends : List (CCF.Envelope NodeID Message)}
    (hp
      : Emits (becomePrimary (CCF.Capabilities.record node) node (cleanCand c node))
          (primaryState (cleanCand c node)) sends)
    : Emits (act (CCF.Capabilities.record node) node c (.timeout .election))
        (primaryState (cleanCand c node)) sends := by
  show Emits (startElection _ c node) _ _
  unfold startElection
  refine emits_congr (emits_bind (emits_guard g) ?_) rfl (List.nil_append _)
  unfold Model.Node.becomePreVoteCandidate
  have q' : hasQuorum (cleanPv c node).activeConfigurations (cleanPv c node).preVotesGranted := q
  show Emits
    (if hasQuorum (cleanPv c node).activeConfigurations
          (cleanPv c node).preVotesGranted then
        _
      else
        _)
    _ _
  rw [ite_eq_left q']
  unfold Model.Node.becomeCandidate
  have nr : Not ((cleanCand c node).isRetiredCommitted node) := by
    have := Vote.retirement_congr (a := cleanCand c node) (b := c) rfl rfl rfl node
    simp only [NodeState.isRetiredCommitted, this]
    exact g.2.2
  have e : Emits (electIfQuorum (CCF.Capabilities.record node) node (cleanCand c node))
      (primaryState (cleanCand c node)) sends := by
    unfold electIfQuorum
    rw [ite_eq_left ⟨rfl, q, nr⟩]
    exact hp
  refine emits_congr (emits_bind e (emits_bind (emits_broadcast node (cleanCand c node) _)
    (emits_pure _))) rfl ?_
  rw [alone]
  simp

theorem pvSends_eq {saved : State} {clean0 : NodeState}
    (invS : inv env.names saved = true) (ag : agrees env.names clean0 saved = true)
    (L0 : 0 < saved.lastIdx) (ne : saved.configurations ≠ [])
    : pvSends clean0 (env.names.id saved.nodeId)
      = saved.otherNodesInActiveConfigs.map
          fun to =>
            ⟨env.names.id saved.nodeId, env.names.id to, rvMsg true saved⟩ := by
  have H := ReplUpdateCommit.Hyps.ofInv invS
  obtain ⟨D, hD, sh⟩ := H.configs L0
  obtain ⟨-, hl, hc, -⟩ := Vote.agrees_frame ag
  have act : (cleanPv clean0 (env.names.id saved.nodeId)).activeMembers
      = configurationMembers (activeConfigurations (abs env.names saved).log saved.commitIdx) := by
    show configurationMembers (activeConfigurations clean0.log clean0.commitIndex) = _
    rw [hl, hc]
  unfold pvSends
  rw [act, others_eq hD sh (names_sorted_of invS ne) (members_known_of invS) H.selfNamed
    H.membersNamed, List.map_map, rvMsg_clean invS ag true]
  rfl

theorem pvSends_inv {names : Names} {c : NodeState} {self : Exec.NodeId}
    (selfNamed : ReplUpdateCommit.Named names self)
    : forall e, e ∈ pvSends c (names.id self) -> msgInv names e = true := by
  intro e mem
  simp only [pvSends, List.mem_map, CCF.Finset.mem_sort, CCF.Finset.mem_erase] at mem
  obtain ⟨p, ⟨ne, -⟩, rfl⟩ := mem
  have hn : names.id (names.name (names.id self)) = names.id self := congrArg names.id selfNamed
  simp [msgInv, hn, Ne.symm ne]

/-! ## M_tv's election -/

/-- The vote-request loop that ends `becomePreVoteCandidate` and `becomeCandidate`. -/
abbrev rvLoop (pre : Bool) : M Unit := do
  let v ← getV
  forIn v.otherNodesInActiveConfigs PUnit.unit
    fun id _ => do
      sendRequestVote pre id
      pure (ForInStep.yield PUnit.unit)
  pure ()

theorem tri_loopNone (pre : Bool) {P : State -> Outbox -> Prop}
    (h : forall w o, P w o -> w.otherNodesInActiveConfigs = [])
    : Tri env P (rvLoop pre) (fun _ => P) := by
  refine Tri.getV_bind fun v => ?_
  intro c a c' e ⟨p, hv⟩ run
  subst hv
  rw [h _ _ p, List.forIn_nil] at run
  exact Tri.bind (Tri.pure' (Q := fun _ => P) PUnit.unit) (fun _ => Tri.pure' (Q := fun _ => P) ())
    c a c' e p run

theorem tri_loopAll (pre : Bool) (v : State) (O : Outbox)
    (h : v.commitIdx <= v.lastCommittable)
    : Tri env (fun w o => w = v /\ o = O) (rvLoop pre)
        (fun _ w o =>
          w = v
          /\ o
              = O
                ++ v.otherNodesInActiveConfigs.map
                    fun to =>
                      ⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩) :=
  tri_getV
    fun w o ⟨hw, ho⟩ => by
      subst w o
      exact Tri.bind (tri_rvLoop pre v h _ O) fun _ => Tri.pure' (Q := fun _ w o => w = v
        /\ o = O ++ v.otherNodesInActiveConfigs.map fun to =>
          ⟨env.names.id v.nodeId, env.names.id to, rvMsg pre v⟩) ()

theorem tri_selfVote (v : State) (O : Outbox) (ne : v.configurations ≠ [])
    (sorted : v.configurations.Pairwise fun a b => a.idx < b.idx)
    (reset
      : v.votesForMe
        = v.configurations.map fun c => (c.idx, [], State.quorum c.nodes.length))
    : Tri env (fun w o => w = v /\ o = O) (recordVote v.nodeId)
        (fun b w o =>
          (w = { v with votesForMe := marked v } /\ o = O)
          /\ b
              = decide
                  (forall c,
                    c ∈ v.configurations
                    -> Lists v.nodeId c /\ c.nodes.length <= 1)) := by
  refine Tri.conseq (tri_recordVote v.nodeId v O ne) (fun _ _ h => h) fun b w o h => ?_
  obtain ⟨hw, ho, hb⟩ := h
  rw [reset, selfVote_eq _ _ sorted] at hw hb
  rw [selfVote_all] at hb
  exact ⟨⟨hw, ho⟩, hb⟩

/-! ## The candidate that elects itself -/

theorem leaderPre_cand {names : Names} {saved : State} (invS : inv names saved = true)
    : Vote.LeaderPre names (candState saved) := by
  have H := ReplUpdateCommit.Hyps.ofInv invS
  obtain ⟨-, -, -, h4, -⟩ := Vote.inv_parts invS
  have vl : saved.views.all (· <= saved.lastIdx + 1) = true := by
    inv_conj invS "views_le_last"
  have rc : saved.isRetiredCommitted
      = decide ((abs names saved).isRetiredCommitted (names.id saved.nodeId)) := by
    inv_conj invS "retired_committed"
  have hp : (saved.lastIdx == 0 || saved.leadership == .none
      || saved.allOtherNodes.map (fun (id, _) => names.id id)
        == (eligiblePeers (abs names saved) (names.id saved.nodeId)).sort) = true := by
    inv_conj invS "peers"
  have hp' : (saved.lastIdx == 0 || saved.leadership != .none
      || saved.allOtherNodes.map (fun (id, _) => names.id id)
        == (eligiblePeers (abs names saved) (names.id saved.nodeId)).sort) = true := by
    inv_conj invS "peers_without_role"
  refine ⟨
    by simp [candState],
    Nat.lt_succ_of_le H.viewsBounded,
    ?_,
    H.size,
    H.commitLe,
    H.committable,
    h4,
    H.terms,
    ?_,
    ?_
  ⟩
  · intro x mem
    exact of_decide_eq_true (Array.all_eq_true_iff_forall_mem.mp vl x (Array.mem_toList_iff.mp mem))
  · show saved.isRetiredCommitted = _
    rw [rc]
    simp only [NodeState.isRetiredCommitted]
    rfl
  · have e := Vote.eligiblePeers_congr (a := abs names (candState saved)) (b := abs names saved)
      rfl rfl (names.id saved.nodeId)
    show saved.lastIdx = 0 \/ saved.allOtherNodes.map (fun x => names.id x.1)
      = (eligiblePeers (abs names (candState saved)) (names.id saved.nodeId)).sort
    rw [e]
    by_cases z : saved.lastIdx = 0
    · exact Or.inl z
    · refine Or.inr ?_
      by_cases n : saved.leadership = .none
      · simpa [z, n] using hp'
      · simpa [z, n] using hp

theorem others_nil {w : State}
    (alone : forall c, c ∈ w.configurations -> Lists w.nodeId c /\ c.nodes.length <= 1)
    : w.otherNodesInActiveConfigs = [] := by
  refine List.eq_nil_iff_forall_not_mem.mpr fun s mem => ?_
  obtain ⟨⟨x, xm, a, am, rfl⟩, ne⟩ := mem_others.mp mem
  obtain ⟨l, len⟩ := alone x xm
  simp only [Lists, List.any_eq_true, beq_iff_eq] at l
  obtain ⟨b, bm, hb⟩ := l
  match h : x.nodes, am, bm, len with
  | [y], am, bm, _ =>
      simp only [List.mem_singleton] at am bm
      exact ne (by rw [am, ← bm, hb])
  | [], am, _, _ => simp at am
  | _ :: _ :: _, _, _, len => simp at len

open ReplUpdateCommit (absConfig Shifted Named) in
theorem cand_alone {names : Names} {saved : State} {c : NodeState} {D : List Config}
    (hD : activeConfigurations c.log c.commitIndex = D.map (absConfig names))
    (sh : Shifted saved.commitIdx D saved.configurations)
    (alone
      : forall x, x ∈ saved.configurations -> Lists saved.nodeId x /\ x.nodes.length <= 1)
    : ((cleanCand c (names.id saved.nodeId)).activeMembers.erase
        (names.id saved.nodeId)).sort
      = [] := by
  refine List.eq_nil_iff_forall_not_mem.mpr fun n mem => ?_
  rw [CCF.Finset.mem_sort, CCF.Finset.mem_erase] at mem
  obtain ⟨ne, mem⟩ := mem
  have := (active_members_iff (names := names) hD sh).mp mem
  obtain ⟨y, ym, a, am, rfl⟩ := this
  have one : saved.otherNodesInActiveConfigs = [] := others_nil alone
  by_cases e : a.1 = saved.nodeId
  · exact ne (by rw [e])
  · have := mem_others.mpr ⟨⟨y, ym, a, am, rfl⟩, e⟩
    rw [one] at this
    simp at this

/-! ## The election in M_tv -/

theorem tri_setV_bind {β : Type} {f : State -> State} {k : PUnit -> M β} {v : State}
    {O : Outbox} {R : β -> State -> Outbox -> Prop}
    (h : Tri env (fun w o => w = f v /\ o = O) (k ()) R)
    : Tri env (fun w o => w = v /\ o = O) (Exec.setV f >>= k) R :=
  Tri.bind
    (Tri.setV (Q := fun _ w o => w = f v /\ o = O) fun _ _ ⟨hw, ho⟩ => ⟨by rw [hw], ho⟩)
    fun _ => h

theorem tri_ofHoare {α : Type} {P : State -> Outbox -> Prop} {x : M α}
    {Q : α -> State -> Outbox -> Prop} (h : Ae.Hoare env P x Q)
    : Tri env P x Q :=
  h

/-- Where a self-elected candidate ends. -/
def ElPost (env : Env) (saved : State) (clean0 : NodeState) (v : State) (o : Outbox)
    : Prop :=
  v.nodeId = saved.nodeId
  /\ v.otherNodesInActiveConfigs = []
  /\ (inv env.names v = true
      -> Acc env (env.names.id saved.nodeId) clean0
          (Final env.names (env.names.id saved.nodeId) clean0) v o)

open ReplUpdateCommit (absConfig Shifted) in
theorem tri_cand {saved : State} {clean0 : NodeState} {D : List Config}
    (invS : inv env.names saved = true) (ag : agrees env.names clean0 saved = true)
    (g : canStartElection clean0 (env.names.id saved.nodeId))
    (ne : saved.configurations ≠ [])
    (sorted : saved.configurations.Pairwise fun a b => a.idx < b.idx)
    (hD
      : activeConfigurations clean0.log clean0.commitIndex = D.map (absConfig env.names))
    (sh : Shifted saved.commitIdx D saved.configurations)
    (alone
      : forall x, x ∈ saved.configurations -> Lists saved.nodeId x /\ x.nodes.length <= 1)
    (q : hasQuorum clean0.activeConfigurations {env.names.id saved.nodeId})
    : Tri env (fun w o => w = pvState saved /\ o = []) Exec.becomeCandidate
        (fun _ => ElPost env saved clean0) := by
  unfold Exec.becomeCandidate Exec.resetVotesForMe
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  refine Tri.ite (fun e => Tri.preFalse fun _ _ _ => ne (by simpa [pvState] using e))
    fun _ => ?_
  refine tri_setV_bind
    (tri_setV_bind (tri_setV_bind (tri_keeps_bind (Spec.trace _) fun _ => ?_)))
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  refine Tri.bind (tri_selfVote _ [] ne sorted rfl) fun b => tri_pre_prop fun hb => ?_
  have hb' : b = true := hb.trans (decide_eq_true alone)
  subst hb'
  dsimp only
  refine Tri.ite (fun _ => ?_) (fun nb => absurd rfl nb)
  refine Tri.bind (Q := fun _ => ElPost env saved clean0) (Tri.discard ?_)
    fun _ => tri_loopNone false fun _ _ h => h.2.1
  have hl := Vote.becomeLeader_spec env (c := cleanCand clean0 (env.names.id saved.nodeId))
      (d := candState saved) (o0 := []) (leaderPre_cand invS) (agrees_cand ag)
  refine Tri.conseq (P' := fun v o => v = candState saved /\ o = [])
    (tri_ofHoare hl)
    (fun w o h => ⟨by rw [h.1]; rfl, h.2⟩) fun _ v o h => ?_
  rcases h with ⟨ret, -, -, -⟩ | ⟨-, -, sends, ho, hn, -, -, sub, fin⟩
  · exfalso
    exact g.2.2 ret
  · refine ⟨hn, others_nil fun x xm => ?_, fun hinv => ?_⟩
    · rw [hn]
      exact alone x (sub x xm)
    · obtain ⟨em, agv, sinv⟩ := fin hinv
      subst ho
      exact Acc.extend (Acc.start (R := fun c v => c = clean0 /\ v = saved) ⟨rfl, rfl⟩)
        (fun clean ⟨hc, _⟩ => by subst hc; exact ⟨.timeout .election, _,
          clean_cand g q (cand_alone hD sh alone) em, admitted_timeout _,
          agv, fun _ => Vote.unmatched_primaryState _ _⟩) sinv

open ReplUpdateCommit (absConfig) in
/-- A non-leader's election timeout: a pre-vote broadcast, or, alone in every configuration,
a self-election. -/
theorem el_tri {saved : State} {clean0 : NodeState} {node : NodeID}
    (invS : inv env.names saved = true) (self : env.names.id saved.nodeId = node)
    (ag : agrees env.names clean0 saved = true)
    : Tri env (fun w o => w = saved /\ o = [])
        (do
          electionGuard; note Note.electionTimeout; Exec.becomePreVoteCandidate)
        (fun _ v o =>
          v.nodeId = saved.nodeId
          /\ (inv env.names v = true
              -> Acc env node clean0 (Final env.names node clean0) v o)) := by
  subst self
  refine Tri.bind (tri_guard saved) fun _ => tri_pre_prop fun g => ?_
  refine tri_keeps_bind (Spec.note _) fun _ => ?_
  have g' := guard_clean ag g
  have L0 := guard_pos g
  have H := ReplUpdateCommit.Hyps.ofInv invS
  obtain ⟨D, hD, sh⟩ := H.configs L0
  obtain ⟨-, hl, hc, -⟩ := Vote.agrees_frame ag
  have hD' : activeConfigurations clean0.log clean0.commitIndex = D.map (absConfig env.names) := by
    rw [hl, hc]
    exact hD
  have sorted := H.sorted L0
  have qiff := hasQuorum_self hD' sh H.selfNamed H.membersNamed H.distinct
  unfold Exec.becomePreVoteCandidate Exec.resetVotesForMe Exec.addVoteForMe
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  refine Tri.ite
    (fun _ =>
      Tri.conseq
        (Tri.pure'
          (Q :=
            fun _ v o =>
              v.nodeId = saved.nodeId
              /\ (inv env.names v = true
                  -> Acc env (env.names.id saved.nodeId) clean0
                      (Final env.names (env.names.id saved.nodeId) clean0) v o))
          _)
        (fun w o ⟨hw, ho⟩ => by subst hw ho; exact ⟨rfl, fun _ => Acc.start ⟨ag, id⟩⟩)
        (fun _ _ _ h => h))
    fun hne => ?_
  have ne : saved.configurations ≠ [] := by simpa using hne
  refine tri_setV_bind (tri_setV_bind (tri_keeps_bind (Spec.trace _) fun _ => ?_))
  refine tri_getV fun w o ⟨hw, ho⟩ => ?_
  subst w o
  by_cases al :
    forall x, x ∈ saved.configurations -> Lists saved.nodeId x /\ x.nodes.length <= 1
  · refine Tri.bind (Q := fun _ => ElPost env saved clean0) ?_ fun _ =>
      Tri.conseq (tri_loopNone true fun _ _ h => h.2.1) (fun _ _ h => h)
        fun _ _ _ h => ⟨h.1, h.2.2⟩
    refine tri_getV fun w o ⟨hw, ho⟩ => ?_
    subst w o
    refine Tri.bind (tri_selfVote _ [] ne sorted rfl) fun b => tri_pre_prop fun hb => ?_
    have hb' : b = true := hb.trans (decide_eq_true al)
    subst hb'
    dsimp only
    refine Tri.ite (fun _ => ?_) (fun nb => absurd rfl nb)
    exact Tri.conseq (tri_cand invS ag g' ne sorted hD' sh al (qiff.mpr ⟨ne, al⟩))
      (fun w o h => ⟨by rw [h.1]; rfl, h.2⟩) (fun _ _ _ h => h)
  · refine Tri.bind (Q := fun _ w o => w = pvState saved /\ o = []) ?_ fun _ => ?_
    · refine tri_getV fun w o ⟨hw, ho⟩ => ?_
      subst w o
      refine Tri.bind (tri_selfVote _ [] ne sorted rfl) fun b => tri_pre_prop fun hb => ?_
      have hb' : b = false := hb.trans (decide_eq_false al)
      subst hb'
      dsimp only
      refine Tri.ite (fun nb => absurd nb Bool.false_ne_true) fun _ => ?_
      exact Tri.conseq (Tri.pure' (Q := fun _ w o => w = pvState saved /\ o = []) _)
        (fun w o h => ⟨by rw [h.1]; rfl, h.2⟩) (fun _ _ _ h => h)
    · have cl := (Vote.lastCommittable_bounds H.commitLe H.committable).1
      refine Tri.conseq (tri_loopAll true (pvState saved) [] cl) (fun _ _ h => h)
        fun _ v o ⟨hv, ho⟩ => ⟨by rw [hv]; rfl, fun _ => ?_⟩
      subst hv
      have e : o = [] ++ pvSends clean0 (env.names.id saved.nodeId) := by
        rw [ho, pvSends_eq invS ag L0 ne]
        rfl
      subst e
      exact Acc.extend (Acc.start (R := fun c v => c = clean0 /\ v = saved) ⟨rfl, rfl⟩)
        (fun clean ⟨hc, _⟩ => by
          subst hc
          exact ⟨.timeout .election, _, clean_pv g' fun q => al (qiff.mp q).2,
            admitted_timeout _, agrees_pv ag, fun _ h => by simp [cleanPv] at h⟩)
        (pvSends_inv H.selfNamed)

end Consensus.TraceValidation.Proofs.Tick
