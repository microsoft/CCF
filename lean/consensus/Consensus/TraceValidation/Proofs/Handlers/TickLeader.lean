module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickSend

@[expose] public section

/-!
# The `Tick` obligation (not reviewed)

A tick hold (`Exec.periodic`) is, depending on the role and on the untraced timers that the
next trace point resolves: nothing; a leader's heartbeat (one clean `sendEntries` per
`send_append_entries_range`); a leader's CheckQuorum step-down (`timeout .checkQuorum`),
possibly after a heartbeat; or a non-leader's election timeout (`timeout .election`).
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)
open Life (Tri Pres)

/-- What a tick ends in: the clean state agrees, and has no stale match index if the start
had none. -/
def Final (names : Names) (node : NodeID) (clean0 : NodeState) (clean : NodeState)
    (v : State)
    : Prop :=
  agrees names clean v = true
  /\ (UnnamedUnmatched node clean0 -> UnnamedUnmatched node clean)

variable {env : Env} {node : NodeID}

/-- A heartbeat's end: the clean state agrees and the node is the same. -/
theorem HbAcc.final {s0 : State} {clean0 : NodeState}
    (H : HbHyps env.names node s0 clean0) {v : State} {o : Outbox}
    (acc : HbAcc env node s0 clean0 v o)
    : v.nodeId = s0.nodeId /\ Acc env node clean0 (Final env.names node clean0) v o := by
  obtain ⟨L, hv, _⟩ := acc.shape
  exact ⟨by subst hv; rfl, acc.mono fun _ r => HbRel.finish H r⟩

/-- A leader whose configurations can lose a quorum has an active member other than itself. -/
theorem cq_member {s0 : State} {clean0 : NodeState} (H : HbHyps env.names node s0 clean0)
    {L : List (NodeId × Peer)}
    (perm : (L.map Prod.fst).Perm (s0.allOtherNodes.map Prod.fst))
    (lose : ({ s0 with allOtherNodes := L } : State).canLoseQuorum = true)
    : (clean0.activeMembers.erase node).Nonempty := by
  have nonempty : (s0.configurations.all fun c => !c.nodes.isEmpty) = true := by
    inv_conj H.inv "configurations_nonempty"
  simp only [State.canLoseQuorum, List.any_eq_true, decide_eq_true_eq] at lose
  obtain ⟨c, cmem, lt⟩ := lose
  have cne : c.nodes ≠ [] := by
    simp only [List.all_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at nonempty
    exact nonempty c cmem
  have found : exists m, m ∈ c.nodes
      /\ (({ s0 with allOtherNodes := L } : State).peer? m.1).isSome = true := by
    false_or_by_contra
    rename_i none
    simp only [not_exists, not_and, Bool.not_eq_true, Option.isSome_eq_false_iff] at none
    rw [List.filter_eq_self.mpr (fun m mem => by simp [none m mem])] at lt
    have pos := List.length_pos_iff.mpr cne
    simp only [State.quorum] at lt
    omega
  obtain ⟨⟨m, mp⟩, mmem, some⟩ := found
  obtain ⟨p, hp⟩ := Option.isSome_iff_exists.mp some
  have keyL : m ∈ L.map Prod.fst := by
    simp only [State.peer?] at hp
    exact List.mem_map.mpr
      ⟨(m, p), (lookup_iff_mem (perm.nodup_iff.mpr H.nodup)).mp hp, rfl⟩
  have key := perm.mem_iff.mp keyL
  have elig := H.eligible m key
  simp only [eligiblePeers, CCF.Finset.mem_erase] at elig
  have pos : 0 < s0.lastIdx := by
    false_or_by_contra
    rename_i z
    have alone : (s0.lastIdx != 0 || s0.leadership != .leader || s0.allOtherNodes.isEmpty)
        = true := by
      inv_conj H.inv "empty_leader_alone"
    simp only [show s0.lastIdx = 0 by omega, H.leader, bne_self_eq_false, Bool.false_or,
      List.isEmpty_iff] at alone
    simp [alone] at key
  have hy := ReplUpdateCommit.Hyps.ofInv H.inv
  obtain ⟨D, hD, sh⟩ := hy.configs pos
  obtain ⟨x, xmem, xnodes⟩ := ReplUpdateCommit.shifted_mem sh cmem
  refine ⟨env.names.id m, CCF.Finset.mem_erase.mpr ⟨elig.1, ?_⟩⟩
  have ceq := agrees_eq H.agrees
  rw [ceq]
  simp only [NodeState.activeMembers, NodeState.activeConfigurations]
  rw [show (abs env.names s0).commitIndex = s0.commitIdx from rfl, hD]
  refine ReplUpdateCommit.mem_configurationMembers (List.mem_map_of_mem xmem) ?_
  simp only [ReplUpdateCommit.absConfig, Names.set, CCF.Finset.mem_ofList, List.map_map,
    List.mem_map, xnodes]
  exact ⟨(m, mp), mmem, rfl⟩

/-- CheckQuorum's step-down after a heartbeat is the clean `timeout .checkQuorum`. -/
theorem tri_cq {s0 : State} {clean0 : NodeState} (H : HbHyps env.names node s0 clean0)
    (v : State) (o : Outbox) (acc : HbAcc env node s0 clean0 v o)
    (lose : v.canLoseQuorum = true)
    : Tri env (fun w o' => w = v /\ o' = o)
        (do
          note Note.checkQuorum; becomeFollower)
        (fun _ v o =>
          v.nodeId = s0.nodeId
          /\ Acc env node clean0 (Final env.names node clean0) v o) := by
  obtain ⟨L, hv, perm⟩ := acc.shape
  subst hv
  have others := cq_member H perm lose
  refine tri_keeps_bind (Spec.note _) fun _ => ?_
  unfold becomeFollower
  refine Tri.bind
    (Tri.setV
      (Q :=
        fun _ w o' =>
          w
            = {
              { s0 with allOtherNodes := L } with
                leaderId := none, leadership := .follower
            }
          /\ o' = o)
      fun _ _ ⟨hw, ho⟩ => ⟨by rw [hw], ho⟩)
    fun _ => ?_
  refine Tri.conseq (Tri.keeps (Spec.trace _)) (fun _ _ h => h) fun _ w o' ⟨hw, ho⟩ => ?_
  subst hw ho
  refine ⟨rfl, ?_⟩
  rw [← List.append_nil o']
  refine acc.extend (fun clean R => ?_) (by simp)
  have ag := (HbRel.finish H R).1
  obtain ⟨_, f, _, rfl, _⟩ := R
  have role : clean0.role = .primary := by
    rw [agrees_eq H.agrees]
    simp [abs, absRole, H.leader]
  let clean' : NodeState :=
    { clean0 with sentIndex := f, role := Role.follower, primaryKnown := false }
  refine ⟨.timeout .checkQuorum, clean', ?_, admitted_timeout _, ?_,
    fun _ h => by simp [clean'] at h⟩
  · show Emits (checkQuorum { clean0 with sentIndex := f } node) _ _
    exact emits_congr (emits_bind (emits_guard ⟨role, others⟩) (emits_pure _)) rfl rfl
  · simp only [clean', agrees, abs, trackedPeers, absRole, Bool.and_eq_true, beq_iff_eq] at ag ⊢
    simp_all

/-- After any heartbeat, a leader may step down on CheckQuorum. -/
theorem tri_jp {s0 : State} {clean0 : NodeState} (H : HbHyps env.names node s0 clean0)
    : Tri env (HbAcc env node s0 clean0)
        (do
          let v ← getV
          let next ← lookFn
          if (v.canLoseQuorum && next == some "become_follower") = true then do
            note Note.checkQuorum
            becomeFollower
          else
            pure ())
        (fun _ v o =>
          v.nodeId = s0.nodeId
          /\ Acc env node clean0 (Final env.names node clean0) v o) := by
  refine tri_getV fun v o acc => tri_keeps_bind Spec.lookFn fun _ => ?_
  refine Tri.ite (fun h => tri_cq H v o acc (by simp_all)) (fun _ => ?_)
  · exact Tri.conseq (Tri.pure' (Q := fun _ v o => v.nodeId = s0.nodeId
        /\ Acc env node clean0 (Final env.names node clean0) v o) _)
      (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact acc.final H) (fun _ _ _ h => h)

theorem tick_tri {saved : State} {clean0 : NodeState} (invS : inv env.names saved = true)
    (self : env.names.id saved.nodeId = node) (ag : agrees env.names clean0 saved = true)
    (el
      : saved.leadership ≠ .leader
        -> saved.isRetiredCommitted = false
        -> saved.ticking = true
        -> Tri env (fun w o => w = saved /\ o = [])
            (do
              electionGuard; note Note.electionTimeout; becomePreVoteCandidate)
            (fun _ v o =>
              v.nodeId = saved.nodeId
              /\ (inv env.names v = true
                  -> Acc env node clean0 (Final env.names node clean0) v o)))
    : Tri env (fun v o => v = saved /\ o = []) periodic
        (fun _ v o =>
          v.nodeId = saved.nodeId
          /\ (inv env.names v = true
              -> Acc env node clean0 (Final env.names node clean0) v o)) := by
  unfold periodic
  refine tri_keeps_bind (Spec.trace _) fun _ => ?_
  refine tri_getV fun v o ⟨hv, ho⟩ => ?_
  subst v ho
  refine Tri.ite (fun leader => ?_) (fun notLeader => ?_)
  · have H := HbHyps.ofInv invS ag self (by simpa using leader)
    refine Tri.conseq (P' := fun v o => v = saved /\ o = [])
      (Q' := fun _ v o => v.nodeId = saved.nodeId
        /\ Acc env node clean0 (Final env.names node clean0) v o) ?_ (fun _ _ h => h)
      (fun _ _ _ h => ⟨h.1, fun _ => h.2⟩)
    refine tri_keeps_bind Spec.lookFn fun _ => ?_
    dsimp only
    refine Tri.ite (fun _ => ?_) (fun _ => Tri.conseq (P' := HbAcc env node saved clean0) ?_
      (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact Acc.start (HbRel.start H)) (fun _ _ _ h => h))
    · refine Tri.conseq (P' := HbAcc env node saved clean0) ?_
        (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact Acc.start (HbRel.start H)) (fun _ _ _ h => h)
      refine Tri.bind (Tri.keeps (Spec.note _)) fun _ => ?_
      refine Tri.bind Life.pres_otherNodesSorted fun ids => ?_
      refine Tri.bind (Tri.forIn_list fun id _ _ => ?_) fun _ => ?_
      · refine tri_getV fun v o acc => ?_
        split
        · rename_i p found
          exact Tri.bind (Tri.conseq (tri_sendAE H _ _ _)
            (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact ⟨acc, p, found, rfl, acc.bound found⟩)
            (fun _ _ _ h => h)) fun _ => Pres.pure _
        · exact Tri.conseq (Tri.pure' (Q := fun _ => HbAcc env node saved clean0) _)
            (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact acc) (fun _ _ _ h => h)
      · exact tri_jp H
    · exact tri_jp H
  · refine tri_keeps_bind Spec.lookFn fun _ => Tri.ite (fun _ => ?_) (fun _ => ?_)
    · exact el (by simpa using notLeader) (by simp_all) (by simp_all)
    · exact Tri.conseq (Tri.pure' (Q := fun _ v o => v.nodeId = saved.nodeId
          /\ (inv env.names v = true -> Acc env node clean0 (Final env.names node clean0) v o)) _)
        (fun w o' ⟨hw, ho⟩ => by subst hw ho; exact ⟨rfl, fun _ => Acc.start ⟨ag, id⟩⟩)
        (fun _ _ _ h => h)

end Consensus.TraceValidation.Proofs.Tick
