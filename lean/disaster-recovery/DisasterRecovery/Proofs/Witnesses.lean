/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Properties
import Mathlib.Tactic

/-! Concrete executions witnessing each recovery property's premises. -/

namespace DisasterRecovery.Proofs.Witnesses

open Shared
open Model.Local

private theorem valid_of_adjacent {config : Model.Config} {trace : Properties.GlobalTrace}
    (initialized
      : exists initial,
          trace.states[0]? = some initial /\ (Model.transitionSystem config).init initial)
    (adjacent
      : forall i : Fin (trace.states.length - 1),
          exists action,
            (Model.transitionSystem config).step (trace.states[i.val]'(by omega)) action
            = some (trace.states[i.val + 1]'(by omega)))
    : trace.Valid (Model.transitionSystem config) := by
  refine ⟨initialized, ?_⟩
  intro i before after atBefore atAfter
  obtain ⟨beforeBound, beforeEq⟩ := List.getElem?_eq_some_iff.mp atBefore
  obtain ⟨afterBound, afterEq⟩ := List.getElem?_eq_some_iff.mp atAfter
  obtain ⟨action, stepped⟩ := adjacent ⟨i, by omega⟩
  exact ⟨action, by simpa only [beforeEq, afterEq] using stepped⟩

private def initial (config : Model.Config) : Model.State :=
  {
    nodes := config.protocol.expectedLocations.map fun node => (node, initialNode node)
    active := config.protocol.expectedLocations
  }

private theorem initialized {config : Model.Config} (valid : config.Valid)
    : (Model.transitionSystem config).init (initial config) := by
  refine ⟨valid, valid.2.1, ?_, valid.2.1, ?_, rfl, ?_⟩
  · simp [initial, Function.comp_def]
  · intro node member
    exact member
  · intro entry member
    obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
    rfl

private def high : TxID := { view := 1, seqno := 10 }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }

private def quorumConfig : Model.Config :=
  {
    protocol := { instanceId := "quorum-witness", expectedLocations := ["A"] }
    recovered := [("A", high)]
  }

private def quorumActions : List Model.Action :=
  [.local "A" .retry, .deliver (gossip "A" "A" high), .local "A" .retry, .deliver vote]

private def quorumSelected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", high)] }

private def quorumReady : Model.State :=
  {
    nodes := [("A", quorumSelected)]
    active := ["A"]
  }

private def quorumVoteSent : Model.State :=
  { quorumReady with network := [vote, gossip "A" "A" high] }

private def quorumOpener : NodeState :=
  { quorumSelected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def quorumOpened : Model.State :=
  {
    nodes := [("A", quorumOpener)]
    active := ["A"]
    network := [gossip "A" "A" high]
  }

private def quorumTrace : Properties.GlobalTrace :=
  {
    states :=
      [
        initial quorumConfig,
        { initial quorumConfig with network := [gossip "A" "A" high] },
        quorumReady,
        quorumVoteSent,
        quorumOpened
      ]
  }

private theorem quorum_valid
    : quorumTrace.Valid (Model.transitionSystem quorumConfig) := by
  refine valid_of_adjacent
    ⟨initial quorumConfig, rfl, initialized (by unfold Model.Config.Valid; decide)⟩ ?_
  intro i
  refine ⟨quorumActions[i.val]'(by simpa [quorumTrace, quorumActions] using i.isLt), ?_⟩
  fin_cases i <;>
    simp only [Model.transitionSystem, quorumConfig, high, MultiNodeTransitionSystem.lift,
      List.nodup_cons, List.not_mem_nil, not_false_eq_true, List.nodup_nil, and_self,
      List.map_eq_singleton_iff, Prod.exists, exists_and_right, exists_eq_right, List.mem_cons,
      or_false, Model.protocol, Model.recoveredTxID, List.find?_singleton, beq_iff_eq,
      Option.map_ite, step, Option.pure_def, bne_iff_ne, ne_eq, ite_not, guard, List.isEmpty_cons,
      Bool.not_false, Bool.or_true, ↓reduceIte, bind_pure_comp, List.forIn_yield_eq_foldlM, id_map',
      List.foldlM_cons, List.foldlM_nil, bind_pure, Option.bind_eq_bind, Option.bind_some,
      Bool.not_eq_eq_eq_not, Bool.not_true, List.isEmpty_eq_false_iff, List.filter_eq_nil_iff,
      Decidable.not_not, forall_eq, Option.failure_eq_none, Prod.forall, true_and, quorumTrace,
      initial, List.map_cons, List.map_nil, gossip, quorumReady, quorumVoteSent, vote, quorumOpened,
      List.getElem_cons_zero, quorumActions, MultiNodeTransitionSystem.next, List.contains_eq_mem,
      decide_eq_true_eq, MultiNodeTransitionSystem.nodeState, List.nil_append, zero_add,
      List.getElem_cons_succ, decide_true, Model.receive, MultiNodeTransitionSystem.removeOne,
      BEq.rfl, Nat.reduceAdd, Envelope.mk.injEq, reduceCtorEq, and_false, or_self, List.cons_append]
      <;> cbv

private theorem quorum_notified
    : Properties.Trace.NotificationAt quorumConfig quorumTrace 3 "A"
        (.opening .quorum) := by
  refine ⟨quorumVoteSent, quorumOpened, .deliver vote, quorumSelected, quorumOpener,
    _, { notifications := [.opening .quorum] }, ?_, ?_, ?_, rfl, rfl, rfl, rfl, ?_, ?_⟩
  · rfl
  · rfl
  · simp only [Model.transitionSystem, MultiNodeTransitionSystem.lift, Prod.forall, quorumVoteSent,
    quorumReady, vote, MultiNodeTransitionSystem.next, guard, List.contains_eq_mem, List.mem_cons,
    List.not_mem_nil, or_false, true_or, decide_true, ↓reduceIte, Option.pure_def,
    MultiNodeTransitionSystem.removeOne, BEq.rfl, decide_eq_true_eq, Option.failure_eq_none,
    MultiNodeTransitionSystem.nodeState, List.find?_singleton, beq_iff_eq, Option.map_ite,
    List.map_cons, List.map_nil, Option.bind_eq_bind, Option.bind_some, List.cons_append,
    List.nil_append]
    cbv
  · cbv
  · simp

theorem quorum_opener_unique_witness : Properties.QuorumOpenerUniqueWitness :=
  ⟨quorumConfig, quorumTrace, 3, "A", quorum_valid, quorum_notified⟩

theorem quorum_open_preserves_commit_witness
    : Properties.QuorumOpenPreservesCommitWitness := by
  refine ⟨
    quorumConfig,
    quorumTrace,
    quorumOpened,
    "A",
    quorumOpener,
    quorum_valid,
    List.mem_iff_getElem?.mpr ⟨4, ?_⟩,
    by simp [quorumOpened],
    rfl,
    ?_
  ⟩
  · rfl
  · intro voter member
    have same : voter = "A" := by simpa [quorumOpener] using member
    subst voter
    refine ⟨quorumReady, List.mem_iff_getElem?.mpr ⟨2, ?_⟩,
      quorumSelected, high, by simp [quorumReady], by simp [quorumSelected]⟩
    rfl

private def fullConfig : Model.Config :=
  {
    protocol :=
      {
        instanceId := "full-gossip-failover-witness", expectedLocations := ["A", "B", "C"]
      }
    recovered :=
      [("A", high), ("B", { view := 1, seqno := 8 }), ("C", { view := 1, seqno := 5 })]
  }

private def fullActions : List Model.Action :=
  [
    .local "A" .retry,
    .local "B" .retry,
    .local "C" .retry,
    .deliver (gossip "A" "A" high),
    .deliver (gossip "B" "A" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "A" { view := 1, seqno := 5 }),
    .deliver (gossip "A" "B" high),
    .deliver (gossip "B" "B" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "B" { view := 1, seqno := 5 }),
    .deliver (gossip "A" "C" high),
    .deliver (gossip "B" "C" { view := 1, seqno := 8 }),
    .deliver (gossip "C" "C" { view := 1, seqno := 5 }),
    .local "A" .retry,
    .deliver vote,
    .local "A" .timeout,
    .local "A" .timeout
  ]

private def fullSelected (node : Location) : NodeState :=
  {
    location := node,
    phase := .voting,
    chosen := some "A",
    gossips := fullConfig.recovered
  }

private def fullGossiped : Model.State :=
  {
    nodes := [("A", fullSelected "A"), ("B", fullSelected "B"), ("C", fullSelected "C")]
    active := ["A", "B", "C"]
  }

private def failoverOpener : NodeState :=
  {
    fullSelected "A" with
      phase := .opening
      timeoutState := .opening
      votes := ["A"]
      openKind := some .failover
  }

private def failoverOpened : Model.State :=
  {
    fullGossiped with
      nodes := [("A", failoverOpener), ("B", fullSelected "B"), ("C", fullSelected "C")]
      network := [gossip "A" "A" high, gossip "A" "B" high, gossip "A" "C" high]
  }

private def fullPending (a b c : Nat) : List Model.Envelope :=
  fullConfig.recovered.zipIdx.flatMap
    fun (entry, index) =>
      ([("A", a), ("B", b), ("C", c)].filter fun target => decide (target.2 <= index)).map
        fun target => gossip entry.1 target.1 entry.2

private def partialNode (node : Location) (count : Nat) : NodeState :=
  match count with
  | 3 => fullSelected node
  | _ => { location := node, gossips := fullConfig.recovered.take count }

private def partialGossip (a b c : Nat) : Model.State :=
  {
    nodes :=
      [("A", partialNode "A" a), ("B", partialNode "B" b), ("C", partialNode "C" c)]
    active := ["A", "B", "C"]
    network := fullPending a b c
  }

private def fullVoteSent : Model.State :=
  { fullGossiped with network := vote :: failoverOpened.network }

private def fullVoted : Model.State :=
  {
    fullGossiped with
      nodes :=
        [
          ("A", { fullSelected "A" with votes := ["A"] }),
          ("B", fullSelected "B"),
          ("C", fullSelected "C")
        ]
      network := failoverOpened.network
  }

private def fullTimeout : Model.State :=
  {
    fullVoted with
      nodes :=
        [
          ("A", { fullSelected "A" with votes := ["A"], timeoutState := .voting }),
          ("B", fullSelected "B"),
          ("C", fullSelected "C")
        ]
  }

private def fullTrace : Properties.GlobalTrace :=
  {
    states :=
      [
        initial fullConfig,
        { initial fullConfig with network := (fullPending 0 0 0).take 3 },
        { initial fullConfig with network := (fullPending 0 0 0).take 6 },
        partialGossip 0 0 0,
        partialGossip 1 0 0,
        partialGossip 2 0 0,
        partialGossip 3 0 0,
        partialGossip 3 1 0,
        partialGossip 3 2 0,
        partialGossip 3 3 0,
        partialGossip 3 3 1,
        partialGossip 3 3 2,
        fullGossiped,
        fullVoteSent,
        fullVoted,
        fullTimeout,
        failoverOpened
      ]
  }

set_option maxHeartbeats 2000000 in
-- Kernel reduction checks every adjacent step of the full-gossip witness.
private theorem full_valid : fullTrace.Valid (Model.transitionSystem fullConfig) := by
  refine valid_of_adjacent
    ⟨initial fullConfig, rfl, initialized (by unfold Model.Config.Valid; decide)⟩ ?_
  intro i
  refine ⟨fullActions[i.val]'(by simpa [fullTrace, fullActions] using i.isLt), ?_⟩
  fin_cases i <;>
    simp only [Model.transitionSystem, fullConfig, high, MultiNodeTransitionSystem.lift,
      List.nodup_cons, List.mem_cons, String.reduceEq, List.not_mem_nil, or_self,
      not_false_eq_true, List.nodup_nil, and_self, or_false, Model.protocol, Model.recoveredTxID,
      step, Option.pure_def, bne_iff_ne, ne_eq, ite_not, guard, beq_iff_eq, List.isEmpty_cons,
      Bool.not_false, Bool.or_true, ↓reduceIte, bind_pure_comp, List.forIn_yield_eq_foldlM,
      id_map', List.foldlM_cons, List.foldlM_nil, bind_pure, map_bind, Option.bind_eq_bind,
      Option.bind_some, Bool.not_eq_eq_eq_not, Bool.not_true, List.isEmpty_eq_false_iff,
      List.filter_eq_nil_iff, Decidable.not_not, forall_eq_or_imp, forall_eq, not_and,
      Option.failure_eq_none, Prod.forall, true_and, fullTrace, initial, List.map_cons,
      List.map_nil, fullPending, gossip, zero_le, decide_true, List.filter_cons_of_pos,
      List.filter_nil, List.zipIdx_cons, zero_add, Nat.reduceAdd, List.zipIdx_nil,
      List.flatMap_cons, List.flatMap_nil, List.append_nil, List.cons_append, List.nil_append,
      List.take_succ_cons, List.take_zero, partialGossip, partialNode, nonpos_iff_eq_zero,
      one_ne_zero, decide_false, Bool.false_eq_true, List.filter_cons_of_neg, Std.le_refl,
      Nat.one_le_ofNat, OfNat.ofNat_ne_zero, Nat.not_ofNat_le_one, fullSelected, Nat.reduceLeDiff,
      fullGossiped, fullVoteSent, vote, failoverOpened, failoverOpener, fullVoted, fullTimeout,
      List.getElem_cons_zero, fullActions, MultiNodeTransitionSystem.next, List.contains_eq_mem,
      Bool.decide_or, Bool.or_eq_true, decide_eq_true_eq, MultiNodeTransitionSystem.nodeState,
      BEq.rfl, List.find?_cons_of_pos, Option.map_some, List.getElem_cons_succ, or_true,
      String.reduceBEq, List.find?_cons_of_neg, Envelope.mk.injEq, and_true, and_false,
      Message.gossip.injEq, TxID.mk.injEq, Nat.reduceEqDiff, Model.receive,
      MultiNodeTransitionSystem.removeOne, StateT.run_bind, StateT.run_map, reduceCtorEq] <;> cbv

theorem full_gossip_preserves_commit_witness
    : Properties.FullGossipPreservesCommitWitness := by
  refine ⟨
    fullConfig,
    fullTrace,
    fullGossiped,
    failoverOpened,
    "A",
    failoverOpener,
    full_valid,
    List.mem_iff_getElem?.mpr ⟨12, ?_⟩,
    ?_,
    List.mem_iff_getElem?.mpr ⟨16, ?_⟩,
    by simp [failoverOpened],
    rfl
  ⟩
  · rfl
  · intro node nodeState member entry
    simp only [fullGossiped, List.mem_cons, List.not_mem_nil, or_false, Prod.mk.injEq] at member
    rcases member with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> rfl
  · rfl

private def frozenGossip : Properties.LocalStep :=
  {
    node := "A"
    before := quorumSelected
    action := .receiveGossip "A" high .accepted
    after := quorumSelected
    effects := { notifications := [.rejected "gossip-frozen"] }
  }

theorem gossip_freezes_after_choice_witness
    : Properties.GossipFreezesAfterChoiceWitness := by
  refine ⟨quorumConfig, frozenGossip, "A", high, ⟨_, rfl, ?_⟩, rfl, rfl⟩
  cbv

private def rejectedGossip : Properties.LocalStep :=
  {
    node := "A"
    before := initialNode "A"
    action := .receiveGossip "A" high .rejected
    after := initialNode "A"
    effects := { notifications := [.rejected "quote-or-certificate"] }
  }

theorem rejected_gossip_stutters_witness : Properties.RejectedGossipStuttersWitness := by
  refine ⟨quorumConfig, rejectedGossip, "A", high, ⟨_, rfl, ?_⟩, rfl⟩
  cbv

private def quorumTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumSelected with votes := ["A"] }
    action := .timeout
    after := { quorumOpener with timeoutState := .voting }
    effects := { notifications := [.opening .quorum] }
  }

theorem quorum_advance_opens_witness : Properties.QuorumAdvanceOpensWitness := by
  refine ⟨quorumConfig, quorumTimeout, ⟨_, rfl, ?_⟩, Or.inl rfl, rfl, by decide⟩
  cbv

private def openingTimeout : Properties.LocalStep :=
  {
    node := "A"
    before := { quorumOpener with timeoutState := .opening }
    action := .timeout
    after := { quorumOpener with timeoutState := .opening, phase := .open }
    effects := { notifications := [.completed] }
  }

theorem aligned_opening_timeout_completes_witness
    : Properties.AlignedOpeningTimeoutCompletesWitness := by
  refine ⟨quorumConfig, openingTimeout, ⟨_, rfl, ?_⟩, rfl, rfl, rfl⟩
  cbv

end DisasterRecovery.Proofs.Witnesses
