/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Properties
import DisasterRecovery.Tests.Initial
import Mathlib.Tactic

/-! A stale quorum opener when voters have not received their own gossip. -/

namespace DisasterRecovery.Tests.QuorumCommit

open Shared
open Model.Local

private def high : TxID := { view := 1, seqno := 10 }
private def low : TxID := { view := 1, seqno := 5 }

private def config : Model.Config :=
  {
    protocol := { instanceId := "quorum-timeout", expectedLocations := ["A", "B", "C"] }
    recovered := [("A", high), ("B", high), ("C", low)]
  }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote (source : Location) : Model.Envelope :=
  { source, target := "C", payload := .vote }

private def heard (node : Location) : NodeState :=
  { location := node, gossips := [("C", low)] }

private def selected (node : Location) : NodeState :=
  { heard node with phase := .voting, timeoutState := .voting, chosen := some "C" }

private def openedC : NodeState :=
  { selected "C" with phase := .opening, votes := ["A", "B"], openKind := some .quorum }

private def snapshot (a b c : NodeState) (network : List Model.Envelope) : Model.State :=
  { nodes := [("A", a), ("B", b), ("C", c)], active := ["A", "B", "C"], network }

private def initial : Model.State := Tests.initial config ["A", "B", "C"]
private def aGossips := [gossip "A" "A" high, gossip "A" "B" high, gossip "A" "C" high]
private def bGossips := [gossip "B" "A" high, gossip "B" "B" high, gossip "B" "C" high]

private def s1 :=
  snapshot (initialNode "A") (initialNode "B") (initialNode "C")
    [gossip "C" "A" low, gossip "C" "B" low, gossip "C" "C" low]

private def s2 :=
  snapshot (heard "A") (initialNode "B") (initialNode "C")
    [gossip "C" "B" low, gossip "C" "C" low]

private def s3 := snapshot (selected "A") (initialNode "B") (initialNode "C") s2.network
private def s4 := { s3 with network := s3.network ++ vote "A" :: aGossips }

private def s5 :=
  snapshot (selected "A") (heard "B") (initialNode "C")
    (gossip "C" "C" low :: vote "A" :: aGossips)

private def s6 := snapshot (selected "A") (selected "B") (initialNode "C") s5.network
private def s7 := { s6 with network := s6.network ++ vote "B" :: bGossips }

private def s8 :=
  snapshot (selected "A") (selected "B") (heard "C")
    (vote "A" :: aGossips ++ vote "B" :: bGossips)

private def s9 := snapshot (selected "A") (selected "B") (selected "C") s8.network

private def s10 :=
  snapshot (selected "A") (selected "B") { selected "C" with votes := ["A"] }
    (aGossips ++ vote "B" :: bGossips)

private def s11 := snapshot (selected "A") (selected "B") openedC (aGossips ++ bGossips)

private def trace : Properties.GlobalTrace :=
  { states := [initial, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] }

private def actions : List Model.Action :=
  [
    .local "C" .retry,
    .deliver (gossip "C" "A" low),
    .local "A" .timeout,
    .local "A" .retry,
    .deliver (gossip "C" "B" low),
    .local "B" .timeout,
    .local "B" .retry,
    .deliver (gossip "C" "C" low),
    .local "C" .timeout,
    .deliver (vote "A"),
    .deliver (vote "B")
  ]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, by decide, rfl, by decide, ?_, rfl, ?_⟩
  · intro node member
    exact member
  · simp [initial, Tests.initial, config, Model.protocol]

private theorem valid : trace.Valid (Model.transitionSystem config) := by
  refine ⟨⟨initial, rfl, initialized⟩, ?_⟩
  intro i before after first second
  have bound : i < 11 := by
    have := (List.getElem?_eq_some_iff.mp second).1
    simp only [trace, List.length_cons, List.length_nil] at this
    omega
  refine ⟨actions[i]'(by simpa [actions] using bound), ?_⟩
  interval_cases i <;> simp only [trace, List.getElem?_cons_zero,
    List.getElem?_cons_succ, Nat.reduceAdd, Option.some.injEq] at first second <;>
    subst before <;> subst after
  all_goals
    simp only [Model.transitionSystem, config, high, low, MultiNodeTransitionSystem.lift,
      List.nodup_cons, List.mem_cons, String.reduceEq, List.not_mem_nil, or_self, not_false_eq_true,
      List.nodup_nil, and_self, or_false, Model.protocol, Model.recoveredTxID, step,
      Option.pure_def, bne_iff_ne, ne_eq, ite_not, guard, beq_iff_eq, List.isEmpty_cons,
      Bool.not_false, Bool.or_true, ↓reduceIte, bind_pure_comp, List.forIn_yield_eq_foldlM, id_map',
      List.foldlM_cons, List.foldlM_nil, bind_pure, map_bind, Option.bind_eq_bind, Option.bind_some,
      Bool.not_eq_eq_eq_not, Bool.not_true, List.isEmpty_eq_false_iff, List.filter_eq_nil_iff,
      Decidable.not_not, forall_eq_or_imp, forall_eq, not_and, Option.failure_eq_none, Prod.forall,
      true_and, actions, gossip, vote, List.getElem_cons_zero, MultiNodeTransitionSystem.next,
      List.contains_eq_mem, decide_eq_true_eq, MultiNodeTransitionSystem.nodeState,
      String.reduceBEq, Bool.false_eq_true, List.find?_cons_of_neg, BEq.rfl, List.find?_cons_of_pos,
      Option.map_some, s1, snapshot, List.getElem_cons_succ, Envelope.mk.injEq, and_true, and_false,
      decide_true, Model.receive, MultiNodeTransitionSystem.removeOne, Bool.decide_or,
      Bool.or_eq_true, List.map_cons, List.map_nil, List.cons_append, List.nil_append, s2, s3, s4,
      aGossips, reduceCtorEq, Message.gossip.injEq, TxID.mk.injEq, Nat.reduceEqDiff, or_true, s5,
      s6, s7, bGossips, s8, s9, s10, s11]
  all_goals cbv

private theorem opened : ("C", openedC) ∈ s11.nodes := by
  simp [s11, snapshot]

private theorem final_in_trace : s11 ∈ trace.states := by
  simp [trace]

private theorem stale : ¬ Properties.UpToDateWithQuorum config low := by
  unfold Properties.UpToDateWithQuorum
  decide

example
    : trace.Valid (Model.transitionSystem config)
      /\ s11 ∈ trace.states
      /\ ("C", openedC) ∈ s11.nodes
      /\ openedC.openKind = some .quorum
      /\ Model.recoveredTxID config "C" = some low
      /\ ¬ Properties.UpToDateWithQuorum config low :=
  ⟨valid, final_in_trace, opened, rfl, rfl, stale⟩

private theorem missing_own : ¬ Properties.ReceivedOwnGossip trace "A" := by
  rintro ⟨state, member, current, txid, present, gossipPresent⟩
  simp only [trace, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    simp [initial, Tests.initial, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9,
      s10, s11, openedC, selected, heard, initialNode] at present
    subst current
    simp at gossipPresent

example
    : ¬ (forall voter,
          voter ∈ openedC.votes -> Properties.ReceivedOwnGossip trace voter) :=
  fun own => missing_own (own "A" (by simp [openedC]))

end DisasterRecovery.Tests.QuorumCommit
