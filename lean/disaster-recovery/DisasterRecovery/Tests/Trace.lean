/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Proofs.Local
import DisasterRecovery.Tests.Initial

/-! Concrete recovery traces and checks of their recorded notifications. -/

namespace DisasterRecovery.Tests.Trace

open Shared
open Model.Local
open Properties.Trace

private def config : Model.Config :=
  {
    protocol := { instanceId := "trace-tests", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }

private def recovered : TxID := { view := 1, seqno := 10 }
private def initial : Model.State := Tests.initial config ["A"]

private def gossip : Model.Envelope :=
  { source := "A", target := "A", payload := .gossip recovered }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }
private def gossipSent : Model.State := { initial with network := [gossip] }

private def selected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", recovered)] }

private def ready : Model.State := { nodes := [("A", selected)], active := ["A"] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }

private def opening : NodeState :=
  { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def opened : Model.State :=
  { ready with nodes := [("A", opening)], network := [gossip] }

private def trace : Properties.GlobalTrace :=
  { states := [initial, gossipSent, ready, voteSent, opened] }

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, by decide, rfl, by decide, ?_, rfl, ?_⟩
  · intro node member
    exact member
  · simp [initial, Tests.initial, config, Model.protocol]

private theorem valid : trace.Valid (Model.transitionSystem config) := by
  refine ⟨⟨initial, rfl, initialized⟩, ?_⟩
  intro i before after first second
  have bound : i < 4 := by
    have := (List.getElem?_eq_some_iff.mp second).1
    simp only [trace, List.length_cons, List.length_nil] at this
    omega
  let actions : List Model.Action :=
    [.local "A" .retry, .deliver gossip, .local "A" .retry, .deliver vote]
  refine ⟨actions[i]'(by simpa [actions] using bound), ?_⟩
  interval_cases i <;> simp only [trace, List.getElem?_cons_zero,
    List.getElem?_cons_succ, Nat.reduceAdd, Option.some.injEq] at first second <;>
    subst before <;> subst after
  all_goals
    simp only [Model.transitionSystem, config, MultiNodeTransitionSystem.lift, List.nodup_cons,
      List.not_mem_nil, not_false_eq_true, List.nodup_nil, and_self, List.map_eq_singleton_iff,
      Prod.exists, exists_and_right, exists_eq_right, List.mem_cons, or_false, Model.protocol,
      Model.recoveredTxID, List.find?_singleton, beq_iff_eq, Option.map_ite, step, Option.pure_def,
      bne_iff_ne, ne_eq, ite_not, guard, List.isEmpty_cons, Bool.not_false, Bool.or_true,
      ↓reduceIte, bind_pure_comp, List.forIn_yield_eq_foldlM, id_map', List.foldlM_cons,
      List.foldlM_nil, bind_pure, Option.bind_eq_bind, Option.bind_some, Bool.not_eq_eq_eq_not,
      Bool.not_true, List.isEmpty_eq_false_iff, List.filter_eq_nil_iff, Decidable.not_not,
      forall_eq, Option.failure_eq_none, Prod.forall, true_and, initial, Tests.initial,
      List.map_cons, List.map_nil, gossip, recovered, vote, List.getElem_cons_zero,
      MultiNodeTransitionSystem.next, List.contains_eq_mem, decide_eq_true_eq,
      MultiNodeTransitionSystem.nodeState, List.nil_append, gossipSent, actions,
      List.getElem_cons_succ, decide_true, Model.receive, MultiNodeTransitionSystem.removeOne,
      BEq.rfl, ready, voteSent, Envelope.mk.injEq, reduceCtorEq, and_false, or_self,
      List.cons_append, opened]
    cbv

private theorem observedOpening
    : NotificationAt config trace 3 "A" (.opening .quorum) := by
  refine ⟨
    voteSent,
    opened,
    .deliver vote,
    selected,
    opening,
    _,
    { notifications := [.opening .quorum] },
    rfl,
    rfl,
    ?_,
    rfl,
    rfl,
    rfl,
    rfl,
    ?_,
    by simp
  ⟩
  · simp only [Model.transitionSystem, MultiNodeTransitionSystem.lift, Prod.forall, voteSent, ready,
    vote, MultiNodeTransitionSystem.next, guard, List.contains_eq_mem, List.mem_cons,
    List.not_mem_nil, or_false, true_or, decide_true, ↓reduceIte, Option.pure_def,
    MultiNodeTransitionSystem.removeOne, BEq.rfl, decide_eq_true_eq, Option.failure_eq_none,
    MultiNodeTransitionSystem.nodeState, List.find?_singleton, beq_iff_eq, Option.map_ite,
    List.map_cons, List.map_nil, Option.bind_eq_bind, Option.bind_some, List.cons_append,
    List.nil_append]
    cbv
  · cbv

example : (Model.transitionSystem config).Reachable opened :=
  valid.reachable (by simp [trace])

example : NotificationAt config trace 3 "A" (.opening .quorum) := observedOpening

example (notification : Notification)
    : ¬ NotificationAt config trace 4 "A" notification := by
  rintro ⟨_, _, _, _, _, _, _, _, after, _⟩
  simp [trace] at after

example (notification : Notification)
    : ¬ NotificationAt config trace 3 "missing-node" notification := by
  rintro ⟨before, _, _, _, _, _, _, first, _, _, _, found, _⟩
  have same : before = voteSent := by simpa [trace] using first.symm
  subst before
  simp [voteSent, ready, MultiNodeTransitionSystem.nodeState] at found

-- The local run alone is insufficient: its successor must match the trace.
example
    : ¬ NotificationAt config { states := [voteSent, voteSent] } 0 "A"
          (.opening .quorum) := by
  rintro ⟨before, after, action, nodeBefore, nodeAfter, execute, outputs,
    first, second, transition, actor, foundBefore, foundAfter, enabled, run, notified⟩
  simp only [List.getElem?_cons_zero, List.getElem?_cons_succ, Option.some.injEq] at first second
  subst before after
  have beforeEq : nodeBefore = selected := by
    simpa [voteSent, ready, MultiNodeTransitionSystem.nodeState] using foundBefore.symm
  have afterEq : nodeAfter = selected := by
    simpa [voteSent, ready, MultiNodeTransitionSystem.nodeState] using foundAfter.symm
  subst nodeBefore nodeAfter
  cases action with
  | «local» node input =>
      simp only [Properties.Trace.actor] at actor
      subst node
      cases input
      · have actual : execute.run {} = (selected, { outgoing := [vote, gossip] }) := by
          have enabled' := enabled
          change _ = some execute at enabled'
          have same : _ = execute := Option.some.inj (rfl.trans enabled')
          rw [← same]
          rfl
        have effects := congrArg Prod.snd (actual.symm.trans run)
        dsimp only at effects
        rw [← effects] at notified
        simp at notified
      · have actual := enabled
        change some _ = some execute at actual
        cases actual
        have impossible := congrArg (fun result => result.1.timeoutState) run
        cases impossible
  | deliver envelope =>
      have pending : envelope ∈ [vote, gossip] := by
        simp only [Model.transitionSystem, MultiNodeTransitionSystem.lift, Prod.forall,
          MultiNodeTransitionSystem.next, guard, List.contains_eq_mem, decide_eq_true_eq,
          Option.pure_def, failure, beq_iff_eq, Option.bind_eq_bind, Option.bind_some,
          Option.bind_eq_some_iff, ite_eq_left_iff, reduceCtorEq, imp_false, Decidable.not_not,
          exists_const] at transition
        exact transition.1
      rcases List.mem_cons.mp pending with rfl | remaining
      · have actual := enabled
        change some _ = some execute at actual
        cases actual
        have impossible := congrArg (fun result => result.1.phase) run
        cbv at impossible
        cases impossible
      · have same : envelope = gossip := by simpa using remaining
        subst envelope
        have actual := enabled
        change some _ = some execute at actual
        cases actual
        change (selected, { outgoing := [], notifications := [.rejected "gossip-frozen"] }) =
          (selected, outputs) at run
        have effects := congrArg Prod.snd run
        dsimp only at effects
        rw [← effects] at notified
        simp at notified

private def quorumBefore : NodeState := { selected with votes := ["A"] }

private def quorumVote : Properties.LocalStep :=
  {
    node := "A",
    before := quorumBefore,
    action := .receiveVote "A" .accepted
    after := { quorumBefore with phase := .opening, openKind := some .quorum }
    effects := { notifications := [.opening .quorum] }
  }

example
    : quorumVote.after.phase = .opening
      /\ quorumVote.after.openKind = some .quorum
      /\ .opening .quorum ∈ quorumVote.effects.notifications :=
  Proofs.Local.quorum_step_opens config quorumVote
    ⟨⟨_, rfl, by cbv⟩, Or.inr ⟨"A", rfl⟩, rfl, by decide⟩

private def quorumTimeout : Properties.LocalStep :=
  {
    quorumVote with
      action := .timeout
      after := { quorumVote.after with timeoutState := .voting }
  }

example
    : quorumTimeout.after.phase = .opening
      /\ quorumTimeout.after.openKind = some .quorum
      /\ .opening .quorum ∈ quorumTimeout.effects.notifications :=
  Proofs.Local.quorum_step_opens config quorumTimeout
    ⟨⟨_, rfl, by cbv⟩, Or.inl rfl, rfl, by decide⟩

example
    : ¬ ({ states := [ready, voteSent] } : Properties.GlobalTrace).Valid
          (Model.transitionSystem config) := by
  rintro ⟨⟨start, first, _, _, _, _, _, _, nodes⟩, _⟩
  have same : start = ready := by simpa using first.symm
  subst start
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

end DisasterRecovery.Tests.Trace
