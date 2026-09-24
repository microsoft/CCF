import DisasterRecovery.Proofs.Local
import DisasterRecovery.Tests.Initial

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
    simp [actions, Model.transitionSystem, MultiNodeTransitionSystem.lift,
      MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState,
      MultiNodeTransitionSystem.removeOne, Model.protocol, Model.recoveredTxID,
      Model.receive, step, guard, initial, Tests.initial, config,
      gossipSent, ready, voteSent, opened, gossip, vote, recovered]
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
  · simp [Model.transitionSystem, MultiNodeTransitionSystem.lift,
      MultiNodeTransitionSystem.next, voteSent, ready, vote,
      MultiNodeTransitionSystem.nodeState, MultiNodeTransitionSystem.removeOne, guard]
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
        simp [Model.transitionSystem, MultiNodeTransitionSystem.lift,
          MultiNodeTransitionSystem.next, Option.bind_eq_some_iff, guard, failure] at transition
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
