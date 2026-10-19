module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Proof
public import DisasterRecovery.Tests.Initial

@[expose] public section

namespace DisasterRecovery.Tests.Trace

open CCF
open Model.Local
open Properties.Trace

private def config : Model.Config :=
  {
    protocol := { instanceId := "trace-tests", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }

private def recovered : TxID := { view := 1, seqno := 10 }
private def unused : Location × NodeState := ("unused", initialNode "unused")

private def initial : Model.State :=
  { Tests.initial config ["A"] with nodes := [unused, ("A", initialNode "A")] }

private def gossip : Model.Envelope :=
  { source := "A", target := "A", payload := .gossip recovered }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }
private def gossipSent : Model.State := { initial with network := [gossip] }

private def selected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", recovered)] }

private def ready : Model.State := { nodes := [unused, ("A", selected)], active := ["A"] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }

private def opening : NodeState :=
  { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def opened : Model.State :=
  { ready with nodes := [unused, ("A", opening)], network := [gossip] }

private def trace : Properties.GlobalTrace :=
  { states := [initial, gossipSent, ready, voteSent, opened] }

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, by decide, ?_, ?_, by decide, rfl, ?_⟩
  · intro node member
    exact member
  · simp [initial, Tests.initial, config]
  · simp [initial, unused, Model.protocol]

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
      gossipSent, ready, voteSent, opened, gossip, vote, recovered, unused]
    cbv

private theorem observedOpening
    : NotificationAt config trace 3 "A" (.opening .quorum) := by
  refine ⟨
    voteSent,
    opened,
    .deliver vote,
    selected,
    opening,
    { notifications := [.opening .quorum] },
    rfl,
    rfl,
    ?_,
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

example
    : exists openerTxID,
        Model.recoveredTxID config "A" = some openerTxID
        /\ Properties.UpToDateWithQuorum config openerTxID := by
  apply Proof.full_gossip_preserves_commit config trace ready opened "A" opening
  refine ⟨valid, by simp [trace], ?_, by simp [trace], by simp [opened, ready], rfl⟩
  intro node nodeState configured member entry
  have nodeEq : node = "A" := by simpa [config] using configured
  subst node
  have stateEq : nodeState = selected := by simpa [ready, unused] using member
  subst nodeState
  rfl

example (notification : Notification)
    : ¬ NotificationAt config trace 4 "A" notification := by
  rintro ⟨_, _, _, _, _, _, _, after, _⟩
  simp [trace] at after

example (notification : Notification)
    : ¬ NotificationAt config trace 3 "missing-node" notification := by
  rintro ⟨before, _, _, _, _, _, first, _, _, _, found, _⟩
  have same : before = voteSent := by simpa [trace] using first.symm
  subst before
  simp [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState] at found

-- The local run alone is insufficient: its successor must match the trace.
example
    : ¬ NotificationAt config { states := [voteSent, voteSent] } 0 "A"
          (.opening .quorum) := by
  rintro ⟨before, after, action, nodeBefore, nodeAfter, outputs,
    first, second, transition, actor, foundBefore, foundAfter, run, notified⟩
  simp only [List.getElem?_cons_zero, List.getElem?_cons_succ, Option.some.injEq] at first second
  subst before after
  have beforeEq : nodeBefore = selected := by
    simpa [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState]
      using foundBefore.symm
  have afterEq : nodeAfter = selected := by
    simpa [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState]
      using foundAfter.symm
  subst nodeBefore nodeAfter
  cases action with
  | «local» node input =>
      simp only [Properties.Trace.actor] at actor
      subst node
      cases input
      · change some (selected, { outgoing := [vote, gossip] }) =
          some (selected, outputs) at run
        have effects := congrArg Prod.snd (Option.some.inj run)
        dsimp only at effects
        rw [← effects] at notified
        simp at notified
      · have impossible := congrArg
          (fun result => result.map (fun value => value.1.timeoutState)) run
        cbv at impossible
        cases impossible
  | deliver envelope =>
      have pending : envelope ∈ [vote, gossip] := by
        simp [Model.transitionSystem, MultiNodeTransitionSystem.lift,
          MultiNodeTransitionSystem.next, Option.bind_eq_some_iff, guard, failure] at transition
        obtain ⟨_, _, _, _, ⟨pending, _⟩, _⟩ := transition
        exact pending
      rcases List.mem_cons.mp pending with rfl | remaining
      · have impossible := congrArg
          (fun result => result.map (fun value => value.1.phase)) run
        cbv at impossible
        cases impossible
      · have same : envelope = gossip := by simpa using remaining
        subst envelope
        change some (selected, { outgoing := [], notifications := [.rejected "gossip-frozen"] }) =
          some (selected, outputs) at run
        have effects := congrArg Prod.snd (Option.some.inj run)
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
    ⟨by cbv, Or.inr ⟨"A", rfl⟩, rfl, by decide⟩

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
  Proofs.Local.quorum_step_opens config quorumTimeout ⟨by cbv, Or.inl rfl, rfl, by decide⟩

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
