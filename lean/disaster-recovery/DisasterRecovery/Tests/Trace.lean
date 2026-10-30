module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Properties
public import DisasterRecovery.Tests.Initial

import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Tests.Trace

open CCF
open Model.Local
open Properties.Trace

attribute [local simp] StateT.run

private def config : Model.Config :=
  {
    protocol := { instanceId := "trace-tests", expectedLocations := ["A"] }
    recovered := [("A", { view := 1, seqno := 10 })]
  }

private def recovered : TxID := { view := 1, seqno := 10 }
private def unused : Location × NodeState := ("unused", initialNode "unused")

private def initial : Model.State :=
  { Tests.initial config with nodes := [unused, ("A", initialNode "A")] }

private def gossip : Model.Envelope :=
  { source := "A", target := "A", payload := .gossip recovered }

private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }
private def gossipSent : Model.State := { initial with network := [gossip] }

private def selected : NodeState :=
  { location := "A", phase := .voting, chosen := some "A", gossips := [("A", recovered)] }

private def ready : Model.State := { nodes := [unused, ("A", selected)] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }

private def opening : NodeState :=
  { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }

private def opened : Model.State :=
  { ready with nodes := [unused, ("A", opening)], network := [gossip] }

private def states : List Model.State := [initial, gossipSent, ready, voteSent, opened]

private def actions : List Model.Action :=
  [.local "A" .retry, .deliver gossip, .local "A" .retry, .deliver vote]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, unused, Model.protocol]

private def trace : Properties.GlobalTrace config := by
  refine {
    states := Stream'.Seq.ofList states
    actions := Stream'.Seq.ofList actions
    valid_init := ⟨initial, rfl, initialized⟩
    valid_domains := by
      intro n
      simp only [Stream'.Seq.ofList_get?, isSome_getElem?]
      change (n < 4) <-> (n + 1 < 5)
      omega
    valid_step := ?_
  }
  intro i before action first chosen
  have bound : i < 4 := by
    have := (List.getElem?_eq_some_iff.mp chosen).1
    simpa [actions] using this
  interval_cases i <;>
    simp only [states, actions, Stream'.Seq.ofList_get?,
      List.getElem?_cons_zero, List.getElem?_cons_succ,
      Option.some.injEq] at first chosen <;> subst before <;> subst action
  all_goals
    simp [states, Model.transitionSystem, MultiNodeTransitionSystem.lift,
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
    rfl,
    rfl,
    rfl,
    rfl,
    ?_,
    by simp
  ⟩
  · simp [Model.protocol, config]
    cbv

example : (Model.transitionSystem config).Reachable opened :=
  trace.reachable (Execution.Trace.stateAt_mem (n := 4) rfl)

example : NotificationAt config trace 3 "A" (.opening .quorum) := observedOpening

example
    : exists openerTxID,
        Model.recoveredTxID config "A" = some openerTxID
        /\ Properties.UpToDateWithQuorum config openerTxID := by
  apply Properties.full_gossip_preserves_commit config trace ready opened "A" opening
  refine ⟨
    Execution.Trace.stateAt_mem (n := 2) rfl,
    ?_,
    Execution.Trace.stateAt_mem (n := 4) rfl,
    by simp [opened],
    rfl
  ⟩
  intro node nodeState configured member entry
  have nodeEq : node = "A" := by simpa [config] using configured
  subst node
  have stateEq : nodeState = selected := by simpa [ready, unused] using member
  subst nodeState
  rfl

example (notification : Notification)
    : ¬ NotificationAt config trace 4 "A" notification := by
  rintro ⟨_, _, _, _, _, _, _, after, _⟩
  simp [trace, states] at after

example (notification : Notification)
    : ¬ NotificationAt config trace 3 "missing-node" notification := by
  rintro ⟨before, _, _, _, _, _, first, _, _, _, found, _⟩
  have same : before = voteSent := by simpa [trace, states] using first.symm
  subst before
  simp [voteSent, ready, unused, MultiNodeTransitionSystem.nodeState] at found

-- Notifications come from the recorded action, not an arbitrary local run.
example : ¬ NotificationAt config trace 2 "A" (.opening .quorum) := by
  rintro ⟨before, _, action, nodeBefore, nodeAfter, outputs,
    first, _, chosen, _, foundBefore, _, run, notified⟩
  have actionEq : action = .local "A" .retry := by
    simpa [trace, actions] using chosen.symm
  have stateEq : before = ready := by simpa [trace, states] using first.symm
  subst action before
  have beforeEq : nodeBefore = selected := by
    simpa [ready, unused, MultiNodeTransitionSystem.nodeState] using foundBefore.symm
  subst nodeBefore
  change some (selected, { outgoing := [vote, gossip] }) = some (nodeAfter, outputs) at run
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
  Properties.quorum_advance_opens config quorumVote
    ⟨
      by
        simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, config,
          quorumVote]
        cbv,
      Or.inr ⟨"A", rfl⟩,
      rfl,
      by decide
    ⟩

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
  Properties.quorum_advance_opens config quorumTimeout
    ⟨
      by
        simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, config,
          quorumTimeout]
        cbv,
      Or.inl rfl,
      rfl,
      by decide
    ⟩

example (candidate : Properties.GlobalTrace config)
    (states : candidate.states = Stream'.Seq.ofList [ready, voteSent])
    : False := by
  obtain ⟨start, first, _, _, _, _, nodes⟩ := candidate.valid_init
  have same : start = ready := by simpa [states] using first.symm
  subst start
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

end DisasterRecovery.Tests.Trace
