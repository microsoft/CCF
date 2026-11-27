module

import all Init.Control.State

public import DisasterRecovery.Properties
public import DisasterRecovery.Tests.Initial

import DisasterRecovery.Proofs.Evaluation

@[expose] public section

namespace DisasterRecovery.Tests.Behaviour

open CCF CCF.Execution
open Model.Local
open Properties.Behaviour


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
  Tests.written (initialNode "A") [((.phase,none),some (.phase .voting)),
    ((.chosen,none),some (.location "A")), ((.gossips,some "A"),some (.txid recovered))]

private def ready : Model.State := { nodes := [unused, ("A", selected)] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }

private def opening : NodeState :=
  Tests.written selected [((.phase,none),some (.phase .opening)),
    ((.openKind,none),some (.openKind .quorum)), ((.votes,some "A"),some .present)]

private def opened : Model.State :=
  { ready with nodes := [unused, ("A", opening)], network := [gossip] }

private def gossipRan := Tests.staged config (initialNode "A") (.receiveGossip "A" recovered .accepted)
private def voteRan := Tests.staged config selected (.receiveVote "A" .accepted)
private def pendingGossip : Model.State := { nodes := [unused,("A",gossipRan)] }
private def pendingVote : Model.State := { nodes := [unused,("A",voteRan)], network := [gossip] }

private def steps : List (Model.Action × Model.State) :=
  [
    (.local "A" .retry, gossipSent),
    (.deliver gossip, pendingGossip), (.local "A" (.commit 0), ready),
    (.local "A" .retry, voteSent),
    (.deliver vote, pendingVote), (.local "A" (.commit 0), opened)
  ]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, unused, Model.protocol]

private def behaviour : Properties.Behaviour config :=
  ofSteps initial steps initialized
    (by
      simp only [StepsFrom, steps, and_true]
      and_intros <;> rfl)

private theorem observedOpening
    : NotificationAt config behaviour 5 "A" (.opening .quorum) := by
  refine ⟨
    pendingVote,
    opened,
    .local "A" (.commit 0),
    voteRan,
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
  rfl

example : (Model.transitionSystem config).Reachable opened :=
  behaviour.reachable (Execution.Behaviour.stateAt_mem (n := 6) rfl)

example : NotificationAt config behaviour 5 "A" (.opening .quorum) := observedOpening

example
    : exists openerTxID,
        Model.recoveredTxID config "A" = some openerTxID
        /\ Properties.UpToDateWithQuorum config openerTxID := by
  apply Properties.full_gossip_preserves_commit config behaviour ready opened "A" opening
  refine ⟨
    Execution.Behaviour.stateAt_mem (n := 3) rfl,
    ?_,
    Execution.Behaviour.stateAt_mem (n := 6) rfl,
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
    : ¬ NotificationAt config behaviour 6 "A" notification := by
  rintro ⟨_, _, _, _, _, _, _, after, _⟩
  rw [behaviour, ofSteps_stateAt] at after
  simp [steps] at after

example (notification : Notification)
    : ¬ NotificationAt config behaviour 5 "missing-node" notification := by
  rintro ⟨before, _, _, _, _, _, first, _, _, _, found, _⟩
  rw [behaviour, ofSteps_stateAt] at first
  have same : before = pendingVote := by simpa [steps] using first.symm
  subst before
  simp [pendingVote, unused, MultiNodeTransitionSystem.nodeState] at found

-- Notifications come from the recorded action, not an arbitrary local run.
example : ¬ NotificationAt config behaviour 3 "A" (.opening .quorum) := by
  rintro ⟨before, _, action, nodeBefore, nodeAfter, outputs,
    first, _, chosen, _, foundBefore, _, run, notified⟩
  rw [behaviour, ofSteps_actionAt] at chosen
  rw [behaviour, ofSteps_stateAt] at first
  have actionEq : action = .local "A" .retry := by simpa [steps] using chosen.symm
  have stateEq : before = ready := by simpa [steps] using first.symm
  subst action before
  have beforeEq : nodeBefore = selected := by
    simpa [ready, unused, MultiNodeTransitionSystem.nodeState] using foundBefore.symm
  subst nodeBefore
  change some (selected, { outgoing := [vote, gossip] }) = some (nodeAfter, outputs) at run
  have effects := congrArg Prod.snd (Option.some.inj run)
  dsimp only at effects
  rw [← effects] at notified
  simp at notified

private def quorumBefore := Tests.written selected [((.votes,some "A"),some .present)]

private def quorumStep (event : Event) (ws : CCF.OCC.Writes Table Key Value) : Properties.LocalStep :=
  ⟨"A", Tests.staged config quorumBefore event, .commit 0, Tests.written quorumBefore ws,
    {notifications := [.opening .quorum]}⟩

private def quorumVote := quorumStep (.receiveVote "A" .accepted)
  [((.phase,none),some (.phase .opening)), ((.openKind,none),some (.openKind .quorum)),
    ((.votes,some "A"),some .present)]

private def quorumTimeout := quorumStep .timeout
  [((.timeoutPhase,none),some (.phase .voting)), ((.phase,none),some (.phase .opening)),
    ((.openKind,none),some (.openKind .quorum))]

example : quorumTimeout.after.phase = .opening ∧ quorumTimeout.after.openKind = some .quorum ∧
    .opening .quorum ∈ quorumTimeout.effects.notifications := by
  apply Properties.quorum_advance_opens config quorumTimeout 0 (quorumTimeout.before.pending[0]'(by decide))
  exact ⟨rfl,rfl,⟨rfl,⟨quorumBefore.store,rfl⟩,by decide⟩,Or.inl rfl,by decide,rfl,by decide⟩

example : quorumVote.after.phase = .opening ∧ quorumVote.after.openKind = some .quorum ∧
    .opening .quorum ∈ quorumVote.effects.notifications := by
  apply Properties.quorum_advance_opens config quorumVote 0 (quorumVote.before.pending[0]'(by decide))
  exact ⟨rfl,rfl,⟨rfl,⟨quorumBefore.store,rfl⟩,by decide⟩,Or.inr ⟨"A",rfl⟩,by decide,rfl,by decide⟩

example (candidate : Properties.Behaviour config)
    (states : candidate.states = CCF.Seq.ofList [ready, voteSent])
    : False := by
  obtain ⟨start, first, _, _, _, _, nodes⟩ := candidate.valid_init
  have same : start = ready := by simpa [states] using first.symm
  subst start
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

end DisasterRecovery.Tests.Behaviour
