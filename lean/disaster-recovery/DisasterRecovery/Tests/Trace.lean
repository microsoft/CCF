import DisasterRecovery.Proof
import DisasterRecovery.Tests.Initial

namespace DisasterRecovery.Tests.Trace

open Shared
open Model.Local
open Properties.Trace

private def config : Model.Config := {
  protocol := { instanceId := "trace-tests", expectedLocations := ["A"] }
  recovered := [("A", { view := 1, seqno := 10 })]
}

private def recovered : TxID := { view := 1, seqno := 10 }
private def initial : Model.State := Tests.initial config ["A"]
private def gossip : Model.Envelope := { source := "A", target := "A", payload := .gossip recovered }
private def vote : Model.Envelope := { source := "A", target := "A", payload := .vote }
private def gossipSent : Model.State := { initial with network := [gossip] }
private def selected : NodeState := {
  location := "A", phase := .voting, chosen := some "A", gossips := [("A", recovered)]
}
private def ready : Model.State := { nodes := [("A", selected)], active := ["A"] }
private def voteSent : Model.State := { ready with network := [vote, gossip] }
private def opened : Model.State := {
  ready with
  nodes := [("A", { selected with phase := .opening, openKind := some .quorum, votes := ["A"] })]
  network := [gossip]
}

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, by decide, rfl, by decide, ?_, rfl, ?_⟩
  · intro node member
    exact member
  · simp [initial, Tests.initial, config, Model.protocol]

private def beforeSend : Properties.GlobalTrace := {
  initial
  steps := [
    { before := initial, action := .local "A" .retry, after := gossipSent },
    { before := gossipSent, action := .deliver gossip, after := ready }
  ]
}

private theorem beforeSend_valid : beforeSend.Valid (Model.transitionSystem config) :=
  ⟨initialized, .cons rfl (.cons (by
    simp [Model.transitionSystem, MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, gossipSent, initial,
      Tests.initial, config, gossip, MultiNodeTransitionSystem.nodeState, MultiNodeTransitionSystem.removeOne, guard]
    cbv) (.nil _))⟩

private def afterSend : Properties.GlobalTrace := {
  initial
  steps := beforeSend.steps ++ [
    { before := ready, action := .local "A" .retry, after := voteSent }
  ]
}

private theorem afterSend_valid : afterSend.Valid (Model.transitionSystem config) :=
  ⟨initialized, beforeSend_valid.2.append (.cons rfl (.nil _))⟩

private def afterOpening : Properties.GlobalTrace := {
  initial
  steps := afterSend.steps ++ [
    { before := voteSent, action := .deliver vote, after := opened }
  ]
}

private theorem afterOpening_valid : afterOpening.Valid (Model.transitionSystem config) :=
  ⟨initialized, afterSend_valid.2.append (.cons (by
      change (Model.transitionSystem config).step voteSent (.deliver vote) = some opened
      simp [Model.transitionSystem, MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, voteSent, ready,
        vote, MultiNodeTransitionSystem.nodeState, MultiNodeTransitionSystem.removeOne, guard]
      cbv) (.nil _))⟩

example : selected.chosen = some "A" /\ selected.gossips = config.recovered := by
  constructor <;> rfl

private theorem noVotesBefore (voter target : Location) :
    ¬ exists edge output, edge ∈ beforeSend.steps /\ OutputAt config edge output /\
      { source := voter, target, payload := .vote } ∈ output.effects.outgoing := by
  rintro ⟨edge, output, member, observed, sent⟩
  simp [beforeSend] at member
  rcases member with rfl | rfl
  · have expected : OutputAt config
        { before := initial, action := .local "A" .retry, after := gossipSent }
        { node := "A", before := initialNode "A", action := .retry, after := initialNode "A",
          effects := { outgoing := [gossip] } } :=
      ⟨rfl, rfl, rfl, ⟨_, rfl, rfl⟩⟩
    rw [Proofs.History.outputAt_unique observed expected] at sent
    simp [gossip] at sent
  · have expected : OutputAt config
        { before := gossipSent, action := .deliver gossip, after := ready }
        { node := "A", before := initialNode "A", action := .receiveGossip "A" recovered .accepted,
          after := selected, effects := {} } :=
      ⟨rfl, rfl, rfl, ⟨_, rfl, by cbv⟩⟩
    rw [Proofs.History.outputAt_unique observed expected] at sent
    simp at sent

example :
    ¬ exists edge output, edge ∈ beforeSend.steps /\ OutputAt config edge output /\
      { source := output.node, target := "A", payload := .vote } ∈ output.effects.outgoing /\
      forall gossip, gossip ∈ output.before.gossips <-> gossip ∈ config.recovered := by
  rintro ⟨edge, output, member, observed, sent, _⟩
  exact noVotesBefore output.node "A" ⟨edge, output, member, observed, sent⟩

private theorem full :
    exists edge output, edge ∈ afterSend.steps /\ OutputAt config edge output /\
      { source := output.node, target := "A", payload := .vote } ∈ output.effects.outgoing /\
      forall gossip, gossip ∈ output.before.gossips <-> gossip ∈ config.recovered := by
  refine ⟨{ before := ready, action := .local "A" .retry, after := voteSent },
    { node := "A", before := selected, action := .retry, after := selected,
      effects := { outgoing := [vote, gossip] } }, by simp [afterSend],
    ⟨rfl, rfl, rfl, ⟨_, rfl, rfl⟩⟩, by simp [vote], ?_⟩
  intro entry
  rfl

example : ∃ txid, Model.recoveredTxID config "A" = some txid /\
    (recovered.view < txid.view \/ (recovered.view = txid.view /\ recovered.seqno <= txid.seqno)) :=
  Proof.full_gossip_selection_preserves_commit config afterSend "A" recovered afterSend_valid full
    ⟨"A", recovered, by simp [config, recovered], Or.inr ⟨rfl, Nat.le_refl _⟩⟩

private def openingEdge : Transition :=
  { before := voteSent, action := .deliver vote, after := opened }

private def openingOutput : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification := {
  node := "A"
  before := selected
  action := .receiveVote "A" .accepted
  after := { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }
  effects := { notifications := [.opening .quorum] }
}

private theorem observedOpening : OutputAt config openingEdge openingOutput := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  refine ⟨_, rfl, ?_⟩
  cbv

example : ¬ OutputAt config openingEdge { openingOutput with effects := {} } := by
  intro fabricated
  have same := Proofs.History.outputAt_unique fabricated observedOpening
  have notifications := congrArg (fun output => output.effects.notifications) same
  simp [openingOutput] at notifications

example (edge : Transition) (member : edge ∈ afterOpening.steps)
    (output : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification)
    (observed : OutputAt config edge output)
    (opening : .opening .quorum ∈ output.effects.notifications) : output.node = "A" :=
  Proof.quorum_opener_unique config afterOpening afterOpening_valid edge openingEdge
    ⟨member, by simp [openingEdge, afterOpening]⟩ output openingOutput ⟨observed, observedOpening⟩
    opening (by simp [openingOutput])

private theorem currentOpened :
    exists current, ("A", current) ∈ afterOpening.final.nodes /\ current.openKind = some .quorum :=
  ⟨{ selected with phase := .opening, openKind := some .quorum, votes := ["A"] },
    by simp [afterOpening, afterSend, beforeSend, Shared.Execution.Trace.final, opened], rfl⟩

example : ∃ txid, Model.recoveredTxID config "A" = some txid /\
    (recovered.view < txid.view \/ (recovered.view = txid.view /\ recovered.seqno <= txid.seqno)) := by
  obtain ⟨current, present, kind⟩ := currentOpened
  have finalState : afterOpening.final ∈ afterOpening.states := by
    simp [afterOpening, afterSend, beforeSend, Shared.Execution.Trace.final, Shared.Execution.Trace.states]
  apply Proof.quorum_open_preserves_commit config afterOpening afterOpening_valid
    afterOpening.final finalState "A" current present kind
  · intro voter vote
    have same : current = openingOutput.after := by
      simpa [afterOpening, afterSend, beforeSend, Shared.Execution.Trace.final, opened,
        ready, openingOutput] using present
    have voterEq : voter = "A" := by simpa [same, openingOutput] using vote
    subst voter
    exact ⟨ready, by simp [afterOpening, afterSend, beforeSend, Shared.Execution.Trace.states],
      selected, recovered, by simp [ready], by simp [selected]⟩
  · unfold Properties.RaftCommittable
    decide

private def quorumBefore : NodeState := { selected with votes := ["A"] }

private def quorumVote : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification := {
  node := "A"
  before := quorumBefore
  action := .receiveVote "A" .accepted
  after := { quorumBefore with phase := .opening, openKind := some .quorum }
  effects := { notifications := [.opening .quorum] }
}

example : quorumVote.after.phase = .opening /\ quorumVote.after.openKind = some .quorum /\
    .opening .quorum ∈ quorumVote.effects.notifications :=
  Proof.quorum_advance_opens config quorumVote ⟨_, rfl, by cbv⟩
    (Or.inr ⟨"A", rfl⟩) rfl (by decide)

private def quorumTimeout : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification := {
  quorumVote with
  action := .timeout
  after := { quorumVote.after with timeoutState := .voting }
}

example : quorumTimeout.after.phase = .opening /\ quorumTimeout.after.openKind = some .quorum /\
    .opening .quorum ∈ quorumTimeout.effects.notifications :=
  Proof.quorum_advance_opens config quorumTimeout ⟨_, rfl, by cbv⟩
    (Or.inl rfl) rfl (by decide)

example :
    ¬ Shared.Execution.ValidSteps (Model.transitionSystem config) initial
      [{ before := ready, action := .local "A" .retry, after := voteSent }] voteSent := by
  intro trace
  cases trace

private theorem ready_not_initial : ¬ (Model.transitionSystem config).init ready := by
  rintro ⟨_, _, _, _, _, _, nodes⟩
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

example :
    ¬ ({ initial := ready, steps := afterSend.steps.drop 2 } : Properties.GlobalTrace).Valid
      (Model.transitionSystem config) := by
  intro valid
  exact ready_not_initial valid.1

end DisasterRecovery.Tests.Trace
