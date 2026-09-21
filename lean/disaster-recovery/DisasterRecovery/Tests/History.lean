import DisasterRecovery.Proof

namespace DisasterRecovery.Tests.History

open Shared
open Model.Local
open Properties.History

private def config : Model.Config := {
  protocol := { instanceId := "history-tests", expectedLocations := ["A"] }
  recovered := [("A", { view := 1, seqno := 10 })]
}

private def recovered : TxID := { view := 1, seqno := 10 }
private def initial : Model.State := Model.initial config ["A"]
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
  · simp [initial, Model.initial, config, Model.protocol]

private def beforeSend : Properties.History.History config ready := {
  initial
  steps := [
    { before := initial, action := .local "A" .retry, after := gossipSent },
    { before := gossipSent, action := .deliver gossip, after := ready }
  ]
  initialized
  valid := .cons rfl (.cons (by
    simp [Model.transitionSystem, Global.lift, Global.next, Global.runLocal, gossipSent, initial,
      Model.initial, config, gossip, Global.nodeState, Global.removeOne, guard]
    cbv) (.nil _))
}

private def afterSend : Properties.History.History config voteSent := {
  initial
  steps := beforeSend.steps ++ [
    { before := ready, action := .local "A" .retry, after := voteSent }
  ]
  initialized
  valid := by
    apply beforeSend.valid.append
    exact .cons rfl (.nil _)
}

private def afterOpening : Properties.History.History config opened := {
  initial
  steps := afterSend.steps ++ [
    { before := voteSent, action := .deliver vote, after := opened }
  ]
  initialized
  valid := by
    apply afterSend.valid.append
    exact .cons (by
      simp [Model.transitionSystem, Global.lift, Global.next, Global.runLocal, voteSent, ready,
        vote, Global.nodeState, Global.removeOne, guard]
      cbv) (.nil _)
}

example : selected.chosen = some "A" /\ selected.gossips = config.recovered := by
  constructor <;> rfl

example : ¬ SentVote beforeSend "A" "A" := by
  rintro ⟨snapshot, edge, member, sent⟩
  simp [beforeSend] at member
  rcases member with rfl | rfl
  · obtain ⟨_, found, next, outgoing, run, member⟩ := sent
    have snapshotEq : snapshot = initialNode "A" := by
      simpa [initial, Model.initial, config, Model.nodeState, Global.nodeState] using found.symm
    subst snapshot
    have runEq :
        Global.runStep (Model.protocol config) "A" (initialNode "A") .retry =
          some (initialNode "A", [("A", .gossip recovered)]) := rfl
    rw [runEq] at run
    cases run
    simp at member
  · obtain ⟨action, _⟩ := sent
    cases action

example : ¬ FullGossipSelection beforeSend "A" := by
  rintro ⟨voter, snapshot, ⟨edge, member, sent⟩, _⟩
  simp [beforeSend] at member
  rcases member with rfl | rfl
  · obtain ⟨action, found, next, outgoing, run, member⟩ := sent
    have voterEq : voter = "A" := by simpa using action.symm
    subst voter
    have snapshotEq : snapshot = initialNode "A" := by
      simpa [initial, Model.initial, config, Model.nodeState, Global.nodeState] using found.symm
    subst snapshot
    have runEq :
        Global.runStep (Model.protocol config) "A" (initialNode "A") .retry =
          some (initialNode "A", [("A", .gossip recovered)]) := rfl
    rw [runEq] at run
    cases run
    simp at member
  · obtain ⟨action, _⟩ := sent
    cases action

private theorem full : FullGossipSelection afterSend "A" := by
  refine ⟨"A", selected, ?_, ?_⟩
  · refine ⟨{ before := ready, action := .local "A" .retry, after := voteSent },
      by simp [afterSend], rfl, rfl, selected, [("A", .vote), ("A", .gossip recovered)],
      rfl, by simp⟩
  · intro entry
    rfl

example : ∃ txid, Model.recoveredTxID config "A" = some txid /\
    Properties.Helpers.TxID.EarlierThan recovered txid :=
  Proof.full_gossip_selection_preserves_commit afterSend full
    ⟨"A", recovered, by simp [config, recovered], Or.inr ⟨rfl, Nat.le_refl _⟩⟩

example : Properties.History.QuorumOpened afterOpening "A" := by
  refine ⟨{ before := voteSent, action := .deliver vote, after := opened },
    by simp [afterOpening], rfl, ?_⟩
  let output : Result := {
    state := { selected with phase := .opening, openKind := some .quorum, votes := ["A"] }
    effects := [.opening .quorum]
  }
  refine ⟨output, ⟨selected, rfl, by cbv⟩, by simp [output]⟩

example :
    ¬ Shared.Execution.Trace (Model.transitionSystem config) initial
      [{ before := ready, action := .local "A" .retry, after := voteSent }] voteSent := by
  intro trace
  cases trace

example : ¬ (Model.transitionSystem config).init ready := by
  rintro ⟨_, _, _, _, _, _, nodes⟩
  have invalid := nodes ("A", selected) (by simp [ready])
  have phase := congrArg NodeState.phase invalid
  cases phase

end DisasterRecovery.Tests.History
