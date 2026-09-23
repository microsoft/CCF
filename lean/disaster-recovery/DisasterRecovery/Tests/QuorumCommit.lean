import DisasterRecovery.Proof
import DisasterRecovery.Tests.Initial

namespace DisasterRecovery.Tests.QuorumCommit

open Shared
open Model.Local

private def high : TxID := { view := 1, seqno := 10 }
private def low : TxID := { view := 1, seqno := 5 }

private def config : Model.Config := {
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

private def s1 := snapshot (initialNode "A") (initialNode "B") (initialNode "C")
  [gossip "C" "A" low, gossip "C" "B" low, gossip "C" "C" low]
private def s2 := snapshot (heard "A") (initialNode "B") (initialNode "C")
  [gossip "C" "B" low, gossip "C" "C" low]
private def s3 := snapshot (selected "A") (initialNode "B") (initialNode "C") s2.network
private def s4 := { s3 with network := s3.network ++ vote "A" :: aGossips }
private def s5 := snapshot (selected "A") (heard "B") (initialNode "C")
  (gossip "C" "C" low :: vote "A" :: aGossips)
private def s6 := snapshot (selected "A") (selected "B") (initialNode "C") s5.network
private def s7 := { s6 with network := s6.network ++ vote "B" :: bGossips }
private def s8 := snapshot (selected "A") (selected "B") (heard "C")
  (vote "A" :: aGossips ++ vote "B" :: bGossips)
private def s9 := snapshot (selected "A") (selected "B") (selected "C") s8.network
private def s10 := snapshot (selected "A") (selected "B") { selected "C" with votes := ["A"] }
  (aGossips ++ vote "B" :: bGossips)
private def s11 := snapshot (selected "A") (selected "B") openedC (aGossips ++ bGossips)

private def trace : Properties.GlobalTrace := {
  initial
  steps := [
    ⟨initial, .local "C" .retry, s1⟩,
    ⟨s1, .deliver (gossip "C" "A" low), s2⟩,
    ⟨s2, .local "A" .timeout, s3⟩,
    ⟨s3, .local "A" .retry, s4⟩,
    ⟨s4, .deliver (gossip "C" "B" low), s5⟩,
    ⟨s5, .local "B" .timeout, s6⟩,
    ⟨s6, .local "B" .retry, s7⟩,
    ⟨s7, .deliver (gossip "C" "C" low), s8⟩,
    ⟨s8, .local "C" .timeout, s9⟩,
    ⟨s9, .deliver (vote "A"), s10⟩,
    ⟨s10, .deliver (vote "B"), s11⟩
  ]
}

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, by decide, rfl, by decide, ?_, rfl, ?_⟩
  · intro node member
    exact member
  · simp [initial, Tests.initial, config, Model.protocol]

private theorem valid : trace.Valid (Model.transitionSystem config) := by
  refine ⟨initialized, .cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_
    (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.nil _)))))))))))⟩
  all_goals
    simp [Model.transitionSystem, MultiNodeTransitionSystem.lift, MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState, MultiNodeTransitionSystem.removeOne,
      Model.protocol, Model.recoveredTxID, Model.GlobalHelper.receive, step,
      guard, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11,
      aGossips, bGossips, gossip, vote, high, low]
  all_goals cbv

private theorem opened : ("C", openedC) ∈ trace.final.nodes := by
  simp [trace, Execution.Trace.final, s11, snapshot]

private theorem final_in_trace : trace.final ∈ trace.states := by
  simp [trace, Execution.Trace.final, Execution.Trace.states]

private theorem committable : Properties.RaftCommittable config high := by
  unfold Properties.RaftCommittable
  decide

private theorem behind :
    ¬ (high.view < low.view \/ (high.view = low.view /\ high.seqno <= low.seqno)) := by decide

example : trace.Valid (Model.transitionSystem config) /\
    ("C", openedC) ∈ trace.final.nodes /\ openedC.openKind = some .quorum /\
    Properties.RaftCommittable config high /\ Model.recoveredTxID config "C" = some low /\
    ¬ (high.view < low.view \/ (high.view = low.view /\ high.seqno <= low.seqno)) :=
  ⟨valid, opened, rfl, committable, rfl, behind⟩

example : ¬ (forall voter, voter ∈ openedC.votes -> Properties.ReceivedOwnGossip trace voter) := by
  intro own
  obtain ⟨recovered, found, covers⟩ := Proof.quorum_open_preserves_commit config trace valid
    trace.final final_in_trace "C" openedC opened rfl own high committable
  have same : low = recovered := Option.some.inj found
  exact behind (by simpa only [← same] using covers)

end DisasterRecovery.Tests.QuorumCommit
