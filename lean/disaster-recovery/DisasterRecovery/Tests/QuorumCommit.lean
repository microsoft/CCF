module

import all Init.Control.State

public import DisasterRecovery.Properties
public import DisasterRecovery.Tests.Initial

import DisasterRecovery.Proofs.Evaluation

@[expose] public section

namespace DisasterRecovery.Tests.QuorumCommit

open CCF
open Model.Local
open Proofs.Evaluation

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
  { nodes := [("A", a), ("B", b), ("C", c)], network }

private def initial : Model.State := Tests.initial config
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

private def steps : List (Model.Action × Model.State) :=
  [
    (.local "C" .retry, s1),
    (.deliver (gossip "C" "A" low), s2),
    (.local "A" .timeout, s3),
    (.local "A" .retry, s4),
    (.deliver (gossip "C" "B" low), s5),
    (.local "B" .timeout, s6),
    (.local "B" .retry, s7),
    (.deliver (gossip "C" "C" low), s8),
    (.local "C" .timeout, s9),
    (.deliver (vote "A"), s10),
    (.deliver (vote "B"), s11)
  ]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, Tests.initial, config, Model.protocol]

private def trace : Properties.GlobalTrace config :=
  ofSteps initial steps initialized
    (by
      simp only [StepsFrom, steps, Model.transitionSystem, MultiNodeTransitionSystem.lift,
        Model.protocol, step, insertGossip_eval, insertVote_eval, and_true]
      and_intros <;> rfl)

private theorem opened : ("C", openedC) ∈ s11.nodes := by
  simp [s11, snapshot]

private theorem final_in_trace : s11 ∈ trace :=
  Execution.Trace.stateAt_mem (n := 11) rfl

private theorem stale : ¬ Properties.UpToDateWithQuorum config low := by
  unfold Properties.UpToDateWithQuorum
  decide

example
    : s11 ∈ trace
      /\ ("C", openedC) ∈ s11.nodes
      /\ openedC.openKind = some .quorum
      /\ Model.recoveredTxID config "C" = some low
      /\ ¬ Properties.UpToDateWithQuorum config low :=
  ⟨final_in_trace, opened, rfl, rfl, stale⟩

private theorem missing_own : ¬ Properties.ReceivedOwnGossip trace "A" := by
  rintro ⟨state, member, current, txid, present, gossipPresent⟩
  rw [trace, mem_ofSteps] at member
  have absent
      : forall snapshot, snapshot ∈ initial :: steps.map Prod.snd
        -> forall entry, entry ∈ snapshot.nodes
        -> forall gossip, gossip ∈ entry.2.gossips -> entry.1 = "A" -> gossip.1 ≠ "A" := by
    decide +kernel
  exact absent state member _ present _ gossipPresent rfl rfl

example
    : ¬ (forall voter,
          voter ∈ openedC.votes -> Properties.ReceivedOwnGossip trace voter) :=
  fun own => missing_own (own "A" (by simp [openedC]))

end DisasterRecovery.Tests.QuorumCommit
