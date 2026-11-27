module

import all Init.Control.State
import all Init.Data.ByteArray.Lex
import all Init.Data.String.Compare

public import DisasterRecovery.Properties.Utils
public import DisasterRecovery.Tests.Initial
public import CCF.Proofs.Execution

@[expose] public section

namespace DisasterRecovery.Tests.QuorumCommit

open CCF CCF.Execution
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
  Tests.written (initialNode node) [((.gossips,some "C"),some (.txid low))]

private def selected (node : Location) : NodeState :=
  Tests.written (heard node)
    [
      ((.timeoutPhase,none),some (.phase .voting)),
      ((.phase,none),some (.phase .voting)),
      ((.chosen,none),some (.location "C"))
    ]

private def openedC : NodeState :=
  Tests.written (Tests.written (selected "C") [((.votes,some "A"),some .present)])
    [
      ((.phase,none),some (.phase .opening)),
      ((.openKind,none),some (.openKind .quorum)),
      ((.votes,some "B"),some .present)
    ]

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
  snapshot (selected "A") (selected "B")
    (Tests.written (selected "C") [((.votes,some "A"),some .present)])
    (aGossips ++ vote "B" :: bGossips)

private def s11 := snapshot (selected "A") (selected "B") openedC (aGossips ++ bGossips)

private def pending (before after : Model.State) (node : Location) (event : Event)
    : Model.State :=
  {
    nodes :=
      before.nodes.map
        fun (n,s) => (n, if n == node then Tests.staged config s event else s),
    network := after.network
  }

private def steps : List (Model.Action × Model.State) :=
  [
    (.local "C" .retry, s1),
    (.deliver (gossip "C" "A" low), pending s1 s2 "A" (.receiveGossip "C" low .accepted)),
    (.local "A" (.commit 0), s2),
    (.local "A" .timeout, pending s2 s3 "A" .timeout),
    (.local "A" (.commit 0), s3),
    (.local "A" .retry, s4),
    (.deliver (gossip "C" "B" low), pending s4 s5 "B" (.receiveGossip "C" low .accepted)),
    (.local "B" (.commit 0), s5),
    (.local "B" .timeout, pending s5 s6 "B" .timeout),
    (.local "B" (.commit 0), s6),
    (.local "B" .retry, s7),
    (.deliver (gossip "C" "C" low), pending s7 s8 "C" (.receiveGossip "C" low .accepted)),
    (.local "C" (.commit 0), s8),
    (.local "C" .timeout, pending s8 s9 "C" .timeout),
    (.local "C" (.commit 0), s9),
    (.deliver (vote "A"), pending s9 s10 "C" (.receiveVote "A" .accepted)),
    (.local "C" (.commit 0), s10),
    (.deliver (vote "B"), pending s10 s11 "C" (.receiveVote "B" .accepted)),
    (.local "C" (.commit 0), s11)
  ]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, Tests.initial, config, Model.protocol]

private def behaviour : Properties.Behaviour config :=
  ofSteps initial steps initialized
    (by
      simp only [StepsFrom, steps, and_true]
      and_intros <;> rfl)

private theorem opened : ("C", openedC) ∈ s11.nodes := by
  simp [s11, snapshot]

private theorem final_in_behaviour : s11 ∈ behaviour :=
  Execution.Behaviour.stateAt_mem (n := 19) rfl

private theorem stale : ¬ Properties.UpToDateWithQuorum config low := by
  unfold Properties.UpToDateWithQuorum
  decide

example
    : s11 ∈ behaviour
      /\ ("C", openedC) ∈ s11.nodes
      /\ openedC.openKind = some .quorum
      /\ Model.recoveredTxID config "C" = some low
      /\ ¬ Properties.UpToDateWithQuorum config low :=
  ⟨final_in_behaviour, opened, rfl, rfl, stale⟩

private theorem missing_own : ¬ Properties.ReceivedOwnGossip behaviour "A" := by
  rintro ⟨state, member, current, txid, present, gossipPresent⟩
  rw [behaviour, mem_ofSteps] at member
  have absent
      : forall snapshot, snapshot ∈ initial :: steps.map Prod.snd
        -> forall entry, entry ∈ snapshot.nodes
        -> forall gossip, gossip ∈ entry.2.gossips -> entry.1 = "A" -> gossip.1 ≠ "A" := by
    decide +kernel
  exact absent state member _ present _ gossipPresent rfl rfl

example
    : ¬ (forall voter,
          voter ∈ openedC.votes -> Properties.ReceivedOwnGossip behaviour voter) :=
  fun own => missing_own (own "A" (by decide +kernel))

end DisasterRecovery.Tests.QuorumCommit
