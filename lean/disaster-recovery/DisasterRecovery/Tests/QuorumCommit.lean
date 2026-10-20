module

import all Init.Control.State
import all Init.Data.List.Sort.Basic

public import DisasterRecovery.Properties
public import DisasterRecovery.Proofs.Trace
public import DisasterRecovery.Tests.Initial
public import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Tests.QuorumCommit

open CCF
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

-- C then finishes opening; its aligned opening timeout leaves the final state unchanged.
private def s12 :=
  snapshot (selected "A") (selected "B") { openedC with timeoutState := .opening }
    (aGossips ++ bGossips)

private def s13 :=
  snapshot (selected "A") (selected "B")
    { openedC with phase := .open, timeoutState := .opening } (aGossips ++ bGossips)

private def trace : Properties.GlobalTrace :=
  Proofs.Trace.lasso [initial, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12] s13

private def actions : List Model.Action :=
  [
    .local "C" .retry,
    .deliver (gossip "C" "A" low),
    .local "A" .timeout,
    .local "A" .retry,
    .deliver (gossip "C" "B" low),
    .local "B" .timeout,
    .local "B" .retry,
    .deliver (gossip "C" "C" low),
    .local "C" .timeout,
    .deliver (vote "A"),
    .deliver (vote "B"),
    .local "C" .timeout,
    .local "C" .timeout
  ]

private theorem initialized : (Model.transitionSystem config).init initial := by
  refine ⟨by unfold Model.Config.Valid; decide, ?_, by decide, rfl, ?_⟩
  · simp [initial, Tests.initial, config]
  · simp [initial, Tests.initial, config, Model.protocol]

private theorem valid : trace.Valid (Model.transitionSystem config) := by
  refine Proofs.Trace.lasso_valid initialized ?_ ⟨.local "C" .timeout, ?_⟩
  · intro i
    refine ⟨actions[i.val]'(by simp [actions]), ?_⟩
    fin_cases i
    all_goals
      dsimp only [Model.transitionSystem, MultiNodeTransitionSystem.lift]
      simp [actions, MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState,
        MultiNodeTransitionSystem.removeOne, Model.protocol, Model.recoveredTxID,
        Model.receive, step, guard, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9,
        s10, s11, s12, s13, openedC, aGossips, bGossips, gossip, vote, high, low]
    all_goals cbv
  · dsimp only [Model.transitionSystem, MultiNodeTransitionSystem.lift]
    simp [MultiNodeTransitionSystem.next, MultiNodeTransitionSystem.nodeState,
      Model.protocol, Model.recoveredTxID, step, guard, config, snapshot, s13, openedC,
      aGossips, bGossips, gossip, high, low]
    cbv

private theorem opened : ("C", openedC) ∈ s11.nodes := by
  simp [s11, snapshot]

private theorem final_in_trace : s11 ∈ trace := ⟨11, rfl⟩

private theorem stale : ¬ Properties.UpToDateWithQuorum config low := by
  unfold Properties.UpToDateWithQuorum
  decide

example
    : trace.Valid (Model.transitionSystem config)
      /\ s11 ∈ trace
      /\ ("C", openedC) ∈ s11.nodes
      /\ openedC.openKind = some .quorum
      /\ Model.recoveredTxID config "C" = some low
      /\ ¬ Properties.UpToDateWithQuorum config low :=
  ⟨valid, final_in_trace, opened, rfl, rfl, stale⟩

private theorem missing_own : ¬ Properties.ReceivedOwnGossip trace "A" := by
  rintro ⟨_, ⟨index, rfl⟩, current, txid, present, gossipPresent⟩
  have member
      : trace.states index
        ∈ [initial, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12] ++ [s13] :=
    Proofs.Trace.lasso_states_mem _ _ index
  generalize trace.states index = state at member present
  simp only [List.cons_append, List.nil_append, List.mem_cons, List.not_mem_nil,
    or_false] at member
  rcases member with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    simp [initial, Tests.initial, config, snapshot, s1, s2, s3, s4, s5, s6, s7, s8, s9,
      s10, s11, s12, s13, openedC, selected, heard, initialNode] at present
    subst current
    simp at gossipPresent

example
    : ¬ (forall voter,
          voter ∈ openedC.votes -> Properties.ReceivedOwnGossip trace voter) :=
  fun own => missing_own (own "A" (by simp [openedC]))

end DisasterRecovery.Tests.QuorumCommit
