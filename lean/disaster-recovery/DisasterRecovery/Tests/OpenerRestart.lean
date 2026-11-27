module

import all Init.Control.State

public import DisasterRecovery.Properties
public import DisasterRecovery.Tests.Initial

import DisasterRecovery.Proofs.Evaluation

@[expose] public section

/-!
A node that opens by quorum also requests a restart, under the rule that a restart is
requested when the transaction of an IAmOpen runs, not when it commits.

`A` and `C` vote for `A`, while `B` hears only itself and opens by failover. `A` runs the
transaction of `C`'s vote, which gives it a quorum, and then that of `B`'s IAmOpen, which
still reads the voting phase and so requests a restart. The vote commits first, so `A`
opens, and the IAmOpen then conflicts on `phase`, runs again, and is rejected.
-/

namespace DisasterRecovery.Tests.OpenerRestart

open CCF CCF.Execution
open Model.Local
open Properties.Behaviour

private def high : TxID := { view := 1, seqno := 10 }
private def low : TxID := { view := 1, seqno := 5 }

private def config : Model.Config :=
  {
    protocol := { instanceId := "opener-restart", expectedLocations := ["A", "B", "C"] }
    recovered := [("A", high), ("B", low), ("C", low)]
  }

private def gossip (source target : Location) (txid : TxID) : Model.Envelope :=
  { source, target, payload := .gossip txid }

private def vote (source target : Location) : Model.Envelope :=
  { source, target, payload := .vote }

private def iAmOpen (source target : Location) : Model.Envelope :=
  { source, target, payload := .iAmOpen }

private def gossips (source : Location) (txid : TxID) : List Model.Envelope :=
  [gossip source "A" txid, gossip source "B" txid, gossip source "C" txid]

private def receivedGossip (source : Location) (txid : TxID) : Event :=
  .receiveGossip source txid .accepted

private def receivedVote (source : Location) : Event :=
  .receiveVote source .accepted

private def receivedIAmOpen : Event :=
  .receiveIAmOpen "B" .accepted

private def committed (s : NodeState) (e : Event) : NodeState :=
  let ran := (transaction config.protocol e).exec s.store
  Tests.written s ran.normal.writes

private def a0 := initialNode "A"
private def a1 := committed a0 (receivedGossip "A" high)
private def a2 := committed a1 .timeout
private def a3 := committed a2 (receivedVote "A")
private def a4 := committed a3 (receivedVote "C")

private def b0 := initialNode "B"
private def b1 := committed b0 (receivedGossip "B" low)
private def b2 := committed b1 .timeout
private def b3 := committed b2 (receivedVote "B")
private def b4 := committed b3 .timeout

private def c0 := initialNode "C"
private def c1 := committed c0 (receivedGossip "A" high)
private def c2 := committed c1 .timeout

private def stage (s : NodeState) (e : Event) : NodeState :=
  Tests.staged config s e

private def snapshot (a b c : NodeState) (network : List Model.Envelope) : Model.State :=
  { nodes := [("A", a), ("B", b), ("C", c)], network }

private def initial : Model.State := Tests.initial config

private def n2 := [gossip "A" "B" high, gossip "A" "C" high]
private def n4 := [gossip "A" "B" high]
private def n10 := n4 ++ vote "A" "A" :: gossips "A" high
private def n11 := n10 ++ vote "C" "A" :: gossips "C" low
private def n12 := n4 ++ gossips "A" high ++ vote "C" "A" :: gossips "C" low
private def n14 := n12 ++ gossips "B" low
private def n15 := n12 ++ [gossip "B" "A" low, gossip "B" "C" low]
private def n19 := n15 ++ vote "B" "B" :: gossips "B" low
private def n20 := n15 ++ gossips "B" low
private def n24 := n20 ++ [iAmOpen "B" "A", iAmOpen "B" "C"]

private def n25 :=
  n4
  ++ gossips "A" high
  ++ gossips "C" low
  ++ [gossip "B" "A" low, gossip "B" "C" low]
  ++ gossips "B" low
  ++ [iAmOpen "B" "A", iAmOpen "B" "C"]

private def n26 :=
  n4
  ++ gossips "A" high
  ++ gossips "C" low
  ++ [gossip "B" "A" low, gossip "B" "C" low]
  ++ gossips "B" low
  ++ [iAmOpen "B" "C"]

private def aVoteRunning := stage a3 (receivedVote "C")
private def aBothRunning := stage aVoteRunning receivedIAmOpen

private def aOpened : NodeState :=
  { a4 with pending := aBothRunning.pending.eraseIdx 0 }

private def voteRunning := snapshot aVoteRunning b4 c2 n25
private def bothRunning := snapshot aBothRunning b4 c2 n26
private def opened := snapshot aOpened b4 c2 n26
private def final := snapshot a4 b4 c2 n26

private def steps : List (Model.Action × Model.State) :=
  [
    -- `A` and `C` hear `A`, time out of gossiping, and vote for `A`.
    (.local "A" .retry, snapshot a0 b0 c0 (gossips "A" high)),
    (
      .deliver (gossip "A" "A" high),
      snapshot (stage a0 (receivedGossip "A" high)) b0 c0 n2
    ),
    (.local "A" (.commit 0), snapshot a1 b0 c0 n2),
    (
      .deliver (gossip "A" "C" high),
      snapshot a1 b0 (stage c0 (receivedGossip "A" high)) n4
    ),
    (.local "C" (.commit 0), snapshot a1 b0 c1 n4),
    (.local "A" .timeout, snapshot (stage a1 .timeout) b0 c1 n4),
    (.local "A" (.commit 0), snapshot a2 b0 c1 n4),
    (.local "C" .timeout, snapshot a2 b0 (stage c1 .timeout) n4),
    (.local "C" (.commit 0), snapshot a2 b0 c2 n4),
    (.local "A" .retry, snapshot a2 b0 c2 n10),
    (.local "C" .retry, snapshot a2 b0 c2 n11),
    (.deliver (vote "A" "A"), snapshot (stage a2 (receivedVote "A")) b0 c2 n12),
    (.local "A" (.commit 0), snapshot a3 b0 c2 n12),
    -- `B` hears only itself, votes for itself, and opens by failover.
    (.local "B" .retry, snapshot a3 b0 c2 n14),
    (
      .deliver (gossip "B" "B" low),
      snapshot a3 (stage b0 (receivedGossip "B" low)) c2 n15
    ),
    (.local "B" (.commit 0), snapshot a3 b1 c2 n15),
    (.local "B" .timeout, snapshot a3 (stage b1 .timeout) c2 n15),
    (.local "B" (.commit 0), snapshot a3 b2 c2 n15),
    (.local "B" .retry, snapshot a3 b2 c2 n19),
    (.deliver (vote "B" "B"), snapshot a3 (stage b2 (receivedVote "B")) c2 n20),
    (.local "B" (.commit 0), snapshot a3 b3 c2 n20),
    (.local "B" .timeout, snapshot a3 (stage b3 .timeout) c2 n20),
    (.local "B" (.commit 0), snapshot a3 b4 c2 n20),
    (.local "B" .retry, snapshot a3 b4 c2 n24),
    -- `A` runs the vote that gives it a quorum, then the IAmOpen, and commits them
    -- in that order.
    (.deliver (vote "C" "A"), voteRunning),
    (.deliver (iAmOpen "B" "A"), bothRunning),
    (.local "A" (.commit 0), opened),
    (.local "A" (.commit 0), final)
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

private theorem restarted : NotificationAt config behaviour 25 "A" (.restart "B") := by
  refine ⟨
    voteRunning,
    bothRunning,
    .deliver (iAmOpen "B" "A"),
    aVoteRunning,
    aBothRunning,
    { notifications := [.restart "B"] },
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    by simp
  ⟩

private theorem openedByQuorum
    : NotificationAt config behaviour 26 "A" (.opening .quorum) := by
  refine ⟨
    bothRunning,
    opened,
    .local "A" (.commit 0),
    aBothRunning,
    aOpened,
    { notifications := [.opening .quorum] },
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    by simp
  ⟩

-- `A` both requests a restart and opens.
example
    : exists (restartStep openingStep : Nat) (node chosen : Location) (kind : OpenKind),
        NotificationAt config behaviour restartStep node (.restart chosen)
        /\ NotificationAt config behaviour openingStep node (.opening kind) :=
  ⟨25, 26, "A", "B", .quorum, restarted, openedByQuorum⟩

-- After the vote commits, committing the IAmOpen conflicts on `phase`, runs again,
-- and is rejected.
example
    : NotificationAt config behaviour 27 "A" (.rejected "already-opening-or-open") := by
  refine ⟨
    opened,
    final,
    .local "A" (.commit 0),
    aOpened,
    a4,
    { notifications := [.rejected "already-opening-or-open"] },
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    rfl,
    by simp
  ⟩

-- `A` ends opening by quorum, with no pending attempts.
example
    : final ∈ behaviour
      /\ ("A", a4) ∈ final.nodes
      /\ a4.phase = .opening
      /\ a4.openKind = some .quorum
      /\ a4.pending = [] :=
  ⟨
    Execution.Behaviour.stateAt_mem (n := 28) rfl,
    by simp [final, snapshot],
    rfl,
    rfl,
    rfl
  ⟩

end DisasterRecovery.Tests.OpenerRestart
