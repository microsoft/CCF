module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Outcomes

public import Consensus.Replay.Outcomes

public section

namespace Consensus.Tests.ReplayOutcomes

open Consensus Consensus.Replay Consensus.Model.Node
open CCF (Finset)

private def configuration : Finset NodeID := {0, 1, 2}

/-- Node 0 is the primary of term 2, holding the configuration; the others are followers. -/
private def node (id : NodeID) : NodeState := Model.initialNodeState configuration id

private def transaction (term : Nat) : Entry := { term, content := .transaction 1 {} }

private def expect (name : String) (actual expected : List Outcome) : IO Unit := do
  unless actual == expected do
    throw
      (IO.userError
        s!"{name}: shown {actual.map Outcome.name}, expected {expected.map Outcome.name}")

/-- What `target`, in `state`, shows on receiving `payload` from `source`. -/
private def receive (target : NodeID) (state : NodeState) (source : NodeID)
    (payload : Message)
    : List Outcome :=
  let envelope : Model.Envelope := { source, target, payload }
  outcomes { nodes := [(target, state)], network := [envelope] } (.deliver envelope)

/-- Deliver the oldest pending message along this directed link. -/
private def oldest (source target : NodeID) (state : Model.State) : Option Model.Action :=
  (state.network.find?
    fun envelope => envelope.source == source && envelope.target == target).map
    fun envelope => .deliver envelope

/-- A batch is replicated to one follower, whose acknowledgement commits it. -/
private def replication : IO Unit := do
  let steps : List (String × (Model.State → Option Model.Action) × List Outcome) :=
    [
      (
        "append",
        fun _ =>
          some
            (.local 0
              (.append [{ content := .transaction 10 {} }, { content := .signature }])),
        [.appendTransaction, .appendSignature, .appendSeveralEntries]
      ),
      ("send", fun _ => some (.local 0 (.sendEntries 1 3)), [.sendEntries]),
      ("receive", oldest 0 1, [.appendEntriesAppends]),
      ("acknowledge", oldest 1 0, [.ackAdvancesMatch, .primaryCommits])
    ]
  let mut state : Model.State := { nodes := [0, 1, 2].map fun id => (id, node id) }
  for (name, action, expected) in steps do
    let some action := action state
    | throw (IO.userError s!"{name}: no pending message")
    expect name (outcomes state action) expected
    let some next := Model.networkStep configuration state action
    | throw (IO.userError s!"{name}: disabled action")
    state := next

/-- A refusal names its reason only when it is the only one. -/
private def refusals : IO Unit := do
  let request : Message :=
    .requestVoteRequest { term := 3, lastCommittableTerm := 0, lastCommittableIndex := 0 }
  let voter := { node 1 with currentTerm := 3, primaryKnown := true }
  expect "primary known" (receive 1 voter 2 request) [.voteRefusedPrimaryKnown]
  expect "primary known and voted" (receive 1 { voter with votedFor := some 0 } 2 request)
    [.voteRefusedSeveralReasons]

/-- The requests which a follower ignores without a response are told apart. -/
private def conflicts : IO Unit := do
  let follower := { node 1 with currentTerm := 3, log := [transaction 2, transaction 2] }
  let request : Message :=
    .appendEntriesRequest
      {
        term := 3
        prevLogIndex := 1
        prevLogTerm := 2
        entries := [transaction 3]
        primaryCommit := 0
      }
  expect "conflict" (receive 1 follower 0 request) [.appendEntriesConflictIgnored]
  expect "conflict for a new follower"
    (receive 1 { follower with isNewFollower := true } 0 request)
    [.appendEntriesTruncates]
  expect "below commit" (receive 1 { follower with commitIndex := 2 } 0 request)
    [.appendEntriesBelowCommit]

/-- A quorum acknowledges a signature of term 2, which a primary of term 3 does not commit. -/
private def deferredCommit : IO Unit := do
  let primary :=
    {
      node 0 with
        currentTerm := 3
        log := (node 0).log ++ [{ term := 2, content := .signature }]
    }
  let acknowledgement : Message :=
    .appendEntriesResponse { term := 3, success := true, lastLogIndex := 2 }
  expect "signature of an earlier term" (receive 0 primary 1 acknowledgement)
    [.ackAdvancesMatch, .commitDeferredForOldTerm]

/-- Responses which arrive after the node has moved on are told apart from refusals. -/
private def lateResponses : IO Unit := do
  let candidate :=
    { node 1 with role := .candidate, currentTerm := 3, log := (node 0).log }
  let preVote : Message := .requestPreVoteResponse { term := 3, voteGranted := true }
  expect "pre-vote for a candidate" (receive 1 candidate 2 preVote)
    [.preVoteResponseToCandidate]
  let acknowledgement : Message :=
    .appendEntriesResponse { term := 2, success := true, lastLogIndex := 0 }
  expect "acknowledgement below the match index"
    (receive 0 { node 0 with matchIndex := fun _ => 1 } 1 acknowledgement)
    [.ackBelowMatch]

private def reporting : IO Unit := do
  let traces : Array (String × Array Outcome) :=
    #[("first", #[.voteGranted, .voteGranted]), ("second", #[.voteGranted])]
  let lines := (report traces).splitOn "\n"
  let expected :=
    [
      "| voteGranted | 3 | 2 | first |",
      "| joinEmpty | 0 | 0 |  |",
      s!"Traces: 2. Outcomes shown: 1 of {Outcome.all.length}."
    ]
  for line in expected do
    unless lines.contains line do
      throw (IO.userError s!"report: missing line '{line}'")

/-- Checks the outcomes of chosen steps, and the report of several traces. -/
def run : IO Unit := do
  replication
  refusals
  conflicts
  deferredCommit
  lateResponses
  reporting
  IO.println "Replay outcome checks passed."

#eval run

end Consensus.Tests.ReplayOutcomes
