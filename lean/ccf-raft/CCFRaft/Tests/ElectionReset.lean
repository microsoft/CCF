module

meta import CCFRaft.Properties.Liveness.Model.Scheduling
import CCFRaft.Properties.Liveness.Model.Scheduling

namespace CCFRaft.Tests.ElectionReset

open CCFRaft.Model.Node
open CCFRaft.Liveness

private instance : HasProtocol Model.State Model.State where
  proto := id

private instance (step : CCF.Execution.Step Model.State Liveness.Event) (node : NodeID)
    : Decidable (ElectionReset step node) := by
  unfold ElectionReset
  repeat' first | split | infer_instance

private def follower : NodeState :=
  {
    Model.initialNodeState {0, 1, 2} 1 with
      log :=
        [
          { term := 2, content := .transaction 0 { configuration := some {0, 1, 2} } },
          { term := 2, content := .signature }
        ]
      commitIndex := 2
  }

private def vote (term : Nat) : RequestVoteRequest :=
  { term, lastCommittableTerm := 2, lastCommittableIndex := 2 }

private def append (term prevLogTerm : Nat) : AppendEntriesRequest :=
  { term, prevLogIndex := 2, prevLogTerm, entries := [], primaryCommit := 2 }

private def checkReset (name : String) (before : NodeState) (event : Model.Node.Event)
    (expected : Bool)
    : IO Unit := do
  let some (after, _) := Model.Node.step (CCF.Capabilities.record 1) 1 before event {}
  | throw (IO.userError s!"{name}: protocol step is disabled")
  let action : Liveness.Event :=
    match event with
    | .internal input => .local 1 input
    | .receive source payload =>
        .deliver { id := 0, envelope := { source, target := 1, payload }, sentAt := 0 }
  let step : CCF.Execution.Step Model.State Liveness.Event :=
    { before := { nodes := [(1, before)] }, action, after := { nodes := [(1, after)] } }
  unless decide (ElectionReset step 1) == expected do
    throw (IO.userError s!"{name}: expected election reset = {expected}")
  unless !(decide (ElectionReset step 0)) do
    throw (IO.userError s!"{name}: reset incorrectly attributed to another node")

private def checkDelivery (name : String) (state : NodeState) (source : NodeID)
    (message : Message) (expected : Bool)
    : IO Unit :=
  checkReset name state (.receive source message) expected

private def checkResets : IO Unit := do
  let primary := { follower with role := .primary, primaryKnown := true }
  let candidate := { follower with role := .candidate, votesGranted := {1} }
  let preCandidate := { follower with role := .preVoteCandidate, preVotesGranted := {1} }
  checkReset "election timeout" follower (.internal (.timeout .election)) true
  checkReset "quorum-check step-down" primary (.internal (.timeout .checkQuorum)) true
  checkReset "nomination" primary (.internal .nominateSuccessor) false

  checkDelivery "matching heartbeat" follower 0 (.appendEntriesRequest (append 2 2)) true
  checkDelivery "mismatched heartbeat" follower 0 (.appendEntriesRequest (append 2 1))
    false
  checkDelivery "stale heartbeat" follower 0 (.appendEntriesRequest (append 1 2)) false
  for state in [candidate, preCandidate] do
    checkDelivery "candidate steps down before log rejection" state 0
      (.appendEntriesRequest (append 2 1)) true
  checkDelivery "new term before log rejection" follower 0
    (.appendEntriesRequest (append 3 1)) true

  checkDelivery "regular vote granted" follower 0 (.requestVoteRequest (vote 2)) true
  checkDelivery "regular vote granted again" { follower with votedFor := some 0 } 0
    (.requestVoteRequest (vote 2)) true
  checkDelivery "already voted for another candidate" { follower with votedFor := some 2 }
    0 (.requestVoteRequest (vote 2)) false
  checkDelivery "known primary prevents regular vote"
    { follower with primaryKnown := true } 0 (.requestVoteRequest (vote 2)) false
  checkDelivery "stale vote request" follower 0 (.requestVoteRequest (vote 1)) false
  checkDelivery "candidate log too old" follower 0
    (.requestVoteRequest
      { term := 2, lastCommittableTerm := 0, lastCommittableIndex := 0 }) false
  checkDelivery "pre-vote granted without resetting" follower 0
    (.requestPreVoteRequest (vote 2)) false
  for message
      in [
        Message.requestVoteRequest
          { term := 3, lastCommittableTerm := 0, lastCommittableIndex := 0 },
        .requestPreVoteRequest
          { term := 3, lastCommittableTerm := 0, lastCommittableIndex := 0 }
      ] do
    checkDelivery "new term resets even when vote refused" follower 9 message true

  for message
      in [
        Message.requestVoteResponse { term := 3, voteGranted := false },
        .requestPreVoteResponse { term := 3, voteGranted := false }
      ] do
    checkDelivery "known response advances term" follower 0 message true
    checkDelivery "unknown response ignored" follower 9 message false
  let newerAck :=
    Message.appendEntriesResponse { term := 3, success := false, lastLogIndex := 0 }
  checkDelivery "primary observes newer acknowledgement" primary 0 newerAck true
  checkDelivery "non-primary ignores newer acknowledgement" follower 0 newerAck false
  checkDelivery "primary ignores unknown acknowledgement" primary 9 newerAck false
  checkDelivery "pre-vote quorum starts regular election" preCandidate 0
    (.requestPreVoteResponse { term := 2, voteGranted := true }) true
  checkDelivery "pre-vote refusal does not restart election" preCandidate 0
    (.requestPreVoteResponse { term := 2, voteGranted := false }) false
  checkDelivery "regular vote elects primary without random reset" candidate 0
    (.requestVoteResponse { term := 2, voteGranted := true }) false
  checkDelivery "stale vote response" candidate 0
    (.requestVoteResponse { term := 1, voteGranted := true }) false
  checkDelivery "proposal starts election" follower 0 (.proposeRequestVoteRequest 2) true
  checkDelivery "newer proposal ignored" follower 0 (.proposeRequestVoteRequest 3) false

#eval checkResets

end CCFRaft.Tests.ElectionReset
