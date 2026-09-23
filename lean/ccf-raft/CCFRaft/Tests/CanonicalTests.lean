-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Replay
import Mathlib.Data.Fintype.Basic

open CCFRaft CCFRaft.Model.Local
open CCFRaft.Shared.MultiNodeTransitionSystem (nodeState)

private abbrev Node := Fin 15

private instance : Bootstrap Node where
  configuration := Finset.univ.filter fun node => node.val < 5
  leader := ⟨0, by decide⟩
  leader_mem := by decide

private abbrev State := Model.State Node Nat
private abbrev Envelope := Model.Envelope Node Nat

private def allNodes : List Node := List.finRange 15

private def system := Model.transitionSystem (TxId := Nat) allNodes

private def initial : State :=
  { nodes := allNodes.map fun node => (node, initialNodeState node)
    active := allNodes }

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

private def get (state : State) (node : Node) : NodeState Node Nat :=
  (nodeState state node).getD (initialNodeState node)

/-- Pending envelopes from `source` to `destination`, oldest first. -/
private def pending (state : State) (source destination : Node) : List Envelope :=
  state.network.filter fun envelope =>
    envelope.source == source && envelope.target == destination

private def apply (state : State) (action : Model.Action Node Nat) : IO State :=
  match system.step state action with
  | some after => do
      check (allNodes.all fun node =>
          decide ((get state node).committedLog <+: (get after node).committedLog))
        "canonical action rolled back or rewrote a committed prefix"
      pure after
  | none => throw (IO.userError "expected canonical action to be enabled")

/-- Deliver the oldest pending envelope from `source` to `destination`. -/
private def receive (state : State) (source destination : Node) : IO State := do
  let some envelope := (pending state source destination).head?
    | throw (IO.userError "no pending envelope to receive")
  apply state (.deliver envelope)

private def bootstrapAndNoMatchingPrefixTerms : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let future : Node := ⟨5, by decide⟩
  check (BOOTSTRAP_TERM == 2 &&
    (get initial source).currentTerm == BOOTSTRAP_TERM &&
    (get initial destination).currentTerm == BOOTSTRAP_TERM)
    "bootstrap leader and follower must start at implementation term 2"
  check ((get initial future).currentTerm == 0 && decide ((get initial future).role = .none))
    "nodes outside the bootstrap configuration must start fresh at term 0"
  let follower := { get initial destination with
    log := [{ term := BOOTSTRAP_TERM, content := .transaction 1 }] }
  let request : AppendEntriesRequest Node Nat := {
    term := BOOTSTRAP_TERM
    prevLogIndex := 1
    prevLogTerm := 1
    entries := []
    leaderCommit := 0
  }
  check (findHighestPossibleMatch follower.log request.prevLogIndex request.prevLogTerm == 0)
    "conflicting prefix must have no possible matching index"
  let some (after, response) := handleAppendEntriesRequest? destination follower request
    | throw (IO.userError "conflicting prefix did not produce a response")
  check (!response.success && response.lastLogIndex == 0 && response.term == 0)
    "no matching prefix must produce a NACK with index 0 and term 0"
  check (after.currentTerm == BOOTSTRAP_TERM && after.log == follower.log)
    "no matching prefix NACK must preserve the follower's term and log"

private def nominationTerms : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  for term in [0, 1, BOOTSTRAP_TERM + 1] do
    let nomination : Envelope := { source, target := destination, payload := .proposeVoteRequest term }
    let state := { initial with network := [nomination] }
    let after ← apply state (.deliver nomination)
    check after.network.isEmpty s!"nomination term {term}: message was not consumed"
    check ((get after destination).currentTerm == (get state destination).currentTerm)
      s!"nomination term {term}: current term changed"
    check (decide ((get after destination).role = (get state destination).role))
      s!"nomination term {term}: role changed"
  let nomination : Envelope :=
    { source, target := destination, payload := .proposeVoteRequest BOOTSTRAP_TERM }
  let after ← apply { initial with network := [nomination] } (.deliver nomination)
  check (decide ((get after destination).role = .candidate))
    "same-term nomination: eligible follower did not become candidate"
  check ((get after destination).currentTerm == BOOTSTRAP_TERM + 1)
    "same-term nomination: election did not increment the term"
  let vote : Envelope := {
    source, target := destination
    payload := .requestVoteRequest
      { makeRequestVoteRequest (get initial source) with term := BOOTSTRAP_TERM + 1 } }
  let after ← apply { initial with network := [vote] } (.deliver vote)
  check ((get after destination).currentTerm == BOOTSTRAP_TERM + 1)
    "newer vote request: current term did not advance"
  check (decide ((get after destination).votedFor = some source))
    "newer vote request: the vote was not granted in the new term"
  let some { payload := .requestVoteResponse response, .. } := after.network.head?
    | throw (IO.userError "newer vote request: no vote response")
  check (response.voteGranted && response.term == BOOTSTRAP_TERM + 1)
    "newer vote request: the response does not grant the vote in the new term"

private def appendEntriesResponseTerms : IO Unit := do
  let leader : Node := ⟨0, by decide⟩
  let follower : Node := ⟨1, by decide⟩
  let response : AppendEntriesResponse := { term := 5, success := false, lastLogIndex := 0 }
  let toFollower : Envelope :=
    { source := leader, target := follower, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toFollower] } (.deliver toFollower)
  check ((get after follower).currentTerm == BOOTSTRAP_TERM && after.network.isEmpty)
    "a non-leader must ignore an AppendEntries response, including its term"
  let toLeader : Envelope :=
    { source := follower, target := leader, payload := .appendEntriesResponse response }
  let after ← apply { initial with network := [toLeader] } (.deliver toLeader)
  check ((get after leader).currentTerm == 5 && decide ((get after leader).role = .follower))
    "a leader must adopt a newer AppendEntries response term as a follower"

private def batches : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let written ← apply initial (.local source (.clientRequest 1))
  let written ← apply written (.local source (.clientRequest 2))
  let written ← apply written (.local source .signCommittableMessages)
  check (system.step written (.local source (.appendEntries destination 4))).isNone
    "batch past the log must be disabled"
  let sent ← apply written (.local source (.appendEntries destination 3))
  check ((pending sent source destination).length == 1)
    "a batch must produce exactly one packet"
  let some { payload := .appendEntriesRequest packet, .. } := sent.network.head?
    | throw (IO.userError "batch did not produce AppendEntries")
  check (packet.entries.length == 3 && packet.prevLogIndex == 0)
    "batch did not snapshot the full requested range"
  let heartbeat ← apply sent (.local source (.appendEntries destination 3))
  let some { payload := .appendEntriesRequest empty, .. } := heartbeat.network.getLast?
    | throw (IO.userError "heartbeat did not produce AppendEntries")
  check (empty.entries.isEmpty && empty.prevLogIndex == 3)
    "heartbeat must be one empty packet at the sent frontier"
  check (system.step sent (.local source (.appendEntries destination 2))).isNone
    "batch cannot move the sent frontier backwards"
  let delivered ← receive sent source destination
  check ((get delivered destination).log.length == 3)
    "receiving a batch must apply all entries atomically"
  let mixedNode := { get written source with log := [
      { term := 1, content := .transaction 1 },
      { term := 2, content := .transaction 2 }] }
  let mixed := { written with
    nodes := written.nodes.map fun (entry : Node × NodeState Node Nat) =>
      if entry.1 == source then (source, mixedNode) else entry }
  check (system.step mixed (.local source (.appendEntries destination 2))).isNone
    "native AppendEntries batches cannot span terms"

private def reorderedDelivery : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let written ← apply initial (.local source (.clientRequest 1))
  let written ← apply written (.local source .signCommittableMessages)
  let sent ← apply written (.local source (.appendEntries destination 2))
  let sent ← apply sent (.local source (.appendEntries destination 2))
  let some heartbeat := (pending sent source destination)[1]?
    | throw (IO.userError "missing second AppendEntries")
  let after ← apply sent (.deliver heartbeat)
  check ((pending after source destination).length == 1 &&
      (get after destination).log.isEmpty)
    "a later envelope may be delivered first, leaving the earlier one pending"
  let some { payload := .appendEntriesResponse response, .. } := (pending after destination source).head?
    | throw (IO.userError "reordered heartbeat did not produce a response")
  check (!response.success && response.lastLogIndex == 0)
    "a heartbeat past the follower log must be NACKed"
  check (system.step sent (.deliver { heartbeat with target := source })).isNone
    "an envelope that is not pending cannot be delivered"

private def committedPrefixSurvivesTruncation : IO Unit := do
  let original : Node := ⟨0, by decide⟩
  let successor : Node := ⟨1, by decide⟩
  let second : Node := ⟨2, by decide⟩
  let third : Node := ⟨3, by decide⟩
  let mut state := initial
  state ← apply state (.local original .initializeConfiguration)
  state ← apply state (.local original .signCommittableMessages)
  for peer in [successor, second] do
    state ← apply state (.local original (.appendEntries peer 2))
    state ← receive state original peer
    state ← receive state peer original
  state ← apply state (.local original .advanceCommitIndex)
  let committed := (get state original).committedLog
  check (committed.length == 2) "truncation test requires a nonempty committed prefix"
  state ← apply state (.local original (.clientRequest 10))
  state ← apply state (.local original (.appendEntries successor 3))
  state ← receive state original successor
  state ← receive state successor original
  check ((get state successor).commitIndex == 2 && (get state successor).log.length == 3)
    "successor must have a committed prefix and an uncommitted suffix"
  state ← apply state (.local successor .timeout)
  for voter in [second, third] do
    state ← apply state (.local successor (.requestVote voter))
    state ← receive state successor voter
    state ← receive state voter successor
  state ← apply state (.local successor .becomeLeader)
  check ((get state successor).log == committed &&
    (get state successor).committedLog == committed)
    "promotion must truncate only the uncommitted suffix"
  state ← apply state (.local successor (.clientRequest 20))
  state ← apply state (.local successor .signCommittableMessages)
  for peer in [original, second] do
    state ← apply state (.local successor (.appendEntries peer 4))
    state ← receive state successor peer
    state ← receive state peer successor
  check ((get state original).committedLog == committed &&
    entryAt? (get state original).log 3 ==
      some { term := BOOTSTRAP_TERM + 1, content := .transaction 20 })
    "conflict resolution must replace the uncommitted entry, not the committed prefix"
  state ← apply state (.local successor .advanceCommitIndex)
  state ← apply state (.local successor (.appendEntries original 4))
  state ← receive state successor original
  check ((get state original).commitIndex == 4 &&
    decide (committed <+: (get state original).committedLog))
    "the retained prefix must extend when the replacement suffix commits"

private def committedLeaderCanHeartbeatBehindCommit : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let laggard : Node := ⟨3, by decide⟩
  let mut state := initial
  state ← apply state (.local source .initializeConfiguration)
  state ← apply state (.local source .signCommittableMessages)
  for peer in ([⟨1, by decide⟩, ⟨2, by decide⟩] : List Node) do
    state ← apply state (.local source (.appendEntries peer 2))
    state ← receive state source peer
    state ← receive state peer source
  state ← apply state (.local source .advanceCommitIndex)
  check ((get state source).commitIndex == 2)
    "leader should have quorum-committed the bootstrap signature"
  state ← apply state (.local source (.appendEntries laggard 0))
  let some { payload := .appendEntriesRequest heartbeat, .. } := (pending state source laggard).head?
    | throw (IO.userError "missing lagging heartbeat")
  check (heartbeat.entries.isEmpty && heartbeat.prevLogIndex == 0 &&
      heartbeat.leaderCommit == 2)
    "empty heartbeat may advertise a commit beyond its verified frontier"
  state ← receive state source laggard
  check ((get state laggard).commitIndex == 0)
    "a lagging heartbeat must not commit an unverified prefix"

private def networkSnapshots : IO Unit := do
  let started ← IO.monoMsNow
  let source : Node := ⟨0, by decide⟩
  let left : Node := ⟨1, by decide⟩
  let right : Node := ⟨2, by decide⟩
  let count := 64
  let mut state := initial
  for _ in [:count] do
    state ← apply state (.local source (.appendEntries left 0))
    state ← apply state (.local source (.appendEntries right 0))
  check ((pending state source left).length == count &&
    (pending state source right).length == count && state.network.length == 2 * count)
    "alternating sends changed queue multiplicity"
  for _ in [:count] do
    state ← receive state source left
    state ← receive state source right
  check ((pending state left source).length == count &&
    (pending state right source).length == count && state.network.length == 2 * count)
    "alternating replies changed queue multiplicity"
  for _ in [:count] do
    state ← receive state left source
    state ← receive state right source
  check (state.network.isEmpty && initial.network.isEmpty)
    "network snapshots were not independent"
  check ((← IO.monoMsNow) - started < 5000)
    "network snapshot regression: 384 simple transitions took over five seconds"

private def repliesAfterStepDown : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let mut state := initial
  for transaction in [:6] do
    state ← apply state (.local source (.clientRequest transaction))
  state ← apply state (.local source (.appendEntries destination 6))
  state ← apply state (.local source (.appendEntries destination 6))
  let sent := state
  state ← apply state (.local destination .timeout)
  state ← receive state source destination
  state ← receive state source destination
  state ← receive state destination source
  check (decide ((get state source).role = .follower))
    "newer-term reply did not demote the old leader"
  for remaining in [0] do
    state ← receive state destination source
    check ((get state source).sentIndex destination == 6 &&
      (get state source).matchIndex destination == 0 &&
      (get state source).log.length == 6 &&
      (pending state destination source).length == remaining)
      "late NACK changed a non-leader's cursor or was not consumed exactly once"
  let some heartbeat := (pending sent source destination)[1]?
    | throw (IO.userError "missing heartbeat")
  let mut leader ← apply sent (.deliver heartbeat)
  leader ← receive leader destination source
  check (decide ((get leader source).role = .leader) &&
    (get leader source).sentIndex destination == 0 &&
    (get leader source).matchIndex destination == 0)
    "current leader must still rewind its sent cursor after a NACK"

private def parseJson (input : String) : IO Lean.Json :=
  match Lean.Json.parse input with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def replayDocument (rawInstructions : List String) : IO Lean.Json := do
  let bootstrap ← parseJson r#"{
    "configuration":["alpha","beta"], "leader":"alpha",
    "pre_vote_enabled":{"alpha":false,"beta":false,"future":true}
  }"#
  let origin ← parseJson r#"[{"file":"captured trace.ndjson","line":17,"rule":"unit"}]"#
  let instructions ← rawInstructions.mapM fun input => do
    let value ← parseJson input
    match value.getObj? with
    | .error error => throw (IO.userError error)
    | .ok fields =>
        return Lean.Json.mkObj (("origin", origin) :: fields.toList)
  return Lean.Json.mkObj [
    ("schema", Lean.toJson "ccfraft-replay/v2"),
    ("bootstrap", bootstrap),
    ("instructions", Lean.toJson instructions)]

private def expectReplayError (instructions : List String) (expected : String) : IO Unit := do
  match CCFRaft.Replay.replay (← replayDocument instructions) with
  | .ok _ => throw (IO.userError s!"replay unexpectedly accepted {expected}")
  | .error error =>
      check (error.contains expected) s!"expected '{expected}', got '{error}'"
      check (error.contains "captured trace.ndjson:17 [unit]")
        "replay failure lost source provenance"

private def jsonReplay : IO Unit := do
  let obsolete := (← replayDocument []).setObjVal! "schema"
    (Lean.toJson "ccfraft-replay/v1")
  match CCFRaft.Replay.replay obsolete with
  | .ok _ => throw (IO.userError "accepted obsolete erased-index schema")
  | .error error =>
      check (error.contains "v1 is unsupported: v2 requires physical ledger indices") error
  match CCFRaft.Replay.replay (← replayDocument []) with
  | .ok _ => throw (IO.userError "accepted an empty replay")
  | .error error => check (error.contains "instructions must not be empty") error
  let initialSteps := [
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"none","currentTerm":0,"preVoteEnabled":true}}"#,
    r#"{"kind":"action","action":"clientRequest","node":"alpha","transaction":"tx-1"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":2}"#]
  let packet := r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","term":2,"prev_idx":0,"prev_term":0,"idx":2,"term_of_idx":2,"leader_commit_idx":0,"contains_new_view":false}}"#
  let receive := r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#
  let complete := initialSteps ++ [packet, receive,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","logLength":2,"commitIndex":0}}"#,
    r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","term":2,"success":"OK","last_log_idx":2}}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","peer":"beta","fields":{"commitIndex":2,"sentIndex":2,"matchIndex":2}}"#]
  match CCFRaft.Replay.replay (← replayDocument complete) with
  | .error error => throw (IO.userError error)
  | .ok result =>
      check (result.instructions == complete.length &&
        result.actions == 6 && result.observations == 5)
        "replayer did not consume every instruction"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":99}}"#,
    r#"{"kind":"garbage"}"#]) "instruction 5"
  expectReplayError [receive] "disabled canonical action 'receive'"
  expectReplayError [
    r#"{"kind":"action","action":"clientRequest","node":"beta","transaction":"tx"}"#]
    "disabled canonical action 'clientRequest'"
  expectReplayError [
    r#"{"kind":"action","action":"timeout","node":"missing"}"#] "undeclared node"
  expectReplayError [
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":-1}"#]
    "instruction 1"
  expectReplayError [
    r#"{"kind":"action","action":"invented","node":"alpha"}"#] "unsupported action"
  expectReplayError [
    r#"{"kind":"action","action":"timeout","node":"beta","ignored":true}"#] "unsupported field"
  expectReplayError [
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"unknown":0}}"#]
    "unsupported observation field"
  expectReplayError [
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":0,"fields":{"kind":"signature"}}"#]
    "log entry index must be positive"
  expectReplayError [
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"signature"}}"#]
    "has no log entry at index 1"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"signature"}}"#])
    "kind: observed"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"committed":true}}"#])
    "committed: observed true, canonical false"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"unknown":0}}"#])
    "unsupported observation field"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","idx":1}}"#])
    "idx: observed 1, canonical 2"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","unknown":0}}"#])
    "unsupported observation field"
  expectReplayError (initialSteps ++ [
    r#"{"kind":"action","action":"drop","source":"alpha","destination":"beta"}"#,
    packet]) "no pending packet"
  let sentTwice := initialSteps ++ [
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":2}"#]
  let latest ← replayDocument (sentTwice ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"last","packet":{"msg":"raft_append_entries","prev_idx":2,"idx":2}}"#,
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","occurrence":1,"packet":{"msg":"raft_append_entries","prev_idx":2,"idx":2}}"#,
    packet])
  match CCFRaft.Replay.replay latest with
  | .ok result => check (result.instructions == 8) "incomplete packet selection replay"
  | .error error => throw (IO.userError error)
  expectReplayError (sentTwice ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","prev_idx":2}}"#])
    "prev_idx: observed 2, canonical 0"
  expectReplayError (sentTwice ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"last","occurrence":1,"packet":{"msg":"raft_append_entries"}}"#])
    "cannot specify both selection and occurrence"
  expectReplayError (sentTwice ++ [
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","selection":"any","packet":{"msg":"raft_append_entries"}}"#])
    "unsupported message selection"
  let reconfiguration ← replayDocument [
    r#"{"kind":"action","action":"changeConfiguration","source":"alpha","configuration":["alpha","beta","future"]}"#,
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"none","currentTerm":0}}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"future","batchEnd":2}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"future"}"#,
    r#"{"kind":"action","action":"becomePreVoteCandidate","node":"future"}"#,
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"preVoteCandidate","currentTerm":2,"logLength":2}}"#]
  match CCFRaft.Replay.replay reconfiguration with
  | .ok result => check (result.instructions == 7) "incomplete reconfiguration replay"
  | .error error => throw (IO.userError error)
  let noOrigin := (← replayDocument [receive]).setObjVal! "instructions"
    (.arr #[Lean.Json.mkObj [("kind", Lean.toJson "action"), ("origin", .arr #[])]])
  match CCFRaft.Replay.replay noOrigin with
  | .ok _ => throw (IO.userError "accepted empty origin")
  | .error error =>
      check (error.contains "instruction 1: invalid origin") error
  let malformed ← parseJson r#"{
    "schema":"ccfraft-replay/v2",
    "bootstrap":{"configuration":["alpha"],"leader":"outsider","pre_vote_enabled":{"alpha":false}},
    "instructions":[]
  }"#
  match CCFRaft.Replay.replay malformed with
  | .ok _ => throw (IO.userError "accepted bootstrap leader outside configuration")
  | .error error => check (error.contains "not in the configuration") error

private def bootstrapPrefix : IO Unit := do
  let document ← replayDocument [
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":1,"committableIndices":[],"configurations":[{"index":1,"nodes":["alpha"]}]}}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"committableIndices":[2]}}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"action","action":"changeConfiguration","source":"alpha","configuration":["alpha","beta"]}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","peer":"beta","fields":{"logLength":3,"commitIndex":2,"committableIndices":[],"sentIndex":2,"configurations":[{"index":1,"nodes":["alpha"]},{"index":3,"nodes":["alpha","beta"]}]}}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":2}"#,
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","prev_idx":2,"idx":2,"prev_term":2,"term_of_idx":2,"leader_commit_idx":2}}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","success":"FAIL","last_log_idx":0,"term":2}}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","currentTerm":2,"logLength":0,"commitIndex":0}}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":3}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"logLength":3,"commitIndex":2,"committableIndices":[],"configurations":[{"index":1,"nodes":["alpha"]},{"index":3,"nodes":["alpha","beta"]}]}}"#]
  let bootstrap ← parseJson r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 16) "incomplete bootstrap prefix replay"
  | .error error => throw (IO.userError error)
  let startup ← replayDocument [
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":2,"commitIndex":2}}"#,
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"configuration","configuration":["alpha"],"term":2,"committed":true}}"#,
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":2,"fields":{"kind":"signature","committed":true}}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":3,"committableIndices":[3]}}"#,
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":3,"fields":{"kind":"signature","committed":false}}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":3,"commitIndex":3,"committableIndices":[]}}"#]
  match CCFRaft.Replay.replay (startup.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 11) "incomplete physical startup replay"
  | .error error => throw (IO.userError error)
  expectReplayError [
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#,
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#]
    "disabled canonical action 'initializeConfiguration'"

private def terminalRetirementRole : IO Unit := do
  let document ← replayDocument [
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"action","action":"changeConfiguration","source":"alpha","configuration":["beta"]}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":4}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":4}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"role":"leader","membershipState":"retirementCompleted","commitIndex":4}}"#,
    r#"{"kind":"action","action":"appendRetiredCommitted","node":"alpha"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":6}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndexAndProposeVote","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"role":"none","membershipState":"retiredCommitted","currentTerm":2,"commitIndex":6,"retiredCommittedIndex":6}}"#,
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_propose_request_vote","term":2}}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"candidate","currentTerm":3}}"#]
  let bootstrap ← parseJson r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 23) "incomplete terminal retirement replay"
  | .error error => throw (IO.userError error)

private def retirementCommitFrontiers : IO Unit := do
  let node : Node := ⟨0, by decide⟩
  let survivor : Node := ⟨1, by decide⟩
  let log : List (Entry Node Nat) := [
    { term := 1, content := .reconfiguration {node, survivor} },
    { term := 1, content := .signature },
    { term := 1, content := .reconfiguration {survivor} },
    { term := 1, content := .signature },
    { term := 1, content := .retiredCommitted {node} },
    { term := 1, content := .signature },
    { term := 1, content := .transaction 7 },
    { term := 1, content := .signature },
    { term := 1, content := .transaction 9 },
    { term := 1, content := .signature }]
  let before : NodeState Node Nat :=
    refreshRetirementState node
      { (initialNodeState node : NodeState Node Nat) with
        role := .follower
        currentTerm := 1
        log := log.take 5
        commitIndex := 4 }
  check (before.retiredCommittedIndex.isNone)
    "an uncommitted retirement marker must not set the commit frontier"
  let jumped := refreshRetirementState node
    { before with log := log.take 8, commitIndex := 8 }
  check (jumped.retiredCommittedIndex == some 8)
    "commit frontier must not be the marker index or marker index plus one"
  let later := refreshRetirementState node
    { jumped with log, commitIndex := 10 }
  check (later.retiredCommittedIndex == some 8)
    "later commits must preserve the first covering retirement frontier"
  for (oldLength, expected) in [(5, 6), (6, 8)] do
    let state := { before with log := log.take oldLength }
    let request : AppendEntriesRequest Node Nat := {
      term := 1
      prevLogIndex := oldLength
      prevLogTerm := 1
      entries := (log.take 8).drop oldLength
      leaderCommit := 8
    }
    let some (received, _) := handleAppendEntriesRequest? node state request
      | throw (IO.userError "retirement batch was rejected")
    let received := refreshRetirementState node received
    check (received.commitIndex == 8 && received.retiredCommittedIndex == some expected)
      s!"batch from {oldLength}: wrong first covering retirement commit"

def main : IO Unit := do
  bootstrapAndNoMatchingPrefixTerms
  nominationTerms
  appendEntriesResponseTerms
  batches
  reorderedDelivery
  committedLeaderCanHeartbeatBehindCommit
  committedPrefixSurvivesTruncation
  networkSnapshots
  repliesAfterStepDown
  jsonReplay
  bootstrapPrefix
  terminalRetirementRole
  retirementCommitFrontiers
  IO.println "Canonical behavior checks passed."
