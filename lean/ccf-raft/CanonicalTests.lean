-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Protocol.Model
import CCFRaft.Replay
import Mathlib.Data.Fintype.Basic

open CCFRaft.Protocol.Model

private abbrev Node := Fin 15

private instance : Bootstrap Node where
  configuration := Finset.univ.filter fun node => node.val < 5
  leader := ⟨0, by decide⟩
  leader_mem := by decide

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do
    throw (IO.userError message)

private def nominationTerms : IO Unit := do
  let initial : State Node Nat := initialState
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  for term in [0, 2] do
    let request : ProposeVoteRequest Node :=
      { source, destination, term }
    let state := { initial with
      network := enqueue initial.network (.proposeVoteRequest request) }
    check (!(decide (Enabled state (.updateTerm source destination))))
      s!"nomination term {term}: must not advance the receiver's term"
    match system.applyAction state (.receive source destination) with
    | none =>
        throw (IO.userError s!"nomination term {term}: receive must consume the message")
    | some after =>
        check (after.network destination |>.isEmpty)
          s!"nomination term {term}: message was not consumed"
        check ((after.nodes destination).currentTerm == (state.nodes destination).currentTerm)
          s!"nomination term {term}: current term changed"
        check (decide ((after.nodes destination).role = (state.nodes destination).role))
          s!"nomination term {term}: role changed"
  let nomination : ProposeVoteRequest Node :=
    { source, destination, term := 1 }
  let nominated := { initial with
    network := enqueue initial.network (.proposeVoteRequest nomination) }
  match system.applyAction nominated (.receive source destination) with
  | none => throw (IO.userError "same-term nomination: receive is disabled")
  | some after =>
      check (decide ((after.nodes destination).role = .candidate))
        "same-term nomination: eligible follower did not become candidate"
      check ((after.nodes destination).currentTerm == 2)
        "same-term nomination: election did not increment the term"
  let vote := { makeRequestVoteRequest initial source destination with term := 2 }
  let voting := { initial with
    network := enqueue initial.network (.requestVoteRequest vote) }
  match system.applyAction voting (.updateTerm source destination) with
  | none => throw (IO.userError "newer vote request: updateTerm is disabled")
  | some after =>
      check ((after.nodes destination).currentTerm == 2)
        "newer vote request: current term did not advance"
      check ((after.network destination).length == 1)
        "newer vote request: updateTerm consumed the message"

private def apply (state : State Node Nat) (action : Action Node Nat) :
    IO (State Node Nat) :=
  match system.applyAction state action with
  | some after => pure after
  | none => throw (IO.userError "expected canonical action to be enabled")

private def batchesAndDrops : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let other : Node := ⟨2, by decide⟩
  let initial : State Node Nat := initialState
  let written ← apply initial (.clientRequest source 1)
  let written ← apply written (.clientRequest source 2)
  let written ← apply written (.signCommittableMessages source)
  check (!(decide (Enabled written (.appendEntries source destination 4))))
    "batch past the log must be disabled"
  let sent ← apply written (.appendEntries source destination 3)
  check ((sent.network destination).length == 1)
    "a batch must produce exactly one packet"
  let some (.appendEntriesRequest packet) := (sent.network destination).head?
    | throw (IO.userError "batch did not produce AppendEntries")
  check (packet.entries.length == 3 && packet.prevLogIndex == 0)
    "batch did not snapshot the full requested range"
  let heartbeat ← apply sent (.appendEntries source destination 3)
  let some (.appendEntriesRequest empty) := (heartbeat.network destination).getLast?
    | throw (IO.userError "heartbeat did not produce AppendEntries")
  check (empty.entries.isEmpty && empty.prevLogIndex == 3)
    "heartbeat must be one empty packet at the sent frontier"
  check (!(decide (Enabled sent (.appendEntries source destination 2))))
    "batch cannot move the sent frontier backwards"
  let delivered ← apply sent (.receive source destination)
  check ((delivered.nodes destination).log.length == 3)
    "receiving a batch must apply all entries atomically"
  let interleaved := enqueue heartbeat.network
    (.proposeVoteRequest { source := other, destination, term := 1 })
  let duplicate := enqueue interleaved (.appendEntriesRequest packet)
  let queued := { heartbeat with network := duplicate }
  let dropped ← apply queued (.drop source destination 1)
  check (decide (dropped.network destination =
    [.appendEntriesRequest packet,
     .proposeVoteRequest { source := other, destination, term := 1 },
     .appendEntriesRequest packet]))
    "drop must preserve unrelated order and equal packet multiplicity"
  check ((dropped.nodes source).log == (queued.nodes source).log &&
      (dropped.nodes source).sentIndex destination ==
        (queued.nodes source).sentIndex destination &&
      dropped.submittedTxIds == queued.submittedTxIds)
    "drop changed protocol state"
  check (!(decide (Enabled dropped (.drop source destination 2))))
    "out-of-range drop must be disabled"
  let again ← apply dropped (.drop source destination 0)
  check ((again.network destination).length == 2)
    "drop removed more than one equal packet"
  let originalNode := written.nodes source
  let mixedNode := { originalNode with log := [
      { term := 1, content := .transaction 1 },
      { term := 2, content := .transaction 2 }] }
  let mixed := { written with nodes := updateNode written.nodes source mixedNode }
  check (!(decide (Enabled mixed (.appendEntries source destination 2))))
    "native AppendEntries batches cannot span terms"

private def committedLeaderCanHeartbeatBehindCommit : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let laggard : Node := ⟨3, by decide⟩
  let mut state : State Node Nat := initialState
  state ← apply state (.initializeConfiguration source)
  state ← apply state (.signCommittableMessages source)
  for peer in ([⟨1, by decide⟩, ⟨2, by decide⟩] : List Node) do
    state ← apply state (.appendEntries source peer 2)
    state ← apply state (.receive source peer)
    state ← apply state (.receive peer source)
  state ← apply state (.advanceCommitIndex source)
  check ((state.nodes source).commitIndex == 2)
    "leader should have quorum-committed the bootstrap signature"
  state ← apply state (.appendEntries source laggard 0)
  let some (.appendEntriesRequest heartbeat) := (state.network laggard).head?
    | throw (IO.userError "missing lagging heartbeat")
  check (heartbeat.entries.isEmpty && heartbeat.prevLogIndex == 0 &&
      heartbeat.leaderCommit == 2)
    "empty heartbeat may advertise a commit beyond its verified frontier"
  state ← apply state (.receive source laggard)
  check ((state.nodes laggard).commitIndex == 0)
    "a lagging heartbeat must not commit an unverified prefix"

private def networkSnapshots : IO Unit := do
  let started ← IO.monoMsNow
  let source : Node := ⟨0, by decide⟩
  let left : Node := ⟨1, by decide⟩
  let right : Node := ⟨2, by decide⟩
  let initial : State Node Nat := initialState
  let count := 64
  let mut state := initial
  for _ in [:count] do
    state ← apply state (.appendEntries source left 0)
    state ← apply state (.appendEntries source right 0)
  check ((state.network left).length == count &&
    (state.network right).length == count && (state.network source).isEmpty)
    "alternating sends changed queue multiplicity"
  for _ in [:count] do
    state ← apply state (.receive source left)
    state ← apply state (.receive source right)
  check ((state.network source).length == 2 * count &&
    (state.network left).isEmpty && (state.network right).isEmpty)
    "alternating replies changed queue multiplicity"
  for _ in [:count] do
    state ← apply state (.receive left source)
    state ← apply state (.receive right source)
  check ((state.network source).isEmpty && (initial.network source).isEmpty &&
    (initial.network left).isEmpty && (initial.network right).isEmpty)
    "network snapshots were not independent"
  check ((← IO.monoMsNow) - started < 5000)
    "network snapshot regression: 384 simple transitions took over five seconds"

private def repliesAfterStepDown : IO Unit := do
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let mut state : State Node Nat := initialState
  for transaction in [:6] do
    state ← apply state (.clientRequest source transaction)
  state ← apply state (.appendEntries source destination 6)
  state ← apply state (.appendEntries source destination 6)
  let sent := state
  state ← apply state (.timeout destination)
  state ← apply state (.receive source destination)
  state ← apply state (.receive source destination)
  state ← apply state (.updateTerm destination source)
  check (decide ((state.nodes source).role = .follower))
    "newer-term reply did not demote the old leader"
  for remaining in [1, 0] do
    state ← apply state (.receive destination source)
    check ((state.nodes source).sentIndex destination == 6 &&
      (state.nodes source).matchIndex destination == 0 &&
      (state.nodes source).log.length == 6 &&
      (state.network source).length == remaining)
      "late NACK changed a non-leader's cursor or was not consumed exactly once"
  let mut leader := sent
  leader ← apply leader (.drop source destination 0)
  leader ← apply leader (.receive source destination)
  leader ← apply leader (.receive destination source)
  check (decide ((leader.nodes source).role = .leader) &&
    (leader.nodes source).sentIndex destination == 0 &&
    (leader.nodes source).matchIndex destination == 0)
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
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"allocated":false,"role":"none","preVoteEnabled":true}}"#,
    r#"{"kind":"action","action":"clientRequest","node":"alpha","transaction":"tx-1"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":2}"#]
  let packet := r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","term":1,"prev_idx":0,"prev_term":0,"idx":2,"term_of_idx":1,"leader_commit_idx":0,"contains_new_view":false}}"#
  let receive := r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#
  let complete := initialSteps ++ [packet, receive,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","logLength":2,"commitIndex":0}}"#,
    r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","term":1,"success":"OK","last_log_idx":2}}"#,
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
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"allocated":true,"role":"none","currentTerm":0}}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"future","batchEnd":2}"#,
    r#"{"kind":"action","action":"updateTerm","source":"alpha","destination":"future"}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"future"}"#,
    r#"{"kind":"action","action":"becomePreVoteCandidate","node":"future"}"#,
    r#"{"kind":"observation","observation":"state","node":"future","fields":{"role":"preVoteCandidate","currentTerm":1,"logLength":2}}"#]
  match CCFRaft.Replay.replay reconfiguration with
  | .ok result => check (result.instructions == 8) "incomplete reconfiguration replay"
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
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_append_entries","prev_idx":2,"idx":2,"prev_term":1,"term_of_idx":1,"leader_commit_idx":2}}"#,
    r#"{"kind":"action","action":"updateTerm","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"message","source":"beta","destination":"alpha","packet":{"msg":"raft_append_entries_response","success":"FAIL","last_log_idx":0,"term":1}}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"follower","currentTerm":1,"logLength":0,"commitIndex":0}}"#,
    r#"{"kind":"action","action":"receive","source":"beta","destination":"alpha"}"#,
    r#"{"kind":"action","action":"appendEntries","source":"alpha","destination":"beta","batchEnd":3}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"logLength":3,"commitIndex":2,"committableIndices":[],"configurations":[{"index":1,"nodes":["alpha"]},{"index":3,"nodes":["alpha","beta"]}]}}"#]
  let bootstrap ← parseJson r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 17) "incomplete bootstrap prefix replay"
  | .error error => throw (IO.userError error)
  let startup ← replayDocument [
    r#"{"kind":"action","action":"initializeConfiguration","node":"alpha"}"#,
    r#"{"kind":"action","action":"signCommittableMessages","node":"alpha"}"#,
    r#"{"kind":"action","action":"advanceCommitIndex","node":"alpha"}"#,
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"logLength":2,"commitIndex":2}}"#,
    r#"{"kind":"observation","observation":"entry","node":"alpha","index":1,"fields":{"kind":"configuration","configuration":["alpha"],"term":1,"committed":true}}"#,
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
    r#"{"kind":"action","action":"updateTerm","source":"alpha","destination":"beta"}"#,
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
    r#"{"kind":"observation","observation":"state","node":"alpha","fields":{"role":"none","membershipState":"retiredCommitted","currentTerm":1,"commitIndex":6,"retiredCommittedIndex":6}}"#,
    r#"{"kind":"observation","observation":"message","source":"alpha","destination":"beta","packet":{"msg":"raft_propose_request_vote","term":1}}"#,
    r#"{"kind":"action","action":"receive","source":"alpha","destination":"beta"}"#,
    r#"{"kind":"observation","observation":"state","node":"beta","fields":{"role":"candidate","currentTerm":2}}"#]
  let bootstrap ← parseJson r#"{"configuration":["alpha"],"leader":"alpha","pre_vote_enabled":{"alpha":false,"beta":false}}"#
  match CCFRaft.Replay.replay (document.setObjVal! "bootstrap" bootstrap) with
  | .ok result => check (result.instructions == 24) "incomplete terminal retirement replay"
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
      { (freshNodeState : NodeState Node Nat) with
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
      source := survivor
      destination := node
    }
    let some (received, _) := handleAppendEntriesRequest? state request
      | throw (IO.userError "retirement batch was rejected")
    let received := refreshRetirementState node received
    check (received.commitIndex == 8 && received.retiredCommittedIndex == some expected)
      s!"batch from {oldLength}: wrong first covering retirement commit"

def main : IO Unit := do
  nominationTerms
  batchesAndDrops
  committedLeaderCanHeartbeatBehindCommit
  networkSnapshots
  repliesAfterStepDown
  jsonReplay
  bootstrapPrefix
  terminalRetirementRole
  retirementCommitFrontiers
  IO.println "Canonical behavior checks passed."
