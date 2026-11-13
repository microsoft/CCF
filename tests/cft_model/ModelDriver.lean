-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Consensus.Replay.Session
import Scenarios

/-!
Runs consensus scenarios with the Lean model of the protocol in the same process.

The driver keeps its trace in memory, and the model replays it: after a whole scenario,
or after each command of a run which reads the model to choose its next command.
-/

open Lean
open CftDriver
open Consensus Consensus.Replay
open CCF.MultiNodeTransitionSystem (nodeState)

namespace ModelDriver

private def fail {α : Type} (message : String) : IO α :=
  throw (IO.userError message)

/-- Take the trace records emitted since the last call, numbered after the `taken` before. -/
private def takeRecords (source : String) (taken : Nat) : IO (Array Record) := do
  (← takeTrace).mapIdxM
    fun index line => do
      let value ← IO.ofExcept (Json.parse line)
      return { file := source, line := taken + index + 1, value }

/--
Run a scenario with its trace kept in memory, then replay the trace against the model:
whole, and one command at a time, which must agree.
-/
private def runScenario (name : String) (steps : IO Unit) : IO Result := do
  startCapture
  steps
  finish
  let records ← takeRecords name 0
  let whole ← IO.ofExcept (replayTrace records)
  let byCommand ← IO.ofExcept (replayByCommand records)
  unless whole == byCommand do
    fail "replay by command disagrees with replay of the whole trace"
  return whole

/-- A run which replays each driver command in the model as soon as it is issued. -/
private structure Run where
  /-- The nodes which the run may start, in lexical order. -/
  nodes : List String
  /-- The records taken so far. -/
  records : Array Record := #[]
  /-- The replay, once a command has started the first node. -/
  session : Option Session := none

/-- The nodes which have started, by name and model identifier. -/
private def started (session : Session) : List (String × Nat) :=
  session.header.declared.zipIdx.filter
    fun (_, id) => (nodeState session.state id).any fun node => !decide node.isFresh

/--
Each undelivered message of the driver must be a distinct envelope in the network of the
model. The model also keeps the messages which the driver has dropped.
-/
private def checkPending (session : Session) : IO Unit := do
  let nodes := started session
  for (source, sourceId) in nodes do
    for (target, targetId) in nodes do
      if sourceId != targetId then
        let mut queued :=
          session.state.network.filter
            fun envelope => envelope.source == sourceId && envelope.target == targetId
        for pending in ← pendingMessages source target do
          let packet ← IO.ofExcept (Json.parse pending)
          let some envelope := queued.find? (packetMatches packet ·.payload)
          | fail s!"the model holds no message from {source} to {target} like {pending}"
          queued := queued.erase envelope

/--
Deliver the message which the model holds as `envelope`, wherever it is among the
undelivered messages of the driver.
-/
private def deliver (session : Session) (envelope : Model.Envelope) : IO Unit := do
  let name (id : Nat) := session.header.declared[id]?.getD (toString id)
  let source := name envelope.source
  let target := name envelope.target
  let wanted := (messageJson envelope.payload).compress
  let pending ← (← pendingMessages source target).mapM (IO.ofExcept <| Json.parse ·)
  let some position := pending.findIdx? (packetMatches · envelope.payload)
  | fail s!"the driver holds no message from {source} to {target} like {wanted}"
  dispatchNth source target position.toUInt64

namespace Run

/-- Replay the records emitted since the last call. -/
private def observe (run : Run) : IO Run := do
  let records ← takeRecords "trace" run.records.size
  let session ←
    match run.session with
    | none => IO.ofExcept (Session.start run.nodes records)
    | some session => IO.ofExcept (session.feed records)
  return { run with records := run.records ++ records, session := some session }

/-- Issue a command, replay what it did, and compare the undelivered messages. -/
private def step (run : Run) (command : IO Unit) : IO Run := do
  command
  let run ← run.observe
  if let some session := run.session then
    checkPending session
  return run

/-- Deliver the messages which the model holds, the newest first, until none is left. -/
private def drain (run : Run) : IO Run := do
  let mut run := run
  for _ in [0:100] do
    let some session := run.session | break
    let some envelope := session.state.network.getLast? | break
    run ← run.step (deliver session envelope)
  return run

end Run

/--
A run in step with the model. A primary sends to a new follower three times, and after
each the messages which the model holds are delivered, the newest first. The commit
indexes of the model are then asserted of the driver, and replay of the whole trace must
give the result of the replay in step.
-/
private def runInStep : IO Result := do
  startCapture
  let mut run : Run := { nodes := ["0", "1"] }
  for command
      in [startNode 0, replicate 2 [signature], trustNode 2 1, replicate 2 [signature]] do
    run ← run.step command
  for _ in [0:3] do
    run ← run.step (periodicOne 0 10)
    run ← run.drain
  let some session := run.session | fail "no command started a node"
  unless session.state.network.isEmpty do
    fail "the model still holds messages"
  for (node, id) in started session do
    let some state := nodeState session.state id | fail s!"the model has no node {node}"
    run ← run.step (assertCommitIdx node state.commitIndex.toUInt64)
  finish
  run ← run.observe
  let some session := run.session | fail "no command started a node"
  let whole ← IO.ofExcept (replayTrace run.records)
  unless session.result == whole do
    fail "replay in step disagrees with replay of the whole trace"
  return whole

/-- The argument which selects the run in step, where a scenario is named. -/
private def inStep : String := "--in-step"

/--
Run every scenario and the run in step, each in a process of its own, because a process
can start the driver once.
-/
private def runAll : IO UInt32 := do
  let app ← IO.appPath
  let names := (← scenarios.get).map (·.1) |>.reverse
  let mut failed := 0
  for name in names ++ [inStep] do
    let child ←
      IO.Process.spawn
        { cmd := app.toString, args := #[name], stdout := .null, stderr := .piped }
    let errors ← child.stderr.readToEnd
    if (← child.wait) == 0 then
      IO.println s!"{name}: ok"
    else
      failed := failed + 1
      IO.println s!"{name}: FAILED\n{errors}"
  IO.println s!"{names.length + 1} runs, {failed} failed"
  return if failed == 0 then 0 else 1

/-- Report the result of one run. -/
private def report (name : String) (run : IO Result) : IO UInt32 := do
  try
    let result ← run
    let status :=
      Json.mkObj
        [
          ("status", toJson "ok"),
          ("run", toJson name),
          ("instructions", toJson result.instructions),
          ("actions", toJson result.actions)
        ]
    IO.println status.compress
    return 0
  catch error =>
    IO.eprintln s!"{name}: {error}"
    return 1

end ModelDriver

open ModelDriver in
/--
Run the scenario named by the argument, `--in-step` for the run in step with the model,
or `--all` for every scenario and the run in step.
-/
def main (args : List String) : IO UInt32 := do
  match args with
  | ["--all"] => runAll
  | [name] =>
      if name == inStep then
        report "in step" runInStep
      else
        match (← scenarios.get).lookup name with
        | some steps => report name (runScenario name steps)
        | none =>
            IO.eprintln s!"Unknown scenario '{name}'"
            return 2
  | _ =>
      IO.eprintln "usage: cft_model_driver SCENARIO | --in-step | --all"
      return 2
