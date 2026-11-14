-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import ModelDriver.Explore

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

/-- Start this program again with `args`. Give its exit status and what it wrote to stderr. -/
private def again (args : Array String) : IO (UInt32 × String) := do
  let child ←
    IO.Process.spawn
      { cmd := (← IO.appPath).toString, args, stdout := .null, stderr := .piped }
  let errors ← child.stderr.readToEnd
  return (← child.wait, errors)

/-- The status and the outcomes in the result file of a run, and its message. -/
private def reported (file : System.FilePath) : IO (String × Json × String) := do
  let result ← IO.ofExcept (Json.parse (← IO.FS.readFile file))
  return (
    ← IO.ofExcept (string result "status"),
    ← IO.ofExcept (field result "outcomes"),
    ← IO.ofExcept (string result "message")
  )

/--
Record the commands of a scenario, and run them as a program, which must show the outcomes
which the scenario shows. Give what went wrong, if anything did.
-/
private def roundTrip (directory : System.FilePath) (name : String) : IO String := do
  let program := directory / s!"{name}.program"
  let (status, errors) ← again #["--record", name, program.toString]
  if status != 0 then
    return s!"recording its commands: {errors}"
  let result := directory / s!"{name}.again.json"
  let (status, errors) ← again #["--run", program.toString, result.toString]
  if status != 0 then
    return s!"running its commands: {errors}"
  let (_, recorded, _) ← reported (program.withExtension "json")
  let (status, ran, message) ← reported result
  if status != "ok" then
    return s!"its commands are {status}: {message}"
  if recorded != ran then
    return "its commands show other outcomes"
  return ""

/--
Run every scenario and the run in step, each in a process of its own, because a process
can start the driver once. Also run each scenario from its commands, and explore briefly.
-/
private def runAll : IO UInt32 := do
  let names := (← scenarios.get).map (·.1) |>.reverse
  let directory ← IO.FS.createTempDir
  let mut failed := 0
  for name in names ++ [inStep] do
    let (status, errors) ← again #[name]
    let mut problem := if status == 0 then "" else errors
    if problem.isEmpty && name != inStep then
      problem ← roundTrip directory name
    if problem.isEmpty then
      IO.println s!"{name}: ok"
    else
      failed := failed + 1
      IO.println s!"{name}: FAILED\n{problem}"
  -- A short exploration must run, whatever it finds
  let (status, errors) ←
    again #["--explore", (directory / "explore").toString, "--runs", "40"]
  if status == 0 then
    IO.println "--explore: ok"
  else
    failed := failed + 1
    IO.println s!"--explore: FAILED\n{errors}"
  IO.FS.removeDirAll directory
  IO.println s!"{names.length + 2} runs, {failed} failed"
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
/-- The options of an exploration, after its directory. -/
private def exploration (options : Exploration) : List String → Except String Exploration
  | [] => pure options
  | name :: value :: rest =>
      match name, value.toNat? with
      | "--seed", some seed => exploration { options with seed } rest
      | "--runs", some runs => exploration { options with runs } rest
      | "--jobs", some jobs => exploration { options with jobs := max jobs 1 } rest
      | _, _ => throw s!"unknown option '{name} {value}'"
  | [name] => throw s!"option '{name}' has no value"

open ModelDriver in
/--
Run the scenario named by the argument, `--in-step` for the run in step with the model,
or `--all` for every scenario and the run in step. `--record` writes the commands of a
scenario as a program, `--run` runs a program, and `--explore` changes the scenarios at
random and runs them.
-/
def main (args : List String) : IO UInt32 := do
  let unknown (name : String) : IO UInt32 := do
    IO.eprintln s!"Unknown scenario '{name}'"
    return 2
  match args with
  | ["--all"] => runAll
  | ["--record", name, file] =>
      match (← scenarios.get).lookup name with
      | some steps => recordScenario name steps file
      | none => unknown name
  | ["--run", program] => runProgram program none
  | ["--run", program, result] => runProgram program (some result)
  | ["--scenario", program, name, output] => writeScenario program name output
  | "--explore" :: directory :: options =>
      match exploration { directory } options with
      | .ok options => explore options ((← scenarios.get).map (·.1) |>.reverse)
      | .error error =>
          IO.eprintln error
          return 2
  | ["--shrink", program, output] => shrink program output none 8
  | ["--shrink", program, output, "--outcome", outcome] =>
      shrink program output (some outcome) 8
  | [name] =>
      if name == inStep then
        report "in step" runInStep
      else
        match (← scenarios.get).lookup name with
        | some steps => report name (runScenario name steps)
        | none => unknown name
  | _ =>
      IO.eprintln
        "usage: cft_model_driver SCENARIO | --in-step | --all | --record SCENARIO PROGRAM | --run PROGRAM [RESULT] | --explore DIRECTORY [--seed N] [--runs N] [--jobs N] | --shrink PROGRAM OUTPUT [--outcome OUTCOME] | --scenario PROGRAM NAME OUTPUT"
      return 2
