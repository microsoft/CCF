-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Consensus.Replay.Reduction
import Scenarios

/-!
Runs consensus scenarios with the Lean model of the protocol in the same process.

The driver keeps its trace in memory, and the model replays it once the scenario has run.
-/

open Lean
open CftDriver
open Consensus Consensus.Replay

namespace ModelDriver

/-- Take the trace records which the driver has emitted, as the lines of `source`. -/
private def takeRecords (source : String) : IO (Array Record) := do
  (← takeTrace).mapIdxM
    fun index line => do
      let value ← IO.ofExcept (Json.parse line)
      return { file := source, line := index + 1, value }

/-- Run a scenario with its trace kept in memory, then replay the trace against the model. -/
private def runScenario (name : String) (steps : IO Unit) : IO Result := do
  startCapture
  steps
  finish
  let records ← takeRecords name
  IO.ofExcept do
    let (events, declared) ← prepareEvents records
    let reduced ← reduce events declared
    replay reduced.header reduced.instructions

/--
Start this program again with `args`. Give what went wrong unless it exits with status 0:
that status, which is all there is of a process which a signal ends, and what it wrote
to stderr.
-/
private def again (args : Array String) : IO (Option String) := do
  let child ←
    IO.Process.spawn
      { cmd := (← IO.appPath).toString, args, stdout := .null, stderr := .piped }
  let errors ← child.stderr.readToEnd
  let status ← child.wait
  if status == 0 then
    return none
  return some (s!"exit status {status}" ++ if errors.isEmpty then "" else s!": {errors}")

/--
Run every scenario, each in a process of its own, because a process can start the driver
once. Fail if one of them does, or if there is none.
-/
private def runAll : IO UInt32 := do
  let names := (← scenarios.get).map (·.1) |>.reverse
  let mut failed := 0
  for name in names do
    match ← again #[name] with
    | none => IO.println s!"{name}: ok"
    | some message =>
        failed := failed + 1
        IO.println s!"{name}: FAILED\n{message}"
  IO.println s!"{names.length} runs, {failed} failed"
  return if failed == 0 && !names.isEmpty then 0 else 1

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
/-- Run the scenario named by the argument, or every scenario for `--all`. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | ["--all"] => runAll
  | [name] =>
      match (← scenarios.get).lookup name with
      | some steps => report name (runScenario name steps)
      | none =>
          IO.eprintln s!"Unknown scenario '{name}'"
          return 2
  | _ =>
      IO.eprintln "usage: cft_model_driver SCENARIO | --all"
      return 2
