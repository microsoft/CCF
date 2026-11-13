module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Session

public section

open Lean Consensus.Replay

/-- Replay one whole trace against the model. -/
private def validate (path : String) : IO (Except String Result) := do
  return (← readLog path) >>= replayTrace

private def accept (result : Result) : IO UInt32 := do
  let status :=
    Json.mkObj
      [
        ("status", toJson "ok"),
        ("instructions", toJson result.instructions),
        ("actions", toJson result.actions),
        ("observations", toJson result.observations)
      ]
  IO.println status.compress
  return 0

private def reject (path error : String) : IO UInt32 := do
  IO.eprintln s!"{path}: {error}"
  return 1

private def disagree (path reason : String) : IO UInt32 := do
  IO.eprintln
    s!"{path}: replay by command disagrees with replay of the whole trace: {reason}"
  return 3

/--
Replay one trace a driver command at a time.
Replay of the whole trace must give the same result.
-/
private def validateByCommand (path : String) : IO UInt32 := do
  let records ← readLog path
  match records >>= replayTrace, records >>= replayByCommand with
  | .ok whole, .ok byCommand =>
      if whole == byCommand then accept byCommand else disagree path "the results differ"
  | .error _, .error error => reject path error
  | .ok _, .error error => disagree path s!"only replay by command rejects it: {error}"
  | .error error, .ok _ =>
      disagree path s!"only replay of the whole trace rejects it: {error}"

/-- Validate each trace, then report the outcomes which they show together. -/
private def reportOutcomes (paths : List String) : IO UInt32 := do
  let mut traces := #[]
  for path in paths do
    match ← validate path with
    | .error error => return ← reject path error
    | .ok result =>
        let name := (System.FilePath.mk path).fileStem.getD path
        traces := traces.push (name, result.outcomes)
  IO.println (report traces)
  return 0

private def usage : IO UInt32 := do
  IO.eprintln "usage: consensus-replay TRACE.ndjson"
  IO.eprintln "       consensus-replay --by-command TRACE.ndjson"
  IO.eprintln "       consensus-replay --outcomes TRACE.ndjson..."
  return 2

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["--outcomes"] | ["--by-command"] => usage
    | "--outcomes" :: paths => reportOutcomes paths
    | ["--by-command", path] => validateByCommand path
    | [path] =>
        match ← validate path with
        | .error error => reject path error
        | .ok result => accept result
    | _ => usage
  catch error =>
    IO.eprintln s!"{error}"
    return 1
