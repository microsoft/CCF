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

/--
Validate each trace, then report the outcomes which they show together. With `expected`,
the outcomes which no trace shows must be those which it names.
-/
private def reportOutcomes (expected : Option (List String)) (paths : List String)
    : IO UInt32 := do
  let mut traces := #[]
  for path in paths do
    match ← validate path with
    | .error error => return ← reject path error
    | .ok result =>
        let name := (System.FilePath.mk path).fileStem.getD path
        traces := traces.push (name, result.outcomes)
  IO.println (report traces)
  let some expected := expected | return 0
  let missing := (notShown traces).map (·.name)
  let known := Outcome.all.map (·.name)
  let problems :=
    [
      ("no trace shows any longer", missing.filter (!expected.contains ·)),
      (
        "a trace now shows, and --not-shown still names",
        expected.filter fun name => known.contains name && !missing.contains name
      ),
      ("not an outcome", expected.filter (!known.contains ·))
    ]
  for (problem, names) in problems do
    unless names.isEmpty do
      IO.eprintln s!"{problem}: {", ".intercalate names}"
  return if problems.all (·.2.isEmpty) then 0 else 1

private def usage : IO UInt32 := do
  IO.eprintln "usage: consensus-replay TRACE.ndjson"
  IO.eprintln "       consensus-replay --by-command TRACE.ndjson"
  IO.eprintln
    "       consensus-replay --outcomes [--not-shown OUTCOME,...] TRACE.ndjson..."
  return 2

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["--outcomes"] | ["--by-command"] => usage
    | "--outcomes" :: "--not-shown" :: names :: path :: paths =>
        reportOutcomes (some ((names.splitOn ",").filter (!·.isEmpty))) (path :: paths)
    | "--outcomes" :: "--not-shown" :: _ => usage
    | "--outcomes" :: paths => reportOutcomes none paths
    | ["--by-command", path] => validateByCommand path
    | [path] =>
        match ← validate path with
        | .error error => reject path error
        | .ok result => accept result
    | _ => usage
  catch error =>
    IO.eprintln s!"{error}"
    return 1
