module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Reduction

public section

open Lean Consensus.Replay

/-- Reduce one trace, and replay it against the model. -/
private def validate (path : String) : IO (Except String Result) := do
  let records ← readLog path
  return do
    let (events, declared) ← prepareEvents (← records)
    let reduced ← reduce events declared
    replay reduced.header reduced.instructions

/-- Validate each trace, then report the outcomes which they show together. -/
private def reportOutcomes (paths : List String) : IO UInt32 := do
  let mut traces := #[]
  for path in paths do
    match ← validate path with
    | .error error => IO.eprintln s!"{path}: {error}"; return 1
    | .ok result =>
        let name := (System.FilePath.mk path).fileStem.getD path
        traces := traces.push (name, result.outcomes)
  IO.println (report traces)
  return 0

private def usage : IO UInt32 := do
  IO.eprintln "usage: consensus-replay TRACE.ndjson"
  IO.eprintln "       consensus-replay --outcomes TRACE.ndjson..."
  return 2

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["--outcomes"] => usage
    | "--outcomes" :: paths => reportOutcomes paths
    | [path] =>
        match ← validate path with
        | .error error => IO.eprintln s!"{path}: {error}"; return 1
        | .ok result =>
            let result :=
              Json.mkObj
                [
                  ("status", toJson "ok"),
                  ("instructions", toJson result.instructions),
                  ("actions", toJson result.actions),
                  ("observations", toJson result.observations)
                ]
            IO.println result.compress
            return 0
    | _ => usage
  catch error =>
    IO.eprintln s!"{error}"
    return 1
