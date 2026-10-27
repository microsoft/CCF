module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Reduction

public section

open Lean CCFRaft.Replay

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | [path] =>
        let records ← readLog path
        let result := do
          let (events, declared) ← prepareEvents (← records)
          let reduced ← reduce events declared
          replay reduced.header reduced.instructions
        match result with
        | .error error => IO.eprintln error; return 1
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
    | _ => IO.eprintln "usage: ccfraft-replay TRACE.ndjson"; return 2
  catch error =>
    IO.eprintln s!"{error}"
    return 1
