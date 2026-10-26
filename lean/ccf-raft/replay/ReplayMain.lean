module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Replayer

public section

open CCFRaft.Replay

private def usage : String :=
  "usage: ccfraft-replay TRACE.ndjson"

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | [path] =>
        let result ← readLog path
        match result >>= replayRecords with
        | .error error => IO.eprintln error; return 1
        | .ok result => IO.println result.json.compress; return 0
    | _ => IO.eprintln usage; return 2
  catch error =>
    IO.eprintln s!"{error}"
    return 1
