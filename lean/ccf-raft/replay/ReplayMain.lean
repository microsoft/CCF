-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Replay

def main (args : List String) : IO UInt32 := do
  let stderr ← IO.getStderr
  let [path] := args
    | stderr.putStrLn "usage: ccfraft-replay <replay.json|->"
      return 2
  let input ← try
      if path == "-" then
        (← IO.getStdin).readToEnd
      else
        IO.FS.readFile path
    catch error =>
      stderr.putStrLn s!"{path}: {error}"
      return 2
  match Lean.Json.parse input >>= CCFRaft.Replay.replay with
  | .error error =>
      stderr.putStrLn s!"{path}: {error}"
      return 1
  | .ok result =>
      IO.println (Lean.Json.mkObj [
        ("status", Lean.toJson "ok"),
        ("instructions", Lean.toJson result.instructions),
        ("actions", Lean.toJson result.actions),
        ("observations", Lean.toJson result.observations)]).compress
      return 0
