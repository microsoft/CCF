-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import consistency.TraceValidation

public section

/-- Validate a consistency capture; any malformed record or disabled action fails. -/
def main (args : List String) : IO UInt32 := do
  let [path] := args
  | (← IO.getStderr).putStrLn "usage: consistency-replay <trace.ndjson>"; return 2
  try
    let events ← consistency.TraceValidation.checkFile path
    IO.println s!"{path}: validated {events} records"
    return 0
  catch error =>
    (← IO.getStderr).putStrLn s!"{error}"
    return 1
