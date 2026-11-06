-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import consistency.TraceValidation

public section

/-- Validate consistency captures; any malformed record or disabled action fails.
Every path is checked, and the exit status is 1 if any capture is rejected. -/
def main (args : List String) : IO UInt32 := do
  if args.isEmpty then
    (← IO.getStderr).putStrLn "usage: consistency-replay <trace.ndjson>..."
    return 2
  let mut status : UInt32 := 0
  for path in args do
    try
      let events ← consistency.TraceValidation.checkFile path
      IO.println s!"{path}: validated {events} records"
    catch error =>
      (← IO.getStderr).putStrLn s!"{error}"
      status := 1
  return status
