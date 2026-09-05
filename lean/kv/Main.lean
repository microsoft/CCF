-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Trace
import AxiomAudit

open Kv.Trace

def main (args : List String) : IO UInt32 := do
  let jsonMode := args.contains "--json"
  let paths := args.filter (· != "--json")
  let report ← match paths with
    | [path] =>
      try
        checkFile path
      catch e =>
        pure { status := "invalid_trace", events := 0, message := s!"cannot read trace: {e}" }
    | _ => pure { status := "invalid_trace", events := 0,
                  message := "usage: kv_trace_check [--json] <trace.ndjson>" }
  if jsonMode then
    (← IO.getStdout).putStrLn report.json.compress
  else
    (← IO.getStderr).putStrLn s!"{report.status}: {report.message}"
  return report.exitCode
