module

public import Kv.TraceValidation

public section

open Kv.TraceValidation

/-- Command-line syntax reported when arguments are invalid. -/
def usage : String :=
  "usage: kv-replay [--json] <trace.ndjson>"

/-- Checks one trace, printing the report as JSON with `--json` or as text on stderr, and
exits with `Report.exitCode`. -/
def main (args : List String) : IO UInt32 := do
  let jsonMode := args.contains "--json"
  let paths := args.filter (· != "--json")
  let report ←
    match paths with
    | [path] =>
        try
          checkFile path
        catch e =>
          pure
            {
              status := "invalid_trace",
              events := 0,
              message := s!"cannot read trace: {e}"
            }
    | _ =>
        pure { status := "invalid_trace", events := 0, message := usage }
  if jsonMode then
    (← IO.getStdout).putStrLn (Lean.toJson report).compress
  else
    (← IO.getStderr).putStrLn s!"{report.status}: {report.message}"
  return report.exitCode
