import DisasterRecovery.Protocol.Trace

open DisasterRecovery.Protocol.Trace

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
      let input <- IO.FS.readFile path
      match parseNDJSON input with
      | .error message =>
          IO.eprintln message
          pure 1
      | .ok events =>
          match validate events with
          | .error failure =>
              IO.eprintln (renderFailure failure)
              pure 1
          | .ok () =>
              IO.println s!"trace accepted: {events.length} events"
              pure 0
  | _ =>
      IO.eprintln "usage: trace-validator TRACE.ndjson"
      pure 2
