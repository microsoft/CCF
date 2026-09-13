import DisasterRecoveryTrace.Protocol.Trace

open DisasterRecoveryTrace.Protocol.Trace

private def validateLogFiles
    (paths : List String) (scenario : Scenario) (timeoutMs : Nat) : IO UInt32 := do
  let deadline := (← IO.monoMsNow) + timeoutMs
  repeat
    let logs <- paths.mapM fun (path : String) => do
      pure (path, ← IO.FS.readBinFile path)
    match validateLogs logs scenario with
    | .ok count =>
        IO.println s!"trace accepted: {count} events from {paths.length} logs"
        return 0
    | .error (.invalid message) =>
        IO.eprintln message
        return 1
    | .error (.incomplete message) =>
        if (← IO.monoMsNow) >= deadline then
          IO.eprintln s!"timed out waiting for a complete recovery trace:\n{message}"
          return 1
        IO.sleep 100

private def usage : IO UInt32 := do
  IO.eprintln ("usage: trace-validator TRACE.ndjson\n" ++
    "       trace-validator --logs NODE_COUNT QUORUM|FAILOVER TIMEOUT_MS LOG...")
  pure 2

def main (args : List String) : IO UInt32 := do
  match args with
  | "--logs" :: count :: kind :: timeout :: paths => do
      let some participatingNodes := count.toNat? | usage
      let some timeoutMs := timeout.toNat? | usage
      let openKind <- match kind with
        | "QUORUM" => pure DisasterRecovery.Protocol.Model.OpenKind.quorum
        | "FAILOVER" => pure DisasterRecovery.Protocol.Model.OpenKind.failover
        | _ => return ← usage
      if participatingNodes == 0 || paths.isEmpty then
        return ← usage
      validateLogFiles paths { participatingNodes, openKind } timeoutMs
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
  | _ => usage
