module

public import DisasterRecovery.TraceValidation.Dump

public section

set_option autoImplicit false

open DisasterRecovery.TraceValidation

/-- How long the nodes have to finish logging the scenario. -/
def completionTimeoutMs : Nat :=
  20000

/-- Command-line syntax reported when replay arguments are invalid. -/
def usage : String :=
  "usage: disaster-recovery-replay --participants N [--wait-ms N] [--dump FILE] LOG..."

/-- Takes `--dump FILE` out of the arguments. The trace viewer reads the file. -/
def takeDump : List String → Option System.FilePath × List String
  | "--dump" :: path :: rest => (some path, (takeDump rest).2)
  | argument :: rest =>
      let (dump, others) := takeDump rest
      (dump, argument :: others)
  | [] => (none, [])

/-- Parses the wait duration, participant count, and nonempty list of log paths. -/
def parseArgs (args : List String) : Option (Nat × Scenario × List System.FilePath) :=
  go completionTimeoutMs none args
where
  /-- Accumulates replay options until the remaining arguments are log paths. -/
  go (waitMs : Nat) (participants : Option Nat)
      : List String → Option (Nat × Scenario × List System.FilePath)
    | "--participants" :: count :: rest => do
        go waitMs (some (← count.toNat?)) rest
    | "--wait-ms" :: value :: rest => do
        go (← value.toNat?) participants rest
    | logs@(_ :: _) => do
        let participants ← participants
        return (waitMs, { participants }, logs.map System.FilePath.mk)
    | [] => none

/-- Reduces the logs once they record a complete scenario. -/
partial def reduceWhenComplete (scenario : Scenario) (logs : List System.FilePath)
    (deadline : Nat)
    : IO (Except String Reduced) := do
  match (← readLogs logs) >>= (reduce · scenario) with
  | .ok reduced => return .ok reduced
  | .error (.invalid message) => return .error message
  | .error (.incomplete message) =>
      if (← IO.monoMsNow) >= deadline then
        return .error s!"timed out waiting for a complete recovery trace:\n{message}"
      IO.sleep 100
      reduceWhenComplete scenario logs deadline

/-- Reduce and replay node logs, optionally writing the viewer dump, with failures fatal. -/
def main (args : List String) : IO UInt32 := do
  let (dump, args) := takeDump args
  let some (waitMs, scenario, logs) := parseArgs args
  |
    IO.eprintln usage
    return 2
  let deadline := (← IO.monoMsNow) + waitMs
  let reduced ← reduceWhenComplete scenario logs deadline
  if let some path := dump then
    Dump.write path scenario logs reduced
  match reduced with
  | .error message =>
      IO.eprintln s!"reduction failed: {message}"
      return 1
  | .ok reduced =>
      match replay reduced.header reduced.instructions with
      | .error message =>
          IO.eprintln s!"replay failed: {message}"
          return 1
      | .ok result =>
          let summary :=
            s!"replayed {result.actions} actions and {result.observations} observations of {reduced.header.config.active.length} participants"
          if let some failure := reduced.scenario then
            IO.eprintln s!"{summary}, but the scenario failed: {failure}"
            return 1
          IO.println summary
          return 0
