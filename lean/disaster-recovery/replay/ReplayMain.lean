import DisasterRecovery.Replay.Reduction

set_option autoImplicit false

open DisasterRecovery.Replay

/-- How long the nodes have to finish logging the scenario. -/
def completionTimeoutMs : Nat :=
  20000

def usage : String :=
  "usage: disaster-recovery-replay --participants N [--wait-ms N] LOG..."

def parseArgs : List String → Option (Nat × Scenario × List System.FilePath) :=
  let rec go (waitMs : Nat) (participants : Option Nat)
      : List String → Option (Nat × Scenario × List System.FilePath)
    | "--participants" :: count :: rest => do
        go waitMs (some (← count.toNat?)) rest
    | "--wait-ms" :: value :: rest => do
        go (← value.toNat?) participants rest
    | logs@(_ :: _) => do
        let participants ← participants
        return (waitMs, { participants }, logs.map System.FilePath.mk)
    | [] => none
  go completionTimeoutMs none

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

def main (args : List String) : IO UInt32 := do
  let some (waitMs, scenario, logs) := parseArgs args
  |
    IO.eprintln usage
    return 2
  let deadline := (← IO.monoMsNow) + waitMs
  match ← reduceWhenComplete scenario logs deadline with
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
            s!"replayed {result.actions} actions and {result.observations} observations of {reduced.header.participants.length} participants"
          if let some failure := reduced.scenario then
            IO.eprintln s!"{summary}, but the scenario failed: {failure}"
            return 1
          IO.println summary
          return 0
