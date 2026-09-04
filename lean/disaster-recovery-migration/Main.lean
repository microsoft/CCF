import DisasterRecoveryMigration.Legacy.Checker

open DisasterRecoveryMigration.Legacy

private def usage : String :=
  "usage: migration-model-checker [--nodes N]"

private def parseNodes : List String -> Except String Nat
  | [] => pure 3
  | ["--nodes", value] =>
      match value.toNat? with
      | some n => if n > 0 then pure n else throw "--nodes must be positive"
      | none => throw s!"invalid node count: {value}"
  | _ => throw usage

def main (args : List String) : IO UInt32 := do
  match parseNodes args with
  | .error message =>
      IO.eprintln message
      pure 2
  | .ok n =>
      let graph <- enumerate n
      if <- checkGraph n graph then pure 0 else pure 1
