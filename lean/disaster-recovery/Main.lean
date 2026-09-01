import DisasterRecovery.Checker

open DisasterRecovery

private def usage : String :=
  "usage: disaster-recovery (check|export) [--nodes N]"

private def parseNodes : List String -> Except String Nat
  | [] => pure 3
  | ["--nodes", value] =>
      match value.toNat? with
      | some n => if n > 0 then pure n else throw "--nodes must be positive"
      | none => throw s!"invalid node count: {value}"
  | _ => throw usage

def main (args : List String) : IO UInt32 := do
  match args with
  | command :: rest =>
      match parseNodes rest with
      | .error message =>
          IO.eprintln message
          pure 2
      | .ok n =>
          match command with
          | "export" =>
              let graph <- enumerate n
              exportGraph n graph
              pure 0
          | "check" =>
              let graph <- enumerate n
              if <- checkGraph n graph then pure 0 else pure 1
          | _ =>
              IO.eprintln usage
              pure 2
  | [] =>
      IO.eprintln usage
      pure 2
