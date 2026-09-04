import DisasterRecovery
import DisasterRecoveryMigration
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

elab "#assert_no_migration_sorries" : command => do
  let env <- getEnv
  let mut offenders : Array Name := #[]
  for (name, _) in env.constants.toList do
    if name.toString.startsWith "DisasterRecoveryMigration" ||
        name.toString.startsWith "DisasterRecovery" then
      let axioms <- liftCoreM <| Lean.collectAxioms name
      if axioms.contains (Name.mkSimple "sorryAx") then
        offenders := offenders.push name
  unless offenders.isEmpty do
    throwError "declarations contain sorryAx: {offenders}"

#assert_no_migration_sorries

def main : IO Unit :=
  pure ()

