import DisasterRecovery.Proof
import Lean

namespace DisasterRecovery.Tests.ProofCoverage

open Lean

-- Every public claim, including each non-vacuity claim, needs an exported theorem.
run_cmd do
  let env ← getEnv
  let declarations := env.constants.toList
  for (name, info) in declarations do
    if name.getPrefix != `DisasterRecovery.Properties || info.type != mkSort .zero then
      continue
    let covered := declarations.any fun (proofName, proofInfo) =>
      proofName.getPrefix == `DisasterRecovery.Proof &&
        (match proofInfo with
        | .thmInfo proof => proof.type.isConstOf name
        | _ => false)
    unless covered do
      throwError "Property has no exported theorem: {name}"
    unless name.getString!.endsWith "Witness" do
      let witness := Name.str `DisasterRecovery.Properties (name.getString! ++ "Witness")
      unless env.contains witness do
        throwError "Property has no non-vacuity claim: {name}"

end DisasterRecovery.Tests.ProofCoverage
