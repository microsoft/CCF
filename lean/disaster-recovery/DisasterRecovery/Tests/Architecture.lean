import DisasterRecovery.Properties
import Lean

namespace DisasterRecovery.Tests.Architecture

open Lean

private def allowedImport (owner dependency : Name) : Bool :=
  if !(`DisasterRecovery).isPrefixOf dependency then
    true
  else if (`DisasterRecovery.Shared).isPrefixOf owner then
    (`DisasterRecovery.Shared).isPrefixOf dependency
  else if (`DisasterRecovery.Model).isPrefixOf owner then
    (`DisasterRecovery.Shared).isPrefixOf dependency ||
      (`DisasterRecovery.Model).isPrefixOf dependency
  else if (`DisasterRecovery.Properties).isPrefixOf owner then
    (`DisasterRecovery.Shared).isPrefixOf dependency ||
      (`DisasterRecovery.Model).isPrefixOf dependency ||
      (`DisasterRecovery.Properties).isPrefixOf dependency
  else
    true

example : allowedImport `DisasterRecovery.Properties `DisasterRecovery.Model = true := rfl
example :
    allowedImport `DisasterRecovery.Properties.Helpers `DisasterRecovery.Shared.Execution =
      true := rfl
example :
    allowedImport `DisasterRecovery.Properties.Helpers `DisasterRecovery.Proofs.Model =
      false := rfl
example : allowedImport `DisasterRecovery.Properties `DisasterRecovery.Proof = false := rfl
example :
    allowedImport `DisasterRecovery.Model.Local `DisasterRecovery.Properties.Helpers =
      false := rfl
example :
    allowedImport `DisasterRecovery.Shared.Global `DisasterRecovery.Model = false := rfl
example : allowedImport `DisasterRecovery.Properties `DisasterRecovery = false := rfl

run_cmd do
  let header := (← getEnv).header
  for name in header.moduleNames do
    if (`DisasterRecovery.Proof).isPrefixOf name ||
        (`DisasterRecovery.Proofs).isPrefixOf name then
      throwError "Property definitions import proof module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden model/property dependency: {owner} imports {dependency.module}"

end DisasterRecovery.Tests.Architecture
