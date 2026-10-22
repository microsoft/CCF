module

import all DisasterRecovery.Properties
import Lean

namespace DisasterRecovery.Tests.Architecture

open Lean

def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    !(`DisasterRecovery).isPrefixOf dependency
  else if !(`DisasterRecovery).isPrefixOf dependency then
    true
  else if (`DisasterRecovery.Model).isPrefixOf owner then
    (`DisasterRecovery.Model).isPrefixOf dependency
  else if owner == `DisasterRecovery.Properties then
    (`DisasterRecovery.Model).isPrefixOf dependency
    || (`DisasterRecovery.Properties).isPrefixOf dependency
    || (`DisasterRecovery.Proofs).isPrefixOf dependency
  else if (`DisasterRecovery.Properties).isPrefixOf owner then
    (`DisasterRecovery.Model).isPrefixOf dependency
    || (dependency != `DisasterRecovery.Properties
        && (`DisasterRecovery.Properties).isPrefixOf dependency)
  else if (`DisasterRecovery.Proofs).isPrefixOf owner then
    (`DisasterRecovery.Model).isPrefixOf dependency
    || (`DisasterRecovery.Proofs).isPrefixOf dependency
    || (dependency != `DisasterRecovery.Properties
        && (`DisasterRecovery.Properties).isPrefixOf dependency)
  else
    true

run_cmd do
  let header := (← getEnv).header
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden layer dependency: {owner} imports {dependency.module}"

end DisasterRecovery.Tests.Architecture
