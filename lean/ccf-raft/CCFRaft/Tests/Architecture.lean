module

import all CCFRaft.Properties
import Lean

namespace CCFRaft.Tests.Architecture

open Lean

private def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    !(`CCFRaft).isPrefixOf dependency
  else if !(`CCFRaft).isPrefixOf dependency then
    true
  else if (`CCFRaft.Model).isPrefixOf owner && owner != `CCFRaft.Model then
    dependency != `CCFRaft.Model && (`CCFRaft.Model).isPrefixOf dependency
  else if owner == `CCFRaft.Model then
    (`CCFRaft.Model).isPrefixOf dependency
  else if (`CCFRaft.Properties).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency
    || (`CCFRaft.Proofs).isPrefixOf dependency
    || (`CCFRaft.Properties).isPrefixOf dependency
  else if (`CCFRaft.Proofs).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency || (`CCFRaft.Proofs).isPrefixOf dependency
  else
    true

-- Model definitions remain independent of the proved properties.
run_cmd do
  let header := (← getEnv).header
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden layer dependency: {owner} imports {dependency.module}"

end CCFRaft.Tests.Architecture
