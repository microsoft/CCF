module

import all Init.Prelude
import all Lean.Data.Name
import all CCFRaft.Theorems
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
  else if (`CCFRaft.Properties).isPrefixOf owner
          || (`CCFRaft.Conjectures).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency
    || (`CCFRaft.Properties).isPrefixOf dependency
    || (`CCFRaft.Conjectures).isPrefixOf dependency
  else if (`CCFRaft.Proofs).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency
    || (`CCFRaft.Properties).isPrefixOf dependency
    || (`CCFRaft.Proofs).isPrefixOf dependency
  else if owner == `CCFRaft.Theorems then
    (`CCFRaft.Model).isPrefixOf dependency
    || (`CCFRaft.Properties).isPrefixOf dependency
    || (`CCFRaft.Proofs).isPrefixOf dependency
  else
    true

example : allowedImport `CCFRaft.Theorems `CCFRaft.Proofs.Election = true := rfl

example : allowedImport `CCFRaft.Properties.Trace `CCFRaft.Proofs.Election = false := rfl

example : allowedImport `CCFRaft.Conjectures `CCFRaft.Theorems = false := rfl

example : allowedImport `CCFRaft.Proofs.Election `CCFRaft.Theorems = false := rfl

example : allowedImport `CCFRaft.Model `CCFRaft.Theorems = false := rfl

example : allowedImport `CCFRaft.Model.Node `CCFRaft.Model = false := rfl

example : allowedImport `CCF.Execution `CCFRaft.Model = false := rfl

-- Model definitions remain independent of statement helpers and proofs.
run_cmd do
  let header := (← getEnv).header
  for name in header.moduleNames do
    if name == `CCFRaft.Properties || name == `CCFRaft.Conjectures then
      throwError "Superseded claim module must not be reintroduced: {name}"
    if (`CCFRaft.Shared).isPrefixOf name then
      throwError "Use ccf_common instead of package-local Shared module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden layer dependency: {owner} imports {dependency.module}"

end CCFRaft.Tests.Architecture
