module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all Init.Prelude
import all Lean.Data.Name

public import CCFRaft.Properties
public import CCFRaft.Tests.AppendTransactions
public import Lean

@[expose] public section

namespace CCFRaft.Tests.Architecture

open Lean

private def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    !(`CCFRaft).isPrefixOf dependency
  else if !(`CCFRaft).isPrefixOf dependency then
    true
  else if (`CCFRaft.Model).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency
  else if (`CCFRaft.Properties).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency || (`CCFRaft.Properties).isPrefixOf dependency
  else
    true

example : allowedImport `CCFRaft.Properties `CCFRaft.Model = true := rfl

example : allowedImport `CCFRaft.Properties.Utils `CCF.Execution = true := rfl

example : allowedImport `CCFRaft.Properties `CCFRaft.Proofs.Model = false := rfl

example : allowedImport `CCFRaft.Properties `CCFRaft.Proof = false := rfl

example : allowedImport `CCFRaft.Model.Node `CCFRaft.Properties.Utils = false := rfl

example : allowedImport `CCF.MultiNodeTransitionSystem `CCFRaft.Model = false :=
  rfl

example : allowedImport `CCFRaft.Properties `CCFRaft = false := rfl

-- The model and properties must not depend on proofs.
run_cmd do
  let env ← getEnv
  let header := env.header
  for name in header.moduleNames do
    if (`CCFRaft.Shared).isPrefixOf name then
      throwError "Use ccf_common instead of package-local Shared module {name}"
    if (`CCFRaft.Proof).isPrefixOf name || (`CCFRaft.Proofs).isPrefixOf name then
      throwError "Model or property definitions import proof module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden model/property dependency: {owner} imports {dependency.module}"

end CCFRaft.Tests.Architecture
