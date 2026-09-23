-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Replay
import Lean

namespace CCFRaft.Tests.Architecture

open Lean

private def allowedImport (owner dependency : Name) : Bool :=
  if !(`CCFRaft).isPrefixOf dependency then
    true
  else if (`CCFRaft.Shared).isPrefixOf owner then
    (`CCFRaft.Shared).isPrefixOf dependency
  else if (`CCFRaft.Model).isPrefixOf owner then
    (`CCFRaft.Shared).isPrefixOf dependency
    || (`CCFRaft.Model).isPrefixOf dependency
  else if (`CCFRaft.Properties).isPrefixOf owner || owner == `CCFRaft.Replay then
    (`CCFRaft.Shared).isPrefixOf dependency
    || (`CCFRaft.Model).isPrefixOf dependency
    || (`CCFRaft.Properties).isPrefixOf dependency
  else
    true

example : allowedImport `CCFRaft.Properties `CCFRaft.Model = true := rfl

example : allowedImport `CCFRaft.Properties.Utils `CCFRaft.Shared.Execution = true := rfl

example : allowedImport `CCFRaft.Properties `CCFRaft.Proofs.Model = false := rfl

example : allowedImport `CCFRaft.Properties `CCFRaft.Proof = false := rfl

example : allowedImport `CCFRaft.Model.Local `CCFRaft.Properties.Utils = false := rfl

example : allowedImport `CCFRaft.Shared.MultiNodeTransitionSystem `CCFRaft.Model = false := rfl

example : allowedImport `CCFRaft.Replay `CCFRaft.Proofs.Model = false := rfl

example : allowedImport `CCFRaft.Properties `CCFRaft = false := rfl

-- The model, properties, and replayer must not depend on proofs.
run_cmd do
  let env ← getEnv
  let header := env.header
  for name in header.moduleNames do
    if (`CCFRaft.Proof).isPrefixOf name || (`CCFRaft.Proofs).isPrefixOf name then
      throwError "Property definitions or the replayer import proof module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden model/property dependency: {owner} imports {dependency.module}"

end CCFRaft.Tests.Architecture
