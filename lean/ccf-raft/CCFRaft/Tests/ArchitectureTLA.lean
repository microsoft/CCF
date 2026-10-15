module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all Init.Prelude
import all Lean.Data.Name
-- `import all` keeps the statements as theorems rather than public axiom stubs.
import all CCFRaft.PropertiesTLA

public import CCFRaft.PropertiesTLA
public import Lean

@[expose] public section

namespace CCFRaft.Tests.ArchitectureTLA

open Lean

private def within (root name : Name) : Bool :=
  root.isPrefixOf name

/-- The TLA+ experiment depends only on the model and its own proofs. -/
private def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    !(`CCFRaft).isPrefixOf dependency
  else if !(`CCFRaft).isPrefixOf dependency then
    true
  else if within `CCFRaft.Model owner then
    within `CCFRaft.Model dependency
  else if within `CCFRaft.ProofTLA owner then
    within `CCFRaft.Model dependency || within `CCFRaft.ProofTLA dependency
  else if within `CCFRaft.PropertiesTLA owner then
    within `CCFRaft.Model dependency || within `CCFRaft.ProofTLA dependency
  else
    false

example : allowedImport `CCFRaft.PropertiesTLA `CCFRaft.ProofTLA.LogInv = true := rfl

example : allowedImport `CCFRaft.ProofTLA.Safety.Commit `CCFRaft.Model = true := rfl

example : allowedImport `CCFRaft.ProofTLA.LogInv `CCFRaft.Proof = false := rfl

example : allowedImport `CCFRaft.ProofTLA.LogInv `CCFRaft.Proofs.Safety = false := rfl

example : allowedImport `CCFRaft.ProofTLA.LogInv `CCFRaft.Properties = false := rfl

example : allowedImport `CCFRaft.PropertiesTLA `CCFRaft.Properties = false := rfl

example : allowedImport `CCFRaft.Model.Node `CCFRaft.ProofTLA.Config = false := rfl

example : allowedImport `CCFRaft.Proof `CCFRaft.ProofTLA = false := rfl

-- The statements and their proofs form a closure separate from other proof layers.
run_cmd do
  let header := (← getEnv).header
  for name in header.moduleNames do
    if within `CCFRaft name && !within `CCFRaft.Model name && !within `CCFRaft.ProofTLA name
        && !within `CCFRaft.PropertiesTLA name then
      throwError "TLA+ property closure includes {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden TLA+ property dependency: {owner} imports {dependency.module}"

-- Each statement is a theorem using only Lean's standard axioms.
run_cmd do
  let standard := [``propext, ``Classical.choice, ``Quot.sound]
  for root in [``CCFRaft.PropertiesTLA.spec_logInv,
      ``CCFRaft.PropertiesTLA.spec_committedLogAppendOnlyProp,
      ``CCFRaft.PropertiesTLA.spec_appendOnlyProp] do
    unless (← getEnv).find? root matches some (.thmInfo _) do
      throwError "Missing TLA+ property theorem: {root}"
    for axiom_ in ← Elab.Command.liftCoreM (collectAxioms root) do
      unless standard.contains axiom_ do
        throwError "{root} depends on nonstandard axiom {axiom_}"

end CCFRaft.Tests.ArchitectureTLA
