module

import all Init.Prelude
import all Lean.Data.Name

public import CCFRaft.Conjectures
public import Lean

@[expose] public section

namespace CCFRaft.Tests.Architecture

open Lean

example : Model.Node.NodeID = Nat := rfl

example : Model.Node.ReqID = Nat := rfl

example (config : Finset Model.Node.NodeID) (node : Model.Node.NodeID)
    (primary : config.min = (node : WithTop Model.Node.NodeID))
    : node ∈ config :=
  Finset.mem_of_min primary

example
    : Model.Node.Caps -> Model.Node.NodeID -> Model.Node.NodeState
      -> Model.Node.Event -> Model.Node.NodeEffect Model.Node.NodeState :=
  Model.Node.step

example : List Model.Node.Entry -> List Model.Node.Configuration :=
  Model.Node.configurationHistory

example (config other : Finset Model.Node.NodeID)
    : (Model.protocol config).step = (Model.protocol other).step :=
  rfl

example (nodes : List Model.Node.NodeID) (state : Model.State)
    : Not ((Model.transitionSystem ∅ nodes).init state) := by
  simp [Model.transitionSystem]

private def allowedImport (owner dependency : Name) : Bool :=
  if (`CCF).isPrefixOf owner then
    !(`CCFRaft).isPrefixOf dependency
  else if !(`CCFRaft).isPrefixOf dependency then
    true
  else if (`CCFRaft.Model).isPrefixOf owner && owner != `CCFRaft.Model then
    dependency != `CCFRaft.Model && (`CCFRaft.Model).isPrefixOf dependency
  else if owner == `CCFRaft.Model then
    (`CCFRaft.Model).isPrefixOf dependency
  else if (`CCFRaft.Conjectures).isPrefixOf owner then
    (`CCFRaft.Model).isPrefixOf dependency || (`CCFRaft.Conjectures).isPrefixOf dependency
  else
    true

example : allowedImport `CCFRaft.Conjectures `CCFRaft.Model = true := rfl

example : allowedImport `CCFRaft.Conjectures `CCF.Execution = true := rfl

example : allowedImport `CCFRaft.Conjectures `CCFRaft.Proofs.Model = false := rfl

example : allowedImport `CCFRaft.Conjectures `CCFRaft.Theorems = false := rfl

example : allowedImport `CCFRaft.Model.Node `CCFRaft.Conjectures = false := rfl

example : allowedImport `CCFRaft.Model.Node `CCFRaft.Model = false := rfl

example : allowedImport `CCFRaft.Model.ClusterConfig `CCFRaft.Model = false := rfl

example : allowedImport `CCF.MultiNodeTransitionSystem `CCFRaft.Model = false :=
  rfl

example : allowedImport `CCFRaft.Conjectures `CCFRaft = false := rfl

-- The model and conjectures must not depend on proofs or theorems.
run_cmd do
  let env ← getEnv
  let header := env.header
  for name in header.moduleNames do
    if (`CCFRaft.Shared).isPrefixOf name then
      throwError "Use ccf_common instead of package-local Shared module {name}"
    if (`CCFRaft.Proof).isPrefixOf name || (`CCFRaft.Proofs).isPrefixOf name ||
        (`CCFRaft.Theorems).isPrefixOf name then
      throwError "Model or conjecture definitions import proof or theorem module {name}"
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport owner dependency.module do
        throwError "Forbidden model/property dependency: {owner} imports {dependency.module}"

end CCFRaft.Tests.Architecture
