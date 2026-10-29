module

public import Lean

@[expose] public section

namespace CCF.Architecture

open Lean

/-- Check an import against the standard layers of the specification rooted at `root`. -/
def allowedImport (root owner dependency : Name) : Bool :=
  let model := root ++ `Model
  let properties := root ++ `Properties
  let proofs := root ++ `Proofs
  if (`CCF).isPrefixOf owner then
    !root.isPrefixOf dependency
  else if !root.isPrefixOf dependency then
    true
  else if model.isPrefixOf owner then
    model.isPrefixOf dependency && (owner == model || dependency != model)
  else if owner == properties then
    model.isPrefixOf dependency
    || properties.isPrefixOf dependency
    || proofs.isPrefixOf dependency
  else if properties.isPrefixOf owner then
    model.isPrefixOf dependency
    || (dependency != properties && properties.isPrefixOf dependency)
  else if proofs.isPrefixOf owner then
    model.isPrefixOf dependency
    || proofs.isPrefixOf dependency
    || (dependency != properties && properties.isPrefixOf dependency)
  else
    true

/-- Reject forbidden imports in an environment, including private transitive imports. -/
def checkImports (root : Name) (environment : Environment) : Except String Unit := do
  let header := environment.header
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedImport root owner dependency.module do
        throw s!"Forbidden layer dependency: {owner} imports {dependency.module}"

end CCF.Architecture
