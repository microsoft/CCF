module

public import Lean

@[expose] public section

namespace CCF.Architecture

open Lean

/-- Check an import against the layers of the shared `CCF` modules: only the `CCF` entrypoint
and other `CCF.Proofs` modules can import `CCF.Proofs`. -/
def allowedCommonImport (owner dependency : Name) : Bool :=
  let proofs := `CCF.Proofs
  !(`CCF).isPrefixOf owner
  || owner == `CCF
  || proofs.isPrefixOf owner
  || !proofs.isPrefixOf dependency

/-- Check an import against the standard layers of the specification rooted at `root`. -/
def allowedImport (root owner dependency : Name) : Bool :=
  let model := root ++ `Model
  let properties := root ++ `Properties
  let proofs := root ++ `Proofs
  let validation := root ++ `TraceValidation
  let correspondence := root ++ `Correspondence
  if (`CCF).isPrefixOf owner then
    !root.isPrefixOf dependency
  else if !root.isPrefixOf dependency then
    -- The `CCF` entrypoint reexports `CCF.Proofs`, so models must import definitions directly.
    !((model.isPrefixOf owner || validation.isPrefixOf owner)
      && ((`CCF.Proofs).isPrefixOf dependency || dependency == `CCF))
  else if model.isPrefixOf owner then
    model.isPrefixOf dependency && (owner == model || dependency != model)
  else if validation.isPrefixOf owner then
    model.isPrefixOf dependency || validation.isPrefixOf dependency
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
    || validation.isPrefixOf dependency
  else if owner == correspondence then
    model.isPrefixOf dependency
    || validation.isPrefixOf dependency
    || (dependency != properties && properties.isPrefixOf dependency)
    || proofs.isPrefixOf dependency
  else
    true

/-- Safety import closure cannot reach trace validation or correspondence, even through proofs. -/
def safetyImportClosure (root owner : Name) (graph : List (Name × List Name)) : Bool :=
  let reachable :=
    (List.range graph.length).foldl
      (fun seen _ =>
        graph.foldl
          (fun reached (source, dependencies) =>
            if seen.contains source then
              dependencies.foldl
                (fun found dependency =>
                  if found.contains dependency then found else dependency :: found)
                reached
            else
              reached)
          seen)
      [owner]
  reachable.all
    fun dependency =>
      !(root ++ `TraceValidation).isPrefixOf dependency
      && !(root ++ `Correspondence).isPrefixOf dependency

/-- Reject forbidden imports in an environment, including private transitive imports. The
shared `CCF` root is checked only against the common layers. -/
def checkImports (root : Name) (environment : Environment) : Except String Unit := do
  let header := environment.header
  let graph :=
    (header.moduleNames.zip header.moduleData).toList.map
      fun (owner, data) => (owner, data.imports.toList.map (·.module))
  for (owner, data) in header.moduleNames.zip header.moduleData do
    for dependency in data.imports do
      unless allowedCommonImport owner dependency.module
              && (root == `CCF || allowedImport root owner dependency.module) do
        throw s!"Forbidden layer dependency: {owner} imports {dependency.module}"
    if (root ++ `Properties).isPrefixOf owner
        && !safetyImportClosure root owner graph then
      throw
        s!"Forbidden safety dependency: {owner} transitively imports trace validation or correspondence"

end CCF.Architecture
