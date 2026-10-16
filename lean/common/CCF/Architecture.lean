module

public import Lean

@[expose] public section

namespace CCF.Architecture

/-!
Layering and proof-coverage checks shared by the protocol packages. A package with root
namespace `root` keeps its model in `root.Model`, its claims in `root.Properties`, their
theorems in `root.Proof`, and the proof implementations in `root.Proofs`. Packages run these
checks from a test module with `run_cmd`.
-/

open Lean

/-- Whether module `owner` may import `dependency`. Common modules must not depend on a
package, models depend only on common and model modules, and properties also on property
modules. Modules outside `root` are unrestricted. -/
def allowedImport (root owner dependency : Name) : Bool :=
  let model := root ++ `Model
  let properties := root ++ `Properties
  if (`CCF).isPrefixOf owner then
    (`CCF).isPrefixOf dependency || !root.isPrefixOf dependency
  else if !root.isPrefixOf dependency then
    true
  else if model.isPrefixOf owner then
    model.isPrefixOf dependency
  else if properties.isPrefixOf owner then
    model.isPrefixOf dependency || properties.isPrefixOf dependency
  else
    true

/-- Layering violations among the modules imported by `env`, which should import every
property module but no proof module: a forbidden import between imported modules, or an
imported `root.Proof` or `root.Proofs` module. -/
def layeringErrors (env : Environment) (root : Name) : Array String :=
  Id.run do
    let header := env.header
    let mut errors := #[]
    for name in header.moduleNames do
      if (root ++ `Proof).isPrefixOf name || (root ++ `Proofs).isPrefixOf name then
        errors := errors.push s!"Property definitions import proof module {name}"
    for (owner, data) in header.moduleNames.zip header.moduleData do
      for dependency in data.imports do
        unless allowedImport root owner dependency.module do
          errors :=
            errors.push
              s!"Forbidden model/property dependency: {owner} imports {dependency.module}"
    return errors

/-- Claims without an exported theorem. A claim is a `Prop` constant directly in
`root.Properties`; it is covered by a theorem directly in `root.Proof` whose type is the
claim. With `requireWitness`, each claim not ending in `Witness` also needs a
`...Witness` non-vacuity claim. -/
def coverageErrors (env : Environment) (root : Name) (requireWitness : Bool)
    : Array String :=
  Id.run do
    let properties := root ++ `Properties
    let proof := root ++ `Proof
    let declarations := env.constants.toList
    let mut errors := #[]
    for (name, info) in declarations do
      if name.getPrefix != properties || info.type != mkSort .zero then
        continue
      let covered :=
        declarations.any
          fun (proofName, proofInfo) =>
            proofName.getPrefix == proof
            && (match proofInfo with
                | .thmInfo theoremInfo => theoremInfo.type.isConstOf name
                | _ => false)
      unless covered do
        errors := errors.push s!"Property has no exported theorem: {name}"
      if requireWitness && !name.getString!.endsWith "Witness" then
        unless env.contains (Name.str properties (name.getString! ++ "Witness")) do
          errors := errors.push s!"Property has no non-vacuity claim: {name}"
    return errors

end CCF.Architecture
