module

import Lake.CLI.Main
import Lake.Load.Workspace
import Lean.Util.Path

open Lake Lean

public section

/-- Check that the current package's library roots import all their source modules. -/
def main : IO Unit := do
  let (elanInstall?, leanInstall?, lakeInstall?) ← findInstall?
  let config ←
    MonadError.runEIO <| mkLoadConfig { elanInstall?, leanInstall?, lakeInstall? }
  let some workspace ← loadWorkspace config |>.toBaseIO
  | throw <| IO.userError "Failed to load the current Lake workspace"
  unless !workspace.root.leanLibs.isEmpty do
    throw <| IO.userError "The current package has no Lean libraries"
  initSearchPath (← findSysroot)
  for library in workspace.root.leanLibs do
    -- Private imports count too: tests need not be publicly reexported.
    let environment ←
      importModules
        (library.roots.map fun root => { module := root, importAll := true }) {}
    let importedModules := environment.header.moduleNames
    for root in library.roots do
      let directory := modToFilePath library.srcDir root ""
      if ← directory.isDir then
        forEachModuleInDir directory
          fun suffix => do
            let sourceModule := root ++ suffix
            unless importedModules.contains sourceModule do
              throw
              <| IO.userError s!"Module is not imported by {library.name}: {sourceModule}"
    IO.println s!"Import coverage passed: {library.name}"
