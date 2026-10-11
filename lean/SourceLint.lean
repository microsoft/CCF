/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
module

import Mathlib.Init

public import Mathlib.Tactic.Linter.TextBased

import all Mathlib.Tactic.Linter.TextBased

public meta import Lean.Elab.Import
public meta import Lean.Util.Path

/-!
# Source and style checks for CCF Lean packages

Load Mathlib's linters only for this checking pass. In particular, the executable
models and standalone replayers do not acquire a dependency on Mathlib.
-/

open Lean

meta section

/-- The upstream standard syntax checks and CCF's existing license notice. -/
def sourceLintOptions : Array LeanOption :=
  #[
    ⟨`linter.mathlibStandardSet, true⟩,
    ⟨`linter.style.longFile, .ofNat 1500⟩,
    ⟨`linter.style.header.license, "Licensed under the Apache 2.0 License."⟩,
    ⟨`warningAsError, true⟩
  ]

/-- Prepare Lean's source-checking pass and run Mathlib's text and module-name checks. -/
def prepareSourceLint (fileName : String) (setupPath : System.FilePath) : IO UInt32 := do
  let input ← IO.FS.readFile fileName
  let setup ← ModuleSetup.load setupPath
  -- Lake leaves files outside its declared targets unnamed.
  let name ←
    if setup.name == `_unknown then
      moduleNameOfFileName fileName none
    else
      pure setup.name
  let (header, _, _) ← Parser.parseHeader (Parser.mkInputContext input fileName)
  let options := setup.options.appendArray sourceLintOptions
  let imports := setup.imports?.getD (Elab.headerToImports header)
  let imports :=
    if imports.any (·.module == `Mathlib.Init) then
      imports
    else
      imports.push { module := `Mathlib.Init }
  let setup := { setup with name, imports? := some imports, options }
  IO.FS.writeFile setupPath (toJson setup).compress
  let textOptions : Linter.LinterOptions :=
    { toOptions := options.toOptions, linterSets := {} }
  let (errors, _) ← Mathlib.Linter.TextBased.lintFile textOptions fileName #[]
  Mathlib.Linter.TextBased.formatErrors errors .humanReadable
  let mut nameErrors := 0
  if (System.FilePath.mk fileName).fileName != some "lakefile.lean" then
    nameErrors ←
      Mathlib.Linter.TextBased.modulesNotUpperCamelCase textOptions #[setup.name]
      <&> (· + nameErrors)
    nameErrors ←
      Mathlib.Linter.TextBased.modulesOSForbidden textOptions #[setup.name]
      <&> (· + nameErrors)
  return if errors.isEmpty && nameErrors == 0 then 0 else 1

/-- Prepare a temporary module setup and check text without changing the source. -/
public def main (args : List String) : IO UInt32 := do
  let [fileName, setupPath] := args
  | throw (IO.userError "usage: lean --run SourceLint.lean SOURCE MODULE-SETUP.json")
  prepareSourceLint fileName setupPath
