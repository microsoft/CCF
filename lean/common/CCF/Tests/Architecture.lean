-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

meta import CCF.Architecture

public import CCF.Architecture

public section

namespace CCF.Tests.Architecture

private def run : IO Unit := do
  let edges : List (Lean.Name × Lean.Name × Bool) :=
    [
      (`Model, `TraceValidation, false),
      (`Model.Types, `TraceValidation.Adapter, false),
      (`TraceValidation, `Model, true),
      (`TraceValidation.Adapter, `Model.Transitions, true),
      (`TraceValidation, `TraceValidation.Records, true),
      (`TraceValidation.Adapter, `TraceValidation, false),
      (`TraceValidation.Adapter, `Properties, false),
      (`TraceValidation.Adapter, `Properties.Programs, false),
      (`TraceValidation.Adapter, `Proofs.Correspondence, false),
      (`Properties, `TraceValidation, true),
      (`Properties.Programs, `TraceValidation.Adapter, true),
      (`Proofs.Correspondence, `TraceValidation.Adapter, true),
      (`Properties.Programs, `Proofs.Correspondence, false),
      (`Proofs.Correspondence, `Properties, false),
      (`Model.Types, `Model, false),
      (`Model, `Model.Types, true)
    ]
  for root in [`Kv, `Example.Nested] do
    for (owner, dependency, expected) in edges do
      unless CCF.Architecture.allowedImport root (root ++ owner) (root ++ dependency)
              == expected do
        throw
          (IO.userError
            s!"wrong architecture policy: {root ++ owner} -> {root ++ dependency}")
    for owner in [root ++ `Model.Types, root ++ `TraceValidation.Adapter] do
      for dependency in [`CCF, `CCF.Proofs.Execution] do
        if CCF.Architecture.allowedImport root owner dependency then
          throw (IO.userError s!"proof infrastructure admitted by {owner}")
    if CCF.Architecture.allowedImport root `CCF.Execution (root ++ `Model.Types) then
      throw (IO.userError "common infrastructure admitted a specification dependency")
  IO.println "shared architecture policy tests passed"

#eval run

end CCF.Tests.Architecture
