module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all CCFRaft
import Mathlib.Util.GetAllModules

-- Include private test imports when checking the root's transitive coverage.
open Lean in
run_cmd do
  let modules := (← getEnv).header.moduleNames
  for name in ← getAllModulesSorted false "CCFRaft" do
    unless modules.contains name.toName do
      throwError "Module is not imported by CCFRaft: {name}"
