/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
import Lean
import Generated
import Shamir

open Lean Elab Command in
run_cmd do
  let env ← getEnv
  let names := env.constants.toList.filterMap fun (declName, _) => do
    let idx ← env.getModuleIdxFor? declName
    let owner := env.header.moduleNames[idx.toNat]!
    if owner.getRoot == `Generated || owner.getRoot == `Shamir then
      some declName
    else
      none
  for required in [`ccf_shamir.reduce, `ccf_shamir.evaluate, `ccf_shamir.share_limb,
      `ccf_shamir.recover, `CCF.Shamir.sharing_refines_cslib, `CCF.Shamir.recovery_refines_cslib,
      `CCF.Shamir.recovery_error_preserves_secret, `CCF.Shamir.recoveredLimb_eq_secret] do
    unless names.contains required do
      throwError "Missing project declaration: {required}"
  for declName in names.mergeSort Name.lt do
    IO.println declName
