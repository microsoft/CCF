-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Lean
import Generated
import Shamir

/-!
Prints every declaration owned by the `Generated` and `Shamir` libraries, including private and
automatically generated ones, so that `scripts/check-shamir.sh` can export and kernel-check all of
them together with their dependencies.
-/

open Lean Elab Command in
run_cmd do
  let env ← getEnv
  let mut names : Array Name := #[]
  for owner in env.header.moduleNames, data in env.header.moduleData do
    if owner.getRoot == `Generated || owner.getRoot == `Shamir then
      names := names ++ data.constNames
  for required in [`ccf_shamir.reduce, `ccf_shamir.evaluate, `ccf_shamir.share_limb,
      `ccf_shamir.recover, `Shamir.Properties.reduction_is_remainder,
      `Shamir.Properties.sharing_refines_cslib, `Shamir.Properties.sharing_refines_cslib_witness,
      `Shamir.Properties.sharing_succeeds_iff, `Shamir.Properties.recovery_refines_cslib,
      `Shamir.Properties.recovery_refines_cslib_witness,
      `Shamir.Properties.recovery_returns_secret,
      `Shamir.Properties.recovery_returns_secret_witness,
      `Shamir.Properties.recovery_succeeds_iff,
      `Shamir.Properties.recovery_error_preserves_secret,
      `Shamir.Properties.recovery_error_preserves_secret_witness] do
    unless names.contains required do
      throwError "Missing project declaration: {required}"
  for declName in names.qsort Name.lt do
    IO.println declName
