-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proof

set_option autoImplicit false

/-!
Print the kernel dependency closure of the public safety proofs, restricted to
the invariant namespace. Run from the package directory:

    lake env lean scripts/invariant-dependencies.lean

The output identifies proof declarations needed by the public claims. Source
tactics can also refer to a declaration that disappears during elaboration, so
rebuild after removing declarations absent from this report.
-/

open Lean in
run_cmd do
  let env ← getEnv
  let mut pending := env.constants.fold (init := #[]) fun names name info =>
    if (`CCFRaft.Proof).isPrefixOf name && info.isTheorem then names.push name else names
  let mut seen : NameSet := {}
  while !pending.isEmpty do
    let name := pending.back!
    pending := pending.pop
    if seen.contains name then continue
    seen := seen.insert name
    let some info := env.find? name | continue
    let expressions :=
      match info with
      | .defnInfo value => #[value.type, value.value]
      | .thmInfo value => #[value.type, value.value]
      | .opaqueInfo value => #[value.type, value.value]
      | _ => #[info.type]
    if let .inductInfo value := info then
      pending := pending ++ value.ctors.toArray
    for expression in expressions do
      pending := pending ++ expression.getUsedConstants
  for name in seen.toArray.qsort Name.lt do
    if (name.toString.splitOn "CCFRaft.Proofs.Invariant.").length > 1 then
      liftM <| IO.println name
