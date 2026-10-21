module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

-- `import all` keeps exported proofs as theorems rather than public axiom stubs.
import all CCFRaft.Properties

public import Lean

@[expose] public section

namespace CCFRaft.Tests.ProofCoverage

open Lean

-- Properties are checked results, not unproved Prop definitions or axioms.
run_cmd do
  let env ← getEnv
  for name in #[
      `CCFRaft.Properties.election_safety,
      `CCFRaft.Properties.committed_logs_prefix,
      `CCFRaft.Properties.committed_frontier_is_signature,
      `CCFRaft.Properties.single_node_committed_log_monotonic
    ] do
    unless (env.find? name).any (fun info => info.isTheorem) do
      throwError "Missing safety theorem: {name}"
  for (name, info) in env.constants.toList do
    if name.getPrefix != `CCFRaft.Properties then continue
    match info with
    | .axiomInfo _ => throwError "Property is an axiom: {name}"
    | .thmInfo _ =>
        unless name.getString!.endsWith "_witness" do
          let witness := Name.str `CCFRaft.Properties (name.getString! ++ "_witness")
          unless (env.find? witness).any (fun info => info.isTheorem) do
            throwError "Property has no witness lemma: {name}"
    | _ =>
        if info.type == mkSort .zero then
          throwError "Property is an unproved Prop definition: {name}"

end CCFRaft.Tests.ProofCoverage
