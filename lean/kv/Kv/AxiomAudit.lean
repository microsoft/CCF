-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Properties
import Lean.Util.CollectAxioms
import Lean.Elab.Command

namespace Kv.BuildAudit
open Lean Elab Command

def trustedAxioms : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]

def mainGuarantees : Array Name := #[
  ``Kv.Properties.read_your_write,
  ``Kv.Properties.read_your_deletion,
  ``Kv.Properties.absent_read,
  ``Kv.Properties.staged_noninterference,
  ``Kv.Properties.previous_ignores_pending,
  ``Kv.Properties.publish_lookup,
  ``Kv.Properties.publication_noninterference,
  ``Kv.Properties.publish_unique,
  ``Kv.Properties.apply_atomic,
  ``Kv.Properties.transaction_snapshot_witness,
  ``Kv.Properties.transaction_application_serial_witness,
  ``Kv.Properties.branch_normal_serializability,
  ``Kv.Properties.executable_branch_serializability,
  ``Kv.Properties.replay_segment_serializability,
  ``Kv.Properties.reachable_store_invariants,
  ``Kv.Properties.reachable_store_data_invariants,
  ``Kv.Properties.step_capture_metadata,
  ``Kv.Properties.step_capture_cut_values,
  ``Kv.Properties.capture_replay_preserves_metadata,
  ``Kv.Properties.replay_snapshot_fixed,
  ``Kv.Properties.step_map_capture,
  ``Kv.Properties.replay_map_global_fixed,
  ``Kv.Properties.capture_replay_preserves_map,
  ``Kv.Properties.captureGlobal_placeholder,
  ``Kv.Properties.captureGlobal_committed,
  ``Kv.Properties.step_global_read_from_captured_map,
  ``Kv.Properties.step_global_has_from_captured_map,
  ``Kv.Properties.compact_above_head_noop,
  ``Kv.Properties.rollback_keeps_prefix,
  ``Kv.Properties.rollback_discards_suffix,
  ``Kv.Properties.durable_cut_survives_rollback,
  ``Kv.Properties.stale_term_cannot_apply,
  ``Kv.Properties.discarded_handle_cannot_apply,
  ``Kv.Properties.discarded_birth_cannot_apply,
  ``Kv.Properties.compacted_map_unavailable,
  ``Kv.Properties.absent_map_available,
  ``Kv.Properties.absent_placeholder_has_no_values
]

def checkDependencies (root : Name) (dependencies : Array Name) : Except String Unit := do
  for dependency in dependencies do
    unless trustedAxioms.contains dependency do
      throw s!"{root}: forbidden proof dependency {dependency}"

def auditDependencies (root : Name) : CommandElabM Unit := do
  let dependencies ← collectAxioms root
  match checkDependencies root dependencies with
  | .ok () => pure ()
  | .error message => throwError "{message}"

def auditGuarantee (root : Name) : CommandElabM Unit := do
  match (← getEnv).checked.get.find? root with
  | some (.thmInfo _) => pure ()
  | _ => throwError "Guarantee {root} is not a kernel-checked theorem"
  auditDependencies root

def auditLibrary : CommandElabM Unit := do
  unless mainGuarantees.toList.eraseDups.length == mainGuarantees.size do
    throwError "Duplicate guarantee in the audit catalogue"
  for root in mainGuarantees do
    auditGuarantee root
  for (name, info) in (← getEnv).constants.toList do
    if name.getPrefix == `Kv.Properties then
      if let .thmInfo _ := info then
        unless mainGuarantees.contains name do
          throwError "Public property {name} is missing from the audit catalogue"
    if (`Kv.Proofs).isPrefixOf name then
      auditDependencies name

end Kv.BuildAudit
