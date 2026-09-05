-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceProperties
import Lean.Util.CollectAxioms
import Lean.Elab.Command

namespace Kv.BuildAudit
open Lean Elab Command

def trustedAxioms : Array Name := #[``propext, ``Classical.choice, ``Quot.sound]

def mainGuarantees : Array Name := #[
  ``Kv.read_your_write,
  ``Kv.read_your_deletion,
  ``Kv.absent_read,
  ``Kv.staged_noninterference,
  ``Kv.previous_ignores_pending,
  ``Kv.publish_lookup,
  ``Kv.publication_noninterference,
  ``Kv.publish_unique,
  ``Kv.apply_atomic,
  ``Kv.transaction_snapshot_witness,
  ``Kv.transaction_application_serial_witness,
  ``Kv.branch_normal_serializability,
  ``Kv.executable_branch_serializability,
  ``Kv.replay_segment_serializability,
  ``Kv.reachable_store_invariants,
  ``Kv.reachable_store_data_invariants,
  ``Kv.step_capture_metadata,
  ``Kv.step_capture_cut_values,
  ``Kv.capture_replay_preserves_metadata,
  ``Kv.replay_snapshot_fixed,
  ``Kv.reachable_initial_frontier_safety,
  ``Kv.step_map_capture,
  ``Kv.replay_map_global_fixed,
  ``Kv.capture_replay_preserves_map,
  ``Kv.captureGlobal_placeholder,
  ``Kv.captureGlobal_committed,
  ``Kv.step_global_read_from_captured_map,
  ``Kv.step_global_has_from_captured_map,
  ``Kv.compact_above_head_noop,
  ``Kv.rollback_keeps_prefix,
  ``Kv.rollback_discards_suffix,
  ``Kv.durable_cut_survives_rollback,
  ``Kv.stale_term_cannot_apply,
  ``Kv.discarded_handle_cannot_apply,
  ``Kv.discarded_birth_cannot_apply,
  ``Kv.compacted_map_unavailable,
  ``Kv.absent_map_available,
  ``Kv.absent_placeholder_has_no_values,
  ``Kv.step_correspondence,
  ``Kv.replay_correspondence
]

def checkDependencies (root : Name) (dependencies : Array Name) : Except String Unit := do
  for dependency in dependencies do
    unless trustedAxioms.contains dependency do
      throw s!"{root}: forbidden proof dependency {dependency}"

def auditGuarantee (root : Name) : CommandElabM Unit := do
  match (← getEnv).checked.get.find? root with
  | some (.thmInfo _) => pure ()
  | _ => throwError "Guarantee {root} is not a kernel-checked theorem"
  let dependencies ← collectAxioms root
  match checkDependencies root dependencies with
  | .ok () => pure ()
  | .error message => throwError "{message}"

run_cmd do
  for root in mainGuarantees do
    auditGuarantee root

end Kv.BuildAudit
