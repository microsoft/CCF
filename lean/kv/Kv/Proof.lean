-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties
public import Kv.Proofs.Execution
public import Kv.Proofs.Trace
public import Kv.Proofs.Witnesses

@[expose] public section

/-! Every claim in `Kv.Properties`, proved by the implementations in `Kv.Proofs`. -/

namespace Kv.Proof

theorem read_your_write : Properties.ReadYourWrite := by
  intro M K V _ _ db ws a v
  exact Proofs.Model.read_your_write db ws a v

theorem read_your_deletion : Properties.ReadYourDeletion := by
  intro M K V _ _ db ws a
  exact Proofs.Model.read_your_deletion db ws a

theorem absent_read : Properties.AbsentRead := by
  intro M K V _ _ db ws a hw hd
  exact Proofs.Model.absent_read db ws a hw hd

theorem absent_read_witness : Properties.AbsentReadWitness :=
  Proofs.Witnesses.absent_read_witness

theorem staged_noninterference : Properties.StagedNoninterference := by
  intro M K V _ _ db ws a b v h
  exact Proofs.Model.staged_noninterference db ws a b v h

theorem staged_noninterference_witness : Properties.StagedNoninterferenceWitness :=
  Proofs.Witnesses.staged_noninterference_witness

theorem previous_ignores_pending : Properties.PreviousIgnoresPending := by
  intro M K V _ _ db a
  exact Proofs.Model.previous_ignores_pending db a

theorem publish_lookup : Properties.PublishLookup := by
  intro M K V _ _ db version ws a
  exact Proofs.Model.publish_lookup db version ws a

theorem publication_noninterference : Properties.PublicationNoninterference := by
  intro M K V _ _ db version ws a h
  exact Proofs.Model.publication_noninterference db version ws a h

theorem publication_noninterference_witness
    : Properties.PublicationNoninterferenceWitness :=
  Proofs.Witnesses.publication_noninterference_witness

theorem publish_unique : Properties.PublishUnique := by
  intro M K V _ _ db version ws h
  exact Proofs.Model.publish_unique db version ws h

theorem publish_unique_witness : Properties.PublishUniqueWitness :=
  Proofs.Witnesses.publish_unique_witness

theorem apply_atomic : Properties.ApplyAtomic := by
  intro s writes
  exact Proofs.Model.apply_atomic s writes

theorem transaction_snapshot_serial : Properties.TransactionSnapshotSerial := by
  intro t snap hs
  exact Proofs.Model.transaction_snapshot_serial t snap hs

theorem transaction_snapshot_serial_witness
    : Properties.TransactionSnapshotSerialWitness :=
  Proofs.Witnesses.transaction_snapshot_serial_witness

theorem transaction_application_serial : Properties.TransactionApplicationSerial := by
  intro s t snap hs hv
  exact Proofs.Model.transaction_application_serial s t snap hs hv

theorem transaction_application_serial_witness
    : Properties.TransactionApplicationSerialWitness :=
  Proofs.Witnesses.transaction_application_serial_witness

theorem executable_branch_serializability
    : Properties.ExecutableBranchSerializability := by
  intro s final ts h
  exact Proofs.Model.executable_branch_serializability s final ts h

theorem executable_branch_serializability_witness
    : Properties.ExecutableBranchSerializabilityWitness :=
  Proofs.Witnesses.executable_branch_serializability_witness

theorem replay_segment_serializability : Properties.ReplaySegmentSerializability := by
  intro w final sid s rs live segment accepted
  exact Proofs.Trace.replay_segment_serializability w final sid s rs live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_segment_serializability_witness
    : Properties.ReplaySegmentSerializabilityWitness :=
  Proofs.Witnesses.replay_segment_serializability_witness

theorem reachable_store_invariants : Properties.ReachableStoreInvariants := by
  intro w sid s _reachable live
  exact Proofs.Trace.reachable_store_invariants w sid s live

theorem reachable_store_invariants_witness : Properties.ReachableStoreInvariantsWitness :=
  Proofs.Witnesses.reachable_store_invariants_witness

theorem reachable_store_data_invariants : Properties.ReachableStoreDataInvariants := by
  intro w sid s _reachable live
  exact Proofs.Trace.reachable_store_data_invariants w sid s live

theorem reachable_store_data_invariants_witness
    : Properties.ReachableStoreDataInvariantsWitness :=
  Proofs.Witnesses.reachable_store_data_invariants_witness

theorem step_capture_metadata : Properties.StepCaptureMetadata := by
  intro w next sid tid version global term seq s t source accepted capturedTx
  exact Proofs.Trace.step_capture_metadata w next sid tid version global term seq s t source ((Proofs.Execution.step_iff_transition _ _ _).mp accepted) capturedTx

theorem step_capture_metadata_witness : Properties.StepCaptureMetadataWitness :=
  Proofs.Witnesses.step_capture_metadata_witness

theorem step_capture_cut_values : Properties.StepCaptureCutValues := by
  intro w next sid tid version global term seq s source accepted
  exact Proofs.Trace.step_capture_cut_values w next sid tid version global term seq s source ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_capture_cut_values_witness : Properties.StepCaptureCutValuesWitness :=
  Proofs.Witnesses.step_capture_cut_values_witness

theorem capture_replay_preserves_metadata
    : Properties.CaptureReplayPreservesMetadata := by
  intro w capturedWorld final sid tid version global term seq s t tail source capture live segment accepted
  exact Proofs.Trace.capture_replay_preserves_metadata w capturedWorld final sid tid version global term seq s t tail source ((Proofs.Execution.step_iff_transition _ _ _).mp capture) live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem capture_replay_preserves_metadata_witness
    : Properties.CaptureReplayPreservesMetadataWitness :=
  Proofs.Witnesses.capture_replay_preserves_metadata_witness

theorem replay_snapshot_fixed : Properties.ReplaySnapshotFixed := by
  intro w final tid before snap rs live captured segment accepted
  exact Proofs.Trace.replay_snapshot_fixed w final tid before snap rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_snapshot_fixed_witness : Properties.ReplaySnapshotFixedWitness :=
  Proofs.Witnesses.replay_snapshot_fixed_witness

theorem step_map_capture : Properties.StepMapCapture := by
  intro w next sid tid localVersion globalVersion seq map s before after snap store tx snapshot accepted live
  exact Proofs.Trace.step_map_capture w next sid tid localVersion globalVersion seq map s before after snap store tx snapshot ((Proofs.Execution.step_iff_transition _ _ _).mp accepted) live

theorem step_map_capture_witness : Properties.StepMapCaptureWitness :=
  Proofs.Witnesses.step_map_capture_witness

theorem replay_map_global_fixed : Properties.ReplayMapGlobalFixed := by
  intro w final tid before map view rs live captured segment accepted
  exact Proofs.Trace.replay_map_global_fixed w final tid before map view rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_map_global_fixed_witness : Properties.ReplayMapGlobalFixedWitness :=
  Proofs.Witnesses.replay_map_global_fixed_witness

theorem capture_replay_preserves_map : Properties.CaptureReplayPreservesMap := by
  intro w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail store tx snapshot capture live segment accepted
  exact Proofs.Trace.capture_replay_preserves_map w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail store tx snapshot ((Proofs.Execution.step_iff_transition _ _ _).mp capture) live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem capture_replay_preserves_map_witness
    : Properties.CaptureReplayPreservesMapWitness :=
  Proofs.Witnesses.capture_replay_preserves_map_witness

theorem captureGlobal_placeholder : Properties.CaptureGlobalPlaceholder := by
  intro s snap map absent
  exact Proofs.Trace.captureGlobal_placeholder s snap map absent

theorem captureGlobal_placeholder_witness : Properties.CaptureGlobalPlaceholderWitness :=
  Proofs.Witnesses.captureGlobal_placeholder_witness

theorem captureGlobal_committed : Properties.CaptureGlobalCommitted := by
  intro s snap map birth existing
  exact Proofs.Trace.captureGlobal_committed s snap map birth existing

theorem captureGlobal_committed_witness : Properties.CaptureGlobalCommittedWitness :=
  Proofs.Witnesses.captureGlobal_committed_witness

theorem step_global_read_from_captured_map
    : Properties.StepGlobalReadFromCapturedMap := by
  intro w next sid tid seq map key value t view source captured accepted
  exact Proofs.Trace.step_global_read_from_captured_map w next sid tid seq map key value t view source captured ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_global_read_from_captured_map_witness
    : Properties.StepGlobalReadFromCapturedMapWitness :=
  Proofs.Witnesses.step_global_read_from_captured_map_witness

theorem step_global_has_from_captured_map : Properties.StepGlobalHasFromCapturedMap := by
  intro w next sid tid seq map key value t view source captured accepted
  exact Proofs.Trace.step_global_has_from_captured_map w next sid tid seq map key value t view source captured ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_global_has_from_captured_map_witness
    : Properties.StepGlobalHasFromCapturedMapWitness :=
  Proofs.Witnesses.step_global_has_from_captured_map_witness

theorem compact_above_head_noop : Properties.CompactAboveHeadNoop := by
  intro s v h
  exact Proofs.Model.compact_above_head_noop s v h

theorem compact_above_head_noop_witness : Properties.CompactAboveHeadNoopWitness :=
  Proofs.Witnesses.compact_above_head_noop_witness

theorem rollback_keeps_prefix : Properties.RollbackKeepsPrefix := by
  intro s v term f h hv
  exact Proofs.Model.rollback_keeps_prefix s v term f h hv

theorem rollback_keeps_prefix_witness : Properties.RollbackKeepsPrefixWitness :=
  Proofs.Witnesses.rollback_keeps_prefix_witness

theorem rollback_discards_suffix : Properties.RollbackDiscardsSuffix := by
  intro s v term f h boundary
  exact Proofs.Model.rollback_discards_suffix s v term f h boundary

theorem rollback_discards_suffix_witness : Properties.RollbackDiscardsSuffixWitness :=
  Proofs.Witnesses.rollback_discards_suffix_witness

theorem durable_cut_survives_rollback : Properties.DurableCutSurvivesRollback := by
  intro s v term cut hcut hboundary
  exact Proofs.Model.durable_cut_survives_rollback s v term cut hcut hboundary

theorem durable_cut_survives_rollback_witness
    : Properties.DurableCutSurvivesRollbackWitness :=
  Proofs.Witnesses.durable_cut_survives_rollback_witness

theorem stale_term_cannot_apply : Properties.StaleTermCannotApply := by
  intro s t snap hs ht
  exact Proofs.Model.stale_term_cannot_apply s t snap hs ht

theorem stale_term_cannot_apply_witness : Properties.StaleTermCannotApplyWitness :=
  Proofs.Witnesses.stale_term_cannot_apply_witness

theorem discarded_handle_cannot_apply : Properties.DiscardedHandleCannotApply := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_handle_cannot_apply s t snap hs m view hm gone

theorem discarded_handle_cannot_apply_witness
    : Properties.DiscardedHandleCannotApplyWitness :=
  Proofs.Witnesses.discarded_handle_cannot_apply_witness

theorem discarded_birth_cannot_apply : Properties.DiscardedBirthCannotApply := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_birth_cannot_apply s t snap hs m view hm gone

theorem discarded_birth_cannot_apply_witness
    : Properties.DiscardedBirthCannotApplyWitness :=
  Proofs.Witnesses.discarded_birth_cannot_apply_witness

theorem compacted_map_unavailable : Properties.CompactedMapUnavailable := by
  intro s f m birth existing h
  exact Proofs.Model.compacted_map_unavailable s f m birth existing h

theorem compacted_map_unavailable_witness : Properties.CompactedMapUnavailableWitness :=
  Proofs.Witnesses.compacted_map_unavailable_witness

theorem absent_map_available : Properties.AbsentMapAvailable := by
  intro s f m absent empty unwritten
  exact Proofs.Model.absent_map_available s f m absent empty unwritten

theorem absent_map_available_witness : Properties.AbsentMapAvailableWitness :=
  Proofs.Witnesses.absent_map_available_witness

theorem absent_placeholder_has_no_values : Properties.AbsentPlaceholderHasNoValues := by
  intro s f m key absent permitted
  exact Proofs.Model.absent_placeholder_has_no_values s f m key absent permitted

theorem absent_placeholder_has_no_values_witness
    : Properties.AbsentPlaceholderHasNoValuesWitness :=
  Proofs.Witnesses.absent_placeholder_has_no_values_witness

end Kv.Proof
