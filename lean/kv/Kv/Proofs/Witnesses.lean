-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties
public import Kv.Proofs.Execution

@[expose] public section

/-!
Non-vacuity witnesses for the claims in `Kv.Properties`. Trace claims are witnessed by prefixes
and segments of one accepted trace, evaluated by the kernel; store claims by directly
constructed stores.
-/

namespace Kv.Proofs.Witnesses

open Kv.Model Kv.Properties

private instance (sid : Nat) : DecidablePred (SegmentEvent sid) :=
  fun e => by
    cases e <;> unfold SegmentEvent <;> infer_instance

private instance (tid : Nat) : DecidablePred (AttemptEvent tid) :=
  fun e => by
    cases e <;> unfold AttemptEvent <;> infer_instance

/-- One attempt writes a key and commits; after compaction, a second reads it globally. -/
private def trace : List Record :=
  [
    .traceStart 1,
    .caseBegin "witness",
    .storeCreate 1,
    .txCreate 1 1,
    .snapshot 1 1 0 0 0,
    .acquire 1 1 "a" 0 0,
    .put 1 1 "a" "00" "11",
    .commitBegin 1 1,
    .apply 1 1 1 0 [(("a", "00"), some "11")],
    .commitResult 1 1 .success 1,
    .txEnd 1 1,
    .compact 1 1 1,
    .txCreate 1 2,
    .snapshot 1 2 1 1 0,
    .acquire 1 2 "a" 1 1,
    .get 1 2 "a" "00" (some "11") true,
    .has 1 2 "a" "00" true true
  ].mapIdx
    fun index event => ⟨index + 1, event⟩

/-- The world after the first `n` records of `trace`. -/
private def world (n : Nat) : World := ((replay {} (trace.take n)).toOption).getD {}

private def storeAt (n sid : Nat) : Store := (find (world n).stores sid).getD {}

private def txAt (n tid : Nat) : Tx := (find (world n).txs tid).getD { store := 0 }

/-- The `n + 1`th record of `trace`. -/
private def record (n : Nat) : Record := trace.getD n ⟨0, .traceEnd 0⟩

private theorem ok_get {ε α : Type} {e : Except ε α} (h : e.toOption.isSome = true)
    : e = .ok (e.toOption.get h) := by
  cases e with
  | error => simp [Except.toOption] at h
  | ok => rfl

private theorem some_get {α : Type} {o : Option α} (h : o.isSome = true)
    : o = some (o.get h) :=
  (Option.some_get h).symm

private theorem world_replay (n : Nat)
    (h : (replay {} (trace.take n)).toOption.isSome = true)
    : replay {} (trace.take n) = .ok (world n) := by
  unfold world
  cases hr : replay {} (trace.take n) with
  | error => simp [hr, Except.toOption] at h
  | ok => rfl

private theorem run_get {w : World} {rs : List Record}
    (h : (replay w rs).toOption.isSome = true)
    : CCF.Execution.Run transitionSystem w rs ((replay w rs).toOption.get h) :=
  (Execution.replay_iff_run _ _ _).mpr (ok_get h)

/-- A store that has applied one write to map `a`. -/
private def written : Store := advance {} [(("a", "00"), some "11")]

private def writtenSnapshot : Snapshot := ⟨written.head, 0, written, rfl⟩

/-- An attempt that acquired map `a` in `writtenSnapshot`. -/
private def writtenTx : Tx :=
  {
    store := 1,
    snapshot := some writtenSnapshot,
    globalViews := [("a", captureGlobal written writtenSnapshot "a")]
  }

theorem absent_read_witness : AbsentReadWitness := ⟨[], [], ("a", "00"), rfl, rfl⟩

theorem staged_noninterference_witness : StagedNoninterferenceWitness :=
  ⟨("a", "00"), ("a", "01"), by decide⟩

theorem publication_noninterference_witness : PublicationNoninterferenceWitness :=
  ⟨[], ("a", "00"), rfl⟩

theorem publish_unique_witness : PublishUniqueWitness := ⟨[], List.nodup_nil⟩

theorem transaction_snapshot_serial_witness : TransactionSnapshotSerialWitness :=
  ⟨txAt 7 1, _, some_get (by decide +kernel), by decide +kernel⟩

theorem transaction_application_serial_witness : TransactionApplicationSerialWitness :=
  ⟨
    storeAt 8 1,
    txAt 8 1,
    _,
    some_get (by decide +kernel),
    by decide +kernel,
    by decide +kernel
  ⟩

theorem executable_branch_serializability_witness
    : ExecutableBranchSerializabilityWitness := by
  have h : canApply (storeAt 8 1) (txAt 8 1) = true := by decide +kernel
  exact ⟨
    storeAt 8 1,
    advance (storeAt 8 1) (txAt 8 1).normal.writes,
    [txAt 8 1],
    .cons _ _ _ _ _ (by simp [tryApply, h]) (.nil _),
    List.cons_ne_nil _ _
  ⟩

theorem replay_segment_serializability_witness : ReplaySegmentSerializabilityWitness :=
  ⟨
    world 3,
    _,
    1,
    _,
    (trace.drop 3).take 9,
    some_get (by decide +kernel),
    by decide +kernel,
    run_get (by decide +kernel),
    List.ne_nil_of_length_pos (by decide +kernel)
  ⟩

private theorem reachable_live_store
    : ∃ (w : World) (sid : Nat) (s : Store),
        transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  ⟨
    world 12,
    1,
    _,
    (Execution.reachable_iff_replay _).mpr ⟨_, world_replay 12 (by decide +kernel)⟩,
    some_get (by decide +kernel)
  ⟩

theorem reachable_store_invariants_witness : ReachableStoreInvariantsWitness :=
  reachable_live_store

theorem reachable_store_data_invariants_witness : ReachableStoreDataInvariantsWitness :=
  reachable_live_store

theorem step_capture_metadata_witness : StepCaptureMetadataWitness :=
  ⟨
    world 13,
    _,
    1,
    2,
    1,
    1,
    0,
    14,
    _,
    _,
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel)
  ⟩

theorem step_capture_cut_values_witness : StepCaptureCutValuesWitness :=
  ⟨
    world 13,
    _,
    1,
    2,
    1,
    1,
    0,
    14,
    _,
    ok_get (by decide +kernel),
    some_get (by decide +kernel)
  ⟩

theorem capture_replay_preserves_metadata_witness
    : CaptureReplayPreservesMetadataWitness :=
  ⟨
    world 4,
    _,
    _,
    1,
    1,
    0,
    0,
    0,
    5,
    _,
    _,
    (trace.drop 5).take 5,
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    by decide +kernel,
    run_get (by decide +kernel),
    List.ne_nil_of_length_pos (by decide +kernel)
  ⟩

theorem replay_snapshot_fixed_witness : ReplaySnapshotFixedWitness :=
  ⟨
    world 5,
    _,
    1,
    _,
    _,
    (trace.drop 5).take 5,
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    by decide +kernel,
    run_get (by decide +kernel),
    List.ne_nil_of_length_pos (by decide +kernel)
  ⟩

theorem step_map_capture_witness : StepMapCaptureWitness :=
  ⟨
    world 14,
    _,
    1,
    2,
    1,
    1,
    15,
    "a",
    _,
    _,
    _,
    _,
    ok_get (by decide +kernel),
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel)
  ⟩

theorem replay_map_global_fixed_witness : ReplayMapGlobalFixedWitness :=
  ⟨
    world 15,
    _,
    2,
    _,
    "a",
    _,
    trace.drop 15,
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    by decide +kernel,
    run_get (by decide +kernel),
    List.ne_nil_of_length_pos (by decide +kernel)
  ⟩

theorem capture_replay_preserves_map_witness : CaptureReplayPreservesMapWitness :=
  ⟨
    world 14,
    _,
    _,
    1,
    2,
    1,
    1,
    15,
    "a",
    _,
    _,
    _,
    _,
    trace.drop 15,
    ok_get (by decide +kernel),
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel),
    by decide +kernel,
    run_get (by decide +kernel),
    List.ne_nil_of_length_pos (by decide +kernel)
  ⟩

theorem captureGlobal_placeholder_witness : CaptureGlobalPlaceholderWitness :=
  ⟨⟨{}, 0, {}, rfl⟩, "a", rfl⟩

theorem captureGlobal_committed_witness : CaptureGlobalCommittedWitness :=
  ⟨writtenSnapshot, "a", _, some_get (by decide +kernel)⟩

theorem step_global_read_from_captured_map_witness
    : StepGlobalReadFromCapturedMapWitness :=
  ⟨
    world 15,
    _,
    1,
    2,
    16,
    "a",
    "00",
    "11",
    _,
    _,
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel)
  ⟩

theorem step_global_has_from_captured_map_witness : StepGlobalHasFromCapturedMapWitness :=
  ⟨
    world 16,
    _,
    1,
    2,
    17,
    "a",
    "00",
    _,
    _,
    ok_get (by decide +kernel),
    some_get (by decide +kernel),
    some_get (by decide +kernel)
  ⟩

theorem compact_above_head_noop_witness : CompactAboveHeadNoopWitness :=
  ⟨{}, 1, Nat.zero_lt_one⟩

theorem rollback_keeps_prefix_witness : RollbackKeepsPrefixWitness :=
  ⟨
    compactStore written 1,
    _,
    List.mem_of_mem_head? (compactStore written 1).headFirst,
    by decide +kernel,
    by decide +kernel
  ⟩

theorem rollback_discards_suffix_witness : RollbackDiscardsSuffixWitness :=
  ⟨
    written,
    0,
    _,
    List.mem_of_mem_head? written.headFirst,
    by decide +kernel,
    by decide +kernel
  ⟩

theorem durable_cut_survives_rollback_witness : DurableCutSurvivesRollbackWitness :=
  ⟨compactStore written 1, 1, 1, by decide +kernel, by decide +kernel, by decide +kernel⟩

theorem stale_term_cannot_apply_witness : StaleTermCannotApplyWitness :=
  ⟨{}, { store := 0, snapshot := some ⟨{}, 1, {}, rfl⟩ }, _, rfl, by decide⟩

theorem discarded_handle_cannot_apply_witness : DiscardedHandleCannotApplyWitness :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    by decide +kernel
  ⟩

theorem discarded_birth_cannot_apply_witness : DiscardedBirthCannotApplyWitness :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    by decide +kernel
  ⟩

theorem compacted_map_unavailable_witness : CompactedMapUnavailableWitness :=
  ⟨
    compactStore (advance written [(("a", "00"), some "22")]) 2,
    written.head,
    "a",
    _,
    some_get (by decide +kernel),
    by decide +kernel
  ⟩

theorem absent_map_available_witness : AbsentMapAvailableWitness :=
  ⟨{}, "a", rfl, rfl, rfl⟩

theorem absent_placeholder_has_no_values_witness : AbsentPlaceholderHasNoValuesWitness :=
  ⟨{}, {}, "a", rfl, by decide +kernel⟩

end Kv.Proofs.Witnesses
