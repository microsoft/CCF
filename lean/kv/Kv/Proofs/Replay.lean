-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.AdapterRetention

@[expose] public section

namespace Kv.Proofs.Trace

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation Kv.Properties Kv.Proofs.Capture Kv.Proofs.AdapterRetention

private theorem step_iff_transition (w next : World) (r : Record)
    : transitionSystem.step w r = some next ↔ step w r = .ok next := by
  simp only [transitionSystem]
  cases step w r <;> simp [Except.toOption]

/-- Snapshot metadata survives every accepted replay segment that retains its attempt. -/
theorem capture_replay_preserves_metadata_claim
    : ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        → transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some t
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run transitionSystem capturedWorld tail final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = term := by
  intro w capturedWorld final sid tid version global term seq s t tail source capture live segment run
  obtain ⟨snap, captured, current, snapshotTerm⟩ :=
    step_capture_metadata w capturedWorld sid tid version global term seq s t source
      ((step_iff_transition _ _ _).mp capture) live
  obtain ⟨after, finalLive, kept⟩ :=
    replay_kept capturedWorld final tid t tail live segment run
  exact ⟨after, snap, finalLive, kept.snapshot snap captured, current, snapshotTerm⟩

/-- A captured snapshot remains fixed through accepted replay. -/
theorem replay_snapshot_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run transitionSystem w rs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  intro w final tid before snap rs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := replay_kept w final tid before rs live segment run
  exact ⟨after, finalLive, kept.snapshot snap captured⟩

/-- Each map's captured global frame remains fixed through accepted replay. -/
theorem replay_map_global_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  intro w final tid before map view rs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := replay_kept w final tid before rs live segment run
  exact ⟨after, finalLive, (kept.maps map view captured).1⟩

/-- Acquired global frames and their reported cut versions survive accepted replay. -/
theorem capture_replay_preserves_map_claim
    : ∀ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        → txOf w sid tid = .ok before
        → before.snapshot = some snap
        → transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some capturedTx
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run transitionSystem capturedWorld tail final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  intro w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail
    store tx snapshot capture live segment run
  obtain ⟨view, localCut, globalCut⟩ :=
    step_map_capture w capturedWorld sid tid localVersion globalVersion seq map s before capturedTx
      snap store tx snapshot ((step_iff_transition _ _ _).mp capture) live
  obtain ⟨after, finalLive, kept⟩ :=
    replay_kept capturedWorld final tid capturedTx tail live segment run
  exact ⟨after, finalLive, (kept.maps map _ view).1, localCut, globalCut⟩

/-- A map's pinned local data remains fixed, including through other maps' lazy acquisitions. -/
theorem replay_map_local_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  intro w final tid before map view rs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := replay_kept w final tid before rs live segment run
  exact ⟨after, finalLive, (kept.maps map view captured).2⟩

end Kv.Proofs.Trace
