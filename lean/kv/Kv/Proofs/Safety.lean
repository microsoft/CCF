-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Retention
public import Kv.Proofs.SemanticInvariant

@[expose] public section

namespace Kv.Proofs.Safety

open Kv.Model Kv.Properties Kv.Proofs.SemanticHelpers

private theorem snapshot_semantic {w next : Model.State} {sid tid : Nat}
    {s : Model.Store} {after : Model.Tx} {output : Output}
    (source : find w.stores sid = some s)
    (accepted : Model.execute w (.snapshot sid tid) = some (next, output))
    (live : find next.txs tid = some after)
    : after.snapshot = some { current := s.head, term := s.term }
      ∧ output = .snapshot s.head.version s.global s.term := by
  dsimp only [Model.execute] at accepted
  obtain ⟨⟨actualStore, before⟩, lookup, accepted⟩ := option_bind_ok accepted
  have store := (lookup_found lookup).1
  cases source.symm.trans store
  try dsimp only at accepted
  split at accepted
  · cases accepted
  · cases accepted
    simp only [find_set_same, Option.some.injEq] at live
    subst after
    exact ⟨rfl, rfl⟩

/-- Capturing a current snapshot computes the frozen head and commit term. -/
theorem step_capture_metadata
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (output : Output),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (next, output)
        → find next.txs tid = some t
        → ∃ snap,
            t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = s.term := by
  intro w next sid tid s t output source accepted live
  exact ⟨{ current := s.head, term := s.term },
    (snapshot_semantic source accepted live).1, rfl, rfl⟩

/-- Snapshot output contains the actual local/global cuts and commit term. -/
theorem step_capture_cut_values
    : ∀ (w next : State) (sid tid version global term : Nat) (s : Store),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (next, .snapshot version global term)
        → version = s.head.version ∧ global = s.global ∧ term = s.term := by
  intro w next sid tid version global term s source accepted
  dsimp only [execute] at accepted
  obtain ⟨⟨actual, t⟩, lookup, accepted⟩ := option_bind_ok accepted
  cases source.symm.trans (lookup_found lookup).1
  dsimp only at accepted
  split at accepted
  · cases accepted
  · cases accepted
    exact ⟨rfl, rfl, rfl⟩

/-- Semantic acquisition installs its selected local/global frames and computes their revisions. -/
theorem step_map_capture
    : ∀ (w next : State) (sid tid localVersion globalVersion : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        lookupTx w sid tid = some (s, before)
        → before.snapshot = some snap
        → execute w (.acquire sid tid map)
          = some (next, .acquired localVersion globalVersion)
        → find next.txs tid = some after
        → find after.globalViews map = some (captureGlobal s snap map)
          ∧ localVersion = (revision (captureLocal s snap map) map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  intro w next sid tid localVersion globalVersion map s before after snap source captured accepted live
  dsimp only [execute] at accepted
  rw [source] at accepted
  obtain ⟨_, selected, accepted⟩ := option_bind_ok accepted
  cases selected
  dsimp only at accepted
  obtain ⟨_, snapshot, accepted⟩ := option_bind_ok accepted
  cases captured.symm.trans snapshot
  try dsimp only at accepted
  split at accepted
  · cases accepted
  · split at accepted
    · cases accepted
      simp only [find_set_same, Option.some.injEq] at live
      subst after
      have current : (captureGlobal s snap map).current = captureLocal s snap map := by
        dsimp only [captureGlobal]
        split <;> rfl
      exact ⟨find_set_same _ _ _, congrArg (fun f => (revision f map).version) current, rfl⟩
    · cases accepted

/-- Every attempt-preserving semantic execution keeps an existing current snapshot fixed. -/
theorem execution_snapshot_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (snap : Snapshot)
        (inputs : List Action),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  intro w final tid before snap inputs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := Retention.run_retains w final tid before inputs live segment run
  exact ⟨after, finalLive, kept.snapshot snap captured⟩

/-- Every attempt-preserving semantic execution keeps already acquired global frames fixed. -/
theorem execution_map_global_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (inputs : List Action),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  intro w final tid before map view inputs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := Retention.run_retains w final tid before inputs live segment run
  exact ⟨after, finalLive, (kept.maps map view captured).1⟩

/-- Later acquisitions and publications cannot change an already acquired map's pinned local data. -/
theorem execution_map_local_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (inputs : List Action),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  intro w final tid before map view inputs live captured segment run
  obtain ⟨after, finalLive, kept⟩ := Retention.run_retains w final tid before inputs live segment run
  exact ⟨after, finalLive, (kept.maps map view captured).2⟩

/-- Metadata computed by capture survives the rest of an attempt-preserving semantic execution. -/
theorem capture_execution_preserves_metadata
    : ∀ (w captured final : State) (sid tid : Nat) (s : Store) (t : Tx)
        (output : Output) (inputs : List Action),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (captured, output)
        → find captured.txs tid = some t
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem captured inputs final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = s.term := by
  intro w captured final sid tid s t output inputs source capture live segment run
  obtain ⟨snap, pinned, current, term⟩ := step_capture_metadata w captured sid tid s t output source capture live
  obtain ⟨after, finalLive, same⟩ := execution_snapshot_fixed captured final tid t snap inputs live pinned segment run
  exact ⟨after, snap, finalLive, same, current, term⟩

/-- Acquired frames and computed revisions survive an attempt-preserving semantic execution. -/
theorem capture_execution_preserves_map
    : ∀ (w captured final : State) (sid tid localVersion globalVersion : Nat)
        (map : String) (s : Store) (before acquired : Tx) (snap : Snapshot)
        (inputs : List Action),
        lookupTx w sid tid = some (s, before)
        → before.snapshot = some snap
        → execute w (.acquire sid tid map)
          = some (captured, .acquired localVersion globalVersion)
        → find captured.txs tid = some acquired
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem captured inputs final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  intro w captured final sid tid localVersion globalVersion map s before acquired snap inputs
    source pinned capture live segment run
  obtain ⟨view, localCut, globalCut⟩ :=
    step_map_capture w captured sid tid localVersion globalVersion map s before acquired snap source pinned capture live
  obtain ⟨after, finalLive, same⟩ :=
    execution_map_global_fixed captured final tid acquired map _ inputs live view segment run
  exact ⟨after, finalLive, same, localCut, globalCut⟩

private theorem provenance (w : State) (sid tid : Nat) (s : Store) (t : Tx) (map : String)
    (view : GlobalView) (reachable : transitionSystem.Reachable w)
    (source : lookupTx w sid tid = some (s, t))
    (captured : find t.globalViews map = some view)
    : view.frame = {}
      ∨ ∃ origin : Store,
          view.frame = atCut origin origin.global
          ∧ view.frame.version = origin.global
          ∧ CellsBounded view.frame.data origin.global :=
  SemanticInvariant.semantic_global_provenance w tid t map view reachable
    (lookup_found source).2.1 captured

/-- Global read outputs are computed from the frozen map frame with committed-prefix provenance. -/
theorem step_global_read_from_captured_map
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (value : Option String) (view : GlobalView),
        transitionSystem.Reachable w
        → lookupTx w sid tid = some (s, t)
        → find t.globalViews map = some view
        → execute w (.operation sid tid (.get map key true)) = some (next, .value value)
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid s t map key value view reachable source captured accepted
  have origin := provenance w sid tid s t map view reachable source captured
  dsimp only [execute] at accepted
  rw [source] at accepted
  obtain ⟨_, selected, accepted⟩ := option_bind_ok accepted
  cases selected
  dsimp only at accepted
  split at accepted
  · cases accepted
  · have computed : executeOperation t (.get map key true) =
        (t, .value ((find view.frame.data (map, key)).map Cell.value)) := by
      simp [executeOperation, captured]
    rw [computed] at accepted
    cases accepted
    exact ⟨rfl, origin⟩

/-- Global presence outputs are computed from the frozen frame with committed-prefix provenance. -/
theorem step_global_has_from_captured_map
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (value : Bool) (view : GlobalView),
        transitionSystem.Reachable w
        → lookupTx w sid tid = some (s, t)
        → find t.globalViews map = some view
        → execute w (.operation sid tid (.has map key true))
          = some (next, .presence value)
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid s t map key value view reachable source captured accepted
  have origin := provenance w sid tid s t map view reachable source captured
  dsimp only [execute] at accepted
  rw [source] at accepted
  obtain ⟨_, selected, accepted⟩ := option_bind_ok accepted
  cases selected
  dsimp only at accepted
  split at accepted
  · cases accepted
  · have computed : executeOperation t (.has map key true) =
        (t, .presence (find view.frame.data (map, key)).isSome) := by
      simp [executeOperation, captured]
    rw [computed] at accepted
    cases accepted
    exact ⟨rfl, origin⟩

end Kv.Proofs.Safety
