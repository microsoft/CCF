-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import Kv.Proofs.Execution
public import Kv.Proofs.Invariants

@[expose] public section

/-!
Non-vacuity witnesses for the claims in `Kv.Properties`. Trace claims are witnessed by prefixes
and segments of one accepted trace, evaluated by the kernel; store claims by directly
constructed stores; read and publication claims by small concrete association lists.
-/

namespace Kv.Proofs.Witnesses

open Kv.Model Kv.Properties Kv.Proofs.Invariants

private instance (sid : Nat) : DecidablePred (SegmentEvent sid) :=
  fun e => by
    cases e <;> unfold SegmentEvent <;> infer_instance

private instance (tid : Nat) : DecidablePred (AttemptEvent tid) :=
  fun e => by
    cases e <;> unfold AttemptEvent <;> infer_instance

/-- One attempt writes a key and commits; after compaction, a second reads it globally. -/
private def trace : List Record :=
  [
    ⟨1, .traceStart 1⟩,
    ⟨2, .caseBegin "witness"⟩,
    ⟨3, .storeCreate 1⟩,
    ⟨4, .txCreate 1 1⟩,
    ⟨5, .snapshot 1 1 0 0 0⟩,
    ⟨6, .acquire 1 1 "a" 0 0⟩,
    ⟨7, .put 1 1 "a" "00" "11"⟩,
    ⟨8, .commitBegin 1 1⟩,
    ⟨9, .apply 1 1 1 0 [(("a", "00"), some "11")]⟩,
    ⟨10, .commitResult 1 1 .success 1⟩,
    ⟨11, .txEnd 1 1⟩,
    ⟨12, .compact 1 1 1⟩,
    ⟨13, .txCreate 1 2⟩,
    ⟨14, .snapshot 1 2 1 1 0⟩,
    ⟨15, .acquire 1 2 "a" 1 1⟩,
    ⟨16, .get 1 2 "a" "00" (some "11") true⟩,
    ⟨17, .has 1 2 "a" "00" true true⟩
  ]

/-- The `n + 1`th record of `trace`. -/
private def record (n : Nat) : Record := trace.getD n ⟨0, .traceEnd 0⟩

/-- The world after the first `n` records of `trace`, defined step by step so the kernel
evaluates each prefix once; a rejected record would yield the empty world. -/
private def world : Nat → World
  | 0 => {}
  | n + 1 => ((step (world n) (record n)).toOption).getD {}

/-- The first `n` records of `trace` are accepted. -/
private def accepted : Nat → Bool
  | 0 => true
  | n + 1 => accepted n && (step (world n) (record n)).toOption.isSome

/-- Store `sid` of `world n`. -/
private def storeAt (n sid : Nat) : Store := (find (world n).stores sid).getD {}

/-- Attempt `tid` of `world n`. -/
private def txAt (n tid : Nat) : Tx := (find (world n).txs tid).getD { store := 0 }

/-- A store that has applied one write to map `a`. -/
private def written : Store := advance {} [(("a", "00"), some "11")]

private def writtenSnapshot : Snapshot := ⟨written.head, 0⟩

/-- An attempt that acquired map `a` in `writtenSnapshot`. -/
private def writtenTx : Tx :=
  {
    store := 1,
    snapshot := some writtenSnapshot,
    globalViews := [("a", captureGlobal written writtenSnapshot "a")]
  }

/-- The concrete facts the witnesses need, checked together by one kernel evaluation so that
each world and store is computed once. -/
private structure Facts : Prop where
  accepted : accepted 17 = true
  store3 : (find (world 3).stores 1).isSome = true
  segment3 : ∀ r ∈ (List.range' 3 9).map record, SegmentEvent 1 r.event
  store4 : (find (world 4).stores 1).isSome = true
  tx5 : (find (world 5).txs 1).isSome = true
  snapshot5 : (txAt 5 1).snapshot.isSome = true
  attempt5 : ∀ r ∈ (List.range' 5 5).map record, AttemptEvent 1 r.event
  tx7 : (find (world 7).txs 1).isSome = true
  snapshot7 : (txAt 7 1).snapshot.isSome = true
  log7 : (txAt 7 1).normal.log ≠ []
  store8 : (find (world 8).stores 1).isSome = true
  tx8 : (find (world 8).txs 1).isSome = true
  owner8 : (txAt 8 1).store = 1
  snapshot8 : (txAt 8 1).snapshot.isSome = true
  canApply8 : canApply (storeAt 8 1) (txAt 8 1) = true
  log8 : (txAt 8 1).normal.log ≠ []
  store12 : (find (world 12).stores 1).isSome = true
  cut12 : 1 ≤ (storeAt 12 1).global
  bound12 : (storeAt 12 1).global ≤ 1
  durable12 : (atCut (storeAt 12 1) 1).data ≠ []
  store13 : (find (world 13).stores 1).isSome = true
  store14 : (find (world 14).stores 1).isSome = true
  tx14 : (find (world 14).txs 2).isSome = true
  owner14 : (txAt 14 2).store = 1
  snapshot14 : (txAt 14 2).snapshot.isSome = true
  store15 : (find (world 15).stores 1).isSome = true
  tx15 : (find (world 15).txs 2).isSome = true
  owner15 : (txAt 15 2).store = 1
  view15 : (find (txAt 15 2).globalViews "a").isSome = true
  attempt15 : ∀ r ∈ (List.range' 15 2).map record, AttemptEvent 2 r.event
  store16 : (find (world 16).stores 1).isSome = true
  tx16 : (find (world 16).txs 2).isSome = true
  owner16 : (txAt 16 2).store = 1
  view16 : (find (txAt 16 2).globalViews "a").isSome = true
  captured : (find (captureLocal written writtenSnapshot "a").births "a").isSome = true
  compactedHead : (compactStore written 1).head.version ≤ (compactStore written 1).global
  compactedData : (compactStore written 1).head.data ≠ []
  writtenHead : 0 < written.head.version
  writtenGlobal : written.global ≤ 0
  discardedRevision
    : ∀ f ∈ (rollbackStore written 0 1).history,
        (revision f "a"
          == revision (captureGlobal written writtenSnapshot "a").current "a")
        = false
  discardedBirth
    : ∀ f ∈ (rollbackStore written 0 1).history,
        (find f.births "a"
          == find (captureGlobal written writtenSnapshot "a").current.births "a")
        = false
  birth : (find written.head.births "a").isSome = true
  compacted
    : (revision written.head "a").version
      < (revision
          (atCut (compactStore (advance written [(("a", "00"), some "22")]) 2)
            (compactStore (advance written [(("a", "00"), some "22")]) 2).global)
          "a").version

/-- A single Boolean check implying every hypothesis `A` of a curried constructor
`A → ... → R`. -/
private class Checks (F R : Prop) where
  /-- Every hypothesis holds. -/
  check : Bool
  /-- A passing check discharges every hypothesis. -/
  sound : check = true → F → R

private instance (R : Prop) : Checks R R := ⟨true, fun _ mk => mk⟩

private instance (A F R : Prop) [Decidable A] [rest : Checks F R] : Checks (A → F) R where
  check := decide A && rest.check
  sound h mk :=
    have h := Bool.and_eq_true_iff.mp h
    rest.sound h.2 (mk (of_decide_eq_true h.1))

private theorem facts : Facts := Checks.sound (by decide +kernel) Facts.mk

private theorem accepted_le {m n : Nat} (le : m ≤ n) (h : accepted n = true)
    : accepted m = true := by
  induction le with
  | refl => exact h
  | step _ ih =>
      simp only [accepted, Bool.and_eq_true] at h
      exact ih h.1

private theorem step_world {n : Nat} (all : accepted 17 = true) (lt : n < 17)
    : transitionSystem.step (world n) (record n) = some (world (n + 1)) := by
  have h := accepted_le lt all
  simp only [accepted, Bool.and_eq_true] at h
  simp only [transitionSystem, world]
  cases hs : step (world n) (record n) with
  | error => simp [hs, Except.toOption] at h
  | ok => rfl

private theorem world_reachable {n : Nat} (all : accepted 17 = true) (le : n ≤ 17)
    : transitionSystem.Reachable (world n) := by
  induction n with
  | zero => exact .initial rfl
  | succ n ih => exact .step (ih (Nat.le_of_succ_le le)) (step_world all le)

private theorem run_world {i k : Nat} (all : accepted 17 = true) (le : i + k ≤ 17)
    : CCF.Execution.Run transitionSystem (world i) ((List.range' i k).map record)
        (world (i + k)) := by
  induction k generalizing i with
  | zero => exact .nil _
  | succ k ih =>
      rw [show i + (k + 1) = i + 1 + k by omega]
      exact .cons (step_world all (by omega)) (ih (by omega))

private theorem some_get {α : Type} {o : Option α} (h : o.isSome = true)
    : o = some (o.get h) :=
  (Option.some_get h).symm

private theorem find_store {n sid : Nat} (h : (find (world n).stores sid).isSome = true)
    : find (world n).stores sid = some (storeAt n sid) := by
  unfold storeAt
  cases found : find (world n).stores sid with
  | none => simp [found] at h
  | some => rfl

private theorem find_tx {n tid : Nat} (h : (find (world n).txs tid).isSome = true)
    : find (world n).txs tid = some (txAt n tid) := by
  unfold txAt
  cases found : find (world n).txs tid with
  | none => simp [found] at h
  | some => rfl

private theorem storeOf_world {n sid : Nat}
    (h : (find (world n).stores sid).isSome = true)
    : storeOf (world n) sid = .ok (storeAt n sid) := by
  simp only [storeOf, find_store h, present]

private theorem txOf_world {n sid tid : Nat}
    (store : (find (world n).stores sid).isSome = true)
    (tx : (find (world n).txs tid).isSome = true) (owner : (txAt n tid).store = sid)
    : txOf (world n) sid tid = .ok (txAt n tid) := by
  simp [txOf, storeOf_world store, find_tx tx, present, require, owner, bind, Except.bind]
  rfl

private theorem written_valid : StoreInvariant written :=
  advance_invariant {} store_initial _

private def committedCell : DB String String String := [(("a", "00"), ⟨"11", 1⟩)]

lemma read_your_write_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String) (v : String),
        valueAt db ws a ≠ some v :=
  ⟨committedCell, [], ("a", "00"), "22", by decide⟩

lemma read_your_deletion_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        valueAt db ws a ≠ none :=
  ⟨committedCell, [], ("a", "00"), by decide⟩

lemma previous_ignores_pending_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        previousAt db a ≠ none ∧ find ws a ≠ none :=
  ⟨committedCell, [(("a", "00"), some "22")], ("a", "00"), by decide, by decide⟩

lemma publish_lookup_witness
    : ∃ (ws : Writes String String String) (kept removed written : Addr String String)
        (v : String),
        find ws kept = none
        ∧ find ws removed = some none
        ∧ find ws written = some (some v) :=
  ⟨
    [(("a", "01"), none), (("a", "02"), some "22")],
    ("a", "00"),
    ("a", "01"),
    ("a", "02"),
    "22",
    by decide,
    by decide,
    by decide
  ⟩

lemma apply_atomic_witness
    : ∃ (writes : Pending) (a b : Addr String String),
        a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none :=
  ⟨
    [(("a", "00"), some "11"), (("b", "00"), none)],
    ("a", "00"),
    ("b", "00"),
    by decide,
    by decide,
    by decide
  ⟩

lemma absent_read_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        find ws a = none ∧ find db a = none :=
  ⟨[], [], ("a", "00"), rfl, rfl⟩

lemma staged_noninterference_witness : ∃ a b : Addr String String, a ≠ b :=
  ⟨("a", "00"), ("a", "01"), by decide⟩

lemma publication_noninterference_witness
    : ∃ (ws : Writes String String String) (a : Addr String String), find ws a = none :=
  ⟨[], ("a", "00"), rfl⟩

lemma publish_unique_witness : ∃ db : DB String String String, Unique db :=
  ⟨[], List.nodup_nil⟩

lemma transaction_snapshot_serial_witness
    : ∃ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] :=
  ⟨
    world 7,
    1,
    txAt 7 1,
    _,
    world_reachable facts.accepted (by decide),
    find_tx facts.tx7,
    some_get facts.snapshot7,
    facts.log7
  ⟩

lemma transaction_application_serial_witness
    : ∃ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok t
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] :=
  ⟨
    world 8,
    1,
    1,
    storeAt 8 1,
    txAt 8 1,
    _,
    world_reachable facts.accepted (by decide),
    storeOf_world facts.store8,
    txOf_world facts.store8 facts.tx8 facts.owner8,
    some_get facts.snapshot8,
    facts.canApply8,
    facts.log8
  ⟩

lemma executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ AppliedBranch s ts final
        ∧ ts ≠ [] :=
  ⟨
    storeAt 8 1,
    advance (storeAt 8 1) (txAt 8 1).normal.writes,
    [txAt 8 1],
    List.forall_mem_singleton.mpr
      ⟨world 8, 1, world_reachable facts.accepted (by decide), find_tx facts.tx8⟩,
    .cons _ _ _ _ _ (by simp [tryApply, facts.canApply8]) (.nil _),
    List.cons_ne_nil _ _
  ⟩

lemma replay_segment_serializability_witness
    : ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 3,
    _,
    1,
    _,
    (List.range' 3 9).map record,
    world_reachable facts.accepted (by decide),
    find_store facts.store3,
    facts.segment3,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

private theorem reachable_live_store
    : ∃ (w : World) (sid : Nat) (s : Store),
        transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  ⟨world 12, 1, _, world_reachable facts.accepted (by decide), find_store facts.store12⟩

lemma reachable_store_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  reachable_live_store

lemma reachable_store_data_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  reachable_live_store

lemma step_capture_metadata_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        ∧ find next.txs tid = some t :=
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
    storeOf_world facts.store13,
    step_world facts.accepted (by decide),
    find_tx facts.tx14
  ⟩

lemma step_capture_cut_values_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next :=
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
    storeOf_world facts.store13,
    step_world facts.accepted (by decide)
  ⟩

lemma capture_replay_preserves_metadata_witness
    : ∃ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some t
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] :=
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
    (List.range' 5 5).map record,
    storeOf_world facts.store4,
    step_world facts.accepted (by decide),
    find_tx facts.tx5,
    facts.attempt5,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

lemma replay_snapshot_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 5,
    _,
    1,
    _,
    _,
    (List.range' 5 5).map record,
    find_tx facts.tx5,
    some_get facts.snapshot5,
    facts.attempt5,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

lemma step_map_capture_witness
    : ∃ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        ∧ find next.txs tid = some after :=
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
    storeOf_world facts.store14,
    txOf_world facts.store14 facts.tx14 facts.owner14,
    some_get facts.snapshot14,
    step_world facts.accepted (by decide),
    find_tx facts.tx15
  ⟩

lemma replay_map_global_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 15,
    _,
    2,
    _,
    "a",
    _,
    (List.range' 15 2).map record,
    find_tx facts.tx15,
    some_get facts.view15,
    facts.attempt15,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

lemma capture_replay_preserves_map_witness
    : ∃ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some capturedTx
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] :=
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
    (List.range' 15 2).map record,
    storeOf_world facts.store14,
    txOf_world facts.store14 facts.tx14 facts.owner14,
    some_get facts.snapshot14,
    step_world facts.accepted (by decide),
    find_tx facts.tx15,
    facts.attempt15,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

lemma captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none :=
  ⟨{}, ⟨{}, 0⟩, "a", rfl⟩

lemma captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth :=
  ⟨written, writtenSnapshot, "a", _, some_get facts.captured⟩

lemma step_global_read_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .get sid tid map key (some value) true⟩
          = some next :=
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
    world_reachable facts.accepted (by decide),
    txOf_world facts.store15 facts.tx15 facts.owner15,
    some_get facts.view15,
    step_world facts.accepted (by decide)
  ⟩

lemma step_global_has_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩
          = some next :=
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
    world_reachable facts.accepted (by decide),
    txOf_world facts.store16 facts.tx16 facts.owner16,
    some_get facts.view16,
    step_world facts.accepted (by decide)
  ⟩

lemma compact_above_head_noop_witness : ∃ (s : Store) (v : Nat), s.head.version < v :=
  ⟨{}, 1, Nat.zero_lt_one⟩

lemma rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] :=
  ⟨
    compactStore written 1,
    _,
    List.mem_of_mem_head? (compact_invariant written written_valid 1).headFirst,
    facts.compactedHead,
    facts.compactedData
  ⟩

lemma rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame), f ∈ s.history ∧ v < f.version ∧ s.global ≤ v :=
  ⟨
    written,
    0,
    _,
    List.mem_of_mem_head? written_valid.headFirst,
    facts.writtenHead,
    facts.writtenGlobal
  ⟩

lemma durable_cut_survives_rollback_witness
    : ∃ (w : World) (sid : Nat) (s : Store) (v cut : Nat),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] :=
  ⟨
    world 12,
    1,
    storeAt 12 1,
    1,
    1,
    world_reachable facts.accepted (by decide),
    find_store facts.store12,
    facts.cut12,
    facts.bound12,
    facts.durable12
  ⟩

lemma stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term :=
  ⟨{}, { store := 0, snapshot := some ⟨{}, 1⟩ }, _, rfl, by decide⟩

lemma discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    facts.discardedRevision
  ⟩

lemma discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    facts.discardedBirth
  ⟩

lemma compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version :=
  ⟨
    compactStore (advance written [(("a", "00"), some "22")]) 2,
    written.head,
    "a",
    _,
    some_get facts.birth,
    facts.compacted
  ⟩

lemma absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none :=
  ⟨{}, "a", rfl, rfl, rfl⟩

lemma absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true :=
  ⟨{}, {}, "a", rfl, rfl⟩

end Kv.Proofs.Witnesses
