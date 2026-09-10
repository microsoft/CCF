-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Invariants
import Kv.Proofs.Model

/-! Supporting lemmas and proof implementations connecting accepted replay to its contracts. -/

namespace Kv.Proofs.Trace
open Kv.Proofs.Types Kv.Proofs.Model

theorem storeOf_ok (w : World) (sid : Nat) (s : Store) :
    storeOf w sid = .ok s ↔ find w.stores sid = some s := by
  cases h : find w.stores sid <;> simp [storeOf, present, invalid, h]

theorem unchanged_store_effect (w next : World) (sid : Nat) (s : Store) (e : Event)
    (hs : find w.stores sid = some s) (same : next.stores = w.stores)
    (noApply : projectedApplication w sid e = []) :
    ∃ after, find next.stores sid = some after ∧
      HeadEffect s after (projectedApplication w sid e) := by
  refine ⟨s, ?_, ?_⟩
  · simpa [same] using hs
  · rw [noApply]
    exact .stutter rfl rfl

theorem stable_update_store_effect (w next : World) (sid id : Nat) (s old new : Store)
    (hs : find w.stores sid = some s) (hold : find w.stores id = some old)
    (same : next.stores = set w.stores id new) (head : new.head = old.head) :
    ∃ after, find next.stores sid = some after ∧
      HeadEffect s after [] := by
  by_cases h : id = sid
  · subst id
    have ho : old = s := Option.some.inj (hold.symm.trans hs)
    subst old
    exact ⟨new, by simp [same, find_set_same], .stutter (congrArg Frame.data head)
      (congrArg Frame.version head)⟩
  · exact ⟨s, by simpa [same, find_set_other _ id sid new h] using hs, .stutter rfl rfl⟩

theorem applied_update_store_effect (w next : World) (sid id tid : Nat)
    (s old new : Store) (t : Tx)
    (hs : find w.stores sid = some s) (hold : storeOf w id = .ok old)
    (htx : txOf w id tid = .ok t) (ha : tryApply old t = some new)
    (same : next.stores = set w.stores id new) :
    ∃ after, find next.stores sid = some after ∧
      HeadEffect s after (if id = sid then (txOf w id tid).toOption.toList else []) := by
  have hf := (storeOf_ok w id old).mp hold
  by_cases h : id = sid
  · subst id
    have ho : old = s := Option.some.inj (hf.symm.trans hs)
    subst old
    refine ⟨new, by simp [same, find_set_same], ?_⟩
    simpa [htx, Except.toOption, Option.toList] using HeadEffect.apply t ha
  · refine ⟨s, by simpa [same, find_set_other _ id sid new h] using hs, ?_⟩
    simpa [h] using HeadEffect.stutter (before := s) rfl rfl

theorem snapshot_store_effect (w next : World) (sid : Nat) (s : Store)
    (id tid version global term : Nat) (hs : find w.stores sid = some s)
    (accepted : stepEvent w (.snapshot id tid version global term) = .ok next) :
    ∃ after, find next.stores sid = some after ∧ HeadEffect s after [] := by
  simp only [stepEvent, Bind.bind, Pure.pure, Except.bind, Except.pure] at accepted
  cases ho : storeOf w id with
  | error err => simp [ho] at accepted
  | ok old =>
    simp only [ho] at accepted
    have same := withTx_preserves_stores _ next id tid _ accepted
    apply stable_update_store_effect w next sid id s old _ hs
      ((storeOf_ok w id old).mp ho) same
    split <;> rfl

theorem stepEvent_store_effect (w next : World) (sid : Nat) (s : Store) (e : Event)
    (hs : find w.stores sid = some s) (segment : SegmentEvent sid e)
    (accepted : stepEvent w e = .ok next) :
    ∃ after, find next.stores sid = some after ∧
      HeadEffect s after (projectedApplication w sid e) := by
  cases e <;> first
    | exact unchanged_store_effect w next sid s _ hs
        (withTx_preserves_stores w next _ _ _ accepted) rfl
    | exact snapshot_store_effect w next sid s _ _ _ _ _ hs accepted
    | skip
  all_goals simp only [stepEvent, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  all_goals simp only [SegmentEvent] at segment
  all_goals repeat' first
    | contradiction
    | exact unchanged_store_effect w next sid s _ hs
        (withTx_preserves_stores w next _ _ _ accepted) rfl
    | exact ⟨s, hs, .stutter rfl rfl⟩
    | exact ⟨s, by simpa [find_set_other, find_erase_other, segment] using hs, .stutter rfl rfl⟩
    | cases accepted
    | split at accepted
  all_goals first
    | exact stable_update_store_effect w _ sid _ s _ _ hs
        ((storeOf_ok _ _ _).mp (by assumption)) rfl (compact_preserves_head _ _)
    | exact applied_update_store_effect w _ sid _ _ s _ _ _ hs
        (by assumption) (by assumption) (by assumption) rfl

theorem step_event_result (w next : World) (r : Record)
    (accepted : step w r = .ok next) :
    ∃ eventNext, stepEvent w r.event = .ok eventNext ∧
      next.stores = eventNext.stores ∧ next.txs = eventNext.txs := by
  simp only [step, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, invalid] at accepted
  repeat' first
    | contradiction
    | exact ⟨_, by assumption, rfl, rfl⟩
    | cases accepted
    | split at accepted
  all_goals
    rename_i eventNext he
    exact ⟨eventNext, he, rfl, rfl⟩

theorem step_store_effect (w next : World) (sid : Nat) (s : Store) (r : Record)
    (hs : find w.stores sid = some s) (segment : SegmentEvent sid r.event)
    (accepted : step w r = .ok next) :
    ∃ after, find next.stores sid = some after ∧
      HeadEffect s after (projectedApplication w sid r.event) := by
  obtain ⟨eventNext, he, stores, _⟩ := step_event_result w next r accepted
  obtain ⟨after, found, effect⟩ := stepEvent_store_effect w eventNext sid s r.event hs segment he
  exact ⟨after, by simpa [stores] using found, effect⟩

theorem HeadEffect.serial_witness (before after : Store) (txs : List Tx)
    (effect : HeadEffect before after txs) :
    serialTransactions before.head.data before.head.version txs = some after.head.data ∧
      after.head.version = before.head.version + txs.length := by
  cases effect with
  | stutter data version => simp [serialTransactions, data, version]
  | apply tx one =>
    have h := tryApply_serial_witness before after tx one
    constructor
    · simpa [serialTransactions, h.1] using congrArg some h.2.symm
    · unfold tryApply at one
      split at one
      next => cases one; rfl
      next => simp at one

theorem serialTransactions_append (db : Data) (version : Nat) (xs ys : List Tx) :
    serialTransactions db version (xs ++ ys) =
      (serialTransactions db version xs).bind
        (fun next => serialTransactions next (version + xs.length) ys) := by
  induction xs generalizing db version with
  | nil => rfl
  | cons tx xs ih =>
    cases h : serialRun db [] tx.normal.log with
    | none => simp [serialTransactions, h]
    | some writes =>
      simp [serialTransactions, h, ih, Nat.add_comm, Nat.add_left_comm]

/-- A selected store stays live throughout the segment. Its rollback/create/end
events partition segments; all other-store events are permitted. The projected
attempts are obtained from the real pre-event txOf, not supplied as a premise. -/
theorem replay_segment_serializability (w final : World) (sid : Nat) (s : Store)
    (rs : List Record) (live : find w.stores sid = some s)
    (segment : ∀ r ∈ rs, SegmentEvent sid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after txs, find final.stores sid = some after ∧
      projectApplications w sid rs = .ok txs ∧
      serialTransactions s.head.data s.head.version txs = some after.head.data ∧
      after.head.version = s.head.version + txs.length := by
  induction rs generalizing w s with
  | nil =>
    cases accepted
    exact ⟨s, [], live, rfl, rfl, by simp⟩
  | cons r rs ih =>
    cases first : step w r with
    | error err => simp [replay, first, Except.bind] at accepted
    | ok middle =>
      have rest : replay middle rs = .ok final := by
        simpa [replay, first, Except.bind] using accepted
      obtain ⟨nextStore, nextLive, effect⟩ := step_store_effect w middle sid s r live
        (segment r (by simp)) first
      obtain ⟨after, tailTxs, afterLive, projected, tailSerial, tailVersion⟩ :=
        ih middle nextStore nextLive (fun e he => segment e (by simp [he])) rest
      have one := HeadEffect.serial_witness s nextStore _ effect
      refine ⟨after, projectedApplication w sid r.event ++ tailTxs, afterLive, ?_, ?_, ?_⟩
      · simp [projectApplications, first, projected, Bind.bind, Except.bind, Pure.pure, Except.pure]
      · rw [serialTransactions_append, one.1]
        simpa [← one.2] using tailSerial
      · simp only [List.length_append]
        rw [tailVersion, one.2]
        omega

/-- Every constructor of Store carries these erased proofs. In particular,
accepted replay cannot produce a hole in history or a provisional global cut. -/
theorem reachable_store_invariants (w : World) (_reachable : Reachable w)
    (sid : Nat) (s : Store) (_live : find w.stores sid = some s) :
    History s.history s.head.version ∧ s.history.head? = some s.head ∧
      s.global ≤ s.head.version ∧ (atCut s s.global).version = s.global :=
  ⟨s.historyShape, s.headFirst, s.globalBound, (atCut_spec s s.global s.globalBound).1⟩

theorem txOf_found (w : World) (sid tid : Nat) (t : Tx)
    (accepted : txOf w sid tid = .ok t) : find w.txs tid = some t := by
  cases lookup : find w.txs tid <;>
    simp only [txOf, lookup, present, Bind.bind, Pure.pure, Except.bind, Except.pure,
      require, invalid] at accepted
  all_goals repeat' first
    | contradiction
    | assumption
    | rfl
    | cases accepted
    | split at accepted

theorem find_set_cases [DecidableEq K] (xs : Assoc K V) (id key : K) (v : V) :
    find (set xs id v) key = if id = key then some v else find xs key := by
  by_cases h : id = key <;> simp [h, find_set_same, find_set_other]

theorem find_erase_cases [DecidableEq K] (xs : Assoc K V) (id key : K) :
    find (erase xs id) key = if id = key then none else find xs key := by
  by_cases h : id = key <;> simp [h, find_erase_same, find_erase_other]

theorem foldlM_snapshot_fixed {A : Type} (items : List A) (f : Tx → A → Except Failure Tx)
    (fixed : ∀ t a next, f t a = .ok next → next.snapshot = t.snapshot)
    (t next : Tx) (accepted : items.foldlM f t = .ok next) :
    next.snapshot = t.snapshot := by
  induction items generalizing t with
  | nil => cases accepted; rfl
  | cons a items ih =>
    simp only [List.foldlM_cons, Bind.bind, Except.bind] at accepted
    cases one : f t a with
    | error err => simp [one] at accepted
    | ok middle =>
      have rest : items.foldlM f middle = .ok next := by simpa [one] using accepted
      exact (ih middle rest).trans (fixed t a middle one)

theorem clearWrites_snapshot_fixed (entries : Assoc String String) (map : String) (t next : Tx)
    (accepted : clearWrites t map entries = .ok next) :
    next.snapshot = t.snapshot :=
  foldlM_snapshot_fixed entries _ (fun t (key, _) next h =>
    runOp_preserves_snapshot t next (.write (map, key) none) h) t next accepted

theorem acquireMap_snapshot_fixed (s : Store) (t next : Tx) (map : String) (version global : Nat)
    (accepted : acquireMap s t map version global = .ok next) : next.snapshot = t.snapshot := by
  simp only [acquireMap, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | rfl
    | cases accepted
    | split at accepted

theorem stepEvent_snapshot_fixed (w next : World) (tid : Nat) (before after : Tx)
    (snap : Snapshot) (e : Event)
    (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
    (captured : before.snapshot = some snap) (segment : AttemptEvent tid e)
    (accepted : stepEvent w e = .ok next) : after.snapshot = some snap := by
  cases e <;> simp only [stepEvent, withTx, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  all_goals simp only [AttemptEvent] at segment
  all_goals repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only [→ txOf_found, → runOp_preserves_snapshot, → clearWrites_snapshot_fixed,
    → acquireMap_snapshot_fixed,
    find_set_cases, find_erase_cases]

theorem step_snapshot_fixed (w next : World) (tid : Nat) (before after : Tx)
    (snap : Snapshot) (r : Record)
    (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
    (captured : before.snapshot = some snap) (segment : AttemptEvent tid r.event)
    (accepted : step w r = .ok next) : after.snapshot = some snap := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next r accepted
  apply stepEvent_snapshot_fixed w eventNext tid before after snap r.event live
    (by simpa [txs] using stillLive) captured segment eventStep

theorem find_set_live [DecidableEq K] (xs : Assoc K V) (key : K) (before : V)
    (id : K) (value : V) (live : find xs key = some before) :
    ∃ after, find (set xs id value) key = some after := by
  by_cases h : id = key
  · exact ⟨value, by simp [h, find_set_same]⟩
  · exact ⟨before, by simpa [find_set_other, h] using live⟩

theorem stepEvent_attempt_live (w next : World) (tid : Nat) (before : Tx) (e : Event)
    (live : find w.txs tid = some before) (segment : AttemptEvent tid e)
    (accepted : stepEvent w e = .ok next) :
    ∃ after, find next.txs tid = some after := by
  cases e <;> simp only [stepEvent, withTx, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  all_goals simp only [AttemptEvent] at segment
  all_goals repeat' first
    | contradiction
    | exact ⟨before, live⟩
    | exact find_set_live _ tid before _ _ live
    | exact ⟨before, by simpa [find_erase_other, segment] using live⟩
    | cases accepted
    | split at accepted

theorem replay_attempt_invariant (tid : Nat) (P : Tx → Prop)
    (preserve : ∀ (w next : World) (before after : Tx) (r : Record),
      find w.txs tid = some before → find next.txs tid = some after →
      P before → AttemptEvent tid r.event → step w r = .ok next → P after)
    (w final : World) (before : Tx)
    (rs : List Record) (live : find w.txs tid = some before)
    (holds : P before)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after, find final.txs tid = some after ∧ P after := by
  induction rs generalizing w before with
  | nil => cases accepted; exact ⟨before, live, holds⟩
  | cons r rs ih =>
    cases one : step w r with
    | error err => simp [replay, one, Except.bind] at accepted
    | ok middle =>
      obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w middle r one
      have thisSegment := segment r (by simp)
      obtain ⟨midTx, midLive⟩ := stepEvent_attempt_live w eventNext tid before r.event
        live thisSegment eventStep
      have midLive' : find middle.txs tid = some midTx := by simpa [txs] using midLive
      have midProperty := preserve w middle before midTx r live midLive' holds thisSegment one
      apply ih middle midTx midLive' midProperty
      · intro e he; exact segment e (by simp [he])
      · simpa [replay, one, Except.bind] using accepted

theorem replay_snapshot_fixed (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot)
    (rs : List Record) (live : find w.txs tid = some before)
    (captured : before.snapshot = some snap)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap :=
  replay_attempt_invariant tid (fun t => t.snapshot = some snap)
    (fun w next before after r => step_snapshot_fixed w next tid before after snap r)
    w final before rs live captured segment accepted

theorem stepEvent_capture_metadata (w next : World) (sid tid version global term : Nat)
    (s : Store) (t : Tx) (source : storeOf w sid = .ok s)
    (accepted : stepEvent w (.snapshot sid tid version global term) = .ok next)
    (capturedTx : find next.txs tid = some t) :
    ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  refine ⟨{ current := s.head, term, origin := ⟨s, rfl⟩ }, ?_, rfl, rfl⟩
  simp only [stepEvent, withTx, source, Bind.bind, Pure.pure, Except.bind, Except.pure,
    expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only [find_set_cases]

theorem step_capture_metadata (w next : World) (sid tid version global term seq : Nat)
    (s : Store) (t : Tx) (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
    (capturedTx : find next.txs tid = some t) :
    ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next _ accepted
  exact stepEvent_capture_metadata w eventNext sid tid version global term s t source eventStep
    (by simpa [txs] using capturedTx)

theorem stepEvent_capture_cut_values (w next : World) (sid tid version global term : Nat)
    (s : Store) (source : storeOf w sid = .ok s)
    (accepted : stepEvent w (.snapshot sid tid version global term) = .ok next) :
    version = s.head.version ∧ global = s.global := by
  simp only [stepEvent, withTx, source, Bind.bind, Pure.pure, Except.bind, Except.pure,
    expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only

theorem step_capture_cut_values (w next : World) (sid tid version global term seq : Nat)
    (s : Store) (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next) :
    version = s.head.version ∧ global = s.global := by
  obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
  exact stepEvent_capture_cut_values w eventNext sid tid version global term s source eventStep

theorem capture_replay_preserves_metadata (w capturedWorld final : World)
    (sid tid version global term seq : Nat) (s : Store) (t : Tx) (tail : List Record)
    (source : storeOf w sid = .ok s)
    (capture : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok capturedWorld)
    (live : find capturedWorld.txs tid = some t)
    (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
    (accepted : replay capturedWorld tail = .ok final) :
    ∃ after snap, find final.txs tid = some after ∧ after.snapshot = some snap ∧
      snap.current = s.head ∧ snap.term = term := by
  obtain ⟨snap, captured, current, snapshotTerm⟩ :=
    step_capture_metadata w capturedWorld sid tid version global term seq s t source capture live
  obtain ⟨after, afterLive, same⟩ := replay_snapshot_fixed capturedWorld final tid t snap
    tail live captured segment accepted
  exact ⟨after, snap, afterLive, same, current, snapshotTerm⟩

theorem publish_cells_bounded (db : Data) (version : Nat) (writes : Pending)
    (before : CellsBounded db version) : CellsBounded (publish db version writes) version := by
  intro key cell found
  rw [publish_lookup] at found
  cases hw : find writes key with
  | none => exact before key cell (by simpa [hw] using found)
  | some value =>
    cases value with
    | none => simp [hw] at found
    | some v =>
      simp [hw] at found
      cases found
      exact Nat.le_refl _

theorem History.head_cells_bounded (fs : List Frame) (n : Nat) (shape : History fs n) :
    CellsBounded (fs.head?.getD {}).data n := by
  induction shape with
  | zero =>
    intro key cell found
    simp [find] at found
  | succ f n fs version effect tail ih =>
    obtain ⟨writes, published⟩ := effect
    simp only [List.head?_cons, Option.getD_some]
    rw [published]
    apply publish_cells_bounded
    intro key cell found
    exact Nat.le_trans (ih key cell found) (Nat.le_succ n)

theorem atCut_cells_bounded (s : Store) (cut : Nat) (within : cut ≤ s.head.version) :
    CellsBounded (atCut s cut).data cut := by
  have spec := atCut_spec s cut within
  have h := History.head_cells_bounded _ cut spec.2.1
  simpa only [spec.2.2, Option.getD_some] using h

theorem History.head_unique (fs : List Frame) (n : Nat) (shape : History fs n) :
    Unique (fs.head?.getD {}).data := by
  induction shape with
  | zero => simp [Unique]
  | succ f n fs version effect tail ih =>
    obtain ⟨writes, published⟩ := effect
    simp only [List.head?_cons, Option.getD_some]
    rw [published]
    exact publish_unique _ _ _ ih

theorem reachable_store_data_invariants (w : World) (_reachable : Reachable w)
    (sid : Nat) (s : Store) (_live : find w.stores sid = some s) :
    Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  have unique := History.head_unique s.history s.head.version s.historyShape
  have bounded := History.head_cells_bounded s.history s.head.version s.historyShape
  simpa only [s.headFirst, Option.getD_some] using And.intro unique bounded

theorem stepEvent_get_global (w next : World) (sid tid : Nat) (map key : String)
    (value : Option String) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : stepEvent w (.get sid tid map key value true) = .ok next) :
    value = (find view.frame.data (map, key)).map Cell.value := by
  simp only [stepEvent, withTx, source, globalOf, captured, present,
    Bind.bind, Pure.pure, Except.bind, Except.pure, expect, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only

theorem map_global_view_safety (view : GlobalView) :
    view.frame = {} ∨ ∃ origin : Store, view.frame = atCut origin origin.global ∧
      view.frame.version = origin.global ∧ CellsBounded view.frame.data origin.global := by
  rcases view.origin with placeholder | ⟨origin, committed⟩
  · exact Or.inl placeholder
  · refine Or.inr ⟨origin, committed, ?_, ?_⟩
    · rw [committed]; exact (atCut_spec origin origin.global origin.globalBound).1
    · rw [committed]; exact atCut_cells_bounded origin origin.global origin.globalBound

theorem step_global_read_from_captured_map (w next : World) (sid tid seq : Nat)
    (map key : String) (value : Option String) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : step w ⟨seq, .get sid tid map key value true⟩ = .ok next) :
    value = (find view.frame.data (map, key)).map Cell.value ∧
      (view.frame = {} ∨ ∃ origin : Store, view.frame = atCut origin origin.global ∧
        view.frame.version = origin.global ∧ CellsBounded view.frame.data origin.global) := by
  obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
  exact ⟨stepEvent_get_global w eventNext sid tid map key value t view source captured eventStep,
    map_global_view_safety view⟩

theorem stepEvent_has_global (w next : World) (sid tid : Nat) (map key : String)
    (value : Bool) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : stepEvent w (.has sid tid map key value true) = .ok next) :
    value = (find view.frame.data (map, key)).isSome := by
  simp only [stepEvent, withTx, source, globalOf, captured, present,
    Bind.bind, Pure.pure, Except.bind, Except.pure, expect, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only

theorem step_global_has_from_captured_map (w next : World) (sid tid seq : Nat)
    (map key : String) (value : Bool) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : step w ⟨seq, .has sid tid map key value true⟩ = .ok next) :
    value = (find view.frame.data (map, key)).isSome ∧
      (view.frame = {} ∨ ∃ origin : Store, view.frame = atCut origin origin.global ∧
        view.frame.version = origin.global ∧ CellsBounded view.frame.data origin.global) := by
  obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
  exact ⟨stepEvent_has_global w eventNext sid tid map key value t view source captured eventStep,
    map_global_view_safety view⟩

theorem captureGlobal_placeholder (s : Store) (snap : Snapshot) (map : String)
    (absent : find snap.current.births map = none) :
    (captureGlobal s snap map).frame = {} := by
  simp [captureGlobal, absent]

theorem captureGlobal_committed (s : Store) (snap : Snapshot) (map : String) (birth : Stamp)
    (existing : find snap.current.births map = some birth) :
    (captureGlobal s snap map).frame = atCut s s.global := by
  simp [captureGlobal, existing]

theorem stepEvent_map_capture (w next : World) (sid tid localVersion globalVersion : Nat)
    (map : String) (s : Store) (before after : Tx) (snap : Snapshot)
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
    (snapshot : before.snapshot = some snap)
    (accepted : stepEvent w (.acquire sid tid map localVersion globalVersion) = .ok next)
    (live : find next.txs tid = some after) :
    find after.globalViews map = some (captureGlobal s snap map) ∧
      localVersion = (revision snap.current map).version ∧
      globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  simp only [stepEvent, withTx, acquireMap, store, tx, snapOf, snapshot, present,
    Bind.bind, Pure.pure, Except.bind, Except.pure, require, expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only [find_set_cases]

theorem step_map_capture (w next : World) (sid tid localVersion globalVersion seq : Nat)
    (map : String) (s : Store) (before after : Tx) (snap : Snapshot)
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
    (snapshot : before.snapshot = some snap)
    (accepted : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok next)
    (live : find next.txs tid = some after) :
    find after.globalViews map = some (captureGlobal s snap map) ∧
      localVersion = (revision snap.current map).version ∧
      globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next _ accepted
  exact stepEvent_map_capture w eventNext sid tid localVersion globalVersion map s before after snap
    store tx snapshot eventStep (by simpa [txs] using live)

theorem runOp_globalViews_fixed (t next : Tx) (op : NormalOp String String String)
    (accepted : runOp t op = .ok next) : next.globalViews = t.globalViews := by
  unfold runOp at accepted
  split at accepted
  next => simp [invalid] at accepted
  next snap hs =>
    split at accepted
    next n hn =>
      simp [Pure.pure, Except.pure] at accepted
      cases accepted
      rfl
    next => simp [reject] at accepted

theorem foldlM_globalViews_fixed {A : Type} (items : List A) (f : Tx → A → Except Failure Tx)
    (fixed : ∀ t a next, f t a = .ok next → next.globalViews = t.globalViews)
    (t next : Tx) (accepted : items.foldlM f t = .ok next) :
    next.globalViews = t.globalViews := by
  induction items generalizing t with
  | nil => cases accepted; rfl
  | cons a items ih =>
    simp only [List.foldlM_cons, Bind.bind, Except.bind] at accepted
    cases one : f t a with
    | error err => simp [one] at accepted
    | ok middle =>
      have rest : items.foldlM f middle = .ok next := by simpa [one] using accepted
      exact (ih middle rest).trans (fixed t a middle one)

theorem clearWrites_globalViews_fixed (entries : Assoc String String) (map : String) (t next : Tx)
    (accepted : clearWrites t map entries = .ok next) :
    next.globalViews = t.globalViews :=
  foldlM_globalViews_fixed entries _ (fun t (key, _) next h =>
    runOp_globalViews_fixed t next (.write (map, key) none) h) t next accepted

theorem acquireMap_global_fixed (s : Store) (t next : Tx) (map wanted : String)
    (version global : Nat) (view : GlobalView)
    (captured : find t.globalViews wanted = some view)
    (accepted : acquireMap s t map version global = .ok next) :
    find next.globalViews wanted = some view := by
  simp only [acquireMap, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals
    by_cases hm : map = wanted
    · subst map; simp_all
    · simpa [find_set_other, hm] using captured

theorem stepEvent_map_global_fixed (w next : World) (tid : Nat) (before after : Tx)
    (map : String) (view : GlobalView) (e : Event)
    (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
    (captured : find before.globalViews map = some view) (segment : AttemptEvent tid e)
    (accepted : stepEvent w e = .ok next) : find after.globalViews map = some view := by
  cases e <;> simp only [stepEvent, withTx, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  all_goals simp only [AttemptEvent] at segment
  all_goals repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals grind only [→ txOf_found, → runOp_globalViews_fixed, → clearWrites_globalViews_fixed,
    → acquireMap_global_fixed,
    find_set_cases, find_erase_cases]

theorem step_map_global_fixed (w next : World) (tid : Nat) (before after : Tx)
    (map : String) (view : GlobalView) (r : Record)
    (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
    (captured : find before.globalViews map = some view) (segment : AttemptEvent tid r.event)
    (accepted : step w r = .ok next) : find after.globalViews map = some view := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next r accepted
  exact stepEvent_map_global_fixed w eventNext tid before after map view r.event live
    (by simpa [txs] using stillLive) captured segment eventStep

theorem replay_map_global_fixed (w final : World) (tid : Nat) (before : Tx)
    (map : String) (view : GlobalView) (rs : List Record)
    (live : find w.txs tid = some before) (captured : find before.globalViews map = some view)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after, find final.txs tid = some after ∧ find after.globalViews map = some view :=
  replay_attempt_invariant tid (fun t => find t.globalViews map = some view)
    (fun w next before after r => step_map_global_fixed w next tid before after map view r)
    w final before rs live captured segment accepted

theorem capture_replay_preserves_map (w capturedWorld final : World)
    (sid tid localVersion globalVersion seq : Nat) (map : String)
    (s : Store) (before capturedTx : Tx) (snap : Snapshot) (tail : List Record)
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
    (snapshot : before.snapshot = some snap)
    (capture : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok capturedWorld)
    (live : find capturedWorld.txs tid = some capturedTx)
    (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
    (accepted : replay capturedWorld tail = .ok final) :
    ∃ after, find final.txs tid = some after ∧
      find after.globalViews map = some (captureGlobal s snap map) ∧
      localVersion = (revision snap.current map).version ∧
      globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  obtain ⟨view, localRevision, globalRevision⟩ :=
    step_map_capture w capturedWorld sid tid localVersion globalVersion seq map s before capturedTx snap
      store tx snapshot capture live
  obtain ⟨after, afterLive, fixed⟩ :=
    replay_map_global_fixed capturedWorld final tid capturedTx map (captureGlobal s snap map)
      tail live view segment accepted
  exact ⟨after, afterLive, fixed, localRevision, globalRevision⟩

end Kv.Proofs.Trace
