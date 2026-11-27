-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.Adapter

@[expose] public section

namespace Kv.TraceValidation

open Kv.Model

/-- Malformed or incomplete instrumentation. -/
def invalid {α : Type} (message : String) : Except Failure α :=
  .error ⟨.invalidTrace, message⟩

/-- A reported behavior forbidden by the model. -/
def reject {α : Type} (message : String) : Except Failure α :=
  .error ⟨.rejected, message⟩

/-- Requires recorded lifecycle information to be present. -/
def present {α : Type} (value : Option α) (message : String) : Except Failure α :=
  match value with
  | some x => .ok x
  | none => invalid message

/-- Checks the instrumentation protocol. -/
def require (condition : Bool) (message : String) : Except Failure Unit :=
  if condition then .ok () else invalid message

/-- Checks a reported observation or model enabling condition. -/
def expect (condition : Bool) (message : String) : Except Failure Unit :=
  if condition then .ok () else reject message

/-- The recorded live store. -/
def storeOf (w : World) (sid : Nat) : Except Failure Store :=
  present (find w.model.stores sid) s!"unknown/closed store {sid}"

/-- The recorded live attempt, with ownership checked. -/
def txOf (w : World) (sid tid : Nat) : Except Failure Tx := do
  let _ ← storeOf w sid
  let t ← present (find w.model.txs tid) s!"unknown/closed attempt {tid}"
  require (t.store == sid) "attempt belongs to another store"
  return t

/-- The attempt's frozen read metadata. -/
def snapOf (t : Tx) : Except Failure Snapshot :=
  present t.snapshot "map operation before current snapshot capture"

/-- Operations must occur before commit begins. -/
def active (t : Tx) : Except Failure Unit :=
  require (t.phase == .active) "operation outside active attempt"

/-- Operations in an iteration must occur inside the reported callback. -/
def operationPosition (t : AttemptRecording) : Except Failure Unit :=
  require (t.iterations.head?.all Iteration.awaitingContinue)
    "operation between iteration callbacks"

/-- A recorded snapshot needs its first acquisition outcome. -/
def completeCapture (t : Tx) : Except Failure Unit :=
  require (t.snapshot.isNone || !t.globalViews.isEmpty || t.unavailable)
    "current snapshot missing first map acquisition/outcome"

/-- Requires an acquired handle in the recorded operation position. -/
def handleOf (t : Tx) (recording : AttemptRecording) (m : String)
    : Except Failure Snapshot := do
  active t
  operationPosition recording
  require ((find t.globalViews m).isSome) s!"map {m} used before acquisition"
  snapOf t

/-- The per-map captured global view. -/
def globalOf (t : Tx) (m : String) : Except Failure GlobalView :=
  present (find t.globalViews m) s!"map {m} has no captured global view"

/-- Detailed normal-observation diagnostic; this does not execute or update a transaction. -/
def validateOp (t : Tx) (op : NormalOp String String String) : Except Failure Unit := do
  match t.snapshot with
  | none => invalid "normal operation before snapshot"
  | some snap =>
      expect (observes t.data t.normal.writes op)
        s!"normal observation disagrees with pinned local views at read version {snap.current.version}: {repr op}"

/-- No reported key occurs twice. -/
def uniqueKeys {K V : Type} [DecidableEq K] (a : Assoc K V) : Bool :=
  decide (a.map Prod.fst).Nodup

/-- Reported range keys strictly ascend. -/
def ascending : Assoc String String → Bool
  | a :: b :: rest => decide (a.1 < b.1) && ascending (b :: rest)
  | _ => true

/-- Detailed validation of a reported ordered range. -/
def rangeMatches (visible observed : Assoc String String) (lower upper : Option String)
    : Bool :=
  let expected := visible.filter fun (k, _) => inRange lower upper k
  ascending observed
  && observed.length == expected.length
  && observed.all fun (k, v) => find expected k == some v

/-- The recorded innermost iteration and its parent stack. -/
def eachTop (t : Tx) (recording : AttemptRecording) (m : String) (id : Nat)
    : Except Failure (Iteration × List Iteration) := do
  active t
  require ((find t.globalViews m).isSome) "iteration uses unacquired map"
  let _ ← snapOf t
  match recording.iterations with
  | [] => invalid "iteration event without foreach_begin"
  | i :: rest =>
      require (i.map == m && i.id == id) "iteration nesting/id mismatch"
      return (i, rest)

/-- Validates trace protocol and reports with the existing first-failure diagnostics.
All model state changes are left to `Model.execute`. -/
def guardEvent (w : World) (event : Event) : Except Failure Unit := do
  match event with
  | .traceStart schema =>
      require (!w.recording.started && w.recording.count == 0)
        "duplicate or late trace_start"
      require (schema == 1) "unsupported schema (expected 1)"
  | .caseBegin name =>
      require
        (w.recording.currentCase.isNone && w.model.stores.isEmpty && w.model.txs.isEmpty)
        "overlapping case or unclosed prior lifecycles"
      require (!name.isEmpty) "empty case name"
  | .caseEnd name failed =>
      require (w.recording.currentCase == some name && w.recording.subcases.isEmpty)
        "case name/scope mismatch"
      require (w.model.stores.isEmpty && w.model.txs.isEmpty)
        "case ended with open lifecycles"
      require (!failed) "failed C++ case is not a complete conformance witness"
  | .subcaseBegin _ => require w.recording.currentCase.isSome "subcase outside case"
  | .subcaseEnd name =>
      require (w.recording.subcases.head? == some name) "subcase nesting/name mismatch"
  | .storeCreate sid =>
      require w.recording.currentCase.isSome "store outside case"
      require (!(w.recording.seenStores.contains sid)) "reused store incarnation"
  | .storeEnd sid =>
      let _ ← storeOf w sid
      require (!(w.model.txs.any fun (_, t) => t.store == sid))
        "store ended with live attempts"
  | .txCreate sid tid =>
      let _ ← storeOf w sid
      require (!(w.recording.seenTxs.contains tid)) "reused attempt ID"
  | .txEnd sid tid =>
      let t ← txOf w sid tid
      completeCapture t
      require (attemptRecording w tid).iterations.isEmpty "attempt ended inside iteration"
      require (t.phase == .active || t.phase == .finished) "commit missing result"
  | .snapshot sid tid version global term =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      active t
      if t.snapshot.isNone then
        let expectedTerm := if (w.recording.knownTerms.contains sid) then s.term else term
        expect (version == s.head.version && global == s.global && term == expectedTerm)
          s!"initial snapshot metadata expected local={s.head.version}, global={s.global}, term={expectedTerm}; observed local={version}, global={global}, term={term}"
      else
        invalid "snapshot refreshed inside attempt"
  | .acquire sid tid m version global =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      active t
      operationPosition (attemptRecording w tid)
      let snap ← snapOf t
      require ((find t.globalViews m).isNone)
        "duplicate map_acquire; handles share one change set"
      let view := captureGlobal s snap m
      expect
        (version == (revision view.current m).version
          && global == (revision view.frame m).version)
        s!"map acquisition expected local={(revision view.current m).version}, global={(revision view.frame m).version}; observed local={version}, global={global}"
      expect (available s snap m) "snapshot no longer available for later map acquisition"
      require (t.normal.log.all (fun op => op.map != m))
        "unacquired map already used by normal operation"
  | .unavailable sid tid m =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      active t
      operationPosition (attemptRecording w tid)
      let snap ← snapOf t
      require ((find t.globalViews m).isNone) "pinned handle reported unavailable"
      expect (!available s snap m || t.crossedRollback)
        "available snapshot reported unavailable without crossing a truncating rollback"
  | .get sid tid m k value global =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      if global then
        let view ← globalOf t m
        let expected := (find view.frame.data (m, k)).map Cell.value
        expect (expected == value)
          s!"global read for map {m} at captured cut {view.frame.version}: expected {repr expected}, observed {repr value}"
      else
        validateOp t (.read (m, k) value)
  | .has sid tid m k value global =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      if global then
        let view ← globalOf t m
        expect ((find view.frame.data (m, k)).isSome == value) "wrong global presence"
      else
        expect ((valueAt t.data t.normal.writes (m, k)).isSome == value)
          "wrong current presence"
  | .previous sid tid m k value =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      validateOp t (.previous (m, k) value)
  | .put sid tid m _ _ | .remove sid tid m _ | .clear sid tid m =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      pure ()
  | .size sid tid m value =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      let entries := scanAt t.data t.normal.writes m
      expect (entries.length == value)
        s!"size expected {entries.length}, observed {value}"
  | .range sid tid m lower upper observed =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      if emptyRange lower upper then
        expect observed.isEmpty "empty range bounds returned entries"
      else
        expect (rangeMatches (scanAt t.data t.normal.writes m) observed lower upper)
          "range entries differ from the visible entries in key order"
  | .foreachBegin sid tid m id =>
      let t ← txOf w sid tid
      let _ ← handleOf t (attemptRecording w tid) m
      require (!((attemptRecording w tid).iterationIds.contains (m, id)))
        "reused iteration ID for this map"
  | .foreachEntry sid tid m id k value =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t (attemptRecording w tid) m id
      require (!i.awaitingContinue && !i.stopped)
        "entry after stop or before callback continuation"
      expect (find i.remaining k == some value)
        "wrong, duplicate, or non-frozen iteration entry"
  | .foreachContinue sid tid m id _ =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t (attemptRecording w tid) m id
      require i.awaitingContinue "continuation without an entry/callback"
  | .foreachEnd sid tid m id =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t (attemptRecording w tid) m id
      require (!i.awaitingContinue) "iteration missing callback continuation"
      expect (i.stopped || i.remaining.isEmpty)
        "incomplete iteration without early termination"
  | .commitBegin sid tid =>
      let t ← txOf w sid tid
      active t
      completeCapture t
      require (attemptRecording w tid).iterations.isEmpty "commit inside active iteration"
  | .apply sid tid version term writes =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      require (t.phase == .committing) "apply without commit_begin, or duplicate apply"
      require (uniqueKeys writes) "duplicate key in logged apply"
      expect (!t.normal.writes.isEmpty) "read-only attempt assigned a write version"
      expect (decide (writes.Perm t.normal.writes))
        "logged apply is not the entire staged multi-map write set"
      expect (canApply s t)
        "application violates read dependencies, branch lineage, or commit term"
      expect (version == s.head.version + 1 && term == s.term)
        "wrong application version/term"
  | .commitResult sid tid result version =>
      let t ← txOf w sid tid
      match t.phase with
      | .applied assigned =>
          expect (result != .conflict && version == assigned)
            "applied transaction lost its effects/version"
      | .committing =>
          expect (version == 0) "unapplied attempt reported an assigned version"
          if result == .success then
            expect (t.normal.writes.isEmpty && !t.unavailable)
              "successful writing attempt missing apply"
      | _ => invalid "commit_result without in-flight commit"
  | .compact sid version requested =>
      let s ← storeOf w sid
      expect (version == (Model.compactStore s requested).global)
        "incorrect effective compaction boundary"
  | .rollback sid version requested term =>
      let s ← storeOf w sid
      expect (requested ≥ s.global) "rollback crosses irrevocable prefix"
      expect (version == min s.head.version requested)
        "incorrect effective rollback boundary"
      expect (!(w.recording.knownTerms.contains sid) || term ≥ s.term) "term decreased"
  | .rollbackRejected sid requested _ =>
      let s ← storeOf w sid
      expect (requested < s.global) "legal rollback reported rejected"
  | .unsupported _ operation =>
      .error ⟨.unsupported, s!"explicitly unsupported operation: {operation}"⟩
  | .traceEnd events =>
      require (events == w.recording.count)
        s!"manifest count expected {w.recording.count}, observed {events}"
      require
        (w.recording.currentCase.isNone
          && w.recording.subcases.isEmpty
          && w.model.stores.isEmpty
          && w.model.txs.isEmpty)
        "trace_end with unclosed cases/lifecycles"
      require
        (w.recording.cases > 0
          && !w.recording.seenStores.isEmpty
          && !w.recording.seenTxs.isEmpty)
        "empty claimed coverage"

/-- Updates only recording metadata; no model state is available to this function. -/
def metadata (w : Recording) (event : Event) (output : Output) : Recording :=
  let modifyAttempt (tid : Nat) (f : AttemptRecording → AttemptRecording) :=
    { w with attempts := set w.attempts tid (f ((find w.attempts tid).getD {})) }
  match event with
  | .traceStart _ => { w with started := true }
  | .caseBegin name => { w with currentCase := some name }
  | .caseEnd _ _ => { w with currentCase := none, cases := w.cases + 1 }
  | .subcaseBegin name => { w with subcases := name :: w.subcases }
  | .subcaseEnd _ => { w with subcases := w.subcases.drop 1 }
  | .storeCreate sid => { w with seenStores := sid :: w.seenStores }
  | .storeEnd sid => { w with knownTerms := w.knownTerms.filter (· != sid) }
  | .txCreate _ tid => { w with seenTxs := tid :: w.seenTxs }
  | .txEnd _ tid => { w with attempts := erase w.attempts tid }
  | .snapshot sid _ _ _ _ | .rollback sid _ _ _ =>
      {
        w with
          knownTerms :=
            if w.knownTerms.contains sid then w.knownTerms else sid :: w.knownTerms
      }
  | .foreachBegin _ tid m id =>
      let entries :=
        match output with
        | .entries entries => entries
        | _ => []
      modifyAttempt tid
        fun t =>
          {
            t with
              iterations := { map := m, id, remaining := entries } :: t.iterations
              iterationIds := (m, id) :: t.iterationIds
          }
  | .foreachEntry _ tid _ _ k _ =>
      modifyAttempt tid
        fun t =>
          match t.iterations with
          | [] => t
          | i :: rest =>
              {
                t with
                  iterations :=
                    { i with remaining := erase i.remaining k, awaitingContinue := true }
                    :: rest
              }
  | .foreachContinue _ tid _ _ value =>
      modifyAttempt tid
        fun t =>
          match t.iterations with
          | [] => t
          | i :: rest =>
              {
                t with
                  iterations :=
                    { i with awaitingContinue := false, stopped := !value } :: rest
              }
  | .foreachEnd _ tid _ _ =>
      modifyAttempt tid fun t => { t with iterations := t.iterations.drop 1 }
  | .traceEnd _ => { w with ended := true }
  | _ => w

/-- Checks a record's inputs and reports directly against the main model. -/
def stepEvent (w : World) (event : Event) : Except Failure World := do
  guardEvent w event
  let (nextState, output) ←
    match executeActions w.model (actions w event) with
    | none => reject "trace adapter disagrees with KV model execution"
    | some pair => pure pair
  expect (reportedMatches event output) "trace adapter disagrees with KV model execution"
  return { model := nextState, recording := metadata w.recording event output }

/-- Applies one ordered record, recording only sequence/count metadata after the event. -/
def step (w : World) (r : Record) : Except Failure World := do
  require (!w.recording.ended) "record after trace_end"
  require (w.recording.lastSeq.all (fun n => n < r.seq))
    "seq must strictly increase run-wide"
  if !w.recording.started then
    match r.event with
    | .traceStart _ => pure ()
    | _ => invalid "first record must be trace_start"
  let next ← stepEvent w r.event
  return {
    next with
      recording :=
        { next.recording with lastSeq := some r.seq, count := w.recording.count + 1 }
  }

/-- Replays records through the authoritative model. -/
def replay (w : World) : List Record → Except Failure World
  | [] => .ok w
  | r :: rs => (step w r).bind fun next => replay next rs

end Kv.TraceValidation
