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

/-- A reported behavior forbidden by the semantic system. -/
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

/-- Checks a reported observation or semantic enabling condition. -/
def expect (condition : Bool) (message : String) : Except Failure Unit :=
  if condition then .ok () else reject message

/-- The recorded live store. -/
def storeOf (w : World) (sid : Nat) : Except Failure Store :=
  present (find w.stores sid) s!"unknown/closed store {sid}"

/-- The recorded live attempt, with ownership checked. -/
def txOf (w : World) (sid tid : Nat) : Except Failure Tx := do
  let _ ← storeOf w sid
  let t ← present (find w.txs tid) s!"unknown/closed attempt {tid}"
  require (t.store == sid) "attempt belongs to another store"
  return t

/-- The attempt's frozen read metadata. -/
def snapOf (t : Tx) : Except Failure Snapshot :=
  present t.snapshot "map operation before current snapshot capture"

/-- Operations must occur before commit begins. -/
def active (t : Tx) : Except Failure Unit :=
  require (t.phase == .active) "operation outside active attempt"

/-- Operations in an iteration must occur inside the reported callback. -/
def operationPosition (t : Tx) : Except Failure Unit :=
  require (t.iterations.head?.all Iteration.awaitingContinue)
    "operation between iteration callbacks"

/-- A recorded snapshot needs its first acquisition outcome. -/
def completeCapture (t : Tx) : Except Failure Unit :=
  require (t.snapshot.isNone || !t.globalViews.isEmpty || t.unavailable)
    "current snapshot missing first map acquisition/outcome"

/-- Requires an acquired handle in the recorded operation position. -/
def handleOf (t : Tx) (m : String) : Except Failure Snapshot := do
  active t
  operationPosition t
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

/-- Lifts the semantic publication primitive through a schema decoration. -/
def advance (s : Store) (writes : Pending) : Store :=
  { toStore := Model.advance s writes, termKnown := s.termKnown }

/-- Lifts semantic OCC application through a schema decoration. -/
def tryApply (s : Store) (t : Tx) : Option Store :=
  (Model.tryApply s t).map fun next => { toStore := next, termKnown := s.termKnown }

/-- Lifts semantic compaction through a schema decoration. -/
def compactStore (s : Store) (requested : Nat) : Store :=
  { toStore := Model.compactStore s requested, termKnown := s.termKnown }

/-- Lifts semantic rollback, which establishes the omitted initial term. -/
def rollbackStore (s : Store) (v term : Nat) : Store :=
  { toStore := Model.rollbackStore s v term, termKnown := true }

/-- Order-insensitive validation of a reported publication echo. -/
def writesEqual (a b : Pending) : Bool :=
  a.length == b.length && a.all (fun (k, v) => find b k == some v)

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
def eachTop (t : Tx) (m : String) (id : Nat)
    : Except Failure (Iteration × List Iteration) := do
  active t
  require ((find t.globalViews m).isSome) "iteration uses unacquired map"
  let _ ← snapOf t
  match t.iterations with
  | [] => invalid "iteration event without foreach_begin"
  | i :: rest =>
      require (i.map == m && i.id == id) "iteration nesting/id mismatch"
      return (i, rest)

/-- Validates trace protocol and reports with the existing first-failure diagnostics.
All semantic state changes are left to `Model.execute`. -/
def guardEvent (w : World) (event : Event) : Except Failure Unit := do
  match event with
  | .traceStart schema =>
      require (!w.started && w.count == 0) "duplicate or late trace_start"
      require (schema == 1) "unsupported schema (expected 1)"
  | .caseBegin name =>
      require (w.currentCase.isNone && w.stores.isEmpty && w.txs.isEmpty)
        "overlapping case or unclosed prior lifecycles"
      require (!name.isEmpty) "empty case name"
  | .caseEnd name failed =>
      require (w.currentCase == some name && w.subcases.isEmpty)
        "case name/scope mismatch"
      require (w.stores.isEmpty && w.txs.isEmpty) "case ended with open lifecycles"
      require (!failed) "failed C++ case is not a complete conformance witness"
  | .subcaseBegin _ => require w.currentCase.isSome "subcase outside case"
  | .subcaseEnd name =>
      require (w.subcases.head? == some name) "subcase nesting/name mismatch"
  | .storeCreate sid =>
      require w.currentCase.isSome "store outside case"
      require (!(w.seenStores.contains sid)) "reused store incarnation"
  | .storeEnd sid =>
      let _ ← storeOf w sid
      require (!(w.txs.any fun (_, t) => t.store == sid)) "store ended with live attempts"
  | .txCreate sid tid =>
      let _ ← storeOf w sid
      require (!(w.seenTxs.contains tid)) "reused attempt ID"
  | .txEnd sid tid =>
      let t ← txOf w sid tid
      completeCapture t
      require t.iterations.isEmpty "attempt ended inside iteration"
      require (t.phase == .active || t.phase == .finished) "commit missing result"
  | .snapshot sid tid version global term =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      active t
      if t.snapshot.isNone then
        let expectedTerm := if s.termKnown then s.term else term
        expect (version == s.head.version && global == s.global && term == expectedTerm)
          s!"initial snapshot metadata expected local={s.head.version}, global={s.global}, term={expectedTerm}; observed local={version}, global={global}, term={term}"
      else
        invalid "snapshot refreshed inside attempt"
  | .acquire sid tid m version global =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      active t
      operationPosition t
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
      operationPosition t
      let snap ← snapOf t
      require ((find t.globalViews m).isNone) "pinned handle reported unavailable"
      expect (!(available s snap m)) "available snapshot reported unavailable"
  | .get sid tid m k value global =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      if global then
        let view ← globalOf t m
        let expected := (find view.frame.data (m, k)).map Cell.value
        expect (expected == value)
          s!"global read for map {m} at captured cut {view.frame.version}: expected {repr expected}, observed {repr value}"
      else
        validateOp t (.read (m, k) value)
  | .has sid tid m k value global =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      if global then
        let view ← globalOf t m
        expect ((find view.frame.data (m, k)).isSome == value) "wrong global presence"
      else
        expect ((valueAt t.data t.normal.writes (m, k)).isSome == value)
          "wrong current presence"
  | .previous sid tid m k value =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      validateOp t (.previous (m, k) value)
  | .put sid tid m _ _ | .remove sid tid m _ | .clear sid tid m =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      pure ()
  | .size sid tid m value =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      let entries := scanAt t.data t.normal.writes m
      expect (entries.length == value)
        s!"size expected {entries.length}, observed {value}"
  | .range sid tid m lower upper observed =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      if emptyRange lower upper then
        expect observed.isEmpty "empty range bounds returned entries"
      else
        expect (rangeMatches (scanAt t.data t.normal.writes m) observed lower upper)
          "range entries differ from the visible entries in key order"
  | .foreachBegin sid tid m id =>
      let t ← txOf w sid tid
      let _ ← handleOf t m
      require (!(t.iterationIds.contains (m, id))) "reused iteration ID for this map"
  | .foreachEntry sid tid m id k value =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t m id
      require (!i.awaitingContinue && !i.stopped)
        "entry after stop or before callback continuation"
      expect (find i.remaining k == some value)
        "wrong, duplicate, or non-frozen iteration entry"
  | .foreachContinue sid tid m id _ =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t m id
      require i.awaitingContinue "continuation without an entry/callback"
  | .foreachEnd sid tid m id =>
      let t ← txOf w sid tid
      let (i, _) ← eachTop t m id
      require (!i.awaitingContinue) "iteration missing callback continuation"
      expect (i.stopped || i.remaining.isEmpty)
        "incomplete iteration without early termination"
  | .commitBegin sid tid =>
      let t ← txOf w sid tid
      active t
      completeCapture t
      require t.iterations.isEmpty "commit inside active iteration"
  | .apply sid tid version term writes =>
      let s ← storeOf w sid
      let t ← txOf w sid tid
      require (t.phase == .committing) "apply without commit_begin, or duplicate apply"
      require (uniqueKeys writes) "duplicate key in logged apply"
      expect (!t.normal.writes.isEmpty) "read-only attempt assigned a write version"
      expect (writesEqual writes t.normal.writes)
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
      expect (!s.termKnown || term ≥ s.term) "term decreased"
  | .rollbackRejected sid requested _ =>
      let s ← storeOf w sid
      expect (requested < s.global) "legal rollback reported rejected"
  | .unsupported _ operation =>
      .error ⟨.unsupported, s!"explicitly unsupported operation: {operation}"⟩
  | .traceEnd events =>
      require (events == w.count) s!"manifest count expected {w.count}, observed {events}"
      require
        (w.currentCase.isNone && w.subcases.isEmpty && w.stores.isEmpty && w.txs.isEmpty)
        "trace_end with unclosed cases/lifecycles"
      require (w.cases > 0 && !w.seenStores.isEmpty && !w.seenTxs.isEmpty)
        "empty claimed coverage"

/-- Updates callback/schema metadata without modifying a semantic transaction field. -/
def metadata (w : World) (event : Event) (output : Output) : World :=
  let modifyTx (tid : Nat) (f : Tx → Tx) :=
    match find w.txs tid with
    | none => w
    | some t => { w with txs := set w.txs tid (f t) }
  let knowTerm (sid : Nat) :=
    match find w.stores sid with
    | none => w
    | some s => { w with stores := set w.stores sid { s with termKnown := true } }
  match event with
  | .traceStart _ => { w with started := true }
  | .caseBegin name => { w with currentCase := some name }
  | .caseEnd _ _ => { w with currentCase := none, cases := w.cases + 1 }
  | .subcaseBegin name => { w with subcases := name :: w.subcases }
  | .subcaseEnd _ => { w with subcases := w.subcases.drop 1 }
  | .storeCreate sid => { w with seenStores := sid :: w.seenStores }
  | .txCreate _ tid => { w with seenTxs := tid :: w.seenTxs }
  | .snapshot sid _ _ _ _ | .rollback sid _ _ _ => knowTerm sid
  | .foreachBegin _ tid m id =>
      let entries :=
        match output with
        | .entries entries => entries
        | _ => []
      modifyTx tid
        fun t =>
          {
            t with
              iterations := { map := m, id, remaining := entries } :: t.iterations
              iterationIds := (m, id) :: t.iterationIds
          }
  | .foreachEntry _ tid _ _ k _ =>
      modifyTx tid
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
      modifyTx tid
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
      modifyTx tid fun t => { t with iterations := t.iterations.drop 1 }
  | .traceEnd _ => { w with ended := true }
  | _ => w

/-- Installs the authoritative semantic result, carrying forward only trace decorations. -/
def liftState (w : World) (semantic : Model.State) : World :=
  {
    w with
      stores :=
        semantic.stores.map
          fun (sid, s) =>
            (
              sid,
              {
                toStore := s
                termKnown := ((find w.stores sid).getD {}).termKnown
              }
            )
      txs :=
        semantic.txs.map
          fun (tid, t) =>
            (
              tid,
              {
                toTx := t
                iterations := ((find w.txs tid).getD { store := t.store }).iterations
                iterationIds := ((find w.txs tid).getD { store := t.store }).iterationIds
              }
            )
  }

/-- Guards the trace, executes semantic inputs once, validates output, then lifts its result. -/
def stepEvent (w : World) (event : Event) : Except Failure World := do
  guardEvent w event
  let (semantic, output) ←
    match executeActions (project w) (actions w event) with
    | none => reject "trace adapter disagrees with semantic KV execution"
    | some pair => pure pair
  expect (reportedMatches event output)
    "trace adapter disagrees with semantic KV execution"
  return liftState (metadata w event output) semantic

/-- Applies one ordered record, recording only sequence/count metadata after the event. -/
def step (w : World) (r : Record) : Except Failure World := do
  require (!w.ended) "record after trace_end"
  require (w.lastSeq.all (fun n => n < r.seq)) "seq must strictly increase run-wide"
  if !w.started then
    match r.event with
    | .traceStart _ => pure ()
    | _ => invalid "first record must be trace_start"
  let next ← stepEvent w r.event
  return { next with lastSeq := some r.seq, count := w.count + 1 }

/-- Replays records through the authoritative semantic executor. -/
def replay (w : World) : List Record → Except Failure World
  | [] => .ok w
  | r :: rs => (step w r).bind fun next => replay next rs

end Kv.TraceValidation
