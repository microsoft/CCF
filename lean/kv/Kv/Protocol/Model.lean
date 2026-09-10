-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Types
import Kv.Proofs.Types

namespace Kv

def invalid (message : String) : Except Failure α := .error ⟨.invalidTrace, message⟩
def reject (message : String) : Except Failure α := .error ⟨.rejected, message⟩

def present (value : Option α) (message : String) : Except Failure α :=
  match value with
  | some x => .ok x
  | none => invalid message

def require (condition : Bool) (message : String) : Except Failure Unit :=
  if condition then .ok () else invalid message

def expect (condition : Bool) (message : String) : Except Failure Unit :=
  if condition then .ok () else reject message

def storeOf (w : World) (sid : Nat) : Except Failure Store :=
  present (find w.stores sid) s!"unknown/closed store {sid}"

def txOf (w : World) (sid tid : Nat) : Except Failure Tx := do
  let _ ← storeOf w sid
  let t ← present (find w.txs tid) s!"unknown/closed attempt {tid}"
  require (t.store == sid) "attempt belongs to another store"
  return t

def snapOf (t : Tx) : Except Failure Snapshot :=
  present t.snapshot "map operation before current snapshot capture"

def active (t : Tx) : Except Failure Unit :=
  require (t.phase == .active) "operation outside active attempt"

def operationPosition (t : Tx) : Except Failure Unit :=
  require (t.iterations.head?.all Iteration.awaitingContinue)
    "operation between iteration callbacks"

def completeCapture (t : Tx) : Except Failure Unit :=
  require (t.snapshot.isNone || !t.globalViews.isEmpty || t.unavailable)
    "current snapshot missing first map acquisition/outcome"

def withTx (w : World) (sid tid : Nat) (f : Tx → Except Failure Tx) :
    Except Failure World := do
  let t ← txOf w sid tid
  let next ← f t
  return { w with txs := set w.txs tid next }

def handleOf (t : Tx) (m : String) : Except Failure Snapshot := do
  active t
  operationPosition t
  require ((find t.globalViews m).isSome) s!"map {m} used before acquisition"
  snapOf t

def globalOf (t : Tx) (m : String) : Except Failure GlobalView :=
  present (find t.globalViews m) s!"map {m} has no captured global view"

def runOp (t : Tx) (op : NormalOp String String String) : Except Failure Tx := do
  match hs : t.snapshot with
  | none => invalid "normal operation before snapshot"
  | some snap =>
    match hn : normalStep snap.current.data t.normal op with
    | some n =>
      return { t with
        normal := n
        certificate := Proofs.Types.operation_certificate t snap n op hs hn }
    | none => reject s!"normal observation disagrees with captured snapshot {snap.current.version}: {repr op}"

def clearWrites (t : Tx) (map : String) (entries : Assoc String String) : Except Failure Tx :=
  entries.foldlM (fun acc (key, _) => runOp acc (.write (map, key) none)) t

def mapLineage (s : Store) (f : Frame) (m : String) : Bool :=
  s.history.any fun old =>
    find old.births m == find f.births m && revision old m == revision f m

def mapAvailable (s : Store) (f : Frame) (m : String) : Bool :=
  match find f.births m with
  | none => (image f.data m).isEmpty && (find f.revisions m).isNone
  | some _ =>
    let stamp := revision f m
    let base := revision (atCut s s.global) m
    decide (base.version ≤ stamp.version) && mapLineage s f m

def available (s : Store) (snap : Snapshot) (m : String) : Bool :=
  mapAvailable s snap.current m

def captureGlobal (s : Store) (snap : Snapshot) (m : String) : GlobalView :=
  if (find snap.current.births m).isNone then
    { frame := {}, origin := Or.inl rfl }
  else
    { frame := atCut s s.global, origin := Or.inr ⟨s, rfl⟩ }

def acquireMap (s : Store) (t : Tx) (m : String) (version global : Nat) : Except Failure Tx := do
  active t
  operationPosition t
  let snap ← snapOf t
  require ((find t.globalViews m).isNone) "duplicate map_acquire; handles share one change set"
  let view := captureGlobal s snap m
  expect (version == (revision snap.current m).version &&
          global == (revision view.frame m).version)
    s!"map acquisition expected local={(revision snap.current m).version}, global={(revision view.frame m).version}; observed local={version}, global={global}"
  expect (available s snap m) "snapshot no longer available for later map acquisition"
  return { t with globalViews := set t.globalViews m view }

def validLineage (s : Store) (t : Tx) : Bool :=
  match t.snapshot with
  | none => true
  | some snap =>
    s.term == snap.term &&
    t.globalViews.all (fun (m, _) => mapLineage s snap.current m)

def canApply (s : Store) (t : Tx) : Bool :=
  !t.unavailable && validLineage s t && validates s.head.data t.normal.deps

def advance (s : Store) (writes : Pending) : Store :=
  let v := s.head.version + 1
  let data := publish s.head.data v writes
  let revisions := writes.foldl (fun rs (a, value) =>
    if value.isSome || (find s.head.data a).isSome then
      set rs a.1 { version := v, identity := s.nextIdentity }
    else rs) s.head.revisions
  let births := writes.foldl (fun bs (a, _) =>
    if (find bs a.1).isSome then bs
    else set bs a.1 { version := v, identity := s.nextIdentity }) s.head.births
  let f : Frame := { version := v, data, revisions, births }
  { s with
    history := f :: s.history, head := f, nextIdentity := s.nextIdentity + 1
    historyShape := Proofs.Types.history_extension s f writes rfl rfl
    headFirst := rfl
    globalBound := Nat.le_trans s.globalBound (Nat.le_succ _) }

def tryApply (s : Store) (t : Tx) : Option Store :=
  if canApply s t then some (advance s t.normal.writes) else none

def compactStore (s : Store) (requested : Nat) : Store :=
  if h : requested ≤ s.head.version then
    { s with global := max s.global requested, globalBound := Nat.max_le.mpr ⟨s.globalBound, h⟩ }
  else s

def rollbackCut (s : Store) (v : Nat) : Nat := max s.global (min s.head.version v)

def rollbackStore (s : Store) (v term : Nat) : Store :=
  let cut := rollbackCut s v
  have within : cut ≤ s.head.version := Nat.max_le.mpr ⟨s.globalBound, Nat.min_le_left _ _⟩
  { s with
    history := s.history.filter (fun f => f.version ≤ cut)
    head := atCut s cut, term, termKnown := true
    historyShape := Proofs.Types.cut_history s cut within
    headFirst := (Proofs.Types.atCut_spec s cut within).2.2
    globalBound := Proofs.Types.cut_global_bound s cut within (Nat.le_max_left _ _) }

def writesEqual (a b : Pending) : Bool :=
  a.length == b.length && a.all (fun (k, v) => find b k == some v)

def uniqueKeys [DecidableEq K] (a : Assoc K V) : Bool :=
  decide (a.map Prod.fst).Nodup

def eachTop (t : Tx) (m : String) (id : Nat) : Except Failure (Iteration × List Iteration) := do
  active t
  require ((find t.globalViews m).isSome) "iteration uses unacquired map"
  let _ ← snapOf t
  match t.iterations with
  | [] => invalid "iteration event without foreach_begin"
  | i :: rest =>
    require (i.map == m && i.id == id) "iteration nesting/id mismatch"
    return (i, rest)

def stepEvent (w : World) (event : Event) : Except Failure World := do
  match event with
  | .traceStart schema =>
    require (!w.started && w.count == 0) "duplicate or late trace_start"
    require (schema == 1) "unsupported schema (expected 1)"
    return { w with started := true }
  | .caseBegin name =>
    require (w.currentCase.isNone && w.stores.isEmpty && w.txs.isEmpty)
      "overlapping case or unclosed prior lifecycles"
    require (!name.isEmpty) "empty case name"
    return { w with currentCase := some name }
  | .caseEnd name failed =>
    require (w.currentCase == some name && w.subcases.isEmpty) "case name/scope mismatch"
    require (w.stores.isEmpty && w.txs.isEmpty) "case ended with open lifecycles"
    require (!failed) "failed C++ case is not a complete conformance witness"
    return { w with currentCase := none, cases := w.cases + 1 }
  | .subcaseBegin name =>
    require w.currentCase.isSome "subcase outside case"
    return { w with subcases := name :: w.subcases }
  | .subcaseEnd name =>
    require (w.subcases.head? == some name) "subcase nesting/name mismatch"
    return { w with subcases := w.subcases.drop 1 }
  | .storeCreate sid =>
    require w.currentCase.isSome "store outside case"
    require (!(w.seenStores.contains sid)) "reused store incarnation"
    return { w with stores := set w.stores sid {}, seenStores := sid :: w.seenStores }
  | .storeEnd sid =>
    let _ ← storeOf w sid
    require (!(w.txs.any fun (_, t) => t.store == sid)) "store ended with live attempts"
    return { w with stores := erase w.stores sid }
  | .txCreate sid tid =>
    let _ ← storeOf w sid
    require (!(w.seenTxs.contains tid)) "reused attempt ID"
    return { w with txs := set w.txs tid { store := sid }, seenTxs := tid :: w.seenTxs }
  | .txEnd sid tid =>
    let t ← txOf w sid tid
    completeCapture t
    require (t.iterations.isEmpty) "attempt ended inside iteration"
    require (t.phase == .active || t.phase == .finished) "commit missing result"
    return { w with txs := erase w.txs tid }
  | .snapshot sid tid version global term =>
    let s ← storeOf w sid
    let established := if s.termKnown then s else { s with term, termKnown := true }
    withTx { w with stores := set w.stores sid established } sid tid fun t => do
      active t
      if hs : t.snapshot = none then
        expect (version == s.head.version && global == s.global && term == established.term)
          s!"initial snapshot metadata expected local={s.head.version}, global={s.global}, term={established.term}; observed local={version}, global={global}, term={term}"
        return { t with
          snapshot := some { current := s.head, term, origin := ⟨s, rfl⟩ }
          certificate := Proofs.Types.snapshot_certificate t s.head.data hs }
      else invalid "snapshot refreshed inside attempt"
  | .acquire sid tid m version global =>
    let s ← storeOf w sid
    withTx w sid tid fun t => acquireMap s t m version global
  | .unavailable sid tid m =>
    let s ← storeOf w sid
    withTx w sid tid fun t => do
      active t
      operationPosition t
      let snap ← snapOf t
      require ((find t.globalViews m).isNone) "pinned handle reported unavailable"
      expect (!(available s snap m)) "available snapshot reported unavailable"
      return { t with unavailable := true }
  | .get sid tid m k value global =>
    withTx w sid tid fun t => do
      let _ ← handleOf t m
      if global then
        let view ← globalOf t m
        let expected := (find view.frame.data (m, k)).map Cell.value
        expect (expected == value)
          s!"global read for map {m} at captured cut {view.frame.version}: expected {repr expected}, observed {repr value}"
        return t
      else runOp t (.read (m, k) value)
  | .has sid tid m k value global =>
    withTx w sid tid fun t => do
      let snap ← handleOf t m
      if global then
        let view ← globalOf t m
        expect ((find view.frame.data (m, k)).isSome == value) "wrong global presence"
        return t
      else
        let actual := valueAt snap.current.data t.normal.writes (m, k)
        expect (actual.isSome == value) "wrong current presence"
        runOp t (.read (m, k) actual)
  | .previous sid tid m k value =>
    withTx w sid tid fun t => do
      let _ ← handleOf t m
      runOp t (.previous (m, k) value)
  | .put sid tid m k value =>
    withTx w sid tid fun t => do
      let _ ← handleOf t m
      runOp t (.write (m, k) (some value))
  | .remove sid tid m k =>
    withTx w sid tid fun t => do
      let _ ← handleOf t m
      runOp t (.write (m, k) none)
  | .clear sid tid m =>
    withTx w sid tid fun t => do
      let snap ← handleOf t m
      let entries := scanAt snap.current.data t.normal.writes m
      let t ← runOp t (.scan m entries)
      clearWrites t m entries
  | .size sid tid m value =>
    withTx w sid tid fun t => do
      let snap ← handleOf t m
      let entries := scanAt snap.current.data t.normal.writes m
      expect (entries.length == value) s!"size expected {entries.length}, observed {value}"
      runOp t (.scan m entries)
  | .foreachBegin sid tid m id =>
    withTx w sid tid fun t => do
      let snap ← handleOf t m
      require (!(t.iterationIds.contains (m, id))) "reused iteration ID for this map"
      let entries := scanAt snap.current.data t.normal.writes m
      let t ← runOp t (.scan m entries)
      return { t with iterations := { map := m, id, remaining := entries } :: t.iterations,
                      iterationIds := (m, id) :: t.iterationIds }
  | .foreachEntry sid tid m id k value =>
    withTx w sid tid fun t => do
      let (i, rest) ← eachTop t m id
      require (!i.awaitingContinue && !i.stopped) "entry after stop or before callback continuation"
      expect (find i.remaining k == some value) "wrong, duplicate, or non-frozen iteration entry"
      return { t with iterations := { i with remaining := erase i.remaining k,
                                             awaitingContinue := true } :: rest }
  | .foreachContinue sid tid m id value =>
    withTx w sid tid fun t => do
      let (i, rest) ← eachTop t m id
      require i.awaitingContinue "continuation without an entry/callback"
      return { t with iterations := { i with awaitingContinue := false, stopped := !value } :: rest }
  | .foreachEnd sid tid m id =>
    withTx w sid tid fun t => do
      let (i, rest) ← eachTop t m id
      require (!i.awaitingContinue) "iteration missing callback continuation"
      expect (i.stopped || i.remaining.isEmpty) "incomplete iteration without early termination"
      return { t with iterations := rest }
  | .commitBegin sid tid =>
    withTx w sid tid fun t => do
      active t
      completeCapture t
      require t.iterations.isEmpty "commit inside active iteration"
      return { t with phase := .committing }
  | .apply sid tid version term writes =>
    let s ← storeOf w sid
    let t ← txOf w sid tid
    require (t.phase == .committing) "apply without commit_begin, or duplicate apply"
    require (uniqueKeys writes) "duplicate key in logged apply"
    expect (!t.normal.writes.isEmpty) "read-only attempt assigned a write version"
    expect (writesEqual writes t.normal.writes) "logged apply is not the entire staged multi-map write set"
    let next ← match tryApply s t with
      | some next => pure next
      | none => reject "application violates read dependencies, branch lineage, or commit term"
    expect (version == s.head.version + 1 && term == s.term) "wrong application version/term"
    return { w with stores := set w.stores sid next,
                    txs := set w.txs tid { t with phase := .applied version } }
  | .commitResult sid tid result version =>
    withTx w sid tid fun t => do
      match t.phase with
      | .applied assigned =>
        expect (result != .conflict && version == assigned) "applied transaction lost its effects/version"
      | .committing =>
        expect (version == 0) "unapplied attempt reported an assigned version"
        if result == .success then
          expect (t.normal.writes.isEmpty && !t.unavailable) "successful writing attempt missing apply"
      | _ => invalid "commit_result without in-flight commit"
      return { t with phase := .finished }
  | .compact sid version requested =>
    let s ← storeOf w sid
    let next := compactStore s requested
    expect (version == next.global) "incorrect effective compaction boundary"
    return { w with stores := set w.stores sid next }
  | .rollback sid version requested term =>
    let s ← storeOf w sid
    expect (requested ≥ s.global) "rollback crosses irrevocable prefix"
    expect (version == min s.head.version requested) "incorrect effective rollback boundary"
    expect (!s.termKnown || term ≥ s.term) "term decreased"
    return { w with stores := set w.stores sid (rollbackStore s version term) }
  | .rollbackRejected sid requested _term =>
    let s ← storeOf w sid
    expect (requested < s.global) "legal rollback reported rejected"
    return w
  | .unsupported _ operation =>
    .error ⟨.unsupported, s!"explicitly unsupported operation: {operation}"⟩
  | .traceEnd events =>
    require (events == w.count) s!"manifest count expected {w.count}, observed {events}"
    require (w.currentCase.isNone && w.subcases.isEmpty && w.stores.isEmpty && w.txs.isEmpty)
      "trace_end with unclosed cases/lifecycles"
    require (w.cases > 0 && !w.seenStores.isEmpty && !w.seenTxs.isEmpty) "empty claimed coverage"
    return { w with ended := true }

def step (w : World) (r : Record) : Except Failure World := do
  require (!w.ended) "record after trace_end"
  require (w.lastSeq.all (fun n => n < r.seq)) "seq must strictly increase run-wide"
  if !w.started then
    match r.event with
    | .traceStart _ => pure ()
    | _ => invalid "first record must be trace_start"
  let next ← stepEvent w r.event
  return { next with lastSeq := some r.seq, count := w.count + 1 }

def replay (w : World) : List Record → Except Failure World
  | [] => .ok w
  | r :: rs => (step w r).bind fun next => replay next rs

end Kv
