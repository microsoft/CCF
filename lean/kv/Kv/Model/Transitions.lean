-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model.Types

@[expose] public section

namespace Kv.Model

/-- Whether an acquired map's birth and revision still occur on this branch. -/
def mapLineage (s : Store) (f : Frame) (m : String) : Bool :=
  s.history.any
    fun old =>
      find old.births m == find f.births m && revision old m == revision f m

/-- Per-map retention, including absent-map placeholders. -/
def mapAvailable (s : Store) (f : Frame) (m : String) : Bool :=
  match find f.births m with
  | none => (image f.data m).isEmpty && (find f.revisions m).isNone
  | some _ =>
      let stamp := revision f m
      let base := revision (atCut s s.global) m
      decide (base.version ≤ stamp.version) && mapLineage s f m

/-- Lazy acquisition selects the surviving branch at the frozen read version. -/
def captureLocal (s : Store) (snap : Snapshot) (m : String) : Frame :=
  if (find (atCut s snap.current.version).births m).isSome then
    atCut s snap.current.version
  else
    {}

/-- Whether a new map handle can still acquire its local snapshot. -/
def available (s : Store) (snap : Snapshot) (m : String) : Bool :=
  mapAvailable s (captureLocal s snap m) m

/-- Computes independent local and global frames for one acquired map. -/
def captureGlobal (s : Store) (snap : Snapshot) (m : String) : GlobalView :=
  let current := captureLocal s snap m
  if (find current.births m).isNone then
    { current, frame := {} }
  else
    { current, frame := atCut s s.global }

/-- Frozen term and acquired map identities are still valid for publication. -/
def validLineage (s : Store) (t : Tx) : Bool :=
  match t.snapshot with
  | none => true
  | some snap =>
      s.term == snap.term
      && t.globalViews.all (fun (m, view) => mapLineage s view.current m)

/-- OCC validation for a writing attempt. -/
def canApply (s : Store) (t : Tx) : Bool :=
  !t.unavailable && validLineage s t && validates s.head.data t.normal.deps

/-- Publishes the complete write set with a fresh application identity. -/
def advance (s : Store) (writes : Pending) : Store :=
  let v := s.head.version + 1
  let data := publish s.head.data v writes
  let revisions :=
    writes.foldl
      (fun rs (a, value) =>
        if value.isSome || (find s.head.data a).isSome then
          set rs a.1 { version := v, identity := s.nextIdentity }
        else
          rs)
      s.head.revisions
  let births :=
    writes.foldl
      (fun bs (a, _) =>
        if (find bs a.1).isSome then
          bs
        else
          set bs a.1 { version := v, identity := s.nextIdentity })
      s.head.births
  let f : Frame := { version := v, data, revisions, births }
  { s with history := f :: s.history, head := f, nextIdentity := s.nextIdentity + 1 }

/-- Executes publication when dependencies and lineage permit it. -/
def tryApply (s : Store) (t : Tx) : Option Store :=
  if canApply s t then some (advance s t.normal.writes) else none

/-- Above-head and backward compaction requests do not lower the global cut. -/
def compactStore (s : Store) (requested : Nat) : Store :=
  if requested ≤ s.head.version then { s with global := max s.global requested } else s

/-- Effective rollback boundary, never below the global cut. -/
def rollbackCut (s : Store) (v : Nat) : Nat := max s.global (min s.head.version v)

/-- Truncates the branch without reusing application identities. -/
def rollbackStore (s : Store) (v term : Nat) : Store :=
  let cut := rollbackCut s v
  {
    s with
      history := s.history.filter (fun f => f.version ≤ cut)
      head := atCut s cut
      term
  }

/-- Range bounds that admit no keys. -/
def emptyRange (lower upper : Option String) : Bool :=
  match lower, upper with
  | some l, some u => decide (u ≤ l)
  | _, _ => false

/-- Membership in the half-open key interval. -/
def inRange (lower upper : Option String) (key : String) : Bool :=
  lower.all (fun l => decide (l ≤ key)) && upper.all (fun u => decide (key < u))

/-- KV operation inputs, with no reported result. -/
inductive Operation where
  /-- Read current or captured global data. -/
  | get (map key : String) (global : Bool)
  /-- Query current or captured global presence. -/
  | has (map key : String) (global : Bool)
  /-- Query a committed previous-write version. -/
  | previous (map key : String)
  /-- Stage a put or deletion. -/
  | write (map key : String) (value : Option String)
  /-- Remove every visible entry. -/
  | clear (map : String)
  /-- Query visible size. -/
  | size (map : String)
  /-- Query an ordered interval. -/
  | range (map : String) (lower upper : Option String)
  /-- Freeze entries for callbacks; callback order is an adapter/environment concern. -/
  | scan (map : String)
deriving Repr

/-- The map needed by an operation. -/
def Operation.map : Operation → String
  | .get m _ _
  | .has m _ _
  | .previous m _
  | .write m _ _
  | .clear m
  | .size m
  | .range m _ _
  | .scan m => m

/-- Results computed from KV state, never supplied as observations to the model. -/
inductive Output where
  /-- No result. -/
  | unit
  /-- Current snapshot metadata. -/
  | snapshot (version global term : Nat)
  /-- Acquired map revision metadata. -/
  | acquired (version global : Nat)
  /-- Required lazy acquisition failed. -/
  | unavailable
  /-- Value result. -/
  | value (value : Option String)
  /-- Presence result. -/
  | presence (value : Bool)
  /-- Previous-write result. -/
  | previous (value : Option Nat)
  /-- Map entries result. -/
  | entries (entries : Assoc String String)
  /-- Count result. -/
  | size (value : Nat)
  /-- Published effects and assigned metadata. -/
  | applied (version term : Nat) (writes : Pending)
  /-- Commit outcome and assigned version. -/
  | committed (result : Outcome) (version : Nat)
  /-- Effective compaction boundary. -/
  | compacted (version : Nat)
  /-- Effective rollback boundary. -/
  | rolledBack (version : Nat)
  /-- Rollback refused at the irrevocable boundary. -/
  | rollbackRejected
deriving Repr, DecidableEq

/-- Computes an operation's result and its dependency/write effect. -/
def executeOperation (t : Tx) (op : Operation) : Tx × Output :=
  let record (op : NormalOp String String String) :=
    { t with normal := recordOp t.data t.normal op }
  match op with
  | .get m k true =>
      (
        t,
        .value
          ((find ((find t.globalViews m).getD { frame := {} }).frame.data (m, k)).map
            Cell.value)
      )
  | .has m k true =>
      (
        t,
        .presence
          ((find ((find t.globalViews m).getD { frame := {} }).frame.data (m, k)).isSome)
      )
  | .get m k false =>
      let v := valueAt t.data t.normal.writes (m, k)
      (record (.read (m, k) v), .value v)
  | .has m k false =>
      let v := valueAt t.data t.normal.writes (m, k)
      (record (.read (m, k) v), .presence v.isSome)
  | .previous m k =>
      let v := previousAt t.data (m, k)
      (record (.previous (m, k) v), .previous v)
  | .write m k v => (record (.write (m, k) v), .unit)
  | .scan m =>
      let entries := scanAt t.data t.normal.writes m
      (record (.scan m entries), .entries entries)
  | .size m =>
      let entries := scanAt t.data t.normal.writes m
      (record (.scan m entries), .size entries.length)
  | .clear m =>
      let entries := scanAt t.data t.normal.writes m
      let next := record (.scan m entries)
      (
        entries.foldl
          (fun acc (k, _) =>
            { acc with normal := recordOp acc.data acc.normal (.write (m, k) none) })
          next,
        .unit
      )
  | .range m lower upper =>
      if emptyRange lower upper then
        (t, .entries [])
      else
        let entries := scanAt t.data t.normal.writes m
        (
          record (.scan m entries),
          .entries
            ((entries.filter fun (k, _) => inRange lower upper k).mergeSort
              (fun a b => decide (a.1 ≤ b.1)))
        )

/-- Semantic environment and transaction inputs. -/
inductive Action where
  /-- Create a live store with an explicit initial term. -/
  | storeCreate (store term : Nat)
  /-- Destroy a live store without live attempts. -/
  | storeEnd (store : Nat)
  /-- Create an attempt. -/
  | txCreate (store tx : Nat)
  /-- Abandon or release an attempt. -/
  | txEnd (store tx : Nat)
  /-- Advance the environment's term without truncating data. -/
  | setTerm (store term : Nat)
  /-- Freeze read metadata. -/
  | snapshot (store tx : Nat)
  /-- Lazily acquire a map or record semantic unavailability. -/
  | acquire (store tx : Nat) (map : String)
  /-- Execute a KV operation. -/
  | operation (store tx : Nat) (op : Operation)
  /-- Begin a commit. -/
  | commitBegin (store tx : Nat)
  /-- Apply the full staged write set. -/
  | apply (store tx : Nat)
  /-- Complete a commit with an environment-selected outcome. -/
  | commitResult (store tx : Nat) (result : Outcome)
  /-- Compact a requested prefix. -/
  | compact (store requested : Nat)
  /-- Roll back a requested provisional suffix and enter a new term. -/
  | rollback (store requested term : Nat)
deriving Repr

/-- Live store and correctly owned attempt. -/
def lookupTx (w : State) (sid tid : Nat) : Option (Store × Tx) := do
  let s ← find w.stores sid
  let t ← find w.txs tid
  if t.store == sid then some (s, t) else none

/-- Executes semantic inputs and computes both the resulting state and output. -/
def execute (w : State) (action : Action) : Option (State × Output) := do
  match action with
  | .storeCreate sid term =>
      if (find w.stores sid).isSome then
        none
      else
        some ({ w with stores := set w.stores sid { term } }, .unit)
  | .storeEnd sid =>
      let _ ← find w.stores sid
      if w.txs.any (fun (_, t) => t.store == sid) then
        none
      else
        some ({ w with stores := erase w.stores sid }, .unit)
  | .txCreate sid tid =>
      let _ ← find w.stores sid
      if (find w.txs tid).isSome then
        none
      else
        some ({ w with txs := set w.txs tid { store := sid } }, .unit)
  | .txEnd sid tid =>
      let _ ← lookupTx w sid tid
      some ({ w with txs := erase w.txs tid }, .unit)
  | .setTerm sid term =>
      let s ← find w.stores sid
      if term < s.term then
        none
      else
        some ({ w with stores := set w.stores sid { s with term } }, .unit)
  | .snapshot sid tid =>
      let (s, t) ← lookupTx w sid tid
      if t.phase != .active || t.snapshot.isSome then
        none
      else
        let next := { t with snapshot := some { current := s.head, term := s.term } }
        some
          ({ w with txs := set w.txs tid next }, .snapshot s.head.version s.global s.term)
  | .acquire sid tid m =>
      let (s, t) ← lookupTx w sid tid
      let snap ← t.snapshot
      if t.phase != .active
          || (find t.globalViews m).isSome
          || !t.normal.log.all (fun op => op.map != m) then
        none
      else if available s snap m then
        let view := captureGlobal s snap m
        let next :=
          {
            t with
              globalViews := set t.globalViews m view
              data := pinData t.data m view.current.data
          }
        some
          (
            { w with txs := set w.txs tid next },
            .acquired (revision view.current m).version (revision view.frame m).version
          )
      else
        some
          ({ w with txs := set w.txs tid { t with unavailable := true } }, .unavailable)
  | .operation sid tid op =>
      let (_, t) ← lookupTx w sid tid
      if t.phase != .active
          || t.snapshot.isNone
          || (find t.globalViews op.map).isNone then
        none
      else
        let (next, output) := executeOperation t op
        some ({ w with txs := set w.txs tid next }, output)
  | .commitBegin sid tid =>
      let (_, t) ← lookupTx w sid tid
      if t.phase != .active then
        none
      else
        some ({ w with txs := set w.txs tid { t with phase := .committing } }, .unit)
  | .apply sid tid =>
      let (s, t) ← lookupTx w sid tid
      if t.phase != .committing || t.normal.writes.isEmpty then
        none
      else
        let next ← tryApply s t
        let version := next.head.version
        let state :=
          {
            w with
              stores := set w.stores sid next
              txs := set w.txs tid { t with phase := .applied version }
          }
        some (state, .applied version s.term t.normal.writes)
  | .commitResult sid tid result =>
      let (_, t) ← lookupTx w sid tid
      let version ←
        match t.phase with
        | .applied v => if result == .conflict then none else some v
        | .committing =>
            if result == .success && (!t.normal.writes.isEmpty || t.unavailable) then
              none
            else
              some 0
        | _ => none
      some
        (
          { w with txs := set w.txs tid { t with phase := .finished } },
          .committed result version
        )
  | .compact sid requested =>
      let s ← find w.stores sid
      let next := compactStore s requested
      some ({ w with stores := set w.stores sid next }, .compacted next.global)
  | .rollback sid requested term =>
      let s ← find w.stores sid
      if requested < s.global then
        some (w, .rollbackRejected)
      else if term < s.term then
        none
      else
        let next := rollbackStore s requested term
        some ({ w with stores := set w.stores sid next }, .rolledBack next.head.version)

/-- State projection of semantic execution. -/
def step (w : State) (action : Action) : Option State :=
  (execute w action).map Prod.fst

end Kv.Model
