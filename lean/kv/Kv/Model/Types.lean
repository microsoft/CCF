-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Std

@[expose] public section

/-! Human-reviewed model state, observations, dependencies, trace events, and failure kinds. -/

namespace Kv.Model

/-- A finite map represented as a list of key-value pairs; the first match wins. -/
abbrev Assoc (K V : Type) := List (K × V)

/-- The value of the first entry for `k`, if any. -/
def find {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K) : Option V :=
  match xs with
  | [] => none
  | (a, v) :: rest => if a = k then some v else find rest k

/-- Removes every entry for `k`. -/
def erase {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K) : Assoc K V :=
  xs.filter fun p => p.1 != k

/-- Replaces every entry for `k` with a single entry mapping it to `v`. -/
def set {K V : Type} [DecidableEq K] (xs : Assoc K V) (k : K) (v : V) : Assoc K V :=
  (k, v) :: erase xs k

/-- A committed value together with the version that wrote it. -/
structure Cell (V : Type) where
  /-- The committed value. -/
  value : V
  /-- The version of the transaction that wrote the value. -/
  version : Nat
deriving Repr, DecidableEq, BEq

/-- A key within a named map. -/
abbrev Addr (M K : Type) := M × K

/-- Committed state: the cell at each present address. -/
abbrev DB (M K V : Type) := Assoc (Addr M K) (Cell V)

/-- Staged writes: `some` value for a put, `none` for a removal. -/
abbrev Writes (M K V : Type) := Assoc (Addr M K) (Option V)

/-- The committed entries of map `m`, keyed by their key within the map. -/
def image {M K V : Type} [DecidableEq M] (db : DB M K V) (m : M) : Assoc K (Cell V) :=
  db.filterMap fun (a, v) => if a.1 = m then some (a.2, v) else none

/-- The value a transaction reads at `a`: its own staged write, else the committed value. -/
def valueAt {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (ws : Writes M K V) (a : Addr M K)
    : Option V :=
  match find ws a with
  | some v => v
  | none => (find db a).map Cell.value

/-- The committed version at `a`, ignoring staged writes. -/
def previousAt {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V)
    (a : Addr M K)
    : Option Nat :=
  (find db a).map Cell.version

/-- Applies staged puts and removals to a map's values. -/
def writeValues {K V : Type} [DecidableEq K] (vs : Assoc K V) (ws : Assoc K (Option V))
    : Assoc K V :=
  ws.foldr
    (fun (k, v) acc =>
      match v with
      | some x => set acc k x
      | none => erase acc k)
    vs

/-- The values a transaction sees in map `m`, including its staged writes. -/
def scanAt {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (ws : Writes M K V) (m : M)
    : Assoc K V :=
  writeValues ((image db m).map fun (k, c) => (k, c.value))
    (ws.filterMap fun (a, v) => if a.1 = m then some (a.2, v) else none)

/-- An operation on a transaction's normal (current snapshot) view, with what it observed. -/
inductive NormalOp (M K V : Type) where
  /-- A read of `addr` that observed `observed`. -/
  | read (addr : Addr M K) (observed : Option V)
  /-- A read of the committed version of `addr`. -/
  | previous (addr : Addr M K) (observed : Option Nat)
  /-- A read of every entry in `map`. -/
  | scan (map : M) (observed : Assoc K V)
  /-- A staged put (`some`) or removal (`none`). -/
  | write (addr : Addr M K) (value : Option V)
deriving Repr, DecidableEq

/-- The map an operation accesses. -/
def NormalOp.map {M K V : Type} : NormalOp M K V → M
  | .read a _ | .previous a _ | .write a _ => a.1
  | .scan m _ => m

/-- A condition on committed state that must still hold when the transaction applies. -/
inductive Dependency (M K V : Type) where
  /-- The cell at `addr` is unchanged. -/
  | key (addr : Addr M K) (expected : Option (Cell V))
  /-- Every cell in map `name` is unchanged. -/
  | map (name : M) (expected : Assoc K (Cell V))
deriving Repr, DecidableEq

/-- The dependency holds in `db`. -/
def Dependency.holds {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V)
    : Dependency M K V → Bool
  | .key a expected => decide (find db a = expected)
  | .map m expected => decide (image db m = expected)

/-- Every dependency holds in `db`. -/
def validates {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (deps : List (Dependency M K V))
    : Bool :=
  deps.all (Dependency.holds db)

/-- The dependencies an operation adds; reads of staged writes add none. -/
def needs {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V)
    (ws : Writes M K V)
    : NormalOp M K V → List (Dependency M K V)
  | .read a _ => if (find ws a).isSome then [] else [.key a (find db a)]
  | .previous a _ => [.key a (find db a)]
  | .scan m _ => [.map m (image db m)]
  | .write _ _ => []

/-- The operation's recorded observation matches the snapshot and staged writes. -/
def observes {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (ws : Writes M K V)
    : NormalOp M K V → Bool
  | .read a v => decide (valueAt db ws a = v)
  | .previous a v => decide (previousAt db a = v)
  | .scan m vs => decide (scanAt db ws m = vs)
  | .write _ _ => true

/-- Stages an operation's write, if it has one. -/
def stage {M K V : Type} [DecidableEq M] [DecidableEq K] (ws : Writes M K V)
    : NormalOp M K V → Writes M K V
  | .write a v => set ws a v
  | _ => ws

/-- A transaction's normal view: staged writes, read dependencies, and its operation log. -/
structure Normal (M K V : Type) where
  /-- Writes staged so far. -/
  writes : Writes M K V := []
  /-- Conditions validated when the transaction applies. -/
  deps : List (Dependency M K V) := []
  /-- Operations executed so far, oldest first. -/
  log : List (NormalOp M K V) := []
deriving Repr

/-- Executes one operation against `snapshot`; `none` if its observation disagrees. -/
def normalStep {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (op : NormalOp M K V)
    : Option (Normal M K V) :=
  if observes snapshot n.writes op then
    some
      {
        writes := stage n.writes op
        deps := needs snapshot n.writes op ++ n.deps
        log := n.log ++ [op]
      }
  else
    none

/-- Applies writes to committed state, stamping new cells with `version`. -/
def publish {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (version : Nat) (writes : Writes M K V)
    : DB M K V :=
  writes.foldr
    (fun (a, v) acc =>
      match v with
      | some value => set acc a { value, version }
      | none => erase acc a)
    db

/-- Committed state of the executable instance: map names, keys, and values are strings. -/
abbrev Data := DB String String String

/-- Replaces just map `m` with its newly acquired local view. -/
def pinData (db : Data) (m : String) (acquired : Data) : Data :=
  db.filter (fun (a, _) => a.1 != m) ++ acquired.filter (fun (a, _) => a.1 == m)

/-- Staged writes of the executable instance. -/
abbrev Pending := Writes String String String

/-- Identifies a map revision or creation: the version and the application that made it. -/
structure Stamp where
  /-- The version at which the change was applied. -/
  version : Nat := 0
  /-- A store-unique identity of the application, distinguishing rolled-back branches. -/
  identity : Nat := 0
deriving Repr, BEq, DecidableEq, Inhabited

/-- The committed state at one version. -/
structure Frame where
  /-- The version this frame was committed at. -/
  version : Nat := 0
  /-- Committed cells. -/
  data : Data := []
  /-- The latest change to each map. -/
  revisions : Assoc String Stamp := []
  /-- The first change to each map on this branch. -/
  births : Assoc String Stamp := []
deriving Repr, Inhabited

/-- The latest revision of map `m` in frame `f`. -/
def revision (f : Frame) (m : String) : Stamp := (find f.revisions m).getD {}

/-- One store's branch of committed frames and its replication metadata. -/
structure Store where
  /-- Frames on the current branch, newest first. -/
  history : List Frame := [{}]
  /-- The newest frame. -/
  head : Frame := {}
  /-- The globally committed (compacted) version, which rollback cannot cross. -/
  global : Nat := 0
  /-- The current term. -/
  term : Nat := 0
  /-- Whether the term has been established by a snapshot or rollback. -/
  termKnown : Bool := false
  /-- The identity assigned to the next application. -/
  nextIdentity : Nat := 1
deriving Repr

instance : Inhabited Store := ⟨{}⟩

/-- The newest frame at or below version `v`. -/
def atCut (s : Store) (v : Nat) : Frame :=
  (s.history.find? fun f => f.version ≤ v).getD {}

/-- The frozen read-version metadata captured by a transaction, before lazy map acquisition. -/
structure Snapshot where
  /-- The captured head frame. -/
  current : Frame
  /-- The term at capture. -/
  term : Nat
deriving Repr

/-- The local and globally committed views of one map captured by a transaction. -/
structure GlobalView where
  /-- The local frame selected when the map was first acquired. -/
  current : Frame := {}
  /-- The captured frame, or the empty frame for a map not yet created. -/
  frame : Frame
deriving Repr

/-- An in-progress `foreach` over a map. -/
structure Iteration where
  /-- The iterated map. -/
  map : String
  /-- The trace's identifier for this iteration. -/
  id : Nat
  /-- Entries not yet visited. -/
  remaining : Assoc String String
  /-- An entry was visited and its callback result is pending. -/
  awaitingContinue : Bool := false
  /-- The callback requested early termination. -/
  stopped : Bool := false
deriving Repr

/-- The commit lifecycle of a transaction attempt. -/
inductive Phase where
  /-- Executing operations. -/
  | active
  /-- Commit started. -/
  | committing
  /-- Writes applied at `version`. -/
  | applied (version : Nat)
  /-- Commit result reported. -/
  | finished
deriving Repr, BEq, DecidableEq

/-- A transaction attempt. -/
structure Tx where
  /-- The store the attempt belongs to. -/
  store : Nat
  /-- The current snapshot, once captured. -/
  snapshot : Option Snapshot := none
  /-- The local and globally committed views pinned by each acquired map. -/
  globalViews : Assoc String GlobalView := []
  /-- The local data pinned by acquired handles, independent of the captured read version. -/
  data : Data := []
  /-- The normal view over the acquired local data. -/
  normal : Normal String String String := {}
  /-- Nested iterations, innermost first. -/
  iterations : List Iteration := []
  /-- Iteration identifiers used so far, per map. -/
  iterationIds : List (String × Nat) := []
  /-- A map acquisition reported its snapshot unavailable. -/
  unavailable : Bool := false
  /-- The commit lifecycle. -/
  phase : Phase := .active
deriving Repr

/-- The reported result of a commit. -/
inductive Outcome where
  /-- Committed (and, for writes, applied). -/
  | success
  /-- Rejected by optimistic concurrency control. -/
  | conflict
  /-- Applied but not replicated. -/
  | noReplicate
deriving Repr, BEq, DecidableEq

/-- A trace record's event. Fields follow the schema 1 record of the same name. -/
inductive Event where
  /-- Opens a trace with the given schema version. -/
  | traceStart (schema : Nat)
  /-- Begins a named C++ test case. -/
  | caseBegin (name : String)
  /-- Ends a named C++ test case. -/
  | caseEnd (name : String) (failed : Bool)
  /-- Begins a named subcase. -/
  | subcaseBegin (name : String)
  /-- Ends a named subcase. -/
  | subcaseEnd (name : String)
  /-- Creates a store. -/
  | storeCreate (store : Nat)
  /-- Destroys a store. -/
  | storeEnd (store : Nat)
  /-- Creates a transaction attempt. -/
  | txCreate (store tx : Nat)
  /-- Destroys a transaction attempt. -/
  | txEnd (store tx : Nat)
  /-- Captures the current snapshot at `version`, with the store's `global` version and `term`. -/
  | snapshot (store tx version global term : Nat)
  /-- Acquires a map handle, reporting its local and global revision versions. -/
  | acquire (store tx : Nat) (map : String) (version global : Nat)
  /-- Reports a map's snapshot unavailable at acquisition. -/
  | unavailable (store tx : Nat) (map : String)
  /-- Reads a value from the current or, if `global`, the globally committed view. -/
  | get (store tx : Nat) (map key : String) (value : Option String) (global : Bool)
  /-- Tests presence in the current or, if `global`, the globally committed view. -/
  | has (store tx : Nat) (map key : String) (value : Bool) (global : Bool)
  /-- Reads the committed version of a key. -/
  | previous (store tx : Nat) (map key : String) (value : Option Nat)
  /-- Stages a put. -/
  | put (store tx : Nat) (map key value : String)
  /-- Stages a removal. -/
  | remove (store tx : Nat) (map key : String)
  /-- Stages removal of every entry in a map. -/
  | clear (store tx : Nat) (map : String)
  /-- Reads the number of entries in a map. -/
  | size (store tx : Nat) (map : String) (value : Nat)
  /-- Reads the entries with keys in `[lower, upper)`, in ascending key order. -/
  | range (store tx : Nat) (map : String) (lower upper : Option String)
    (entries : Assoc String String)
  /-- Begins iterating over a map. -/
  | foreachBegin (store tx : Nat) (map : String) (iteration : Nat)
  /-- Visits one entry. -/
  | foreachEntry (store tx : Nat) (map : String) (iteration : Nat) (key value : String)
  /-- Records the callback's continue (`true`) or stop (`false`) result. -/
  | foreachContinue (store tx : Nat) (map : String) (iteration : Nat) (value : Bool)
  /-- Ends an iteration. -/
  | foreachEnd (store tx : Nat) (map : String) (iteration : Nat)
  /-- Begins committing an attempt. -/
  | commitBegin (store tx : Nat)
  /-- Applies an attempt's writes at `version` in `term`. -/
  | apply (store tx version term : Nat) (writes : Pending)
  /-- Reports an attempt's commit result and assigned version, or 0. -/
  | commitResult (store tx : Nat) (result : Outcome) (version : Nat)
  /-- Compacts to the effective `version` after a `requested` one. -/
  | compact (store version requested : Nat)
  /-- Rolls back to the effective `version` after a `requested` one, entering `term`. -/
  | rollback (store version requested term : Nat)
  /-- Reports a rollback rejected because it would cross the global version. -/
  | rollbackRejected (store requested term : Nat)
  /-- Reports an operation outside the model. -/
  | unsupported (store : Option Nat) (operation : String)
  /-- Closes a trace that contained `events` records. -/
  | traceEnd (events : Nat)
deriving Repr

/-- A trace record: a run-wide sequence number and an event. -/
structure Record where
  /-- Strictly increasing sequence number. -/
  seq : Nat
  /-- The recorded event. -/
  event : Event
deriving Repr

/-- Why a trace was not accepted. -/
inductive FailureKind where
  /-- The trace records behavior the model forbids. -/
  | rejected
  /-- The trace is malformed, incomplete, or inconsistent with its own lifecycle events. -/
  | invalidTrace
  /-- The implementation reported an operation outside the model. -/
  | unsupported
deriving Repr, BEq, DecidableEq

/-- A replay failure and its diagnostic. -/
structure Failure where
  /-- The failure category. -/
  kind : FailureKind
  /-- A human-readable diagnostic. -/
  message : String
deriving Repr

/-- The replay state: live stores and attempts plus trace bookkeeping. -/
structure World where
  /-- Live stores by identifier. -/
  stores : Assoc Nat Store := []
  /-- Live attempts by identifier. -/
  txs : Assoc Nat Tx := []
  /-- Every store identifier used so far. -/
  seenStores : List Nat := []
  /-- Every attempt identifier used so far. -/
  seenTxs : List Nat := []
  /-- The open test case, if any. -/
  currentCase : Option String := none
  /-- Open subcases, innermost first. -/
  subcases : List String := []
  /-- Completed test cases. -/
  cases : Nat := 0
  /-- `trace_start` was accepted. -/
  started : Bool := false
  /-- `trace_end` was accepted. -/
  ended : Bool := false
  /-- The last accepted sequence number. -/
  lastSeq : Option Nat := none
  /-- Accepted records. -/
  count : Nat := 0
deriving Repr

end Kv.Model
