-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Std

@[expose] public section

/-! Semantic KV data, computed observations, dependencies, and live references. -/

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

/-- A computed operation in the normal-view history, including its semantic result. -/
inductive NormalOp (M K V : Type) where
  /-- A read of `addr` with its computed value. -/
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
deriving Repr, DecidableEq

/-- Records a computed operation, tracking its writes and dependencies. -/
def recordOp {M K V : Type} [DecidableEq M] [DecidableEq K]
    (snapshot : DB M K V) (n : Normal M K V) (op : NormalOp M K V)
    : Normal M K V :=
  {
    writes := stage n.writes op
    deps := needs snapshot n.writes op ++ n.deps
    log := n.log ++ [op]
  }

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
deriving Repr, Inhabited, DecidableEq

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
  /-- The identity assigned to the next application. -/
  nextIdentity : Nat := 1
deriving Repr, DecidableEq

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
deriving Repr, DecidableEq

/-- The local and globally committed views of one map captured by a transaction. -/
structure GlobalView where
  /-- The local frame selected when the map was first acquired. -/
  current : Frame := {}
  /-- The captured frame, or the empty frame for a map not yet created. -/
  frame : Frame
deriving Repr, DecidableEq

/-- The commit lifecycle of a transaction attempt. -/
inductive Phase where
  /-- Executing operations. -/
  | active
  /-- Commit started. -/
  | committing
  /-- Writes applied at `version`. -/
  | applied (version : Nat)
  /-- Commit completed. -/
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
  /-- A required lazy acquisition could not retain its snapshot. -/
  unavailable : Bool := false
  /-- The commit lifecycle. -/
  phase : Phase := .active
deriving Repr, DecidableEq

/-- The environment's commit outcome, including conservative pre-apply conflict. -/
inductive Outcome where
  /-- Committed (and, for writes, applied). -/
  | success
  /-- Rejected by optimistic concurrency control. -/
  | conflict
  /-- Applied but not replicated. -/
  | noReplicate
deriving Repr, BEq, DecidableEq

/-- Live stores and attempts, with reusable semantic references. -/
structure State where
  /-- Live stores. -/
  stores : Assoc Nat Store := []
  /-- Live attempts. -/
  txs : Assoc Nat Tx := []
deriving Repr, DecidableEq

end Kv.Model
