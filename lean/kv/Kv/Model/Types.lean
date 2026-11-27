-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import CCF.OCC

@[expose] public section

/-! KV data, computed observations, dependencies, and live references. -/

namespace Kv.Model

export CCF.OCC (
  Assoc find erase set Cell Addr DB Writes image valueAt previousAt writeValues scanAt
  NormalOp Dependency validates needs stage Normal recordOp publish
  Cell.mk Cell.value Cell.version
  NormalOp.read NormalOp.previous NormalOp.scan NormalOp.write NormalOp.map
  Dependency.key Dependency.map Dependency.holds
  Normal.mk Normal.writes Normal.deps Normal.log
)

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

/-- Live stores and attempts, with reusable references. -/
structure State where
  /-- Live stores. -/
  stores : Assoc Nat Store := []
  /-- Live attempts. -/
  txs : Assoc Nat Tx := []
deriving Repr, DecidableEq

end Kv.Model
