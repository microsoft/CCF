-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Std

namespace Kv

abbrev Assoc (K V : Type) := List (K × V)

def find [DecidableEq K] (xs : Assoc K V) (k : K) : Option V :=
  match xs with
  | [] => none
  | (a, v) :: rest => if a = k then some v else find rest k

def erase [DecidableEq K] (xs : Assoc K V) (k : K) : Assoc K V :=
  xs.filter fun p => p.1 != k

def set [DecidableEq K] (xs : Assoc K V) (k : K) (v : V) : Assoc K V :=
  (k, v) :: erase xs k

def Unique (xs : Assoc K V) : Prop := (xs.map Prod.fst).Nodup

structure Cell (V : Type) where
  value : V
  version : Nat
  deriving Repr, DecidableEq, BEq

abbrev Addr (M K : Type) := M × K
abbrev DB (M K V : Type) := Assoc (Addr M K) (Cell V)
abbrev Writes (M K V : Type) := Assoc (Addr M K) (Option V)

def image [DecidableEq M] (db : DB M K V) (m : M) : Assoc K (Cell V) :=
  db.filterMap fun (a, v) => if a.1 = m then some (a.2, v) else none

def valueAt [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (ws : Writes M K V) (a : Addr M K) : Option V :=
  match find ws a with
  | some v => v
  | none => (find db a).map Cell.value

def previousAt [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (a : Addr M K) : Option Nat :=
  (find db a).map Cell.version

def writeValues [DecidableEq K] (vs : Assoc K V) (ws : Assoc K (Option V)) :
    Assoc K V :=
  ws.foldr (fun (k, v) acc => match v with
    | some x => set acc k x
    | none => erase acc k) vs

def scanAt [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (ws : Writes M K V) (m : M) : Assoc K V :=
  writeValues ((image db m).map fun (k, c) => (k, c.value))
    (ws.filterMap fun (a, v) => if a.1 = m then some (a.2, v) else none)

inductive NormalOp (M K V : Type) where
  | read (addr : Addr M K) (observed : Option V)
  | previous (addr : Addr M K) (observed : Option Nat)
  | scan (map : M) (observed : Assoc K V)
  | write (addr : Addr M K) (value : Option V)
  deriving Repr, DecidableEq

inductive Dependency (M K V : Type) where
  | key (addr : Addr M K) (expected : Option (Cell V))
  | map (name : M) (expected : Assoc K (Cell V))
  deriving Repr, DecidableEq

def Dependency.holds [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) : Dependency M K V → Bool
  | .key a expected => decide (find db a = expected)
  | .map m expected => decide (image db m = expected)

def validates [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (deps : List (Dependency M K V)) : Bool :=
  deps.all (Dependency.holds db)

def needs [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (ws : Writes M K V) : NormalOp M K V → List (Dependency M K V)
  | .read a _ => if (find ws a).isSome then [] else [.key a (find db a)]
  | .previous a _ => [.key a (find db a)]
  | .scan m _ => [.map m (image db m)]
  | .write _ _ => []

def observes [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (ws : Writes M K V) : NormalOp M K V → Bool
  | .read a v => decide (valueAt db ws a = v)
  | .previous a v => decide (previousAt db a = v)
  | .scan m vs => decide (scanAt db ws m = vs)
  | .write _ _ => true

def stage [DecidableEq M] [DecidableEq K]
    (ws : Writes M K V) : NormalOp M K V → Writes M K V
  | .write a v => set ws a v
  | _ => ws

structure Normal (M K V : Type) where
  writes : Writes M K V := []
  deps : List (Dependency M K V) := []
  log : List (NormalOp M K V) := []
  deriving Repr

def normalStep [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (op : NormalOp M K V) :
    Option (Normal M K V) :=
  if observes snapshot n.writes op then
    some { writes := stage n.writes op
           deps := needs snapshot n.writes op ++ n.deps
           log := n.log ++ [op] }
  else none

def normalRun [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (ops : List (NormalOp M K V)) :
    Option (Normal M K V) :=
  ops.foldlM (normalStep snapshot) n

def publish [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (version : Nat) (writes : Writes M K V) : DB M K V :=
  writes.foldr (fun (a, v) acc => match v with
    | some value => set acc a { value, version }
    | none => erase acc a) db

abbrev Data := DB String String String
abbrev Pending := Writes String String String

structure Stamp where
  version : Nat := 0
  identity : Nat := 0
  deriving Repr, BEq, DecidableEq, Inhabited

structure Frame where
  version : Nat := 0
  data : Data := []
  revisions : Assoc String Stamp := []
  births : Assoc String Stamp := []
  deriving Repr, Inhabited

def revision (f : Frame) (m : String) : Stamp := (find f.revisions m).getD {}

inductive History : List Frame → Nat → Prop
  | zero : History [{}] 0
  | succ (f : Frame) (n : Nat) (fs : List Frame) (version : f.version = n + 1)
      (effect : ∃ writes : Pending, f.data = publish (fs.head?.getD {}).data (n + 1) writes)
      (tail : History fs n) : History (f :: fs) (n + 1)

structure Store where
  history : List Frame := [{}]
  head : Frame := {}
  global : Nat := 0
  term : Nat := 0
  termKnown : Bool := false
  nextIdentity : Nat := 1
  historyShape : History history head.version := by exact .zero
  headFirst : history.head? = some head := by rfl
  globalBound : global ≤ head.version := by exact Nat.le_refl 0
  deriving Repr

instance : Inhabited Store := ⟨{}⟩

def atCut (s : Store) (v : Nat) : Frame :=
  (s.history.find? fun f => f.version ≤ v).getD {}

structure Snapshot where
  current : Frame
  term : Nat
  origin : ∃ s : Store, current = s.head
  deriving Repr

structure GlobalView where
  frame : Frame
  origin : frame = {} ∨ ∃ s : Store, frame = atCut s s.global
  deriving Repr

structure Iteration where
  map : String
  id : Nat
  remaining : Assoc String String
  awaitingContinue : Bool := false
  stopped : Bool := false
  deriving Repr

inductive Phase where
  | active
  | committing
  | applied (version : Nat)
  | finished
  deriving Repr, BEq, DecidableEq

structure Tx where
  store : Nat
  snapshot : Option Snapshot := none
  globalViews : Assoc String GlobalView := []
  normal : Normal String String String := {}
  iterations : List Iteration := []
  iterationIds : List (String × Nat) := []
  unavailable : Bool := false
  phase : Phase := .active
  certificate : match snapshot with
    | none => normal = {}
    | some snap => normalRun snap.current.data {} normal.log = some normal := by rfl
  deriving Repr

inductive Outcome where
  | success | conflict | noReplicate
  deriving Repr, BEq, DecidableEq

inductive Event where
  | traceStart (schema : Nat)
  | caseBegin (name : String)
  | caseEnd (name : String) (failed : Bool)
  | subcaseBegin (name : String)
  | subcaseEnd (name : String)
  | storeCreate (store : Nat)
  | storeEnd (store : Nat)
  | txCreate (store tx : Nat)
  | txEnd (store tx : Nat)
  | snapshot (store tx version global term : Nat)
  | acquire (store tx : Nat) (map : String) (version global : Nat)
  | unavailable (store tx : Nat) (map : String)
  | get (store tx : Nat) (map key : String) (value : Option String) (global : Bool)
  | has (store tx : Nat) (map key : String) (value : Bool) (global : Bool)
  | previous (store tx : Nat) (map key : String) (value : Option Nat)
  | put (store tx : Nat) (map key value : String)
  | remove (store tx : Nat) (map key : String)
  | clear (store tx : Nat) (map : String)
  | size (store tx : Nat) (map : String) (value : Nat)
  | foreachBegin (store tx : Nat) (map : String) (iteration : Nat)
  | foreachEntry (store tx : Nat) (map : String) (iteration : Nat) (key value : String)
  | foreachContinue (store tx : Nat) (map : String) (iteration : Nat) (value : Bool)
  | foreachEnd (store tx : Nat) (map : String) (iteration : Nat)
  | commitBegin (store tx : Nat)
  | apply (store tx version term : Nat) (writes : Pending)
  | commitResult (store tx : Nat) (result : Outcome) (version : Nat)
  | compact (store version requested : Nat)
  | rollback (store version requested term : Nat)
  | rollbackRejected (store requested term : Nat)
  | unsupported (store : Option Nat) (operation : String)
  | traceEnd (events : Nat)
  deriving Repr

structure Record where
  seq : Nat
  event : Event
  deriving Repr

inductive FailureKind where
  | rejected | invalidTrace | unsupported
  deriving Repr, BEq, DecidableEq

structure Failure where
  kind : FailureKind
  message : String
  deriving Repr

structure World where
  stores : Assoc Nat Store := []
  txs : Assoc Nat Tx := []
  seenStores : List Nat := []
  seenTxs : List Nat := []
  currentCase : Option String := none
  subcases : List String := []
  cases : Nat := 0
  started : Bool := false
  ended : Bool := false
  lastSeq : Option Nat := none
  count : Nat := 0
  deriving Repr

end Kv
