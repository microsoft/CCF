module

public import Std

@[expose] public section

/-!
Optimistic concurrency control over a versioned key-value store, as in CCF's KV.

A transaction reads a snapshot of the committed state and stages its writes. Each read
adds a dependency on what it read. The transaction applies only if every dependency
still holds on the committed state at that time; otherwise it conflicts.

`Program` is a transaction body written against these operations, and `Program.exec`
runs one on a snapshot.
-/

namespace CCF.OCC

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

/-- A computed operation in the normal-view history, including its result. -/
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
  | .map m expected => decide ((image db m).Perm expected)

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

/-- A transaction body: reads and writes on a key-value store, outputs to release if the
transaction commits, and failure. It cannot observe the store except through its reads. -/
inductive Program (M K V O : Type) (α : Type) where
  /-- Finish with a result. -/
  | done (result : α)
  /-- Fail with a reason. Nothing the transaction staged is applied. -/
  | fail (reason : String)
  /-- Read the value at `addr`: the transaction's own staged write, else the snapshot's. -/
  | get (addr : Addr M K) (next : Option V → Program M K V O α)
  /-- Read every entry of `map`, including the transaction's own staged writes. -/
  | scan (map : M) (next : Assoc K V → Program M K V O α)
  /-- Stage a put (`some`) or a removal (`none`) at `addr`. -/
  | put (addr : Addr M K) (value : Option V) (next : Program M K V O α)
  /-- Record an output. -/
  | output (out : O) (next : Program M K V O α)

namespace Program

variable {M K V O : Type}

/-- Runs `first`, then `next` on its result. -/
def bind {α β : Type} (first : Program M K V O α) (next : α → Program M K V O β)
    : Program M K V O β :=
  match first with
  | .done result => next result
  | .fail reason => .fail reason
  | .get addr rest => .get addr fun value => (rest value).bind next
  | .scan map rest => .scan map fun entries => (rest entries).bind next
  | .put addr value rest => .put addr value (rest.bind next)
  | .output out rest => .output out (rest.bind next)

instance : Monad (Program M K V O) where
  pure := .done
  bind := bind

/-- Reads the value at `addr`. -/
def read (addr : Addr M K) : Program M K V O (Option V) :=
  .get addr .done

/-- Reads every entry of `map`. -/
def entries (map : M) : Program M K V O (Assoc K V) :=
  .scan map .done

/-- Stages a put at `addr`. -/
def write (addr : Addr M K) (value : V) : Program M K V O Unit :=
  .put addr (some value) (.done ())

/-- Stages a removal at `addr`. -/
def remove (addr : Addr M K) : Program M K V O Unit :=
  .put addr none (.done ())

/-- Records an output, to release if the transaction commits. -/
def emit (out : O) : Program M K V O Unit :=
  .output out (.done ())

/-- A transaction after its body ran on a snapshot. -/
structure Ran (M K V O : Type) (α : Type) where
  /-- Its staged writes, read dependencies, and operation log. -/
  normal : Normal M K V := {}
  /-- Its outputs, in order. -/
  outputs : List O := []
  /-- Its result, or the reason it failed. -/
  result : Except String α

/-- Runs a body on `snapshot`, continuing from the writes, dependencies and outputs
so far. -/
def execFrom {α : Type} [DecidableEq M] [DecidableEq K] (snapshot : DB M K V)
    (normal : Normal M K V) (outputs : List O)
    : Program M K V O α → Ran M K V O α
  | .done result => { normal, outputs, result := .ok result }
  | .fail reason => { normal, outputs, result := .error reason }
  | .get addr next =>
      let value := valueAt snapshot normal.writes addr
      execFrom snapshot (recordOp snapshot normal (.read addr value)) outputs (next value)
  | .scan map next =>
      let entries := scanAt snapshot normal.writes map
      execFrom snapshot (recordOp snapshot normal (.scan map entries)) outputs
        (next entries)
  | .put addr value next =>
      execFrom snapshot (recordOp snapshot normal (.write addr value)) outputs next
  | .output out next => execFrom snapshot normal (outputs ++ [out]) next

/-- Runs a transaction body on `snapshot`. -/
def exec {α : Type} [DecidableEq M] [DecidableEq K] (snapshot : DB M K V)
    (body : Program M K V O α)
    : Ran M K V O α :=
  execFrom snapshot {} [] body

end Program

/-- Whether a transaction that ran may apply to `db`. One that staged no write always
may: it reads its snapshot and conflicts with nothing. -/
def canApply {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (normal : Normal M K V)
    : Bool :=
  normal.writes.isEmpty || validates db normal.deps

end CCF.OCC
