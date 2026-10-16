module

public import Kv.Properties.Invariants

@[expose] public section

/-!
# Human-reviewed KV properties

Review these statements with the definitions in `Kv/Model/`, `Kv/Model.lean`, and
`Kv/Properties/`. Each claim is a `Prop`; `Kv.Proof` proves every one of them.
-/

namespace Kv.Properties

open Kv.Model

/-! ## Reads and atomic publication -/

/-- A staged put is visible to the transaction that staged it. -/
def ReadYourWrite : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a : Addr M K) (v : V),
    valueAt db (set ws a (some v)) a = some v

/-- A staged removal is visible to the transaction that staged it. -/
def ReadYourDeletion : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a : Addr M K),
    valueAt db (set ws a none) a = none

/-- A key neither staged nor committed reads as absent. -/
def AbsentRead : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a : Addr M K),
    find ws a = none → find db a = none → valueAt db ws a = none

/-- Staging a write at one address does not change reads at another. -/
def StagedNoninterference : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a b : Addr M K) (v : Option V),
    a ≠ b → valueAt db (set ws a v) b = valueAt db ws b

/-- Reading the committed version ignores staged writes. -/
def PreviousIgnoresPending : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (a : Addr M K),
    previousAt db a = (find db a).map Cell.version

/-- Publishing replaces each written cell, stamped with the new version, and keeps the rest. -/
def PublishLookup : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
    (ws : Writes M K V) (a : Addr M K),
    find (publish db version ws) a
    = match find ws a with
      | none => find db a
      | some none => none
      | some (some v) => some { value := v, version }

/-- Publishing leaves unwritten addresses unchanged. -/
def PublicationNoninterference : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
    (ws : Writes M K V) (a : Addr M K),
    find ws a = none → find (publish db version ws) a = find db a

/-- Publishing preserves key uniqueness. -/
def PublishUnique : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
    (ws : Writes M K V),
    Unique db → Unique (publish db version ws)

/-- Applying OCC-validated programs on a branch matches running them serially. -/
def BranchNormalSerializability : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V] (db final : DB M K V)
    (programs : List (AppliedProgram M K V)),
    BranchExecution db programs final → serialBranch db programs = some final

/-- Applying an attempt publishes its entire write set at the next version. -/
def ApplyAtomic : Prop :=
  ∀ (s : Store) (writes : Pending),
    (advance s writes).head.data = publish s.head.data (s.head.version + 1) writes

/-! ## Snapshot witnesses and normal-view serializability -/

/-- An attempt's operation log runs serially on its captured snapshot to its staged writes. -/
def TransactionSnapshotWitness : Prop :=
  ∀ (t : Tx) (snap : Snapshot),
    t.snapshot = some snap
    → serialRun snap.current.data [] t.normal.log = some t.normal.writes

/-- An attempt that may apply runs serially on the current head to the same staged writes. -/
def TransactionApplicationSerialWitness : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot),
    t.snapshot = some snap
    → canApply s t = true
    → serialRun s.head.data [] t.normal.log = some t.normal.writes

/-- A branch of applied attempts matches running their logs serially from the start. -/
def ExecutableBranchSerializability : Prop :=
  ∀ (s final : Store) (ts : List Tx),
    AppliedBranch s ts final
    → serialTransactions s.head.data s.head.version ts = some final.head.data

/-- In an accepted record segment that keeps store `sid` alive, the applications projected
onto that store run serially to its final head. -/
def ReplaySegmentSerializability : Prop :=
  ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
    find w.stores sid = some s
    → (∀ r ∈ rs, SegmentEvent sid r.event)
    → CCF.Execution.Run Model.transitionSystem w rs final
    → ∃ after txs,
        find final.stores sid = some after
        ∧ projectApplications w sid rs = .ok txs
        ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
        ∧ after.head.version = s.head.version + txs.length

/-! ## Reachable store invariants -/

/-- Every live store in a reachable world has a well-formed history whose head is newest, and a
global version within it that is the version of its global cut. -/
def ReachableStoreInvariants : Prop :=
  ∀ (w : World) (sid : Nat) (s : Store),
    Model.transitionSystem.Reachable w
    → find w.stores sid = some s
    → History s.history s.head.version
      ∧ s.history.head? = some s.head
      ∧ s.global ≤ s.head.version
      ∧ (atCut s s.global).version = s.global

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head. -/
def ReachableStoreDataInvariants : Prop :=
  ∀ (w : World) (sid : Nat) (s : Store),
    Model.transitionSystem.Reachable w
    → find w.stores sid = some s
    → Unique s.head.data ∧ CellsBounded s.head.data s.head.version

/-! ## Current snapshot capture and preservation -/

/-- Capturing a snapshot records the store's head and the reported term. -/
def StepCaptureMetadata : Prop :=
  ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
    storeOf w sid = .ok s
    → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next
    → find next.txs tid = some t
    → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term

/-- An accepted snapshot capture reports the store's head and global versions. -/
def StepCaptureCutValues : Prop :=
  ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
    storeOf w sid = .ok s
    → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next
    → version = s.head.version ∧ global = s.global

/-- A captured snapshot's head and term are unchanged by later records that do not end the
attempt. -/
def CaptureReplayPreservesMetadata : Prop :=
  ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat) (s : Store)
    (t : Tx) (tail : List Record),
    storeOf w sid = .ok s
    → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some capturedWorld
    → find capturedWorld.txs tid = some t
    → (∀ r ∈ tail, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
    → ∃ after snap,
        find final.txs tid = some after
        ∧ after.snapshot = some snap
        ∧ snap.current = s.head
        ∧ snap.term = term

/-- An attempt's captured snapshot is unchanged by later records that do not end it. -/
def ReplaySnapshotFixed : Prop :=
  ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
    find w.txs tid = some before
    → before.snapshot = some snap
    → (∀ r ∈ rs, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem w rs final
    → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap

/-! ## Per-map globally committed views -/

/-- Acquiring a map records its global view and checks the reported revision versions. -/
def StepMapCapture : Prop :=
  ∀ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
    (s : Store) (before after : Tx) (snap : Snapshot),
    storeOf w sid = .ok s
    → txOf w sid tid = .ok before
    → before.snapshot = some snap
    → Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
      = some next
    → find next.txs tid = some after
    → find after.globalViews map = some (captureGlobal s snap map)
      ∧ localVersion = (revision snap.current map).version
      ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version

/-- A map's captured global view is unchanged by later records that do not end the attempt. -/
def ReplayMapGlobalFixed : Prop :=
  ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
    (rs : List Record),
    find w.txs tid = some before
    → find before.globalViews map = some view
    → (∀ r ∈ rs, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem w rs final
    → ∃ after, find final.txs tid = some after ∧ find after.globalViews map = some view

/-- A map acquisition's global view and reported versions persist through later records that do
not end the attempt. -/
def CaptureReplayPreservesMap : Prop :=
  ∀ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
    (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
    (tail : List Record),
    storeOf w sid = .ok s
    → txOf w sid tid = .ok before
    → before.snapshot = some snap
    → Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
      = some capturedWorld
    → find capturedWorld.txs tid = some capturedTx
    → (∀ r ∈ tail, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
    → ∃ after,
        find final.txs tid = some after
        ∧ find after.globalViews map = some (captureGlobal s snap map)
        ∧ localVersion = (revision snap.current map).version
        ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version

/-- The global view of a map not yet created is the empty frame. -/
def CaptureGlobalPlaceholder : Prop :=
  ∀ (s : Store) (snap : Snapshot) (map : String),
    find snap.current.births map = none → (captureGlobal s snap map).frame = {}

/-- The global view of an existing map is the store's global cut. -/
def CaptureGlobalCommitted : Prop :=
  ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
    find snap.current.births map = some birth
    → (captureGlobal s snap map).frame = atCut s s.global

/-- A global read returns the captured view's value, and that view is empty or a store's global
cut with no cell newer than it. -/
def StepGlobalReadFromCapturedMap : Prop :=
  ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
    (t : Tx) (view : GlobalView),
    txOf w sid tid = .ok t
    → find t.globalViews map = some view
    → Model.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next
    → value = (find view.frame.data (map, key)).map Cell.value
      ∧ (view.frame = {}
          ∨ ∃ origin : Store,
              view.frame = atCut origin origin.global
              ∧ view.frame.version = origin.global
              ∧ CellsBounded view.frame.data origin.global)

/-- A global presence test reflects the captured view, and that view is empty or a store's
global cut with no cell newer than it. -/
def StepGlobalHasFromCapturedMap : Prop :=
  ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
    (view : GlobalView),
    txOf w sid tid = .ok t
    → find t.globalViews map = some view
    → Model.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next
    → value = (find view.frame.data (map, key)).isSome
      ∧ (view.frame = {}
          ∨ ∃ origin : Store,
              view.frame = atCut origin origin.global
              ∧ view.frame.version = origin.global
              ∧ CellsBounded view.frame.data origin.global)

/-! ## Compaction, rollback, and invalidated attempts -/

/-- Compacting beyond the head leaves the store unchanged. -/
def CompactAboveHeadNoop : Prop :=
  ∀ (s : Store) (v : Nat), s.head.version < v → compactStore s v = s

/-- Rollback keeps every frame at or below the global version. -/
def RollbackKeepsPrefix : Prop :=
  ∀ (s : Store) (v term : Nat) (f : Frame),
    f ∈ s.history → f.version ≤ s.global → f ∈ (rollbackStore s v term).history

/-- Rollback discards every frame above the requested version. -/
def RollbackDiscardsSuffix : Prop :=
  ∀ (s : Store) (v term : Nat) (f : Frame),
    v < f.version → s.global ≤ v → f ∉ (rollbackStore s v term).history

/-- Rollback preserves the data at every cut at or below the global version. -/
def DurableCutSurvivesRollback : Prop :=
  ∀ (s : Store) (v term cut : Nat),
    cut ≤ s.global
    → s.global ≤ v
    → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data

/-- An attempt whose snapshot term differs from the store's cannot apply. -/
def StaleTermCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot),
    t.snapshot = some snap → s.term ≠ snap.term → canApply s t = false

/-- An attempt whose acquired map revision is no longer on the branch cannot apply. -/
def DiscardedHandleCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    → (m, view) ∈ t.globalViews
    → (∀ f ∈ s.history, (revision f m == revision snap.current m) = false)
    → canApply s t = false

/-- An attempt whose acquired map creation is no longer on the branch cannot apply. -/
def DiscardedBirthCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    → (m, view) ∈ t.globalViews
    → (∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false)
    → canApply s t = false

/-- A map revised before the global cut's revision is unavailable. -/
def CompactedMapUnavailable : Prop :=
  ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
    find f.births m = some birth
    → (revision f m).version < (revision (atCut s s.global) m).version
    → mapAvailable s f m = false

/-- A map that does not exist, has no data, and was never revised is available. -/
def AbsentMapAvailable : Prop :=
  ∀ (s : Store) (f : Frame) (m : String),
    find f.births m = none
    → image f.data m = []
    → find f.revisions m = none
    → mapAvailable s f m = true

/-- An available map that does not exist has no values. -/
def AbsentPlaceholderHasNoValues : Prop :=
  ∀ (s : Store) (f : Frame) (m key : String),
    find f.births m = none → mapAvailable s f m = true → find f.data (m, key) = none

end Kv.Properties
