-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants

@[expose] public section

/-!
# Human-reviewed KV properties

Review these statements with the definitions in `Kv/Model/`, `Kv/Model.lean`, and
`Kv/Properties/`. Each claim is a `Prop`; `Kv.Proof` proves every one of them.
Each claim with premises has a `Witness` claim that its premises can hold.
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

/-- Witness: a key can be neither staged nor committed. -/
def AbsentReadWitness : Prop :=
  ∃ (db : DB String String String) (ws : Writes String String String)
    (a : Addr String String),
    find ws a = none ∧ find db a = none

/-- Staging a write at one address does not change reads at another. -/
def StagedNoninterference : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
    (a b : Addr M K) (v : Option V),
    a ≠ b → valueAt db (set ws a v) b = valueAt db ws b

/-- Witness: two addresses can differ. -/
def StagedNoninterferenceWitness : Prop :=
  ∃ a b : Addr String String, a ≠ b

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

/-- Witness: an address can be unwritten. -/
def PublicationNoninterferenceWitness : Prop :=
  ∃ (ws : Writes String String String) (a : Addr String String), find ws a = none

/-- Publishing preserves key uniqueness. -/
def PublishUnique : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
    (ws : Writes M K V),
    Unique db → Unique (publish db version ws)

/-- Witness: a database can have unique keys. -/
def PublishUniqueWitness : Prop :=
  ∃ db : DB String String String, Unique db

/-- Applying OCC-validated programs on a branch matches running them serially. -/
def BranchNormalSerializability : Prop :=
  ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V] (db final : DB M K V)
    (programs : List (AppliedProgram M K V)),
    BranchExecution db programs final → serialBranch db programs = some final

/-- Witness: a nonempty branch of applied programs exists. -/
def BranchNormalSerializabilityWitness : Prop :=
  ∃ (db final : DB String String String)
    (programs : List (AppliedProgram String String String)),
    BranchExecution db programs final ∧ programs ≠ []

/-- Applying an attempt publishes its entire write set at the next version. -/
def ApplyAtomic : Prop :=
  ∀ (s : Store) (writes : Pending),
    (advance s writes).head.data = publish s.head.data (s.head.version + 1) writes

/-! ## Serial snapshot runs and normal-view serializability -/

/-- An attempt's operation log runs serially on its captured snapshot to its staged writes. -/
def TransactionSnapshotSerial : Prop :=
  ∀ (t : Tx) (snap : Snapshot),
    t.snapshot = some snap
    → serialRun snap.current.data [] t.normal.log = some t.normal.writes

/-- Witness: an attempt with a snapshot can have a nonempty log. -/
def TransactionSnapshotSerialWitness : Prop :=
  ∃ (t : Tx) (snap : Snapshot), t.snapshot = some snap ∧ t.normal.log ≠ []

/-- An attempt that may apply runs serially on the current head to the same staged writes. -/
def TransactionApplicationSerial : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot),
    t.snapshot = some snap
    → canApply s t = true
    → serialRun s.head.data [] t.normal.log = some t.normal.writes

/-- Witness: an attempt with a nonempty log can apply. -/
def TransactionApplicationSerialWitness : Prop :=
  ∃ (s : Store) (t : Tx) (snap : Snapshot),
    t.snapshot = some snap ∧ canApply s t = true ∧ t.normal.log ≠ []

/-- A branch of applied attempts matches running their logs serially from the start. -/
def ExecutableBranchSerializability : Prop :=
  ∀ (s final : Store) (ts : List Tx),
    AppliedBranch s ts final
    → serialTransactions s.head.data s.head.version ts = some final.head.data

/-- Witness: a nonempty branch of applied attempts exists. -/
def ExecutableBranchSerializabilityWitness : Prop :=
  ∃ (s final : Store) (ts : List Tx), AppliedBranch s ts final ∧ ts ≠ []

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

/-- Witness: an accepted nonempty segment can keep a store alive. -/
def ReplaySegmentSerializabilityWitness : Prop :=
  ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
    find w.stores sid = some s
    ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
    ∧ CCF.Execution.Run Model.transitionSystem w rs final
    ∧ rs ≠ []

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

/-- Witness: a reachable world can have a live store. -/
def ReachableStoreInvariantsWitness : Prop :=
  ∃ (w : World) (sid : Nat) (s : Store),
    Model.transitionSystem.Reachable w ∧ find w.stores sid = some s

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head. -/
def ReachableStoreDataInvariants : Prop :=
  ∀ (w : World) (sid : Nat) (s : Store),
    Model.transitionSystem.Reachable w
    → find w.stores sid = some s
    → Unique s.head.data ∧ CellsBounded s.head.data s.head.version

/-- Witness: a reachable world can have a live store. -/
def ReachableStoreDataInvariantsWitness : Prop :=
  ∃ (w : World) (sid : Nat) (s : Store),
    Model.transitionSystem.Reachable w ∧ find w.stores sid = some s

/-! ## Current snapshot capture and preservation -/

/-- Capturing a snapshot records the store's head and the reported term. -/
def StepCaptureMetadata : Prop :=
  ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
    storeOf w sid = .ok s
    → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next
    → find next.txs tid = some t
    → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term

/-- Witness: a snapshot capture can be accepted. -/
def StepCaptureMetadataWitness : Prop :=
  ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
    storeOf w sid = .ok s
    ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next
    ∧ find next.txs tid = some t

/-- An accepted snapshot capture reports the store's head and global versions. -/
def StepCaptureCutValues : Prop :=
  ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
    storeOf w sid = .ok s
    → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next
    → version = s.head.version ∧ global = s.global

/-- Witness: a snapshot capture can be accepted. -/
def StepCaptureCutValuesWitness : Prop :=
  ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
    storeOf w sid = .ok s
    ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some next

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

/-- Witness: a snapshot capture can be followed by an accepted nonempty run that keeps the attempt. -/
def CaptureReplayPreservesMetadataWitness : Prop :=
  ∃ (w capturedWorld final : World) (sid tid version global term seq : Nat) (s : Store)
    (t : Tx) (tail : List Record),
    storeOf w sid = .ok s
    ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
      = some capturedWorld
    ∧ find capturedWorld.txs tid = some t
    ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
    ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
    ∧ tail ≠ []

/-- An attempt's captured snapshot is unchanged by later records that do not end it. -/
def ReplaySnapshotFixed : Prop :=
  ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
    find w.txs tid = some before
    → before.snapshot = some snap
    → (∀ r ∈ rs, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem w rs final
    → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap

/-- Witness: an attempt with a snapshot can be followed by an accepted nonempty run that keeps it. -/
def ReplaySnapshotFixedWitness : Prop :=
  ∃ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
    find w.txs tid = some before
    ∧ before.snapshot = some snap
    ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
    ∧ CCF.Execution.Run Model.transitionSystem w rs final
    ∧ rs ≠ []

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

/-- Witness: a map acquisition can be accepted. -/
def StepMapCaptureWitness : Prop :=
  ∃ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
    (s : Store) (before after : Tx) (snap : Snapshot),
    storeOf w sid = .ok s
    ∧ txOf w sid tid = .ok before
    ∧ before.snapshot = some snap
    ∧ Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
      = some next
    ∧ find next.txs tid = some after

/-- A map's captured global view is unchanged by later records that do not end the attempt. -/
def ReplayMapGlobalFixed : Prop :=
  ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
    (rs : List Record),
    find w.txs tid = some before
    → find before.globalViews map = some view
    → (∀ r ∈ rs, AttemptEvent tid r.event)
    → CCF.Execution.Run Model.transitionSystem w rs final
    → ∃ after, find final.txs tid = some after ∧ find after.globalViews map = some view

/-- Witness: an attempt with an acquired map can be followed by an accepted nonempty run that keeps it. -/
def ReplayMapGlobalFixedWitness : Prop :=
  ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
    (rs : List Record),
    find w.txs tid = some before
    ∧ find before.globalViews map = some view
    ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
    ∧ CCF.Execution.Run Model.transitionSystem w rs final
    ∧ rs ≠ []

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

/-- Witness: a map acquisition can be followed by an accepted nonempty run that keeps the attempt. -/
def CaptureReplayPreservesMapWitness : Prop :=
  ∃ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
    (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
    (tail : List Record),
    storeOf w sid = .ok s
    ∧ txOf w sid tid = .ok before
    ∧ before.snapshot = some snap
    ∧ Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
      = some capturedWorld
    ∧ find capturedWorld.txs tid = some capturedTx
    ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
    ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
    ∧ tail ≠ []

/-- The global view of a map not yet created is the empty frame. -/
def CaptureGlobalPlaceholder : Prop :=
  ∀ (s : Store) (snap : Snapshot) (map : String),
    find snap.current.births map = none → (captureGlobal s snap map).frame = {}

/-- Witness: a snapshot can lack a map. -/
def CaptureGlobalPlaceholderWitness : Prop :=
  ∃ (snap : Snapshot) (map : String), find snap.current.births map = none

/-- The global view of an existing map is the store's global cut. -/
def CaptureGlobalCommitted : Prop :=
  ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
    find snap.current.births map = some birth
    → (captureGlobal s snap map).frame = atCut s s.global

/-- Witness: a snapshot can contain a map. -/
def CaptureGlobalCommittedWitness : Prop :=
  ∃ (snap : Snapshot) (map : String) (birth : Stamp),
    find snap.current.births map = some birth

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

/-- Witness: a global read of a committed value can be accepted. -/
def StepGlobalReadFromCapturedMapWitness : Prop :=
  ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
    (view : GlobalView),
    txOf w sid tid = .ok t
    ∧ find t.globalViews map = some view
    ∧ Model.transitionSystem.step w ⟨seq, .get sid tid map key (some value) true⟩
      = some next

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

/-- Witness: a global presence test of a committed key can be accepted. -/
def StepGlobalHasFromCapturedMapWitness : Prop :=
  ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx) (view : GlobalView),
    txOf w sid tid = .ok t
    ∧ find t.globalViews map = some view
    ∧ Model.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩ = some next

/-! ## Compaction, rollback, and invalidated attempts -/

/-- Compacting beyond the head leaves the store unchanged. -/
def CompactAboveHeadNoop : Prop :=
  ∀ (s : Store) (v : Nat), s.head.version < v → compactStore s v = s

/-- Witness: a version can be beyond the head. -/
def CompactAboveHeadNoopWitness : Prop :=
  ∃ (s : Store) (v : Nat), s.head.version < v

/-- Rollback keeps every frame at or below the global version. -/
def RollbackKeepsPrefix : Prop :=
  ∀ (s : Store) (v term : Nat) (f : Frame),
    f ∈ s.history → f.version ≤ s.global → f ∈ (rollbackStore s v term).history

/-- Witness: a nonempty frame can be on the branch at or below the global version. -/
def RollbackKeepsPrefixWitness : Prop :=
  ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ []

/-- Rollback discards every frame above the requested version. -/
def RollbackDiscardsSuffix : Prop :=
  ∀ (s : Store) (v term : Nat) (f : Frame),
    v < f.version → s.global ≤ v → f ∉ (rollbackStore s v term).history

/-- Witness: a frame on the branch can be above a version at or above the global version. -/
def RollbackDiscardsSuffixWitness : Prop :=
  ∃ (s : Store) (v : Nat) (f : Frame), f ∈ s.history ∧ v < f.version ∧ s.global ≤ v

/-- Rollback preserves the data at every cut at or below the global version. -/
def DurableCutSurvivesRollback : Prop :=
  ∀ (s : Store) (v term cut : Nat),
    cut ≤ s.global
    → s.global ≤ v
    → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data

/-- Witness: a nonempty cut can be at or below the global version. -/
def DurableCutSurvivesRollbackWitness : Prop :=
  ∃ (s : Store) (v cut : Nat), cut ≤ s.global ∧ s.global ≤ v ∧ (atCut s cut).data ≠ []

/-- An attempt whose snapshot term differs from the store's cannot apply. -/
def StaleTermCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot),
    t.snapshot = some snap → s.term ≠ snap.term → canApply s t = false

/-- Witness: an attempt's snapshot term can differ from the store's. -/
def StaleTermCannotApplyWitness : Prop :=
  ∃ (s : Store) (t : Tx) (snap : Snapshot), t.snapshot = some snap ∧ s.term ≠ snap.term

/-- An attempt whose acquired map revision is no longer on the branch cannot apply. -/
def DiscardedHandleCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    → (m, view) ∈ t.globalViews
    → (∀ f ∈ s.history, (revision f m == revision snap.current m) = false)
    → canApply s t = false

/-- Witness: an attempt can hold a map whose revision is no longer on the branch. -/
def DiscardedHandleCannotApplyWitness : Prop :=
  ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    ∧ (m, view) ∈ t.globalViews
    ∧ (∀ f ∈ s.history, (revision f m == revision snap.current m) = false)

/-- An attempt whose acquired map creation is no longer on the branch cannot apply. -/
def DiscardedBirthCannotApply : Prop :=
  ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    → (m, view) ∈ t.globalViews
    → (∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false)
    → canApply s t = false

/-- Witness: an attempt can hold a map whose creation is no longer on the branch. -/
def DiscardedBirthCannotApplyWitness : Prop :=
  ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
    t.snapshot = some snap
    ∧ (m, view) ∈ t.globalViews
    ∧ (∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false)

/-- A map revised before the global cut's revision is unavailable. -/
def CompactedMapUnavailable : Prop :=
  ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
    find f.births m = some birth
    → (revision f m).version < (revision (atCut s s.global) m).version
    → mapAvailable s f m = false

/-- Witness: a map can be revised before the global cut's revision. -/
def CompactedMapUnavailableWitness : Prop :=
  ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
    find f.births m = some birth
    ∧ (revision f m).version < (revision (atCut s s.global) m).version

/-- A map that does not exist, has no data, and was never revised is available. -/
def AbsentMapAvailable : Prop :=
  ∀ (s : Store) (f : Frame) (m : String),
    find f.births m = none
    → image f.data m = []
    → find f.revisions m = none
    → mapAvailable s f m = true

/-- Witness: a map can be absent, empty, and unrevised. -/
def AbsentMapAvailableWitness : Prop :=
  ∃ (f : Frame) (m : String),
    find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none

/-- An available map that does not exist has no values. -/
def AbsentPlaceholderHasNoValues : Prop :=
  ∀ (s : Store) (f : Frame) (m key : String),
    find f.births m = none → mapAvailable s f m = true → find f.data (m, key) = none

/-- Witness: an absent map can be available. -/
def AbsentPlaceholderHasNoValuesWitness : Prop :=
  ∃ (s : Store) (f : Frame) (m : String),
    find f.births m = none ∧ mapAvailable s f m = true

end Kv.Properties
