module

public import consistency.Proofs.Observations

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.LedgerIdentity

open Model Properties Observations

theorem at_bounds {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : 0 < index ∧ index ≤ xs.length := by
  by_cases zero : index = 0
  · simp [at?, zero] at found
  · have lookup : xs[index - 1]? = some value := by simpa [at?, zero] using found
    have bound := (List.getElem?_eq_some_iff.mp lookup).1
    omega

theorem at_prefix {α : Type} {before after : List α} (isPrefix : before <+: after)
    {index : Nat} {value : α} (found : at? before index = some value)
    : at? after index = some value := by
  have bounds := at_bounds found
  obtain ⟨tail, rfl⟩ := isPrefix
  simpa [at?, Nat.ne_of_gt bounds.1,
    List.getElem?_append_left (by omega : index - 1 < before.length)]
    using found

theorem take_of_prefix {α : Type} {before after : List α} (isPrefix : before <+: after)
    (count : Nat) (bound : count ≤ before.length)
    : after.take count = before.take count := by
  obtain ⟨tail, rfl⟩ := isPrefix
  exact List.take_append_of_le_length bound

theorem at_take {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : at? (xs.take index) index = some value := by
  have bounds := at_bounds found
  simpa [at?, Nat.ne_of_gt bounds.1, List.getElem?_take,
    show index - 1 < index by omega]
    using found

theorem at_snoc {α : Type} {xs : List α} {value entry : α} {index : Nat}
    (found : at? (xs ++ [entry]) index = some value)
    : at? xs index = some value ∨ (index = xs.length + 1 ∧ value = entry) := by
  have bounds := at_bounds found
  by_cases inside : index ≤ xs.length
  · left
    simpa [at?, Nat.ne_of_gt bounds.1,
      List.getElem?_append_left (by omega : index - 1 < xs.length)] using found
  · right
    have endpoint : index = xs.length + 1 := by simp at bounds; omega
    subst index
    exact ⟨rfl, by simpa [at?] using found.symm⟩

def Anchored (branches : List (List Entry)) : Prop :=
  ∀ branch ledger,
    at? branches branch = some ledger
    → ∀ seqno entry,
        at? ledger seqno = some entry
        → entry.view ≤ branch
          ∧ ∃ origin, at? branches entry.view = some origin ∧ ledger.take seqno <+: origin

theorem anchored_modify (branches : List (List Entry)) (anchored : Anchored branches)
    (branch : Nat) (entry : Entry) (view : entry.view = branch)
    (positive : 0 < branch)
    : Anchored (branches.modify (branch - 1) (· ++ [entry])) := by
  intro index ledger found seqno value atEntry
  have bounds := at_bounds found
  have lookup : (branches.modify (branch - 1) (· ++ [entry]))[index - 1]? =
      some ledger := by simpa [at?, Nat.ne_of_gt bounds.1] using found
  rw [List.getElem?_modify] at lookup
  obtain ⟨oldLedger, oldLookup, same⟩ := Option.map_eq_some_iff.mp lookup
  have oldFound : at? branches index = some oldLedger := by
    simpa [at?, Nat.ne_of_gt bounds.1] using oldLookup
  by_cases selected : branch - 1 = index - 1
  · simp only [selected, ite_true] at same
    subst ledger
    rcases at_snoc atEntry with old | ⟨endpoint, equalEntry⟩
    · obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ oldFound _ _ old
      obtain ⟨extended, extendedFound, extension⟩ :=
        Structural.branches_modify branches (branch - 1) entry _ _ originFound
      refine ⟨bound, extended, extendedFound, ?_⟩
      rw [List.take_append_of_le_length (at_bounds old).2]
      exact isPrefix.trans extension
    · subst value
      have equal : branch = index := by omega
      refine ⟨by omega, oldLedger ++ [entry], ?_, ?_⟩
      · simpa [view, equal] using found
      · exact List.take_prefix _ _
  · simp only [selected, ite_false] at same
    subst ledger
    obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ oldFound _ _ atEntry
    obtain ⟨extended, extendedFound, extension⟩ :=
      Structural.branches_modify branches (branch - 1) entry _ _ originFound
    exact ⟨bound, extended, extendedFound, isPrefix.trans extension⟩

theorem anchored_elect (branches : List (List Entry)) (anchored : Anchored branches)
    {branch : Nat} {ledger : List Entry} (found : at? branches branch = some ledger)
    (count : Nat)
    : Anchored (branches ++ [ledger.take count]) := by
  intro index candidate listed seqno entry atEntry
  rcases at_snoc listed with old | ⟨endpoint, rfl⟩
  · obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ old _ _ atEntry
    exact ⟨bound, origin, at_prefix (by simp) originFound, isPrefix⟩
  · have oldEntry := at_prefix (List.take_prefix count ledger) atEntry
    obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ oldEntry
    refine ⟨by have := (at_bounds found).2; omega,
      origin, at_prefix (by simp) originFound, ?_⟩
    rw [take_of_prefix (List.take_prefix count ledger) seqno (at_bounds atEntry).2] at isPrefix
    exact isPrefix

theorem active_positive (state : State) {branch : Nat}
    (active : activeBranch state branch = true)
    : 0 < branch := by
  simp [activeBranch] at active
  omega

theorem step_anchored (before after : State) (action : Action)
    (anchored : Anchored before.branches)
    (transition : step before action = some after)
    : Anchored after.branches := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact anchored)
      | (solve | apply anchored_modify _ anchored _ _ rfl; apply active_positive before; assumption)
      | (solve | apply anchored_elect _ anchored; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem anchored_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Anchored state.branches := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      intro branch ledger found seqno entry atEntry
      have empty : ledger = [] :=
        (List.mem_replicate.mp (mem_of_at? found)).2
      simp [empty, at?] at atEntry
  | @step before after action _ transition ih =>
      exact step_anchored before after action ih transition

def Snapshot (branches : List (List Entry)) (kind : TxType) (tx : TxContent)
    (observed : List TxContent) (txid : TxID)
    : Prop :=
  ∃ ledger,
    at? branches txid.view = some ledger
    ∧ observed = writes (ledger.take txid.seqno)
    ∧ ∃ entry,
        at? ledger txid.seqno = some entry
        ∧ entry.view = txid.view
        ∧ (kind = .rw → entry.tx = some tx)

def Snapshots (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → Snapshot branches kind tx observed txid

theorem snapshot_source (branches : List (List Entry)) (anchored : Anchored branches)
    {branch seqno : Nat} {ledger : List Entry} {entry : Entry}
    (found : at? branches branch = some ledger) (atEntry : at? ledger seqno = some entry)
    (kind : TxType) (tx : TxContent) (txMatches : kind = .rw → entry.tx = some tx)
    : Snapshot branches kind tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩ := by
  obtain ⟨_, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ atEntry
  have length : seqno ≤ (ledger.take seqno).length := by
    simp [List.length_take, Nat.min_eq_left (at_bounds atEntry).2]
  refine ⟨
    origin,
    originFound,
    ?_,
    entry,
    at_prefix isPrefix (at_take atEntry),
    rfl,
    txMatches
  ⟩
  rw [take_of_prefix isPrefix seqno length, List.take_take, Nat.min_self]

theorem snapshot_mono {before after : List (List Entry)}
    (extension : Structural.BranchExtension before after)
    {kind : TxType} {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (snapshot : Snapshot before kind tx observed txid)
    : Snapshot after kind tx observed txid := by
  obtain ⟨ledger, found, obs, entry, atEntry, view, txMatches⟩ := snapshot
  obtain ⟨extended, extendedFound, isPrefix⟩ := extension _ _ found
  exact ⟨
    extended,
    extendedFound,
    by rw [take_of_prefix isPrefix txid.seqno (at_bounds atEntry).2]; exact obs,
    entry,
    at_prefix isPrefix atEntry,
    view,
    txMatches
  ⟩

theorem snapshots_mono (before after : List (List Entry)) (history : List Event)
    (snapshots : Snapshots before history)
    (extension : Structural.BranchExtension before after)
    : Snapshots after history := by
  intro index kind tx observed txid found
  exact snapshot_mono extension (snapshots _ _ _ _ _ found)

theorem snapshots_snoc (branches : List (List Entry)) (history : List Event)
    (event : Event) (snapshots : Snapshots branches history)
    (newResponse
      : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response kind tx observed txid
          → Snapshot branches kind tx observed txid)
    : Snapshots branches (history ++ [event]) := by
  intro index kind tx observed txid found
  rcases History.lookup_snoc found with ⟨_, old⟩ | ⟨_, current⟩
  · exact snapshots _ _ _ _ _ old
  · exact newResponse _ _ _ _ current

theorem snapshots_response (branches : List (List Entry)) (history : List Event)
    (snapshots : Snapshots branches history) {kind : TxType} {tx : TxContent}
    {observed : List TxContent} {txid : TxID}
    (snapshot : Snapshot branches kind tx observed txid)
    : Snapshots branches (history ++ [.response kind tx observed txid]) := by
  apply snapshots_snoc _ _ _ snapshots
  intro _ _ _ _ same
  cases same
  exact snapshot

theorem at_last {α : Type} {ledger : List α} {entry : α}
    (found : ledger.getLast? = some entry)
    : at? ledger ledger.length = some entry := by
  cases ledger with
  | nil => simp at found
  | cons head tail => simpa [at?, List.getLast?_eq_getElem?] using found

theorem snapshot_last (branches : List (List Entry)) (anchored : Anchored branches)
    {branch : Nat} {ledger : List Entry} {entry : Entry}
    (found : at? branches branch = some ledger) (last : ledger.getLast? = some entry)
    (tx : TxContent)
    : Snapshot branches .ro tx (writes ledger) ⟨entry.view, ledger.length⟩ := by
  have snapshot := snapshot_source branches anchored found (at_last last) .ro tx (by simp)
  simpa using snapshot

theorem step_snapshots (before after : State) (action : Action)
    (anchored : Anchored before.branches)
    (snapshots : Snapshots before.branches before.history)
    (transition : step before action = some after)
    : Snapshots after.branches after.history := by
  have extension := Structural.step_branches before after action transition
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact snapshots_mono _ _ _ snapshots extension)
      | (solve | apply snapshots_snoc _ _ _ snapshots; simp)
      | (solve | apply snapshots_response _ _ snapshots; apply snapshot_source _ anchored
          <;> first | assumption | simp_all)
      | (solve | apply snapshots_response _ _ snapshots; apply snapshot_last _ anchored
          <;> assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem snapshots_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Snapshots state.branches state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [Snapshots, initialState]
  | @step before after action reachable transition ih =>
      exact step_snapshots before after action
        (anchored_reachable reachable) ih transition

theorem unique_txs
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ responsesOf state.history .rw,
          ∀ right ∈ responsesOf state.history .rw,
            left.2.txid = right.2.txid → left.2.tx = right.2.tx := by
  intro trace state member left first right second same
  obtain ⟨leftKind, firstLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp first
  obtain ⟨rightKind, secondLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp second
  have snapshots := snapshots_reachable (trace.reachable member)
  obtain ⟨firstLedger, firstFound, _, firstEntry, firstAt, _, firstTx⟩ :=
    snapshots _ _ _ _ _ firstLookup
  obtain ⟨secondLedger, secondFound, _, secondEntry, secondAt, _, secondTx⟩ :=
    snapshots _ _ _ _ _ secondLookup
  rw [← same, firstFound] at secondFound
  cases secondFound
  rw [← same, firstAt] at secondAt
  cases secondAt
  exact Option.some.inj ((firstTx leftKind).symm.trans (secondTx rightKind))

theorem same_observations
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ responses state.history,
          ∀ right ∈ responses state.history,
            left.2.txid = right.2.txid → left.2.observed = right.2.observed := by
  intro trace state member left first right second same
  have snapshots := snapshots_reachable (trace.reachable member)
  obtain ⟨firstLedger, firstFound, firstObs, _⟩ :=
    snapshots _ _ _ _ _ ((History.mem_responses_iff _ _).mp first)
  obtain ⟨secondLedger, secondFound, secondObs, _⟩ :=
    snapshots _ _ _ _ _ ((History.mem_responses_iff _ _).mp second)
  rw [← same, firstFound] at secondFound
  cases secondFound
  rw [firstObs, secondObs, same]

end consistency.Proofs.LedgerIdentity
