module

public import consistency.Proofs.Statuses

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.InvalidObservations

open Model Properties Observations LedgerIdentity Commitment Statuses

def UniqueWrites (branches : List (List Entry)) : Prop :=
  ∀ left ∈ branches,
  ∀ right ∈ branches,
    ∀ (leftSeq rightSeq : Nat) (leftEntry rightEntry : Entry) (tx : TxContent),
      at? left leftSeq = some leftEntry
      → at? right rightSeq = some rightEntry
      → leftEntry.tx = some tx
      → rightEntry.tx = some tx
      → leftEntry.view = rightEntry.view ∧ leftSeq = rightSeq

theorem modified_location (branches : List (List Entry)) (branch : Nat)
    (target : List Entry) (entry : Entry) (found : at? branches branch = some target)
    {ledger : List Entry} (member : ledger ∈ branches.modify (branch - 1) (· ++ [entry]))
    {seqno : Nat} {value : Entry} (atEntry : at? ledger seqno = some value)
    : (∃ source ∈ branches, at? source seqno = some value)
      ∨ (seqno = target.length + 1 ∧ value = entry) := by
  have classification : ∀ candidate ∈ branches.modify (branch - 1) (· ++ [entry]),
      candidate ∈ branches ∨ candidate = target ++ [entry] := by
    apply ViewOrder.forall_modify_at
    · intro candidate listed
      exact Or.inl listed
    · intro candidate lookup
      have oldLookup : branches[branch - 1]? = some target := by
        simpa [at?, Nat.ne_of_gt (at_bounds found).1] using found
      rw [oldLookup] at lookup
      cases lookup
      exact Or.inr rfl
  rcases classification ledger member with old | changed
  · exact Or.inl ⟨ledger, old, atEntry⟩
  · rw [changed] at atEntry
    rcases at_snoc atEntry with old | last
    · exact Or.inl ⟨target, mem_of_at? found, old⟩
    · exact Or.inr last

theorem unique_modify (branches : List (List Entry)) (unique : UniqueWrites branches)
    (branch : Nat) (target : List Entry) (entry : Entry)
    (found : at? branches branch = some target)
    (fresh
      : ∀ tx, entry.tx = some tx → ∀ ledger ∈ branches, ∀ old ∈ ledger, old.tx ≠ some tx)
    : UniqueWrites (branches.modify (branch - 1) (· ++ [entry])) := by
  intro left first right second leftSeq rightSeq leftEntry rightEntry tx leftAt rightAt leftTx rightTx
  rcases modified_location branches branch target entry found first leftAt with
    ⟨oldLeft, oldLeftMember, oldLeftAt⟩ | ⟨leftLast, leftNew⟩
  · rcases modified_location branches branch target entry found second rightAt with
      ⟨oldRight, oldRightMember, oldRightAt⟩ | ⟨_, rightNew⟩
    · exact unique _ oldLeftMember _ oldRightMember _ _ _ _ _ oldLeftAt oldRightAt leftTx rightTx
    · subst rightEntry
      exact False.elim (fresh tx rightTx oldLeft oldLeftMember leftEntry (mem_of_at? oldLeftAt) leftTx)
  · rcases modified_location branches branch target entry found second rightAt with
      ⟨oldRight, oldRightMember, oldRightAt⟩ | ⟨rightLast, rightNew⟩
    · subst leftEntry
      exact False.elim (fresh tx leftTx oldRight oldRightMember rightEntry (mem_of_at? oldRightAt) rightTx)
    · subst leftEntry
      subst rightEntry
      exact ⟨rfl, leftLast.trans rightLast.symm⟩

theorem active_ledger (state : State) {branch : Nat}
    (active : activeBranch state branch = true)
    : ∃ ledger, at? state.branches branch = some ledger := by
  have positive := active_positive state active
  have bound : branch ≤ state.branches.length := by
    simp [activeBranch] at active
    omega
  have inside : branch - 1 < state.branches.length := by omega
  exact ⟨
    state.branches[branch - 1]'inside,
    by simp [at?, Nat.ne_of_gt positive, List.getElem?_eq_getElem]
  ⟩

theorem unique_write (state : State)
    (unique : UniqueWrites state.branches) (branch : Nat) (tx : TxContent)
    (active : activeBranch state branch = true)
    (fresh : ∀ ledger ∈ state.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx)
    : UniqueWrites (appendEntry state branch ⟨branch, some tx⟩).branches := by
  obtain ⟨ledger, found⟩ := active_ledger state active
  apply unique_modify _ unique _ ledger _ found
  intro _ same
  cases same
  exact fresh

theorem unique_other (state : State)
    (unique : UniqueWrites state.branches) (branch : Nat)
    (active : activeBranch state branch = true)
    : UniqueWrites (appendEntry state branch ⟨branch, none⟩).branches := by
  obtain ⟨ledger, found⟩ := active_ledger state active
  apply unique_modify _ unique _ ledger _ found
  simp

theorem elected_location (branches : List (List Entry)) {target : List Entry}
    (targetMember : target ∈ branches) (count : Nat) {ledger : List Entry}
    (member : ledger ∈ branches ++ [target.take count]) {seqno : Nat} {entry : Entry}
    (found : at? ledger seqno = some entry)
    : ∃ source ∈ branches, at? source seqno = some entry := by
  rcases List.mem_append.mp member with old | new
  · exact ⟨ledger, old, found⟩
  · have same := List.mem_singleton.mp new
    subst ledger
    exact ⟨target, targetMember, at_prefix (List.take_prefix _ _) found⟩

theorem unique_elect (branches : List (List Entry)) (unique : UniqueWrites branches)
    {ledger : List Entry} (member : ledger ∈ branches) (count : Nat)
    : UniqueWrites (branches ++ [ledger.take count]) := by
  intro left first right second leftSeq rightSeq leftEntry rightEntry tx leftAt rightAt leftTx rightTx
  obtain ⟨oldLeft, oldLeftMember, oldLeftAt⟩ := elected_location branches member count first leftAt
  obtain ⟨oldRight, oldRightMember, oldRightAt⟩ := elected_location branches member count second rightAt
  exact unique _ oldLeftMember _ oldRightMember _ _ _ _ _ oldLeftAt oldRightAt leftTx rightTx

theorem step_unique (before after : State) (action : Action)
    (unique : UniqueWrites before.branches)
    (transition : step before action = some after)
    : UniqueWrites after.branches := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact unique)
      | (solve | apply unique_write before unique <;> assumption)
      | (solve | apply unique_other before unique; assumption)
      | (solve | apply unique_elect _ unique; apply mem_of_at?; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem unique_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : UniqueWrites state.branches := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [UniqueWrites, initialState, List.mem_replicate, at?]
  | @step before after action _ transition ih =>
      exact step_unique before after action ih transition

def Excludes (branches : List (List Entry)) (committed invalid : TxID) : Prop :=
  ∀ origin,
    at? branches committed.view = some origin
    → ∀ entry,
        at? origin invalid.seqno = some entry
        → invalid.seqno ≤ committed.seqno
        → entry.view ≠ invalid.view

def Clean (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ committed ∈ statusIDs history .committed,
  ∀ invalid ∈ statusIDs history .invalid, Excludes branches committed invalid

theorem committed_origin (branches : List (List Entry)) (history : List Event)
    (current : Current branches history) (anchored : Anchored branches) {txid : TxID}
    (known : txid ∈ statusIDs history .committed)
    : ∃ origin,
        at? branches txid.view = some origin
        ∧ ∃ entry, at? origin txid.seqno = some entry := by
  obtain ⟨latest, latestFound, entry, atEntry, view⟩ := current txid known
  obtain ⟨_, origin, found, isPrefix⟩ := anchored _ _ latestFound _ _ atEntry
  exact ⟨origin, by simpa [view] using found, entry, at_prefix isPrefix (at_take atEntry)⟩

theorem at_of_prefix {α : Type} {before after : List α} (isPrefix : before <+: after)
    {index : Nat} {value : α} (found : at? after index = some value)
    (bound : index ≤ before.length)
    : at? before index = some value := by
  have positive := (at_bounds found).1
  obtain ⟨tail, rfl⟩ := isPrefix
  simpa [at?, Nat.ne_of_gt positive,
    List.getElem?_append_left (by omega : index - 1 < before.length)]
    using found

theorem clean_mono (before after : List (List Entry)) (history : List Event)
    (clean : Clean before history) (current : Current before history)
    (anchored : Anchored before) (extension : Structural.BranchExtension before after)
    : Clean after history := by
  intro committed known invalid invalidKnown origin originFound entry atEntry bound
  obtain ⟨oldOrigin, oldFound, endpoint, atEndpoint⟩ :=
    committed_origin before history current anchored known
  obtain ⟨extended, extendedFound, isPrefix⟩ := extension _ _ oldFound
  rw [originFound] at extendedFound
  cases extendedFound
  have oldEntry := at_of_prefix isPrefix atEntry
    (Nat.le_trans bound (at_bounds atEndpoint).2)
  exact clean committed known invalid invalidKnown oldOrigin oldFound entry oldEntry bound

theorem clean_snoc (branches : List (List Entry)) (history : List Event) (event : Event)
    (clean : Clean branches history)
    (newCommit
      : ∀ committed,
          event = .status committed .committed
          → ∀ invalid ∈ statusIDs history .invalid, Excludes branches committed invalid)
    (newInvalid
      : ∀ invalid,
          event = .status invalid .invalid
          → ∀ committed ∈ statusIDs history .committed,
              Excludes branches committed invalid)
    : Clean branches (history ++ [event]) := by
  intro committed known invalid invalidKnown
  rcases (status_ids_snoc _ _ _ _).mp known with oldCommit | newCommitted
  · rcases (status_ids_snoc _ _ _ _).mp invalidKnown with oldInvalid | newInvalidated
    · exact clean committed oldCommit invalid oldInvalid
    · exact newInvalid invalid newInvalidated committed oldCommit
  · rcases (status_ids_snoc _ _ _ _).mp invalidKnown with oldInvalid | newInvalidated
    · exact newCommit committed newCommitted invalid oldInvalid
    · simp_all

theorem origin_entry_in_branch (branches : List (List Entry))
    (anchored : Anchored branches) {branch : Nat} {ledger origin : List Entry}
    {endpoint entry : Entry} {txid : TxID} {seqno : Nat}
    (ledgerFound : at? branches branch = some ledger)
    (endpointFound : at? ledger txid.seqno = some endpoint)
    (view : endpoint.view = txid.view)
    (originFound : at? branches txid.view = some origin)
    (entryFound : at? origin seqno = some entry) (bound : seqno ≤ txid.seqno)
    : at? ledger seqno = some entry := by
  obtain ⟨otherOrigin, otherFound, samePrefix⟩ :=
    anchored_prefix branches anchored ledgerFound endpointFound
  rw [view, originFound] at otherFound
  cases otherFound
  have inside := at_take_of_le entryFound bound
  rw [← samePrefix] at inside
  exact at_prefix (List.take_prefix _ _) inside

theorem clean_commit (state : State) (clean : Clean state.branches state.history)
    (anchored : Anchored state.branches) (txid : TxID)
    {ledger : List Entry} {endpoint : Entry}
    (latest : state.branches.getLast? = some ledger)
    (endpointFound : at? ledger txid.seqno = some endpoint)
    (view : endpoint.view = txid.view)
    (allowed
      : ∀ invalid ∈ statusIDs state.history .invalid,
          invalid.seqno ≤ txid.seqno
          → (match at? ledger invalid.seqno with
              | some entry => entry.view == invalid.view
              | none => false)
            = false)
    : Clean state.branches (state.history ++ [.status txid .committed]) := by
  apply clean_snoc _ _ _ clean
  · intro _ same
    cases same
    intro invalid known origin originFound entry entryFound bound sameView
    have actual := origin_entry_in_branch state.branches anchored (at_last latest)
      endpointFound view originFound entryFound bound
    have denied := allowed invalid known bound
    simp [actual, sameView] at denied
  · simp

theorem clean_invalidate (state : State) (clean : Clean state.branches state.history)
    (anchored : Anchored state.branches) (current : Current state.branches state.history)
    (txid : TxID) (allowed : mayInvalidate state txid = true)
    : Clean state.branches (state.history ++ [.status txid .invalid]) := by
  apply clean_snoc _ _ _ clean
  · simp
  · intro _ same
    cases same
    intro committed known origin originFound entry entryFound bound sameView
    obtain ⟨latest, latestFound, endpoint, endpointFound, view⟩ := current committed known
    have actual := origin_entry_in_branch state.branches anchored latestFound
      endpointFound view originFound entryFound bound
    have frontier := Nat.le_trans bound (frontier_bound state.history known)
    have denied : mayInvalidate state txid = false := by
      simp [mayInvalidate, last_of_at latestFound, actual, sameView,
        show ¬commitSeqno state.history < txid.seqno by omega,
        show ¬txid.seqno > commitSeqno state.history by omega]
    simp [denied] at allowed

theorem step_clean (before after : State) (action : Action)
    (clean : Clean before.branches before.history) (anchored : Anchored before.branches)
    (current : Current before.branches before.history)
    (transition : step before action = some after)
    : Clean after.branches after.history := by
  have extension := Structural.step_branches before after action transition
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact clean_mono _ _ _ clean current anchored extension)
      | (solve | apply clean_snoc _ _ _ clean <;> simp)
      | (solve | apply clean_commit before clean anchored <;> assumption)
      | (solve | apply clean_invalidate before clean anchored current; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem clean_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Clean state.branches state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [Clean, initialState, statusIDs]
  | @step before after action reachable transition ih =>
      exact step_clean before after action ih (anchored_reachable reachable)
        (current_reachable reachable) transition

theorem invalid_not_observed_by_committed
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ invalid ∈ responsesOf state.history .rw,
          ∀ observer ∈ committedResponses state.history .rw,
            invalid.1 ≠ observer.1
            → invalid.2.txid ∈ statusIDs state.history .invalid
            → invalid.2.tx ∉ observer.2.observed := by
  intro trace state member invalid first observer second _ invalidKnown observed
  have reachable := trace.reachable member
  have snapshots := snapshots_reachable reachable
  obtain ⟨invalidKind, invalidLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp first
  obtain ⟨invalidOrigin, invalidFound, _, invalidEntry, invalidAt, invalidView, invalidTx⟩ :=
    snapshots _ _ _ _ _ invalidLookup
  obtain ⟨observerKind, observerLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp
    (List.mem_filter.mp second).1
  obtain ⟨observerOrigin, observerFound, observerObs, _⟩ :=
    snapshots _ _ _ _ _ observerLookup
  rw [observerObs] at observed
  obtain ⟨observedEntry, inPrefix, observedTx⟩ := List.mem_filterMap.mp observed
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp inPrefix
  have prefixAt : at? (observerOrigin.take observer.2.txid.seqno) (index + 1) =
      some observedEntry := by simpa [at?] using lookup
  have observerAt := at_prefix (List.take_prefix _ _) prefixAt
  have bound : index + 1 ≤ observer.2.txid.seqno := by
    have := (at_bounds prefixAt).2
    simp only [List.length_take] at this
    omega
  obtain ⟨sameView, sameSeq⟩ := unique_reachable reachable
    invalidOrigin (mem_of_at? invalidFound) observerOrigin (mem_of_at? observerFound)
    _ _ _ _ _ invalidAt observerAt (invalidTx invalidKind) observedTx
  have committed : observer.2.txid ∈ statusIDs state.history .committed := by
    simpa using (List.mem_filter.mp second).2
  have excluded := clean_reachable reachable observer.2.txid committed
    invalid.2.txid invalidKnown observerOrigin observerFound observedEntry
    (by simpa [sameSeq] using observerAt) (by omega)
  exact excluded (sameView.symm.trans invalidView)

end consistency.Proofs.InvalidObservations
