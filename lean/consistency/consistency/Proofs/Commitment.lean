module

public import consistency.Proofs.LedgerIdentity

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Commitment

open Model Properties Observations LedgerIdentity

theorem at_take_of_le {α : Type} {xs : List α} {index count : Nat} {value : α}
    (found : at? xs index = some value) (bound : index ≤ count)
    : at? (xs.take count) index = some value := by
  have positive := (at_bounds found).1
  simpa [at?, Nat.ne_of_gt positive, List.getElem?_take,
    show index - 1 < count by omega]
    using found

theorem anchored_prefix (branches : List (List Entry)) (anchored : Anchored branches)
    {branch seqno : Nat} {ledger : List Entry} {entry : Entry}
    (found : at? branches branch = some ledger) (atEntry : at? ledger seqno = some entry)
    : ∃ origin,
        at? branches entry.view = some origin
        ∧ ledger.take seqno = origin.take seqno := by
  obtain ⟨_, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ atEntry
  refine ⟨origin, originFound, ?_⟩
  have bound : seqno ≤ (ledger.take seqno).length := by
    simp [List.length_take, Nat.min_eq_left (at_bounds atEntry).2]
  simpa [List.take_take] using (take_of_prefix isPrefix seqno bound).symm

theorem equal_prefixes (branches : List (List Entry)) (anchored : Anchored branches)
    {leftBranch rightBranch seqno : Nat} {left right : List Entry}
    {leftEntry rightEntry : Entry} (leftFound : at? branches leftBranch = some left)
    (rightFound : at? branches rightBranch = some right)
    (leftAt : at? left seqno = some leftEntry)
    (rightAt : at? right seqno = some rightEntry)
    (sameView : leftEntry.view = rightEntry.view)
    : left.take seqno = right.take seqno := by
  obtain ⟨leftOrigin, leftLookup, leftPrefix⟩ := anchored_prefix branches anchored leftFound leftAt
  obtain ⟨rightOrigin, rightLookup, rightPrefix⟩ := anchored_prefix branches anchored rightFound rightAt
  rw [← sameView, leftLookup] at rightLookup
  cases rightLookup
  exact leftPrefix.trans rightPrefix.symm

theorem fold_max_bound (ids : List TxID) (start : Nat) {txid : TxID} (member : txid ∈ ids)
    : txid.seqno ≤ ids.foldl (fun seqno id => max seqno id.seqno) start := by
  have accumulator : ∀ (ids : List TxID) (start : Nat),
      start ≤ ids.foldl (fun seqno id => max seqno id.seqno) start := by
    intro ids
    induction ids with
    | nil => simp
    | cons head tail ih =>
        intro start
        exact Nat.le_trans (Nat.le_max_left _ _) (ih _)
  induction ids generalizing start with
  | nil => simp at member
  | cons head tail ih =>
      rcases List.mem_cons.mp member with same | later
      · subst head
        exact Nat.le_trans (Nat.le_max_right _ _) (accumulator tail _)
      · exact ih _ later

theorem frontier_bound (history : List Event) {txid : TxID}
    (member : txid ∈ statusIDs history .committed)
    : txid.seqno ≤ commitSeqno history :=
  fold_max_bound _ _ member

def Current (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ txid ∈ statusIDs history .committed,
    ∃ ledger,
      at? branches branches.length = some ledger
      ∧ ∃ entry, at? ledger txid.seqno = some entry ∧ entry.view = txid.view

theorem current_mono (before after : List (List Entry)) (history : List Event)
    (current : Current before history)
    (extension : Structural.BranchExtension before after)
    (length : after.length = before.length)
    : Current after history := by
  intro txid member
  obtain ⟨ledger, found, entry, atEntry, view⟩ := current txid member
  obtain ⟨extended, extendedFound, isPrefix⟩ := extension _ _ found
  exact ⟨
    extended,
    by simpa [length] using extendedFound,
    entry,
    at_prefix isPrefix atEntry,
    view
  ⟩

theorem current_snoc (branches : List (List Entry)) (history : List Event) (event : Event)
    (current : Current branches history)
    (newCommit
      : ∀ txid,
          event = .status txid .committed
          → ∃ ledger,
              at? branches branches.length = some ledger
              ∧ ∃ entry, at? ledger txid.seqno = some entry ∧ entry.view = txid.view)
    : Current branches (history ++ [event]) := by
  intro txid member
  simp only [statusIDs, List.filterMap_append, List.mem_append] at member
  rcases member with old | new
  · exact current txid old
  · cases event <;> simp_all

theorem current_commit (branches : List (List Entry)) (history : List Event)
    (current : Current branches history) (txid : TxID) {ledger : List Entry}
    {entry : Entry} (latest : branches.getLast? = some ledger)
    (found : at? ledger txid.seqno = some entry) (view : entry.view = txid.view)
    : Current branches (history ++ [.status txid .committed]) := by
  apply current_snoc _ _ _ current
  intro _ same
  cases same
  exact ⟨ledger, at_last latest, entry, found, view⟩

theorem frontier_entry (state : State) {ledger : List Entry}
    (compatible : hasCommittedPrefix state ledger = true)
    (positive : 0 < commitSeqno state.history)
    : ∃ entry,
        at? ledger (commitSeqno state.history) = some entry
        ∧ (⟨entry.view, commitSeqno state.history⟩ : TxID)
          ∈ statusIDs state.history .committed := by
  unfold hasCommittedPrefix at compatible
  simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at compatible
  rcases compatible.2 with zero | matched
  · omega
  · cases found : at? ledger (commitSeqno state.history) with
    | none => simp [found] at matched
    | some entry => exact ⟨entry, rfl, by simpa [found] using matched⟩

theorem current_elect (state : State) (current : Current state.branches state.history)
    (anchored : Anchored state.branches) {branch : Nat} {ledger : List Entry}
    (found : at? state.branches branch = some ledger) (count : Nat)
    (compatible : hasCommittedPrefix state ledger = true)
    (retained : commitSeqno state.history ≤ count)
    : Current (state.branches ++ [ledger.take count]) state.history := by
  intro txid member
  obtain ⟨latest, latestFound, entry, atEntry, view⟩ := current txid member
  have bound := frontier_bound state.history member
  have positive : 0 < commitSeqno state.history := by
    have := (at_bounds atEntry).1
    omega
  obtain ⟨frontierEntry, candidateAt, known⟩ := frontier_entry state compatible positive
  obtain ⟨currentLedger, currentFound, currentEntry, currentAt, currentView⟩ := current _ known
  rw [latestFound] at currentFound
  cases currentFound
  have same := equal_prefixes state.branches anchored found latestFound
    candidateAt currentAt currentView.symm
  have inPrefix := at_take_of_le atEntry bound
  rw [← same] at inPrefix
  have preserved := at_prefix (List.take_prefix_take_left (l := ledger) retained) inPrefix
  exact ⟨ledger.take count, by simp [at?], entry, preserved, view⟩

theorem step_current (before after : State) (action : Action)
    (current : Current before.branches before.history)
    (anchored : Anchored before.branches)
    (transition : step before action = some after)
    : Current after.branches after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (solve | apply current_snoc _ _ _ current; simp)
      | (solve | apply current_commit _ _ current <;> assumption)
      | (exact current_mono _ _ _ current (Structural.branches_modify _ _ _) (by simp))
      | (solve | apply current_elect before current anchored <;> first | assumption | omega)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem current_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Current state.branches state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [Current, initialState, statusIDs]
  | @step before after action reachable transition ih =>
      exact step_current before after action ih (anchored_reachable reachable) transition

theorem snapshot_on_branch (branches : List (List Entry)) (anchored : Anchored branches)
    {kind : TxType} {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (snapshot : Snapshot branches kind tx observed txid) {branch : Nat}
    {ledger : List Entry} {entry : Entry} (found : at? branches branch = some ledger)
    (atEntry : at? ledger txid.seqno = some entry) (view : entry.view = txid.view)
    : observed = writes (ledger.take txid.seqno) ∧ (kind = .rw → entry.tx = some tx) := by
  obtain ⟨origin, originFound, obs, originalEntry, originalAt, _, txMatches⟩ := snapshot
  obtain ⟨_, anchoredOrigin, anchorFound, isPrefix⟩ := anchored _ _ found _ _ atEntry
  rw [view, originFound] at anchorFound
  cases anchorFound
  have actual := at_prefix isPrefix (at_take atEntry)
  rw [originalAt] at actual
  cases actual
  obtain ⟨otherOrigin, otherFound, same⟩ := anchored_prefix branches anchored found atEntry
  rw [view, originFound] at otherFound
  cases otherFound
  exact ⟨by rw [same]; exact obs, txMatches⟩

theorem committed_snapshot {state : State}
    (reachable : transitionSystem.Reachable state) {response : Nat × Response}
    (listed : response ∈ committedResponses state.history .rw)
    : ∃ ledger,
        at? state.branches state.branches.length = some ledger
        ∧ response.2.observed = writes (ledger.take response.2.txid.seqno)
        ∧ ∃ entry,
            at? ledger response.2.txid.seqno = some entry
            ∧ entry.tx = some response.2.tx := by
  obtain ⟨inResponses, committed⟩ := List.mem_filter.mp listed
  have known : response.2.txid ∈ statusIDs state.history .committed := by simpa using committed
  obtain ⟨kind, responseFound⟩ := (History.mem_responsesOf_iff _ _ _).mp inResponses
  obtain ⟨ledger, found, entry, atEntry, view⟩ := current_reachable reachable _ known
  have snapshot := snapshots_reachable reachable _ _ _ _ _ responseFound
  have ⟨obs, txMatches⟩ := snapshot_on_branch state.branches
    (anchored_reachable reachable) snapshot found atEntry view
  exact ⟨ledger, found, obs, entry, atEntry, txMatches kind⟩

theorem unique_seq_nums_committed
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ committedResponses state.history .rw,
          ∀ right ∈ committedResponses state.history .rw,
            left.2.txid.seqno = right.2.txid.seqno → left.2.tx = right.2.tx := by
  intro trace state member left first right second same
  have reachable := trace.reachable member
  obtain ⟨leftLedger, leftFound, _, leftEntry, leftAt, leftTx⟩ :=
    committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, _, rightEntry, rightAt, rightTx⟩ :=
    committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  rw [← same, leftAt] at rightAt
  cases rightAt
  exact Option.some.inj (leftTx.symm.trans rightTx)

theorem committed_rw_serializable
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ committedResponses state.history .rw,
          ∀ right ∈ committedResponses state.history .rw,
            left.2.observed <+: right.2.observed
            ∨ right.2.observed <+: left.2.observed := by
  intro trace state member left first right second
  have reachable := trace.reachable member
  obtain ⟨leftLedger, leftFound, leftObs, _⟩ := committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, rightObs, _⟩ := committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  rw [leftObs, rightObs]
  rcases Nat.le_total left.2.txid.seqno right.2.txid.seqno with bound | bound
  · exact Or.inl ((List.take_prefix_take_left (l := leftLedger) bound).filterMap Entry.tx)
  · exact Or.inr ((List.take_prefix_take_left (l := leftLedger) bound).filterMap Entry.tx)

end consistency.Proofs.Commitment
