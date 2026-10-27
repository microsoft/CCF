module

public import consistency.Proofs.ViewOrder

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Statuses

open Model Properties Observations LedgerIdentity Commitment

theorem last_of_at {α : Type} {xs : List α} {value : α}
    (found : at? xs xs.length = some value)
    : xs.getLast? = some value := by
  cases xs with
  | nil => simp [at?] at found
  | cons head tail => simpa [at?, List.getLast?_eq_getElem?] using found

theorem cannot_invalidate (state : State) (anchored : Anchored state.branches)
    (current : Current state.branches state.history) {committed invalid : TxID}
    (known : committed ∈ statusIDs state.history .committed)
    {kind : TxType} {tx : TxContent} {observed : List TxContent}
    (snapshot : Snapshot state.branches kind tx observed invalid)
    (sameView : invalid.view = committed.view) (bound : invalid.seqno ≤ committed.seqno)
    : mayInvalidate state invalid = false := by
  obtain ⟨latest, latestFound, entry, atEntry, view⟩ := current committed known
  obtain ⟨origin, originFound, _, invalidEntry, invalidAt, invalidView, _⟩ := snapshot
  obtain ⟨otherOrigin, otherFound, samePrefix⟩ :=
    anchored_prefix state.branches anchored latestFound atEntry
  rw [view, ← sameView, originFound] at otherFound
  cases otherFound
  have inPrefix := at_take_of_le invalidAt bound
  rw [← samePrefix] at inPrefix
  have actual := at_prefix (List.take_prefix committed.seqno latest) inPrefix
  have frontier := Nat.le_trans bound (frontier_bound state.history known)
  simp [mayInvalidate, last_of_at latestFound, actual, invalidView,
    show ¬commitSeqno state.history < invalid.seqno by omega,
    show ¬invalid.seqno > commitSeqno state.history by omega]

theorem status_ids_snoc (history : List Event) (event : Event) (txid : TxID)
    (status : Status)
    : txid ∈ statusIDs (history ++ [event]) status
      ↔ txid ∈ statusIDs history status ∨ event = .status txid status := by
  cases event with
  | request kind tx => simp [statusIDs, List.filterMap_append]
  | response kind tx observed id => simp [statusIDs, List.filterMap_append]
  | status id value =>
      cases value <;> cases status <;> simp [statusIDs, List.filterMap_append, eq_comm]

def Separated (history : List Event) : Prop :=
  ∀ committed ∈ statusIDs history .committed,
  ∀ invalid ∈ statusIDs history .invalid,
    invalid.view = committed.view → committed.seqno < invalid.seqno

theorem separated_snoc (history : List Event) (event : Event)
    (separated : Separated history)
    (newCommit
      : ∀ committed,
          event = .status committed .committed
          → ∀ invalid ∈ statusIDs history .invalid,
              invalid.view = committed.view → committed.seqno < invalid.seqno)
    (newInvalid
      : ∀ invalid,
          event = .status invalid .invalid
          → ∀ committed ∈ statusIDs history .committed,
              invalid.view = committed.view → committed.seqno < invalid.seqno)
    : Separated (history ++ [event]) := by
  intro committed commitKnown invalid invalidKnown sameView
  rcases (status_ids_snoc _ _ _ _).mp commitKnown with oldCommit | currentCommit
  · rcases (status_ids_snoc _ _ _ _).mp invalidKnown with oldInvalid | currentInvalid
    · exact separated committed oldCommit invalid oldInvalid sameView
    · exact newInvalid invalid currentInvalid committed oldCommit sameView
  · rcases (status_ids_snoc _ _ _ _).mp invalidKnown with oldInvalid | currentInvalid
    · exact newCommit committed currentCommit invalid oldInvalid sameView
    · simp_all

theorem separated_commit (history : List Event) (separated : Separated history)
    (txid : TxID)
    (allowed
      : ∀ invalid ∈ statusIDs history .invalid,
          invalid.view = txid.view → txid.seqno < invalid.seqno)
    : Separated (history ++ [.status txid .committed]) := by
  apply separated_snoc _ _ separated
  · intro _ same
    cases same
    exact allowed
  · simp

theorem separated_invalidate (state : State) (separated : Separated state.history)
    (anchored : Anchored state.branches) (current : Current state.branches state.history)
    (snapshots : Snapshots state.branches state.history) {index : Nat}
    {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (response : at? state.history index = some (.response .rw tx observed txid))
    (allowed : mayInvalidate state txid = true)
    : Separated (state.history ++ [.status txid .invalid]) := by
  apply separated_snoc _ _ separated
  · simp
  · intro _ same
    cases same
    intro committed known sameView
    by_contra notLater
    have lookup : state.history[index - 1]? = some (.response .rw tx observed txid) := by
      simpa [at?, Nat.ne_of_gt (at_bounds response).1] using response
    have denied := cannot_invalidate state anchored current known
      (snapshots _ _ _ _ _ lookup) sameView (by omega)
    simp [denied] at allowed

theorem step_separated (before after : State) (action : Action)
    (separated : Separated before.history) (anchored : Anchored before.branches)
    (current : Current before.branches before.history)
    (snapshots : Snapshots before.branches before.history)
    (transition : step before action = some after)
    : Separated after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact separated)
      | (solve | apply separated_snoc _ _ separated <;> simp)
      | (solve | apply separated_commit _ separated; assumption)
      | (solve | apply separated_invalidate before separated anchored current snapshots
          <;> assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem separated_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Separated state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [Separated, initialState, statusIDs]
  | @step before after action reachable transition ih =>
      exact step_separated before after action ih (anchored_reachable reachable)
        (current_reachable reachable) (snapshots_reachable reachable) transition

theorem mem_statuses_iff (history : List Event) (txid : TxID) (status : Status)
    : (txid, status) ∈ statuses history ↔ txid ∈ statusIDs history status := by
  constructor
  · intro member
    obtain ⟨event, listed, mapped⟩ := List.mem_filterMap.mp member
    cases event <;> simp_all [statusIDs, List.mem_filterMap]
    exact ⟨.status txid status, listed, by simp⟩
  · intro member
    obtain ⟨event, listed, mapped⟩ := List.mem_filterMap.mp member
    cases event <;> simp_all [statuses, List.mem_filterMap]
    exact ⟨.status txid status, listed, rfl⟩

theorem committed_or_invalid
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  intro trace state ⟨valid, member⟩ txid committed invalid
  have impossible := separated_reachable (valid.reachable member)
    txid committed txid invalid rfl
  omega

theorem once_committed_prev_committed
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .committed
            → left.1.view = right.1.view
            → right.1.seqno ≤ left.1.seqno
            → right.2 = .committed := by
  intro trace state ⟨valid, member⟩ left first right second leftCommitted sameView bound
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftCommitted] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed => rfl
  | invalid =>
      rw [value] at secondKnown
      have impossible := separated_reachable (valid.reachable member)
        left.1 firstKnown right.1 secondKnown sameView.symm
      omega

theorem once_invalid_next_invalid
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .invalid
            → left.1.view = right.1.view
            → left.1.seqno ≤ right.1.seqno
            → right.2 = .invalid := by
  intro trace state ⟨valid, member⟩ left first right second leftInvalid sameView bound
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftInvalid] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed =>
      rw [value] at secondKnown
      have impossible := separated_reachable (valid.reachable member)
        right.1 secondKnown left.1 firstKnown sameView
      omega
  | invalid => rfl

theorem once_committed_next_invalid
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .committed
            → left.1.seqno ≤ right.1.seqno
            → right.1.view < left.1.view
            → right.2 = .invalid := by
  intro trace state ⟨valid, member⟩ left first right second leftCommitted bound older
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftCommitted] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed =>
      rw [value] at secondKnown
      have impossible := ViewOrder.committed_views (valid.reachable member)
        firstKnown secondKnown bound
      omega
  | invalid => rfl

theorem committed_or_invalid_strong
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → (∀ left ∈ statuses state.history,
            ∀ right ∈ statuses state.history,
              left.2 = .committed
              → left.1.view = right.1.view
              → right.1.seqno ≤ left.1.seqno
              → right.2 = .committed)
          ∧ (∀ left ∈ statuses state.history,
              ∀ right ∈ statuses state.history,
                left.2 = .committed
                → left.1.seqno ≤ right.1.seqno
                → right.1.view < left.1.view
                → right.2 = .invalid)
          ∧ (∀ left ∈ statuses state.history,
              ∀ right ∈ statuses state.history,
                left.2 = .invalid
                → left.1.view = right.1.view
                → left.1.seqno ≤ right.1.seqno
                → right.2 = .invalid) := by
  intro trace state valid
  exact ⟨once_committed_prev_committed trace state valid,
    once_committed_next_invalid trace state valid,
    once_invalid_next_invalid trace state valid⟩

end consistency.Proofs.Statuses
