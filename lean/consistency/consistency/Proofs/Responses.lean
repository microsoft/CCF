module

public import consistency.Proofs.History

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Responses

open Model Properties History

theorem responded_of_lookup (history : List Event) {requestIndex index : Nat}
    {kind : TxType} {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (afterRequest : requestIndex ≤ index)
    (found : history[index]? = some (.response kind tx observed txid))
    : responded history requestIndex kind tx = true := by
  have inDrop : (history.drop requestIndex)[index - requestIndex]? =
      some (.response kind tx observed txid) := by
    rw [List.getElem?_drop]
    simpa [Nat.add_sub_of_le afterRequest] using found
  apply List.any_eq_true.mpr
  exact ⟨_, List.mem_of_getElem? inDrop, by simp⟩

theorem no_previous_response (history : List Event) (causal : Causal history)
    (requests : RequestInvariant history) {requestIndex : Nat} {kind : TxType}
    {tx : TxContent} (requestFound : at? history requestIndex = some (.request kind tx))
    (unanswered : responded history requestIndex kind tx = false) {index : Nat}
    {otherKind : TxType} {observed : List TxContent} {txid : TxID}
    (responseFound : history[index]? = some (.response otherKind tx observed txid))
    : False := by
  have nonzero : requestIndex ≠ 0 := by
    rintro rfl
    simp [at?] at requestFound
  have newRequest : history[requestIndex - 1]? = some (.request kind tx) := by
    simpa [at?, nonzero] using requestFound
  obtain ⟨oldIndex, earlier, oldRequest⟩ := causal _ _ _ _ _ responseFound
  have sameIndex := requests.2 _ _ _ _ _ _ oldRequest newRequest rfl
  rw [sameIndex, newRequest] at oldRequest
  have sameKind : kind = otherKind := by simpa using oldRequest
  subst otherKind
  have delivered := responded_of_lookup history (by omega : requestIndex ≤ index) responseFound
  simp [unanswered] at delivered

def UniqueResponses (history : List Event) : Prop :=
  ∀ (left right : Nat) (leftKind rightKind : TxType) (tx : TxContent)
    (leftObserved rightObserved : List TxContent) (leftID rightID : TxID),
    history[left]? = some (.response leftKind tx leftObserved leftID)
    → history[right]? = some (.response rightKind tx rightObserved rightID)
    → left = right

theorem responses_snoc (history : List Event) (event : Event)
    (invariant : UniqueResponses history)
    (fresh
      : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response kind tx observed txid
          → ∀ (index : Nat) (otherKind : TxType) (otherObserved : List TxContent)
              (otherID : TxID),
              history[index]? = some (.response otherKind tx otherObserved otherID)
              → False)
    : UniqueResponses (history ++ [event]) := by
  intro left right leftKind rightKind tx leftObserved rightObserved leftID rightID first second
  rcases lookup_snoc first with ⟨_, oldLeft⟩ | ⟨lastLeft, newLeft⟩
  · rcases lookup_snoc second with ⟨_, oldRight⟩ | ⟨_, newRight⟩
    · exact invariant _ _ _ _ _ _ _ _ _ oldLeft oldRight
    · exact False.elim (fresh _ _ _ _ newRight _ _ _ _ oldLeft)
  · rcases lookup_snoc second with ⟨_, oldRight⟩ | ⟨lastRight, _⟩
    · exact False.elim (fresh _ _ _ _ newLeft _ _ _ _ oldRight)
    · omega

theorem responses_response (history : List Event) (invariant : UniqueResponses history)
    (causal : Causal history) (requests : RequestInvariant history) {requestIndex : Nat}
    {kind : TxType} {tx : TxContent} (observed : List TxContent) (txid : TxID)
    (requestFound : at? history requestIndex = some (.request kind tx))
    (unanswered : responded history requestIndex kind tx = false)
    : UniqueResponses (history ++ [.response kind tx observed txid]) := by
  apply responses_snoc history _ invariant
  intro _ _ _ _ same
  cases same
  intro index otherKind otherObserved otherID found
  exact no_previous_response history causal requests requestFound unanswered found

theorem step_responses (before after : State) (action : Action)
    (invariant : UniqueResponses before.history) (causal : Causal before.history)
    (requests : RequestInvariant before.history)
    (transition : step before action = some after)
    : UniqueResponses after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact invariant)
      | (solve | apply responses_snoc _ _ invariant; simp)
      | (solve | apply responses_response _ invariant causal requests <;> assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem responses_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : UniqueResponses state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [initialState, UniqueResponses]
  | @step before after action reachable transition ih =>
      exact step_responses before after action ih
        (causal_reachable reachable) (requests_reachable reachable) transition

theorem unique_tx_ids
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.tx = right.2.tx -> left.2.txid = right.2.txid := by
  intro trace state member left first right second sameTx
  have firstLookup := (mem_responses_iff _ _).mp first
  have secondLookup := (mem_responses_iff _ _).mp second
  rw [← sameTx] at secondLookup
  have sameIndex := responses_reachable (trace.reachable member)
    _ _ _ _ _ _ _ _ _ firstLookup secondLookup
  rw [sameIndex, secondLookup] at firstLookup
  exact (Event.response.inj (Option.some.inj firstLookup)).2.2.2.symm

end consistency.Proofs.Responses
