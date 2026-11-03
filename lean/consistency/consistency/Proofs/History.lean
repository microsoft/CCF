module

public import consistency.Proofs.Structural

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.History

open Model Properties

theorem lookup_snoc {history : List Event} {event value : Event} {index : Nat}
    (found : (history ++ [event])[index]? = some value)
    : (index < history.length ∧ history[index]? = some value)
      ∨ (index = history.length ∧ event = value) := by
  by_cases inside : index < history.length
  · exact Or.inl ⟨inside, by simpa [List.getElem?_append_left inside] using found⟩
  · have bound := (List.getElem?_eq_some_iff.mp found).1
    have endpoint : index = history.length := by simp at bound; omega
    subst index
    exact Or.inr ⟨rfl, by simpa using found⟩

theorem mem_requests_iff (history : List Event) (index : Nat) (kind : TxType)
    (tx : TxContent)
    : (index, kind, tx) ∈ requests history
      ↔ history[index]? = some (.request kind tx) := by
  simp only [requests, List.mem_filterMap]
  constructor
  · rintro ⟨⟨event, position⟩, member, mapped⟩
    cases event <;> simp_all [List.mem_zipIdx_iff_getElem?]
  · intro found
    exact ⟨(.request kind tx, index), List.mem_zipIdx_iff_getElem?.mpr found, rfl⟩

theorem mem_responses_iff (history : List Event) (response : Nat × Response)
    : response ∈ responses history
      ↔ history[response.1]?
        = some
            (.response response.2.kind response.2.tx response.2.observed
              response.2.txid) := by
  rcases response with ⟨index, kind, tx, observed, txid⟩
  simp only [responses, List.mem_filterMap]
  constructor
  · rintro ⟨⟨event, position⟩, member, mapped⟩
    cases event <;> simp_all [List.mem_zipIdx_iff_getElem?]
  · intro found
    exact ⟨(.response kind tx observed txid, index),
      List.mem_zipIdx_iff_getElem?.mpr found, rfl⟩

theorem mem_responsesOf_iff (history : List Event) (kind : TxType)
    (response : Nat × Response)
    : response ∈ responsesOf history kind
      ↔ response.2.kind = kind
        ∧ history[response.1]?
          = some
              (.response response.2.kind response.2.tx response.2.observed
                response.2.txid) := by
  simp [responsesOf, mem_responses_iff, and_comm]

def Causal (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → ∃ requestIndex,
        requestIndex < index ∧ history[requestIndex]? = some (.request kind tx)

theorem causal_snoc (history : List Event) (event : Event) (causal : Causal history)
    (newResponse
      : ∀ kind tx observed txid,
          event = .response kind tx observed txid
          → ∃ index, index < history.length ∧ history[index]? = some (.request kind tx))
    : Causal (history ++ [event]) := by
  intro index kind tx observed txid found
  rcases lookup_snoc found with ⟨inside, old⟩ | ⟨rfl, current⟩
  · obtain ⟨requestIndex, earlier, requestFound⟩ := causal _ _ _ _ _ old
    exact ⟨requestIndex, earlier,
      by simpa [List.getElem?_append_left (by omega : requestIndex < history.length)]
        using requestFound⟩
  · obtain ⟨requestIndex, earlier, requestFound⟩ := newResponse _ _ _ _ current
    exact ⟨requestIndex, earlier,
      by simpa [List.getElem?_append_left earlier] using requestFound⟩

theorem causal_request (history : List Event) (causal : Causal history) (kind : TxType)
    (tx : TxContent)
    : Causal (history ++ [.request kind tx]) := by
  apply causal_snoc history _ causal
  simp

theorem causal_status (history : List Event) (causal : Causal history)
    (txid : TxID) (status : Status)
    : Causal (history ++ [.status txid status]) := by
  apply causal_snoc history _ causal
  simp

theorem causal_response (history : List Event) (causal : Causal history)
    {requestIndex : Nat} {kind : TxType} {tx : TxContent} (observed : List TxContent)
    (txid : TxID) (found : at? history requestIndex = some (.request kind tx))
    : Causal (history ++ [.response kind tx observed txid]) := by
  apply causal_snoc history _ causal
  intro _ _ _ _ same
  cases same
  have nonzero : requestIndex ≠ 0 := by
    rintro rfl
    simp [at?] at found
  have lookup : history[requestIndex - 1]? = some (.request kind tx) := by
    simpa [at?, nonzero] using found
  exact ⟨requestIndex - 1, (List.getElem?_eq_some_iff.mp lookup).1, lookup⟩

theorem step_causal (before after : State) (action : Action)
    (causal : Causal before.history) (transition : step before action = some after)
    : Causal after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact causal)
      | (exact causal_request _ causal _ _)
      | (exact causal_status _ causal _ _)
      | (solve | apply causal_response _ causal <;> assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem causal_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Causal state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [initialState, Causal]
  | @step before after action _ transition ih =>
      exact step_causal before after action ih transition

theorem all_received_is_first_sent
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        -> forall (kind : TxType),
            ∀ response ∈ responsesOf state.history kind,
              ∃ request ∈ requests state.history,
                request.1 < response.1 /\ request.2 = (kind, response.2.tx) := by
  intro trace state member kind response listed
  obtain ⟨kindEq, found⟩ := (mem_responsesOf_iff _ _ _).mp listed
  obtain ⟨requestIndex, earlier, requestFound⟩ :=
    causal_reachable (trace.reachable member) _ _ _ _ _ found
  refine ⟨(requestIndex, kind, response.2.tx), ?_, earlier, rfl⟩
  apply (mem_requests_iff _ _ _ _).mpr
  simpa [kindEq] using requestFound

def RequestInvariant (history : List Event) : Prop :=
  (∀ (index : Nat) (kind : TxType) (tx : TxContent),
    history[index]? = some (.request kind tx) → tx < nextRequestId history)
  ∧ (∀ (left right : Nat) (leftKind rightKind : TxType) (leftTx rightTx : TxContent),
      history[left]? = some (.request leftKind leftTx)
      → history[right]? = some (.request rightKind rightTx)
      → leftTx = rightTx
      → left = right)

theorem next_request_snoc (history : List Event) (event : Event)
    : nextRequestId (history ++ [event])
      = match event with
        | .request _ tx => tx + 1
        | _ => nextRequestId history := by
  cases event <;> simp [nextRequestId, List.foldl_append]

theorem requests_snoc (history : List Event) (event : Event)
    (invariant : RequestInvariant history)
    (allocated : ∀ kind tx, event = .request kind tx → tx = nextRequestId history)
    : RequestInvariant (history ++ [event]) := by
  have monotonic : nextRequestId history ≤ nextRequestId (history ++ [event]) := by
    cases event with
    | request kind tx =>
        have assigned := allocated kind tx rfl
        simp [next_request_snoc, ← assigned]
    | response => simp [next_request_snoc]
    | status => simp [next_request_snoc]
  constructor
  · intro index kind tx found
    rcases lookup_snoc found with ⟨_, old⟩ | ⟨rfl, rfl⟩
    · exact lt_of_lt_of_le (invariant.1 _ _ _ old) monotonic
    · simp [next_request_snoc]
  · intro left right leftKind rightKind leftTx rightTx first second same
    rcases lookup_snoc first with ⟨_, oldLeft⟩ | ⟨lastLeft, newLeft⟩
    · rcases lookup_snoc second with ⟨_, oldRight⟩ | ⟨lastRight, newRight⟩
      · exact invariant.2 _ _ _ _ _ _ oldLeft oldRight same
      · have fresh := invariant.1 _ _ _ oldLeft
        have assigned := allocated _ _ newRight
        exact False.elim ((Nat.ne_of_lt fresh) (same.trans assigned))
    · rcases lookup_snoc second with ⟨_, oldRight⟩ | ⟨lastRight, _⟩
      · have fresh := invariant.1 _ _ _ oldRight
        have assigned := allocated _ _ newLeft
        exact False.elim ((Nat.ne_of_lt fresh) (same.symm.trans assigned))
      · omega

theorem step_requests (before after : State) (action : Action)
    (invariant : RequestInvariant before.history)
    (transition : step before action = some after)
    : RequestInvariant after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact invariant)
      | (solve | apply requests_snoc _ _ invariant; simp)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem requests_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : RequestInvariant state.history := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [initialState, RequestInvariant, nextRequestId]
  | @step before after action _ transition ih =>
      exact step_requests before after action ih transition

theorem unique_tx_requests
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        -> ∀ left ∈ requests state.history,
            ∀ right ∈ requests state.history,
              left.1 ≠ right.1 -> left.2.2 ≠ right.2.2 := by
  intro trace state member left first right second distinct same
  have invariant := requests_reachable (trace.reachable member)
  have firstLookup := (mem_requests_iff _ _ _ _).mp first
  have secondLookup := (mem_requests_iff _ _ _ _).mp second
  exact distinct (invariant.2 _ _ _ _ _ _ firstLookup secondLookup same)

end consistency.Proofs.History
