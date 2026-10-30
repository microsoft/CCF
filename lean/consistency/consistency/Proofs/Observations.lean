module

public import consistency.Proofs.History

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Observations

open Model Properties

theorem mem_of_at? {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : value ∈ xs := by
  by_cases zero : index = 0
  · simp [at?, zero] at found
  · exact List.mem_of_getElem? (by simpa [at?, zero] using found)

theorem forall_modify {α : Type} (xs : List α) (index : Nat) (f : α → α)
    (P : α → Prop) (original : ∀ x ∈ xs, P x)
    (updated : ∀ x ∈ xs, P (f x))
    : ∀ x ∈ xs.modify index f, P x := by
  intro x member
  obtain ⟨position, found⟩ := List.mem_iff_getElem?.mp member
  rw [List.getElem?_modify] at found
  obtain ⟨before, lookup, same⟩ := Option.map_eq_some_iff.mp found
  by_cases selected : index = position
  · simp only [selected, ite_true] at same
    subst x
    exact updated before (List.mem_of_getElem? lookup)
  · simp only [selected, ite_false] at same
    subst x
    exact original before (List.mem_of_getElem? lookup)

def LedgerSafe (history : List Event) (ledger : List Entry) : Prop :=
  (writes ledger).Nodup ∧ ∀ tx ∈ writes ledger, Event.request .rw tx ∈ history

def ObservedSafe (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → observed.Nodup
      ∧ ∀ write ∈ observed,
          ∃ requestIndex,
            requestIndex < index ∧ history[requestIndex]? = some (.request .rw write)

def Safe (state : State) : Prop :=
  (∀ ledger ∈ state.branches, LedgerSafe state.history ledger)
  ∧ ObservedSafe state.history

theorem ledger_take (history : List Event) (ledger : List Entry) (count : Nat)
    (safe : LedgerSafe history ledger)
    : LedgerSafe history (ledger.take count) := by
  have sub : List.Sublist (writes (ledger.take count)) (writes ledger) :=
    (List.take_sublist count ledger).filterMap Entry.tx
  exact ⟨sub.nodup safe.1, fun tx member => safe.2 tx (sub.subset member)⟩

theorem ledger_history_append (history extra : List Event) (ledger : List Entry)
    (safe : LedgerSafe history ledger)
    : LedgerSafe (history ++ extra) ledger := by
  exact ⟨safe.1, fun tx member => List.mem_append_left _ (safe.2 tx member)⟩

theorem ledger_write (history : List Event) (ledger : List Entry) (view : Nat)
    (tx : TxContent) (safe : LedgerSafe history ledger)
    (sent : Event.request .rw tx ∈ history) (fresh : tx ∉ writes ledger)
    : LedgerSafe history (ledger ++ [⟨view, some tx⟩]) := by
  constructor
  · have appended : (writes ledger ++ [tx]).Nodup := by
      apply List.nodup_append.mpr
      refine ⟨safe.1, by simp, ?_⟩
      intro a member b singleton equal
      have same : b = tx := List.mem_singleton.mp singleton
      subst b
      subst a
      exact fresh member
    simpa only [writes, List.filterMap_append, List.filterMap_cons, List.filterMap_nil]
      using appended
  · intro write member
    simp only [writes, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
      List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with old | rfl
    · exact safe.2 write old
    · exact sent

theorem observed_snoc (history : List Event) (event : Event) (safe : ObservedSafe history)
    (newResponse
      : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response kind tx observed txid
          → observed.Nodup ∧ ∀ write ∈ observed, Event.request .rw write ∈ history)
    : ObservedSafe (history ++ [event]) := by
  intro index kind tx observed txid found
  rcases History.lookup_snoc found with ⟨_, old⟩ | ⟨rfl, current⟩
  · obtain ⟨nodup, sent⟩ := safe _ _ _ _ _ old
    refine ⟨nodup, ?_⟩
    intro write member
    obtain ⟨requestIndex, earlier, lookup⟩ := sent write member
    exact ⟨requestIndex, earlier,
      by simpa [List.getElem?_append_left (by omega : requestIndex < history.length)]
        using lookup⟩
  · obtain ⟨nodup, sent⟩ := newResponse _ _ _ _ current
    refine ⟨nodup, ?_⟩
    intro write member
    obtain ⟨requestIndex, lookup⟩ := List.mem_iff_getElem?.mp (sent write member)
    have earlier := (List.getElem?_eq_some_iff.mp lookup).1
    exact ⟨requestIndex, earlier,
      by simpa [List.getElem?_append_left earlier] using lookup⟩

theorem safe_event (state : State) (event : Event) (safe : Safe state)
    (newResponse
      : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response kind tx observed txid
          → observed.Nodup ∧ ∀ write ∈ observed, Event.request .rw write ∈ state.history)
    : Safe (appendEvent state event) := by
  exact ⟨fun ledger member => ledger_history_append _ _ _ (safe.1 ledger member),
    observed_snoc _ _ safe.2 newResponse⟩

theorem safe_response (state : State) (safe : Safe state) (kind : TxType) (tx : TxContent)
    (ledger : List Entry) (txid : TxID) (source : LedgerSafe state.history ledger)
    : Safe (appendEvent state (.response kind tx (writes ledger) txid)) := by
  apply safe_event state _ safe
  intro _ _ _ _ same
  cases same
  exact source

theorem safe_write (state : State) (safe : Safe state) (branch : Nat) (tx : TxContent)
    (sent : Event.request .rw tx ∈ state.history)
    (fresh : ∀ ledger ∈ state.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx)
    : Safe (appendEntry state branch ⟨branch, some tx⟩) := by
  refine ⟨?_, safe.2⟩
  apply forall_modify _ _ _ _ safe.1
  intro ledger member
  apply ledger_write _ _ _ _ (safe.1 ledger member) sent
  intro present
  obtain ⟨entry, inLedger, value⟩ := List.mem_filterMap.mp present
  exact fresh ledger member entry inLedger value

theorem safe_response_branch (state : State) (safe : Safe state) (kind : TxType)
    (tx : TxContent) (ledger : List Entry) (txid : TxID) {branch : Nat}
    (found : at? state.branches branch = some ledger)
    : Safe (appendEvent state (.response kind tx (writes ledger) txid)) :=
  safe_response state safe kind tx ledger txid (safe.1 ledger (mem_of_at? found))

theorem safe_response_take (state : State) (safe : Safe state) (kind : TxType)
    (tx : TxContent) (ledger : List Entry) (count : Nat) (txid : TxID) {branch : Nat}
    (found : at? state.branches branch = some ledger)
    : Safe (appendEvent state (.response kind tx (writes (ledger.take count)) txid)) :=
  safe_response state safe kind tx (ledger.take count) txid
    (ledger_take _ _ _ (safe.1 ledger (mem_of_at? found)))

theorem safe_other (state : State) (safe : Safe state) (branch : Nat)
    : Safe (appendEntry state branch ⟨branch, none⟩) := by
  refine ⟨?_, safe.2⟩
  apply forall_modify _ _ _ _ safe.1
  intro ledger member
  simpa [LedgerSafe, writes, List.filterMap_append] using safe.1 ledger member

theorem safe_elect (state : State) (safe : Safe state) (ledger : List Entry) (count : Nat)
    (member : ledger ∈ state.branches)
    : Safe { state with branches := state.branches ++ [ledger.take count] } := by
  refine ⟨?_, safe.2⟩
  intro candidate listed
  rcases List.mem_append.mp listed with old | new
  · exact safe.1 candidate old
  · simp only [List.mem_singleton] at new
    subst candidate
    exact ledger_take _ _ _ (safe.1 ledger member)

theorem step_safe (before after : State) (action : Action)
    (safe : Safe before) (transition : step before action = some after)
    : Safe after := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (solve | apply safe_event _ _ safe; simp)
      | (solve | apply safe_write _ safe <;> first | assumption | apply mem_of_at?; assumption)
      | (exact safe_other _ safe _)
      | (solve | apply safe_elect _ safe; apply mem_of_at?; assumption)
      | (solve | apply safe_response_branch _ safe; assumption)
      | (solve | apply safe_response_take _ safe; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem safe_reachable {state : State} (reachable : transitionSystem.Reachable state)
    : Safe state := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      simp [Safe, LedgerSafe, ObservedSafe, initialState, writes, List.mem_replicate]
  | @step before after action _ transition ih =>
      exact step_safe before after action ih transition

theorem at_most_once_observed
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ response ∈ responses state.history, response.2.observed.Nodup := by
  intro trace state ⟨valid, member⟩ response listed
  exact ((safe_reachable (valid.reachable member)).2 _ _ _ _ _
    ((History.mem_responses_iff _ _).mp listed)).1

theorem only_observe_sent_requests
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ response ∈ responses state.history,
          ∀ tx ∈ response.2.observed,
            ∃ request ∈ requests state.history,
              request.1 < response.1 ∧ request.2 = (.rw, tx) := by
  intro trace state ⟨valid, member⟩ response listed tx observed
  obtain ⟨index, earlier, found⟩ :=
    ((safe_reachable (valid.reachable member)).2 _ _ _ _ _
      ((History.mem_responses_iff _ _).mp listed)).2 tx observed
  exact ⟨(index, .rw, tx), (History.mem_requests_iff _ _ _ _).mpr found, earlier, rfl⟩

end consistency.Proofs.Observations
