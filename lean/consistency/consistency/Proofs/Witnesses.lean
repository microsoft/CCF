module

public import consistency.Properties.History
public import CCF.Execution

/-!
Non-vacuity witnesses and the history-only safety proofs.
Witness executions are constructed by replaying model actions.
The history-only invariants (causality, unique request IDs, observation safety and unique
responses) are proved here as well.

Each proof module under `Proofs/` is self-contained: lemmas needed by more than one module are
duplicated as private declarations, so the modules do not import each other and Lake can check
them in parallel. This layout is chosen to minimize verification wall-clock time.
-/

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Structural

open Model

private theorem guard_bind_some {α : Type} {p : Prop} [Decidable p] {f : Unit → Option α}
    {a : α} (bound : ((if p then pure () else failure : Option Unit) >>= f) = some a)
    : p ∧ f () = some a := by
  by_cases holds : p
  · rw [ite_eq_left holds] at bound
    exact ⟨holds, bound⟩
  · rw [ite_eq_right holds] at bound
    cases bound

private theorem request_some {before after : State} {kind : TxType}
    (transition : step before (.request kind) = some after)
    : after = appendEvent before (.request kind (nextRequestId before.history)) :=
  (Option.some.inj transition).symm

private theorem execute_some {before after : State} {requestIndex branch : Nat}
    (transition : step before (.execute requestIndex branch) = some after)
    : ∃ tx,
        after = appendEntry before branch ⟨branch, some tx⟩
        ∧ at? before.history requestIndex = some (.request .rw tx)
        ∧ activeBranch before branch = true
        ∧ (∀ ledger ∈ before.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  cases event with
  | request kind tx =>
      cases kind with
      | rw =>
          obtain ⟨active, rest⟩ := guard_bind_some rest
          obtain ⟨fresh, rest⟩ := guard_bind_some rest
          refine ⟨tx, (Option.some.inj rest).symm, found, active, ?_⟩
          rw [Bool.not_eq_true'] at fresh
          intro ledger member entry inLedger same
          apply List.any_eq_false.mp fresh ledger member
          exact List.any_eq_true.mpr ⟨entry, inLedger, beq_iff_eq.mpr same⟩
      | ro => cases rest
  | _ => cases rest

private theorem respond_some {before after : State} {requestIndex branch seqno : Nat}
    (transition : step before (.respond requestIndex branch seqno) = some after)
    : ∃ tx ledger entry,
        after
          = appendEvent before
              (.response .rw tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩)
        ∧ at? before.history requestIndex = some (.request .rw tx)
        ∧ responded before.history requestIndex .rw tx = false
        ∧ activeBranch before branch = true
        ∧ at? before.branches branch = some ledger
        ∧ at? ledger seqno = some entry
        ∧ entry.tx = some tx := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  cases event with
  | request kind tx =>
      cases kind with
      | rw =>
          obtain ⟨unanswered, rest⟩ := guard_bind_some rest
          obtain ⟨active, rest⟩ := guard_bind_some rest
          obtain ⟨ledger, ledgerFound, rest⟩ := Option.bind_eq_some_iff.mp rest
          obtain ⟨entry, entryFound, rest⟩ := Option.bind_eq_some_iff.mp rest
          obtain ⟨txMatches, rest⟩ := guard_bind_some rest
          exact ⟨
            tx,
            ledger,
            entry,
            (Option.some.inj rest).symm,
            found,
            by simpa only [Bool.not_eq_eq_eq_not, Bool.not_true] using unanswered,
            active,
            ledgerFound,
            entryFound,
            eq_of_beq txMatches
          ⟩
      | ro => cases rest
  | _ => cases rest

private theorem read_some {before after : State} {requestIndex branch : Nat}
    (transition : step before (.read requestIndex branch) = some after)
    : ∃ tx ledger entry,
        after
          = appendEvent before
              (.response .ro tx (writes ledger) ⟨entry.view, ledger.length⟩)
        ∧ at? before.history requestIndex = some (.request .ro tx)
        ∧ responded before.history requestIndex .ro tx = false
        ∧ activeBranch before branch = true
        ∧ at? before.branches branch = some ledger
        ∧ ledger.getLast? = some entry := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  cases event with
  | request kind tx =>
      cases kind with
      | ro =>
          obtain ⟨unanswered, rest⟩ := guard_bind_some rest
          obtain ⟨active, rest⟩ := guard_bind_some rest
          obtain ⟨ledger, ledgerFound, rest⟩ := Option.bind_eq_some_iff.mp rest
          obtain ⟨entry, last, rest⟩ := Option.bind_eq_some_iff.mp rest
          exact ⟨
            tx,
            ledger,
            entry,
            (Option.some.inj rest).symm,
            found,
            by simpa only [Bool.not_eq_eq_eq_not, Bool.not_true] using unanswered,
            active,
            ledgerFound,
            last
          ⟩
      | rw => cases rest
  | _ => cases rest

private theorem commit_some {before after : State} {responseIndex : Nat}
    (transition : step before (.commit responseIndex) = some after)
    : ∃ txid,
        after = appendEvent before (.status txid .committed)
        ∧ ∃ tx observed latest entry,
            at? before.history responseIndex = some (.response .rw tx observed txid)
            ∧ before.branches.getLast? = some latest
            ∧ at? latest txid.seqno = some entry
            ∧ entry.view = txid.view
            ∧ (∀ invalid ∈ statusIDs before.history .invalid,
                invalid.view = txid.view → txid.seqno < invalid.seqno)
            ∧ (∀ invalid ∈ statusIDs before.history .invalid,
                invalid.seqno ≤ txid.seqno
                → ∀ predecessor,
                    at? latest invalid.seqno = some predecessor
                    → predecessor.view ≠ invalid.view) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  cases event with
  | response kind tx observed txid =>
      cases kind with
      | rw =>
          obtain ⟨latest, latestFound, rest⟩ := Option.bind_eq_some_iff.mp rest
          obtain ⟨entry, entryFound, rest⟩ := Option.bind_eq_some_iff.mp rest
          obtain ⟨view, rest⟩ := guard_bind_some rest
          obtain ⟨sameView, rest⟩ := guard_bind_some rest
          obtain ⟨copied, rest⟩ := guard_bind_some rest
          rw [Bool.not_eq_true'] at sameView copied
          refine ⟨txid, (Option.some.inj rest).symm, tx, observed, latest, entry, found, latestFound,
            entryFound, eq_of_beq view, ?_, ?_⟩
          · intro invalid member same
            have denied := List.any_eq_false.mp sameView invalid member
            simp only [same, beq_self_eq_true, Bool.true_and, decide_eq_true_eq] at denied
            exact Nat.lt_of_not_le denied
          · intro invalid member bound predecessor predecessorFound same
            apply List.any_eq_false.mp copied invalid member
            simp only [bound, predecessorFound, same, decide_true, beq_self_eq_true, Bool.true_and]
      | ro => cases rest
  | _ => cases rest

private theorem invalidate_some {before after : State} {responseIndex : Nat}
    (transition : step before (.invalidate responseIndex) = some after)
    : ∃ txid,
        after = appendEvent before (.status txid .invalid)
        ∧ ∃ tx observed,
            at? before.history responseIndex = some (.response .rw tx observed txid)
            ∧ mayInvalidate before txid = true := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  cases event with
  | response kind tx observed txid =>
      cases kind with
      | rw =>
          obtain ⟨allowed, rest⟩ := guard_bind_some rest
          exact ⟨txid, (Option.some.inj rest).symm, tx, observed, found, allowed⟩
      | ro => cases rest
  | _ => cases rest

private theorem appendOther_some {before after : State} {branch : Nat}
    (transition : step before (.appendOther branch) = some after)
    : after = appendEntry before branch ⟨branch, none⟩
      ∧ activeBranch before branch = true := by
  obtain ⟨active, rest⟩ := guard_bind_some transition
  exact ⟨(Option.some.inj rest).symm, active⟩

private theorem elect_some {before after : State} {branch prefixLength : Nat}
    (transition : step before (.elect branch prefixLength) = some after)
    : ∃ ledger,
        after = { before with branches := before.branches ++ [ledger.take prefixLength] }
        ∧ at? before.branches branch = some ledger
        ∧ hasCommittedPrefix before ledger = true
        ∧ commitSeqno before.history ≤ prefixLength
        ∧ prefixLength ≤ ledger.length := by
  obtain ⟨ledger, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  obtain ⟨compatible, rest⟩ := guard_bind_some rest
  obtain ⟨bounds, rest⟩ := guard_bind_some rest
  simp only [Bool.and_eq_true, decide_eq_true_eq] at bounds
  exact ⟨ledger, (Option.some.inj rest).symm, found, compatible, bounds.1, bounds.2⟩

end consistency.Proofs.Structural

namespace consistency.Proofs.History

open Model Properties

private theorem lookup_snoc {history : List Event} {event value : Event} {index : Nat}
    (found : (history ++ [event])[index]? = some value)
    : (index < history.length ∧ history[index]? = some value)
      ∨ (index = history.length ∧ event = value) := by
  by_cases inside : index < history.length
  · exact Or.inl ⟨inside, by simpa only [List.getElem?_append_left inside] using found⟩
  · have bound := (List.getElem?_eq_some_iff.mp found).1
    have endpoint : index = history.length :=
      Nat.le_antisymm (Nat.le_of_lt_succ (Nat.lt_of_lt_of_le bound (Nat.le_of_eq List.length_append)))
        (Nat.le_of_not_lt inside)
    subst index
    exact Or.inr ⟨rfl, Option.some.inj (List.getElem?_concat_length.symm.trans found)⟩

private theorem mem_requests_iff (history : List Event) (index : Nat) (kind : TxType)
    (tx : TxContent)
    : (index, kind, tx) ∈ requests history
      ↔ history[index]? = some (.request kind tx) := by
  simp only [requests, List.mem_filterMap]
  constructor
  · rintro ⟨⟨event, position⟩, member, mapped⟩
    cases event <;> simp_all only [List.mem_zipIdx_iff_getElem?, Option.some.injEq, Prod.mk.injEq, reduceCtorEq]
  · intro found
    exact ⟨(.request kind tx, index), List.mem_zipIdx_iff_getElem?.mpr found, rfl⟩

private theorem mem_responses_iff (history : List Event) (response : Nat × Response)
    : response ∈ responses history
      ↔ history[response.1]?
        = some
            (.response response.2.kind response.2.tx response.2.observed
              response.2.txid) := by
  rcases response with ⟨index, kind, tx, observed, txid⟩
  simp only [responses, List.mem_filterMap]
  constructor
  · rintro ⟨⟨event, position⟩, member, mapped⟩
    cases event <;> simp_all only [List.mem_zipIdx_iff_getElem?, reduceCtorEq, Option.some.injEq, Prod.mk.injEq, Response.mk.injEq]
  · intro found
    exact ⟨(.response kind tx observed txid, index),
      List.mem_zipIdx_iff_getElem?.mpr found, rfl⟩

private theorem mem_responsesOf_iff (history : List Event) (kind : TxType)
    (response : Nat × Response)
    : response ∈ responsesOf history kind
      ↔ response.2.kind = kind
        ∧ history[response.1]?
          = some
              (.response response.2.kind response.2.tx response.2.observed
                response.2.txid) := by
  simp only [responsesOf, List.mem_filter, mem_responses_iff, beq_iff_eq, and_comm]

private def Causal (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → ∃ requestIndex,
        requestIndex < index ∧ history[requestIndex]? = some (.request kind tx)

private theorem causal_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Causal state.history := by
  have causal_snoc (history : List Event) (event : Event) (causal : Causal history)
      (newResponse
        : ∀ kind tx observed txid,
            event = .response kind tx observed txid
            → ∃ index, index < history.length ∧ history[index]? = some (.request kind tx))
      : Causal (history ++ [event]) := by
    intro index kind tx observed txid found
    rcases lookup_snoc found with ⟨inside, old⟩ | ⟨rfl, current⟩
    · obtain ⟨requestIndex, earlier, requestFound⟩ := causal _ _ _ _ _ old
      exact ⟨requestIndex, earlier,
        (List.getElem?_append_left (Nat.lt_trans earlier inside)).trans requestFound⟩
    · obtain ⟨requestIndex, earlier, requestFound⟩ := newResponse _ _ _ _ current
      exact ⟨requestIndex, earlier,
        by simpa only [List.getElem?_append_left earlier] using requestFound⟩
  have causal_request (history : List Event) (causal : Causal history) (kind : TxType)
      (tx : TxContent)
      : Causal (history ++ [Event.request kind tx]) := by
    apply causal_snoc history _ causal
    simp only [reduceCtorEq, IsEmpty.forall_iff, implies_true]
  have causal_status (history : List Event) (causal : Causal history)
      (txid : TxID) (status : Status)
      : Causal (history ++ [Event.status txid status]) := by
    apply causal_snoc history _ causal
    simp only [reduceCtorEq, IsEmpty.forall_iff, implies_true]
  have causal_response (history : List Event) (causal : Causal history)
      {requestIndex : Nat} {kind : TxType} {tx : TxContent} (observed : List TxContent)
      (txid : TxID) (found : at? history requestIndex = some (.request kind tx))
      : Causal (history ++ [Event.response kind tx observed txid]) := by
    apply causal_snoc history _ causal
    intro _ _ _ _ same
    cases same
    have nonzero : requestIndex ≠ 0 := by
      rintro rfl
      simp only [at?, ↓reduceIte, reduceCtorEq] at found
    have lookup : history[requestIndex - 1]? = some (.request kind tx) := by
      simpa only [at?, nonzero, ↓reduceIte] using found
    exact ⟨requestIndex - 1, (List.getElem?_eq_some_iff.mp lookup).1, lookup⟩
  have step_causal (before after : State) (action : Action)
      (causal : Causal before.history) (transition : step before action = some after)
      : Causal after.history := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact causal_request _ causal _ _
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact causal
    | respond =>
        obtain ⟨_, _, _, rfl, found, _, _, _, _, _⟩ := Structural.respond_some transition
        exact causal_response _ causal _ _ found
    | read =>
        obtain ⟨_, _, _, rfl, found, _, _, _, _⟩ := Structural.read_some transition
        exact causal_response _ causal _ _ found
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact causal_status _ causal _ _
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact causal_status _ causal _ _
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact causal
    | elect =>
        obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
        exact causal
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact fun _ _ _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim
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
  simpa only [kindEq] using requestFound

private def RequestInvariant (history : List Event) : Prop :=
  (∀ (index : Nat) (kind : TxType) (tx : TxContent),
    history[index]? = some (.request kind tx) → tx < nextRequestId history)
  ∧ (∀ (left right : Nat) (leftKind rightKind : TxType) (leftTx rightTx : TxContent),
      history[left]? = some (.request leftKind leftTx)
      → history[right]? = some (.request rightKind rightTx)
      → leftTx = rightTx
      → left = right)

private theorem requests_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : RequestInvariant state.history := by
  have next_request_snoc (history : List Event) (event : Event)
      : nextRequestId (history ++ [event])
        = match event with
          | .request _ tx => tx + 1
          | _ => nextRequestId history := by
    cases event <;> simp only [nextRequestId, List.foldl_append, List.foldl_cons, List.foldl_nil, Nat.add_left_cancel_iff]
  have requests_snoc (history : List Event) (event : Event)
      (invariant : RequestInvariant history)
      (allocated : ∀ kind tx, event = .request kind tx → tx = nextRequestId history)
      : RequestInvariant (history ++ [event]) := by
    have monotonic : nextRequestId history ≤ nextRequestId (history ++ [event]) := by
      cases event with
      | request kind tx =>
          have assigned := allocated kind tx rfl
          simp only [← assigned, next_request_snoc, Nat.le_add_right]
      | response => simp only [next_request_snoc, Std.le_refl]
      | status => simp only [next_request_snoc, Std.le_refl]
    constructor
    · intro index kind tx found
      rcases lookup_snoc found with ⟨_, old⟩ | ⟨rfl, rfl⟩
      · exact lt_of_lt_of_le (invariant.1 _ _ _ old) monotonic
      · simp only [next_request_snoc, Nat.lt_add_one]
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
        · exact lastLeft.trans lastRight.symm
  have step_requests (before after : State) (action : Action)
      (invariant : RequestInvariant before.history)
      (transition : step before action = some after)
      : RequestInvariant after.history := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact requests_snoc _ _ invariant (by intro _ _ same; cases same; rfl)
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact invariant
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact requests_snoc _ _ invariant (by intro _ _ same; cases same)
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact requests_snoc _ _ invariant (by intro _ _ same; cases same)
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact requests_snoc _ _ invariant (by intro _ _ same; cases same)
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact requests_snoc _ _ invariant (by intro _ _ same; cases same)
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact invariant
    | elect =>
        obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
        exact invariant
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact ⟨fun _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim,
        fun _ _ _ _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim⟩
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

namespace consistency.Proofs.Observations

open Model Properties

private theorem mem_of_at? {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : value ∈ xs := by
  by_cases zero : index = 0
  · subst zero
    cases found
  · exact List.mem_of_getElem? ((ite_eq_right zero).symm.trans found)

private def LedgerSafe (history : List Event) (ledger : List Entry) : Prop :=
  (writes ledger).Nodup ∧ ∀ tx ∈ writes ledger, Event.request .rw tx ∈ history

private def ObservedSafe (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → observed.Nodup
      ∧ ∀ write ∈ observed,
          ∃ requestIndex,
            requestIndex < index ∧ history[requestIndex]? = some (.request .rw write)

private def Safe (state : State) : Prop :=
  (∀ ledger ∈ state.branches, LedgerSafe state.history ledger)
  ∧ ObservedSafe state.history

private theorem forall_modify {α : Type} (xs : List α) (index : Nat) (f : α → α)
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

private theorem safe_write (state : State) (safe : Safe state) (branch : Nat)
    (tx : TxContent) (sent : Event.request .rw tx ∈ state.history)
    (fresh : ∀ ledger ∈ state.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx)
    : Safe (appendEntry state branch ⟨branch, some tx⟩) := by
  have ledger_write (history : List Event) (ledger : List Entry) (view : Nat)
      (tx : TxContent) (safe : LedgerSafe history ledger)
      (sent : Event.request .rw tx ∈ history) (fresh : tx ∉ writes ledger)
      : LedgerSafe history (ledger ++ [⟨view, some tx⟩]) := by
    constructor
    · have appended : (writes ledger ++ [tx]).Nodup := by
        apply List.nodup_append.mpr
        refine ⟨safe.1, by simp only [List.nodup_cons, List.not_mem_nil, not_false_eq_true, List.nodup_nil, and_self], ?_⟩
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
  refine ⟨?_, safe.2⟩
  apply forall_modify _ _ _ _ safe.1
  intro ledger member
  apply ledger_write _ _ _ _ (safe.1 ledger member) sent
  intro present
  obtain ⟨entry, inLedger, value⟩ := List.mem_filterMap.mp present
  exact fresh ledger member entry inLedger value

private theorem observed_snoc (history : List Event) (event : Event)
    (safe : ObservedSafe history)
    (newResponse
      : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response kind tx observed txid
          → observed.Nodup ∧ ∀ write ∈ observed, Event.request .rw write ∈ history)
    : ObservedSafe (history ++ [event]) := by
  intro index kind tx observed txid found
  rcases History.lookup_snoc found with ⟨inside, old⟩ | ⟨rfl, current⟩
  · obtain ⟨nodup, sent⟩ := safe _ _ _ _ _ old
    refine ⟨nodup, ?_⟩
    intro write member
    obtain ⟨requestIndex, earlier, lookup⟩ := sent write member
    exact ⟨requestIndex, earlier,
      (List.getElem?_append_left (Nat.lt_trans earlier inside)).trans lookup⟩
  · obtain ⟨nodup, sent⟩ := newResponse _ _ _ _ current
    refine ⟨nodup, ?_⟩
    intro write member
    obtain ⟨requestIndex, lookup⟩ := List.mem_iff_getElem?.mp (sent write member)
    have earlier := (List.getElem?_eq_some_iff.mp lookup).1
    exact ⟨requestIndex, earlier,
      by simpa only [List.getElem?_append_left earlier] using lookup⟩

private theorem safe_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Safe state := by
  have ledger_take (history : List Event) (ledger : List Entry) (count : Nat)
      (safe : LedgerSafe history ledger)
      : LedgerSafe history (ledger.take count) := by
    have sub : List.Sublist (writes (ledger.take count)) (writes ledger) :=
      (List.take_sublist count ledger).filterMap Entry.tx
    exact ⟨sub.nodup safe.1, fun tx member => safe.2 tx (sub.subset member)⟩
  have ledger_history_append (history extra : List Event) (ledger : List Entry)
      (safe : LedgerSafe history ledger)
      : LedgerSafe (history ++ extra) ledger := by
    exact ⟨safe.1, fun tx member => List.mem_append_left _ (safe.2 tx member)⟩
  have safe_event (state : State) (event : Event) (safe : Safe state)
      (newResponse
        : ∀ (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID),
            event = .response kind tx observed txid
            → observed.Nodup ∧ ∀ write ∈ observed, Event.request .rw write ∈ state.history)
      : Safe (appendEvent state event) := by
    exact ⟨fun ledger member => ledger_history_append _ _ _ (safe.1 ledger member),
      observed_snoc _ _ safe.2 newResponse⟩
  have safe_response (state : State) (safe : Safe state) (kind : TxType) (tx : TxContent)
      (ledger : List Entry) (txid : TxID) (source : LedgerSafe state.history ledger)
      : Safe (appendEvent state (.response kind tx (writes ledger) txid)) := by
    apply safe_event state _ safe
    intro _ _ _ _ same
    cases same
    exact source
  have safe_response_branch (state : State) (safe : Safe state) (kind : TxType)
      (tx : TxContent) (ledger : List Entry) (txid : TxID) {branch : Nat}
      (found : at? state.branches branch = some ledger)
      : Safe (appendEvent state (.response kind tx (writes ledger) txid)) :=
    safe_response state safe kind tx ledger txid (safe.1 ledger (mem_of_at? found))
  have safe_response_take (state : State) (safe : Safe state) (kind : TxType)
      (tx : TxContent) (ledger : List Entry) (count : Nat) (txid : TxID) {branch : Nat}
      (found : at? state.branches branch = some ledger)
      : Safe (appendEvent state (.response kind tx (writes (ledger.take count)) txid)) :=
    safe_response state safe kind tx (ledger.take count) txid
      (ledger_take _ _ _ (safe.1 ledger (mem_of_at? found)))
  have safe_other (state : State) (safe : Safe state) (branch : Nat)
      : Safe (appendEntry state branch ⟨branch, none⟩) := by
    refine ⟨?_, safe.2⟩
    apply forall_modify _ _ _ _ safe.1
    intro ledger member
    simpa only [LedgerSafe, writes, List.filterMap_append, List.filterMap_cons_none, List.filterMap_nil, List.append_nil, List.mem_filterMap, forall_exists_index, and_imp] using safe.1 ledger member
  have safe_elect (state : State) (safe : Safe state) (ledger : List Entry) (count : Nat)
      (member : ledger ∈ state.branches)
      : Safe { state with branches := state.branches ++ [ledger.take count] } := by
    refine ⟨?_, safe.2⟩
    intro candidate listed
    rcases List.mem_append.mp listed with old | new
    · exact safe.1 candidate old
    · simp only [List.mem_singleton] at new
      subst candidate
      exact ledger_take _ _ _ (safe.1 ledger member)
  have step_safe (before after : State) (action : Action)
      (safe : Safe before) (transition : step before action = some after)
      : Safe after := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact safe_event _ _ safe (by intro _ _ _ _ same; cases same)
    | execute =>
        obtain ⟨_, rfl, found, _, fresh⟩ := Structural.execute_some transition
        exact safe_write _ safe _ _ (mem_of_at? found) fresh
    | respond =>
        obtain ⟨_, _, _, rfl, _, _, _, ledgerFound, _, _⟩ := Structural.respond_some transition
        exact safe_response_take _ safe _ _ _ _ _ ledgerFound
    | read =>
        obtain ⟨_, _, _, rfl, _, _, _, ledgerFound, _⟩ := Structural.read_some transition
        exact safe_response_branch _ safe _ _ _ _ ledgerFound
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact safe_event _ _ safe (by intro _ _ _ _ same; cases same)
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact safe_event _ _ safe (by intro _ _ _ _ same; cases same)
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact safe_other _ safe _
    | elect =>
        obtain ⟨_, rfl, found, _, _, _⟩ := Structural.elect_some transition
        exact safe_elect _ safe _ _ (mem_of_at? found)
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact ⟨fun ledger member => (List.mem_replicate.mp member).2 ▸
          ⟨List.nodup_nil, fun _ h => absurd h List.not_mem_nil⟩,
        fun _ _ _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim⟩
  | @step before after action _ transition ih =>
      exact step_safe before after action ih transition

theorem at_most_once_observed
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ response ∈ responses state.history, response.2.observed.Nodup := by
  intro trace state member response listed
  exact ((safe_reachable (trace.reachable member)).2 _ _ _ _ _
    ((History.mem_responses_iff _ _).mp listed)).1

theorem only_observe_sent_requests
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ response ∈ responses state.history,
          ∀ tx ∈ response.2.observed,
            ∃ request ∈ requests state.history,
              request.1 < response.1 ∧ request.2 = (.rw, tx) := by
  intro trace state member response listed tx observed
  obtain ⟨index, earlier, found⟩ :=
    ((safe_reachable (trace.reachable member)).2 _ _ _ _ _
      ((History.mem_responses_iff _ _).mp listed)).2 tx observed
  exact ⟨(index, .rw, tx), (History.mem_requests_iff _ _ _ _).mpr found, earlier, rfl⟩

end consistency.Proofs.Observations

namespace consistency.Proofs.Responses

open Model Properties History

private def UniqueResponses (history : List Event) : Prop :=
  ∀ (left right : Nat) (leftKind rightKind : TxType) (tx : TxContent)
    (leftObserved rightObserved : List TxContent) (leftID rightID : TxID),
    history[left]? = some (.response leftKind tx leftObserved leftID)
    → history[right]? = some (.response rightKind tx rightObserved rightID)
    → left = right

theorem unique_tx_ids
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.tx = right.2.tx -> left.2.txid = right.2.txid := by
  have responses_reachable {state : State} (reachable : transitionSystem.Reachable state)
      : UniqueResponses state.history := by
    have responded_of_lookup (history : List Event) {requestIndex index : Nat}
        {kind : TxType} {tx : TxContent} {observed : List TxContent} {txid : TxID}
        (afterRequest : requestIndex ≤ index)
        (found : history[index]? = some (.response kind tx observed txid))
        : responded history requestIndex kind tx = true := by
      have inDrop : (history.drop requestIndex)[index - requestIndex]? =
          some (.response kind tx observed txid) := by
        rw [List.getElem?_drop]
        simpa only [Nat.add_sub_of_le afterRequest] using found
      apply List.any_eq_true.mpr
      exact ⟨_, List.mem_of_getElem? inDrop, by simp only [decide_true, Bool.and_self]⟩
    have no_previous_response (history : List Event) (causal : Causal history)
        (requests : RequestInvariant history) {requestIndex : Nat} {kind : TxType}
        {tx : TxContent} (requestFound : at? history requestIndex = some (.request kind tx))
        (unanswered : responded history requestIndex kind tx = false) {index : Nat}
        {otherKind : TxType} {observed : List TxContent} {txid : TxID}
        (responseFound : history[index]? = some (.response otherKind tx observed txid))
        : False := by
      have nonzero : requestIndex ≠ 0 := by
        rintro rfl
        simp only [at?, ↓reduceIte, reduceCtorEq] at requestFound
      have newRequest : history[requestIndex - 1]? = some (.request kind tx) := by
        simpa only [at?, nonzero, ↓reduceIte] using requestFound
      obtain ⟨oldIndex, earlier, oldRequest⟩ := causal _ _ _ _ _ responseFound
      have sameIndex := requests.2 _ _ _ _ _ _ oldRequest newRequest rfl
      rw [sameIndex, newRequest] at oldRequest
      have sameKind : kind = otherKind := by simpa only [Option.some.injEq, Event.request.injEq, and_true] using oldRequest
      subst otherKind
      have delivered := responded_of_lookup history (Nat.le_of_pred_lt (Nat.lt_of_le_of_lt (Nat.le_of_eq sameIndex.symm) earlier) :
        requestIndex ≤ index) responseFound
      simp only [unanswered, Bool.false_eq_true] at delivered
    have responses_snoc (history : List Event) (event : Event)
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
        · exact lastLeft.trans lastRight.symm
    have responses_response (history : List Event) (invariant : UniqueResponses history)
        (causal : Causal history) (requests : RequestInvariant history) {requestIndex : Nat}
        {kind : TxType} {tx : TxContent} (observed : List TxContent) (txid : TxID)
        (requestFound : at? history requestIndex = some (.request kind tx))
        (unanswered : responded history requestIndex kind tx = false)
        : UniqueResponses (history ++ [Event.response kind tx observed txid]) := by
      apply responses_snoc history _ invariant
      intro _ _ _ _ same
      cases same
      intro index otherKind otherObserved otherID found
      exact no_previous_response history causal requests requestFound unanswered found
    have step_responses (before after : State) (action : Action)
        (invariant : UniqueResponses before.history) (causal : Causal before.history)
        (requests : RequestInvariant before.history)
        (transition : step before action = some after)
        : UniqueResponses after.history := by
      cases action with
      | request =>
          rw [Structural.request_some transition]
          exact responses_snoc _ _ invariant (by intro _ _ _ _ same; cases same)
      | execute =>
          obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
          exact invariant
      | respond =>
          obtain ⟨_, _, _, rfl, found, unanswered, _, _, _, _⟩ := Structural.respond_some transition
          exact responses_response _ invariant causal requests _ _ found unanswered
      | read =>
          obtain ⟨_, _, _, rfl, found, unanswered, _, _, _⟩ := Structural.read_some transition
          exact responses_response _ invariant causal requests _ _ found unanswered
      | commit =>
          obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
          exact responses_snoc _ _ invariant (by intro _ _ _ _ same; cases same)
      | invalidate =>
          obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
          exact responses_snoc _ _ invariant (by intro _ _ _ _ same; cases same)
      | appendOther =>
          obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
          exact invariant
      | elect =>
          obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
          exact invariant
    induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
    | @initial state initialized =>
        change state = initialState at initialized
        subst state
        exact fun _ _ _ _ _ _ _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim
    | @step before after action reachable transition ih =>
        exact step_responses before after action ih
          (causal_reachable reachable) (requests_reachable reachable) transition
  intro trace state member left first right second sameTx
  have firstLookup := (mem_responses_iff _ _).mp first
  have secondLookup := (mem_responses_iff _ _).mp second
  rw [← sameTx] at secondLookup
  have sameIndex := responses_reachable (trace.reachable member)
    _ _ _ _ _ _ _ _ _ firstLookup secondLookup
  rw [sameIndex, secondLookup] at firstLookup
  exact (Event.response.inj (Option.some.inj firstLookup)).2.2.2.symm

end consistency.Proofs.Responses

namespace consistency.Proofs.Witnesses

open Model Properties

private theorem replay_reachable (actions : List Action)
    {before after : State} (reachable : transitionSystem.Reachable before)
    (executed : actions.foldlM step before = some after)
    : transitionSystem.Reachable after := by
  induction actions generalizing before with
  | nil =>
      cases executed
      exact reachable
  | cons action actions ih =>
      obtain ⟨next, transition, rest⟩ := Option.bind_eq_some_iff.mp executed
      exact ih (.step reachable transition) rest

private theorem writes_and_reads_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem,
        ({
            history :=
              [
                .request .rw 0,
                .response .rw 0 [0] ⟨2, 1⟩,
                .request .rw 1,
                .response .rw 1 [0, 1] ⟨2, 2⟩,
                .status ⟨2, 1⟩ .committed,
                .status ⟨2, 2⟩ .committed,
                .request .ro 2,
                .response .ro 2 [0, 1] ⟨2, 2⟩,
                .request .ro 3,
                .response .ro 3 [0, 1] ⟨2, 2⟩
              ]
            branches := [[], [⟨2, some 0⟩, ⟨2, some 1⟩]]
          }
          : State)
        ∈ trace :=
  (CCF.Execution.reachable_iff_trace (system := transitionSystem)).mp
    (replay_reachable
      [
        .request .rw,
        .execute 1 2,
        .respond 1 2 1,
        .request .rw,
        .execute 3 2,
        .respond 3 2 2,
        .commit 2,
        .commit 4,
        .request .ro,
        .read 7 2,
        .request .ro,
        .read 9 2
      ]
      (.initial rfl) (by decide))

private theorem replaced_writes_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem,
        ({
            history :=
              [
                .request .rw 0,
                .response .rw 0 [0] ⟨2, 1⟩,
                .request .rw 1,
                .response .rw 1 [0, 1] ⟨2, 2⟩,
                .status ⟨2, 1⟩ .invalid,
                .status ⟨2, 2⟩ .invalid,
                .request .rw 2,
                .response .rw 2 [2] ⟨3, 1⟩,
                .status ⟨3, 1⟩ .committed,
                .request .rw 3,
                .response .rw 3 [2, 3] ⟨3, 2⟩,
                .status ⟨3, 2⟩ .committed,
                .request .ro 4,
                .response .ro 4 [2, 3] ⟨3, 2⟩,
                .request .ro 5,
                .response .ro 5 [0, 1] ⟨2, 2⟩
              ]
            branches := [[], [⟨2, some 0⟩, ⟨2, some 1⟩], [⟨3, some 2⟩, ⟨3, some 3⟩]]
          }
          : State)
        ∈ trace :=
  (CCF.Execution.reachable_iff_trace (system := transitionSystem)).mp
    (replay_reachable
      [
        .request .rw,
        .execute 1 2,
        .respond 1 2 1,
        .request .rw,
        .execute 3 2,
        .respond 3 2 2,
        .invalidate 2,
        .invalidate 4,
        .elect 2 0,
        .request .rw,
        .execute 7 3,
        .respond 7 3 1,
        .commit 8,
        .request .rw,
        .execute 10 3,
        .respond 10 3 2,
        .commit 11,
        .request .ro,
        .read 13 3,
        .request .ro,
        .read 15 2
      ]
      (.initial rfl) (by decide))

/-- Older-view writes are invalidated after a higher view commits, through the
frontier-passed and higher-view-below alternatives of `mayInvalidate`. A leader is
then elected from a branch whose length equals the commit frontier, and a write
copied into a newer view commits. -/
private theorem superseded_writes_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem,
        ({
            history :=
              [
                .request .rw 0,
                .response .rw 0 [0] ⟨2, 1⟩,
                .request .rw 1,
                .response .rw 1 [0, 1] ⟨2, 2⟩,
                .request .rw 2,
                .response .rw 2 [2] ⟨3, 1⟩,
                .status ⟨3, 1⟩ .committed,
                .status ⟨2, 1⟩ .invalid,
                .status ⟨2, 2⟩ .invalid,
                .request .rw 3,
                .response .rw 3 [2, 3] ⟨3, 2⟩,
                .status ⟨3, 2⟩ .committed
              ]
            branches :=
              [
                [],
                [⟨2, some 0⟩, ⟨2, some 1⟩],
                [⟨3, some 2⟩, ⟨3, some 3⟩],
                [⟨3, some 2⟩],
                [⟨3, some 2⟩, ⟨3, some 3⟩]
              ]
          }
          : State)
        ∈ trace :=
  (CCF.Execution.reachable_iff_trace (system := transitionSystem)).mp
    (replay_reachable
      [
        .request .rw,
        .execute 1 2,
        .respond 1 2 1,
        .request .rw,
        .execute 3 2,
        .respond 3 2 2,
        .elect 2 0,
        .request .rw,
        .execute 5 3,
        .respond 5 3 1,
        .commit 6,
        .invalidate 2,
        .invalidate 4,
        .elect 3 1,
        .request .rw,
        .execute 10 3,
        .respond 10 3 2,
        .elect 3 2,
        .commit 11
      ]
      (.initial rfl) (by decide))

/-- Overlapping writes respond out of request and transaction-ID order, a ledger
entry carries no application write, and a former leader keeps responding after an
election. The former leader's later write shares a sequence number with the new
leader's committed write and is invalidated. -/
private theorem reordered_writes_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem,
        ({
            history :=
              [
                .request .rw 0,
                .request .rw 1,
                .response .rw 1 [0, 1] ⟨2, 2⟩,
                .response .rw 0 [0] ⟨2, 1⟩,
                .status ⟨2, 2⟩ .committed,
                .status ⟨2, 1⟩ .committed,
                .request .rw 2,
                .request .rw 3,
                .response .rw 3 [0, 1, 2, 3] ⟨3, 5⟩,
                .response .rw 2 [0, 1, 2] ⟨2, 4⟩,
                .status ⟨3, 5⟩ .committed,
                .status ⟨2, 4⟩ .committed,
                .request .rw 4,
                .response .rw 4 [0, 1, 2, 4] ⟨2, 5⟩,
                .status ⟨2, 5⟩ .invalid
              ]
            branches :=
              [
                [],
                [⟨2, some 0⟩, ⟨2, some 1⟩, ⟨2, none⟩, ⟨2, some 2⟩, ⟨2, some 4⟩],
                [⟨2, some 0⟩, ⟨2, some 1⟩, ⟨2, none⟩, ⟨2, some 2⟩, ⟨3, some 3⟩]
              ]
          }
          : State)
        ∈ trace :=
  (CCF.Execution.reachable_iff_trace (system := transitionSystem)).mp
    (replay_reachable
      [
        .request .rw,
        .request .rw,
        .execute 1 2,
        .execute 2 2,
        .respond 2 2 2,
        .respond 1 2 1,
        .commit 3,
        .commit 4,
        .appendOther 2,
        .request .rw,
        .execute 7 2,
        .elect 2 4,
        .request .rw,
        .execute 8 3,
        .respond 8 3 5,
        .respond 7 2 4,
        .commit 9,
        .commit 10,
        .request .rw,
        .execute 13 2,
        .respond 13 2 5,
        .invalidate 14
      ]
      (.initial rfl) (by decide))

theorem all_received_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (write read : Nat × Response),
        state ∈ trace
        ∧ write ∈ responsesOf state.history .rw
        ∧ read ∈ responsesOf state.history .ro := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨7, ⟨.ro, 2, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem unique_txs_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responsesOf state.history .rw
        ∧ right ∈ responsesOf state.history .rw
        ∧ left.2.txid = right.2.txid := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem same_observations_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responses state.history
        ∧ right ∈ responses state.history
        ∧ left.2.txid = right.2.txid := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨7, ⟨.ro, 2, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response),
    (⟨9, ⟨.ro, 3, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem unique_tx_requests_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × (TxType × TxContent)),
        state ∈ trace
        ∧ left ∈ requests state.history
        ∧ right ∈ requests state.history
        ∧ left.1 ≠ right.1 := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, _, ⟨0, .rw, 0⟩, ⟨6, .ro, 2⟩, member, by decide⟩

theorem unique_tx_ids_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responses state.history
        ∧ right ∈ responses state.history
        ∧ left.2.tx = right.2.tx := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem unique_seq_nums_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.2.txid.seqno = right.2.txid.seqno := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem committed_or_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State) (committed : TxID),
        state ∈ trace ∧ committed ∈ statusIDs state.history .committed := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, _, ⟨3, 1⟩, member, by decide⟩

theorem once_committed_prev_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.view = right.1.view
        ∧ right.1.seqno ≤ left.1.seqno := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, _, ⟨⟨3, 2⟩, .committed⟩, ⟨⟨3, 1⟩, .committed⟩, member, by decide⟩

theorem once_committed_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.seqno ≤ right.1.seqno
        ∧ right.1.view < left.1.view := by
  obtain ⟨trace, member⟩ := superseded_writes_trace
  exact ⟨trace, _, ⟨⟨3, 1⟩, .committed⟩, ⟨⟨2, 2⟩, .invalid⟩, member, by decide⟩

theorem once_invalid_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .invalid
        ∧ left.1.view = right.1.view
        ∧ left.1.seqno ≤ right.1.seqno := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, _, ⟨⟨2, 1⟩, .invalid⟩, ⟨⟨2, 2⟩, .invalid⟩, member, by decide⟩

theorem only_observe_sent_requests_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (response : Nat × Response) (tx : TxContent),
        state ∈ trace
        ∧ response ∈ responses state.history
        ∧ tx ∈ response.2.observed := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, _, (⟨7, ⟨.ro, 2, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response), 0, member, by decide⟩

theorem at_most_once_observed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (response : Nat × Response),
        state ∈ trace ∧ response ∈ responses state.history := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, _, (⟨7, ⟨.ro, 2, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response), member, by decide⟩

theorem real_time_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1 := by
  obtain ⟨trace, member⟩ := reordered_writes_trace
  exact ⟨
    trace,
    _,
    (⟨3, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨8, ⟨.rw, 3, [0, 1, 2, 3], ⟨3, 5⟩⟩⟩ : Nat × Response),
    ⟨7, .rw, 3⟩,
    member,
    by decide
  ⟩

theorem invalid_not_observed_by_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (invalid observer : Nat × Response),
        state ∈ trace
        ∧ invalid ∈ responsesOf state.history .rw
        ∧ observer ∈ committedResponses state.history .rw
        ∧ invalid.1 ≠ observer.1
        ∧ invalid.2.txid ∈ statusIDs state.history .invalid := by
  obtain ⟨trace, member⟩ := reordered_writes_trace
  exact ⟨
    trace,
    _,
    (⟨13, ⟨.rw, 4, [0, 1, 2, 4], ⟨2, 5⟩⟩⟩ : Nat × Response),
    (⟨8, ⟨.rw, 3, [0, 1, 2, 3], ⟨3, 5⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem write_pair_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    _,
    (⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩ : Nat × Response),
    (⟨3, ⟨.rw, 1, [0, 1], ⟨2, 2⟩⟩⟩ : Nat × Response),
    member,
    by decide
  ⟩

theorem committed_rw_ordered_serializable_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Response),
        state ∈ trace
        ∧ (left, right)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail := by
  -- Sorting reverses both the same-view and the cross-view response pairs.
  have reordered_writes_ordered
      : committedRwResponses ({
        history :=
          [
            .request .rw 0,
            .request .rw 1,
            .response .rw 1 [0, 1] ⟨2, 2⟩,
            .response .rw 0 [0] ⟨2, 1⟩,
            .status ⟨2, 2⟩ .committed,
            .status ⟨2, 1⟩ .committed,
            .request .rw 2,
            .request .rw 3,
            .response .rw 3 [0, 1, 2, 3] ⟨3, 5⟩,
            .response .rw 2 [0, 1, 2] ⟨2, 4⟩,
            .status ⟨3, 5⟩ .committed,
            .status ⟨2, 4⟩ .committed,
            .request .rw 4,
            .response .rw 4 [0, 1, 2, 4] ⟨2, 5⟩,
            .status ⟨2, 5⟩ .invalid
          ]
        branches :=
          [
            [],
            [⟨2, some 0⟩, ⟨2, some 1⟩, ⟨2, none⟩, ⟨2, some 2⟩, ⟨2, some 4⟩],
            [⟨2, some 0⟩, ⟨2, some 1⟩, ⟨2, none⟩, ⟨2, some 2⟩, ⟨3, some 3⟩]
          ]
      } : State).history
        = [
            (⟨.rw, 0, [0], ⟨2, 1⟩⟩ : Response),
            (⟨.rw, 1, [0, 1], ⟨2, 2⟩⟩ : Response),
            (⟨.rw, 2, [0, 1, 2], ⟨2, 4⟩⟩ : Response),
            (⟨.rw, 3, [0, 1, 2, 3], ⟨3, 5⟩⟩ : Response)
          ] := by
    change ([(⟨.rw, 1, [0, 1], ⟨2, 2⟩⟩ : Response), (⟨.rw, 0, [0], ⟨2, 1⟩⟩ : Response)]
            ++ [(⟨.rw, 3, [0, 1, 2, 3], ⟨3, 5⟩⟩ : Response),
              (⟨.rw, 2, [0, 1, 2], ⟨2, 4⟩⟩ : Response)]).mergeSort
            _
    = _
    rw [List.mergeSort_append _ _ (by simp) (by simp)]
    simp [txIDStrictlyLessThan]
  obtain ⟨trace, member⟩ := reordered_writes_trace
  exact ⟨
    trace,
    _,
    (⟨.rw, 0, [0], ⟨2, 1⟩⟩ : Response),
    (⟨.rw, 1, [0, 1], ⟨2, 2⟩⟩ : Response),
    member,
    by rw [reordered_writes_ordered]; decide
  ⟩

end consistency.Proofs.Witnesses
