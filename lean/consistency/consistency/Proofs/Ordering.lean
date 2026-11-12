module

public import consistency.Properties.History
public import CCF.Proofs.Execution

/-!
Ledger identity, commitment, serializability, ordering and real-time proofs.

This module is self-contained: shared lemmas are duplicated as private declarations in each
proof module so that the proof modules can be checked in parallel.
-/

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Structural

open Model

private def BranchExtension (before after : List (List Entry)) : Prop :=
  ∀ index ledger,
    at? before index = some ledger
    → ∃ extended, at? after index = some extended ∧ ledger <+: extended

private theorem branches_modify (branches : List (List Entry)) (position : Nat)
    (entry : Entry)
    : BranchExtension branches (branches.modify position (· ++ [entry])) := by
  intro index ledger found
  have nonzero : index ≠ 0 := by
    rintro rfl
    simp only [at?, ↓reduceIte, reduceCtorEq] at found
  have lookup : branches[index - 1]? = some ledger := by simpa only [at?, nonzero, ↓reduceIte] using found
  by_cases same : position = index - 1
  · refine ⟨ledger ++ [entry], ?_, by simp only [List.prefix_append]⟩
    simp only [at?, nonzero, ↓reduceIte, same, List.getElem?_modify_eq, lookup, Option.map_eq_map, Option.map_some]
  · refine ⟨ledger, ?_, List.prefix_refl _⟩
    simp only [at?, nonzero, ↓reduceIte, ne_eq, same, not_false_eq_true, List.getElem?_modify_ne, lookup]

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

private theorem step_branches (before after : State) (action : Action)
    (transition : step before action = some after)
    : BranchExtension before.branches after.branches := by
  have branches_refl (branches : List (List Entry))
      : BranchExtension branches branches := by
    intro index ledger found
    exact ⟨ledger, found, List.prefix_refl _⟩
  have branches_append (branches extra : List (List Entry))
      : BranchExtension branches (branches ++ extra) := by
    intro index ledger found
    have nonzero : index ≠ 0 := by
      rintro rfl
      simp only [at?, ↓reduceIte, reduceCtorEq] at found
    have lookup : branches[index - 1]? = some ledger := by simpa only [at?, nonzero, ↓reduceIte] using found
    refine ⟨ledger, ?_, List.prefix_refl _⟩
    simp only [at?, nonzero, ↓reduceIte, List.getElem?_append_left (List.getElem?_eq_some_iff.mp lookup).1, lookup]
  cases action with
  | request => rw [request_some transition]; exact branches_refl _
  | execute =>
      obtain ⟨_, rfl, -⟩ := execute_some transition
      exact branches_modify _ _ _
  | respond =>
      obtain ⟨_, _, _, rfl, -⟩ := respond_some transition
      exact branches_refl _
  | read =>
      obtain ⟨_, _, _, rfl, -⟩ := read_some transition
      exact branches_refl _
  | commit =>
      obtain ⟨_, rfl, -⟩ := commit_some transition
      exact branches_refl _
  | invalidate =>
      obtain ⟨_, rfl, -⟩ := invalidate_some transition
      exact branches_refl _
  | appendOther =>
      obtain ⟨rfl, -⟩ := appendOther_some transition
      exact branches_modify _ _ _
  | elect =>
      obtain ⟨_, rfl, -⟩ := elect_some transition
      exact branches_append _ _

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
      · exact Nat.lt_of_lt_of_le (invariant.1 _ _ _ old) monotonic
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

end consistency.Proofs.Observations

namespace consistency.Proofs.LedgerIdentity

open Model Properties Observations

private theorem at_bounds {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : 0 < index ∧ index ≤ xs.length := by
  by_cases zero : index = 0
  · subst zero
    cases found
  · exact ⟨Nat.pos_of_ne_zero zero,
      Nat.le_of_pred_lt (List.getElem?_eq_some_iff.mp ((ite_eq_right zero).symm.trans found)).1⟩

private theorem at_prefix {α : Type} {before after : List α} (isPrefix : before <+: after)
    {index : Nat} {value : α} (found : at? before index = some value)
    : at? after index = some value := by
  have bounds := at_bounds found
  obtain ⟨tail, rfl⟩ := isPrefix
  have nz := Nat.ne_of_gt bounds.1
  exact (ite_eq_right nz).trans ((List.getElem?_append_left (Nat.lt_of_lt_of_le (Nat.sub_one_lt nz) bounds.2)).trans ((ite_eq_right nz).symm.trans found))

private theorem take_of_prefix {α : Type} {before after : List α}
    (isPrefix : before <+: after) (count : Nat) (bound : count ≤ before.length)
    : after.take count = before.take count := by
  obtain ⟨tail, rfl⟩ := isPrefix
  exact List.take_append_of_le_length bound

private theorem at_take {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : at? (xs.take index) index = some value := by
  have nz := Nat.ne_of_gt (at_bounds found).1
  exact (ite_eq_right nz).trans ((List.getElem?_take_of_lt (Nat.sub_one_lt nz)).trans ((ite_eq_right nz).symm.trans found))

private theorem at_snoc {α : Type} {xs : List α} {value entry : α} {index : Nat}
    (found : at? (xs ++ [entry]) index = some value)
    : at? xs index = some value ∨ (index = xs.length + 1 ∧ value = entry) := by
  have bounds := at_bounds found
  have nz := Nat.ne_of_gt bounds.1
  by_cases inside : index ≤ xs.length
  · exact Or.inl ((ite_eq_right nz).trans ((List.getElem?_append_left (Nat.lt_of_lt_of_le (Nat.sub_one_lt nz) inside)).symm.trans ((ite_eq_right nz).symm.trans found)))
  · have endpoint : index = xs.length + 1 :=
      Nat.le_antisymm (Nat.le_trans bounds.2 (Nat.le_of_eq List.length_append)) (Nat.lt_of_not_le inside)
    subst index
    exact Or.inr ⟨rfl, Option.some.inj (found.symm.trans ((ite_eq_right nz).trans List.getElem?_concat_length))⟩

private def Anchored (branches : List (List Entry)) : Prop :=
  ∀ branch ledger,
    at? branches branch = some ledger
    → ∀ seqno entry,
        at? ledger seqno = some entry
        → entry.view ≤ branch
          ∧ ∃ origin, at? branches entry.view = some origin ∧ ledger.take seqno <+: origin

private theorem active_positive (state : State) {branch : Nat}
    (active : activeBranch state branch = true)
    : 0 < branch := by
  simp only [activeBranch, Bool.and_eq_true, decide_eq_true_eq] at active
  exact Nat.lt_of_lt_of_le (Nat.zero_lt_succ 1) active.1

private theorem anchored_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Anchored state.branches := by
  have at_of_pos {α : Type} {xs : List α} {index : Nat} (positive : 0 < index)
      : at? xs index = xs[index - 1]? :=
    ite_eq_right (Nat.ne_of_gt positive)
  have anchored_modify (branches : List (List Entry)) (anchored : Anchored branches)
      (branch : Nat) (entry : Entry) (view : entry.view = branch)
      (positive : 0 < branch)
      : Anchored (branches.modify (branch - 1) (· ++ [entry])) := by
    intro index ledger found seqno value atEntry
    have bounds := at_bounds found
    have lookup : (branches.modify (branch - 1) (· ++ [entry]))[index - 1]? =
        some ledger := (at_of_pos bounds.1).symm.trans found
    rw [List.getElem?_modify] at lookup
    obtain ⟨oldLedger, oldLookup, same⟩ := Option.map_eq_some_iff.mp lookup
    have oldFound : at? branches index = some oldLedger :=
      (at_of_pos bounds.1).trans oldLookup
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
        have equal : branch = index := Nat.sub_one_cancel positive bounds.1 selected
        refine ⟨Nat.le_of_eq (view.trans equal), oldLedger ++ [entry], ?_, ?_⟩
        · rw [view.trans equal]
          exact found
        · exact List.take_prefix _ _
    · simp only [selected, ite_false] at same
      subst ledger
      obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ oldFound _ _ atEntry
      obtain ⟨extended, extendedFound, extension⟩ :=
        Structural.branches_modify branches (branch - 1) entry _ _ originFound
      exact ⟨bound, extended, extendedFound, isPrefix.trans extension⟩
  have anchored_elect (branches : List (List Entry)) (anchored : Anchored branches)
      {branch : Nat} {ledger : List Entry} (found : at? branches branch = some ledger)
      (count : Nat)
      : Anchored (branches ++ [ledger.take count]) := by
    intro index candidate listed seqno entry atEntry
    rcases at_snoc listed with old | ⟨endpoint, rfl⟩
    · obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ old _ _ atEntry
      exact ⟨bound, origin, at_prefix (by simp only [List.prefix_append]) originFound, isPrefix⟩
    · have oldEntry := at_prefix (List.take_prefix count ledger) atEntry
      obtain ⟨bound, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ oldEntry
      refine ⟨Nat.le_trans (Nat.le_succ_of_le (Nat.le_trans bound (at_bounds found).2))
          (Nat.le_of_eq endpoint.symm),
        origin, at_prefix (List.prefix_append _ _) originFound, ?_⟩
      rw [take_of_prefix (List.take_prefix count ledger) seqno (at_bounds atEntry).2] at isPrefix
      exact isPrefix
  have step_anchored (before after : State) (action : Action)
      (anchored : Anchored before.branches)
      (transition : step before action = some after)
      : Anchored after.branches := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact anchored
    | execute =>
        obtain ⟨_, rfl, _, active, _⟩ := Structural.execute_some transition
        exact anchored_modify _ anchored _ _ rfl (active_positive before active)
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact anchored
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact anchored
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact anchored
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact anchored
    | appendOther =>
        obtain ⟨rfl, active⟩ := Structural.appendOther_some transition
        exact anchored_modify _ anchored _ _ rfl (active_positive before active)
    | elect =>
        obtain ⟨_, rfl, found, _, _, _⟩ := Structural.elect_some transition
        exact anchored_elect _ anchored found _
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      intro branch ledger found seqno entry atEntry
      have empty : ledger = [] :=
        (List.mem_replicate.mp (mem_of_at? found)).2
      exact (List.not_mem_nil (empty ▸ mem_of_at? atEntry)).elim
  | @step before after action _ transition ih =>
      exact step_anchored before after action ih transition

private def Snapshot (branches : List (List Entry)) (kind : TxType) (tx : TxContent)
    (observed : List TxContent) (txid : TxID)
    : Prop :=
  ∃ ledger,
    at? branches txid.view = some ledger
    ∧ observed = writes (ledger.take txid.seqno)
    ∧ ∃ entry,
        at? ledger txid.seqno = some entry
        ∧ entry.view = txid.view
        ∧ (kind = .rw → entry.tx = some tx)

private def Snapshots (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ (index : Nat) (kind : TxType) (tx : TxContent) (observed : List TxContent)
    (txid : TxID),
    history[index]? = some (.response kind tx observed txid)
    → Snapshot branches kind tx observed txid

private theorem at_last {α : Type} {ledger : List α} {entry : α}
    (found : ledger.getLast? = some entry)
    : at? ledger ledger.length = some entry := by
  cases ledger with
  | nil => cases found
  | cons head tail =>
      exact (ite_eq_right (Nat.succ_ne_zero _)).trans (List.getLast?_eq_getElem?.symm.trans found)

private theorem snapshots_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Snapshots state.branches state.history := by
  have snapshot_source (branches : List (List Entry)) (anchored : Anchored branches)
      {branch seqno : Nat} {ledger : List Entry} {entry : Entry}
      (found : at? branches branch = some ledger) (atEntry : at? ledger seqno = some entry)
      (kind : TxType) (tx : TxContent) (txMatches : kind = .rw → entry.tx = some tx)
      : Snapshot branches kind tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩ := by
    obtain ⟨_, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ atEntry
    have length : seqno ≤ (ledger.take seqno).length := by
      simp only [List.length_take, Nat.min_eq_left (at_bounds atEntry).2, Std.le_refl]
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
  have snapshot_mono {before after : List (List Entry)}
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
  have snapshots_mono (before after : List (List Entry)) (history : List Event)
      (snapshots : Snapshots before history)
      (extension : Structural.BranchExtension before after)
      : Snapshots after history := by
    intro index kind tx observed txid found
    exact snapshot_mono extension (snapshots _ _ _ _ _ found)
  have snapshots_snoc (branches : List (List Entry)) (history : List Event)
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
  have snapshots_response (branches : List (List Entry)) (history : List Event)
      (snapshots : Snapshots branches history) {kind : TxType} {tx : TxContent}
      {observed : List TxContent} {txid : TxID}
      (snapshot : Snapshot branches kind tx observed txid)
      : Snapshots branches (history ++ [Event.response kind tx observed txid]) := by
    apply snapshots_snoc _ _ _ snapshots
    intro _ _ _ _ same
    cases same
    exact snapshot
  have snapshot_last (branches : List (List Entry)) (anchored : Anchored branches)
      {branch : Nat} {ledger : List Entry} {entry : Entry}
      (found : at? branches branch = some ledger) (last : ledger.getLast? = some entry)
      (tx : TxContent)
      : Snapshot branches .ro tx (writes ledger) ⟨entry.view, ledger.length⟩ := by
    have snapshot := snapshot_source branches anchored found (at_last last) .ro tx (by simp only [reduceCtorEq, forall_false])
    simpa only [List.take_length] using snapshot
  have step_snapshots (before after : State) (action : Action)
      (anchored : Anchored before.branches)
      (snapshots : Snapshots before.branches before.history)
      (transition : step before action = some after)
      : Snapshots after.branches after.history := by
    have extension := Structural.step_branches before after action transition
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact snapshots_snoc _ _ _ snapshots (by intro _ _ _ _ same; cases same)
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact snapshots_mono _ _ _ snapshots extension
    | respond =>
        obtain ⟨tx, _, _, rfl, _, _, _, ledgerFound, entryFound, txMatches⟩ := Structural.respond_some transition
        exact snapshots_response _ _ snapshots
          (snapshot_source _ anchored ledgerFound entryFound .rw tx fun _ => txMatches)
    | read =>
        obtain ⟨tx, _, _, rfl, _, _, _, ledgerFound, last⟩ := Structural.read_some transition
        exact snapshots_response _ _ snapshots (snapshot_last _ anchored ledgerFound last tx)
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact snapshots_snoc _ _ _ snapshots (by intro _ _ _ _ same; cases same)
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact snapshots_snoc _ _ _ snapshots (by intro _ _ _ _ same; cases same)
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact snapshots_mono _ _ _ snapshots extension
    | elect =>
        obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
        exact snapshots_mono _ _ _ snapshots extension
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact fun _ _ _ _ _ found => (Option.some_ne_none _ (found.symm.trans List.getElem?_nil)).elim
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

namespace consistency.Proofs.Commitment

open Model Properties Observations LedgerIdentity

private theorem at_take_of_le {α : Type} {xs : List α} {index count : Nat} {value : α}
    (found : at? xs index = some value) (bound : index ≤ count)
    : at? (xs.take count) index = some value := by
  have nz := Nat.ne_of_gt (at_bounds found).1
  exact (ite_eq_right nz).trans ((List.getElem?_take_of_lt (Nat.lt_of_lt_of_le (Nat.sub_one_lt nz) bound)).trans ((ite_eq_right nz).symm.trans found))

private theorem anchored_prefix (branches : List (List Entry))
    (anchored : Anchored branches) {branch seqno : Nat} {ledger : List Entry}
    {entry : Entry} (found : at? branches branch = some ledger)
    (atEntry : at? ledger seqno = some entry)
    : ∃ origin,
        at? branches entry.view = some origin
        ∧ ledger.take seqno = origin.take seqno := by
  obtain ⟨_, origin, originFound, isPrefix⟩ := anchored _ _ found _ _ atEntry
  refine ⟨origin, originFound, ?_⟩
  have bound : seqno ≤ (ledger.take seqno).length := by
    simp only [List.length_take, Nat.min_eq_left (at_bounds atEntry).2, Std.le_refl]
  simpa only [List.take_take, Nat.min_self]
    using (take_of_prefix isPrefix seqno bound).symm

private theorem frontier_bound (history : List Event) {txid : TxID}
    (member : txid ∈ statusIDs history .committed)
    : txid.seqno ≤ commitSeqno history := by
  have fold_max_bound (ids : List TxID) (start : Nat) {txid : TxID} (member : txid ∈ ids)
      : txid.seqno ≤ ids.foldl (fun seqno id => max seqno id.seqno) start := by
    have accumulator : ∀ (ids : List TxID) (start : Nat),
        start ≤ ids.foldl (fun seqno id => max seqno id.seqno) start := by
      intro ids
      induction ids with
      | nil => simp only [List.foldl_nil, Std.le_refl, implies_true]
      | cons head tail ih =>
          intro start
          exact Nat.le_trans (Nat.le_max_left _ _) (ih _)
    induction ids generalizing start with
    | nil => simp only [List.not_mem_nil] at member
    | cons head tail ih =>
        rcases List.mem_cons.mp member with same | later
        · subst head
          exact Nat.le_trans (Nat.le_max_right _ _) (accumulator tail _)
        · exact ih _ later
  exact fold_max_bound _ _ member

private def Current (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ txid ∈ statusIDs history .committed,
    ∃ ledger,
      at? branches branches.length = some ledger
      ∧ ∃ entry, at? ledger txid.seqno = some entry ∧ entry.view = txid.view

private theorem current_snoc (branches : List (List Entry)) (history : List Event)
    (event : Event) (current : Current branches history)
    (newCommit
      : ∀ txid,
          event = .status txid .committed
          → ∃ ledger,
              at? branches branches.length = some ledger
              ∧ ∃ entry, at? ledger txid.seqno = some entry ∧ entry.view = txid.view)
    : Current branches (history ++ [event]) := by
  intro txid member
  unfold statusIDs at member
  rw [List.filterMap_append, List.mem_append] at member
  rcases member with old | new
  · exact current txid old
  · apply newCommit
    cases event with
    | status id value =>
        cases value
        · simp only [List.filterMap_cons, List.filterMap_nil, ite_true, List.mem_singleton] at new
          rw [new]
        · simp only [List.filterMap_cons, List.filterMap_nil, reduceCtorEq, ite_false,
            List.not_mem_nil] at new
    | _ => simp only [List.filterMap_cons, List.filterMap_nil, List.not_mem_nil] at new

private theorem current_elect (state : State)
    (current : Current state.branches state.history) (anchored : Anchored state.branches)
    {branch : Nat} {ledger : List Entry} (found : at? state.branches branch = some ledger)
    (count : Nat) (compatible : hasCommittedPrefix state ledger = true)
    (retained : commitSeqno state.history ≤ count)
    : Current (state.branches ++ [ledger.take count]) state.history := by
  have frontier_entry (state : State) {ledger : List Entry}
      (compatible : hasCommittedPrefix state ledger = true)
      (positive : 0 < commitSeqno state.history)
      : ∃ entry,
          at? ledger (commitSeqno state.history) = some entry
          ∧ (⟨entry.view, commitSeqno state.history⟩ : TxID)
            ∈ statusIDs state.history .committed := by
    unfold hasCommittedPrefix at compatible
    simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at compatible
    rcases compatible.2 with zero | matched
    · exact absurd zero (Nat.ne_of_gt positive)
    · cases found : at? ledger (commitSeqno state.history) with
      | none => simp only [found, Bool.false_eq_true] at matched
      | some entry =>
          exact ⟨
            entry,
            rfl,
            by simpa only [found, List.contains_eq_mem, decide_eq_true_eq] using matched
          ⟩
  have equal_prefixes (branches : List (List Entry)) (anchored : Anchored branches)
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
  intro txid member
  obtain ⟨latest, latestFound, entry, atEntry, view⟩ := current txid member
  have bound := frontier_bound state.history member
  have positive : 0 < commitSeqno state.history :=
    Nat.lt_of_lt_of_le (at_bounds atEntry).1 bound
  obtain ⟨frontierEntry, candidateAt, known⟩ := frontier_entry state compatible positive
  obtain ⟨currentLedger, currentFound, currentEntry, currentAt, currentView⟩ := current _ known
  rw [latestFound] at currentFound
  cases currentFound
  have same := equal_prefixes state.branches anchored found latestFound
    candidateAt currentAt currentView.symm
  have inPrefix := at_take_of_le atEntry bound
  rw [← same] at inPrefix
  have preserved := at_prefix (List.take_prefix_take_left (l := ledger) retained) inPrefix
  exact ⟨
    ledger.take count,
    by
      simp only [at?, List.length_append, List.length_cons, List.length_nil, Nat.zero_add, Nat.add_eq_zero_iff, List.length_eq_zero_iff, Nat.succ_ne_self, and_false, ↓reduceIte, Nat.add_one_sub_one, Nat.lt_add_one, getElem?_pos, Std.le_refl, List.getElem_append_right, Nat.sub_self, List.getElem_cons_zero],
    entry,
    preserved,
    view
  ⟩

private theorem current_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Current state.branches state.history := by
  have current_mono (before after : List (List Entry)) (history : List Event)
      (current : Current before history)
      (extension : Structural.BranchExtension before after)
      (length : after.length = before.length)
      : Current after history := by
    intro txid member
    obtain ⟨ledger, found, entry, atEntry, view⟩ := current txid member
    obtain ⟨extended, extendedFound, isPrefix⟩ := extension _ _ found
    exact ⟨
      extended,
      by simpa only [length] using extendedFound,
      entry,
      at_prefix isPrefix atEntry,
      view
    ⟩
  have current_commit (branches : List (List Entry)) (history : List Event)
      (current : Current branches history) (txid : TxID) {ledger : List Entry}
      {entry : Entry} (latest : branches.getLast? = some ledger)
      (found : at? ledger txid.seqno = some entry) (view : entry.view = txid.view)
      : Current branches (history ++ [Event.status txid .committed]) := by
    apply current_snoc _ _ _ current
    intro _ same
    cases same
    exact ⟨ledger, at_last latest, entry, found, view⟩
  have step_current (before after : State) (action : Action)
      (current : Current before.branches before.history)
      (anchored : Anchored before.branches)
      (transition : step before action = some after)
      : Current after.branches after.history := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact current_snoc _ _ _ current (by intro _ same; cases same)
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact current_mono _ _ _ current (Structural.branches_modify _ _ _)
          (List.length_modify _ _ _)
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact current_snoc _ _ _ current (by intro _ same; cases same)
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact current_snoc _ _ _ current (by intro _ same; cases same)
    | commit =>
        obtain ⟨txid, rfl, ⟨_, _, _, _, _, latestFound, entryFound, view, _, _⟩⟩ := Structural.commit_some transition
        exact current_commit _ _ current txid latestFound entryFound view
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact current_snoc _ _ _ current (by intro _ same; cases same)
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact current_mono _ _ _ current (Structural.branches_modify _ _ _)
          (List.length_modify _ _ _)
    | elect =>
        obtain ⟨_, rfl, found, compatible, retained, _⟩ := Structural.elect_some transition
        exact current_elect before current anchored found _ compatible retained
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact fun _ member => (List.not_mem_nil member).elim
  | @step before after action reachable transition ih =>
      exact step_current before after action ih (anchored_reachable reachable) transition

private theorem committed_snapshot {state : State}
    (reachable : transitionSystem.Reachable state) {response : Nat × Response}
    (listed : response ∈ committedResponses state.history .rw)
    : ∃ ledger,
        at? state.branches state.branches.length = some ledger
        ∧ response.2.observed = writes (ledger.take response.2.txid.seqno)
        ∧ ∃ entry,
            at? ledger response.2.txid.seqno = some entry
            ∧ entry.tx = some response.2.tx := by
  have snapshot_on_branch (branches : List (List Entry)) (anchored : Anchored branches)
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
  obtain ⟨inResponses, committed⟩ := List.mem_filter.mp listed
  have known : response.2.txid ∈ statusIDs state.history .committed := by simpa only [List.contains_eq_mem, decide_eq_true_eq] using committed
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

namespace consistency.Proofs.ViewOrder

open Model Properties Observations LedgerIdentity Commitment

private theorem forall_modify_at {α : Type} (xs : List α) (index : Nat) (f : α → α)
    (P : α → Prop) (original : ∀ x ∈ xs, P x)
    (updated : ∀ x, xs[index]? = some x → P (f x))
    : ∀ x ∈ xs.modify index f, P x := by
  intro x member
  obtain ⟨position, found⟩ := List.mem_iff_getElem?.mp member
  rw [List.getElem?_modify] at found
  obtain ⟨before, lookup, same⟩ := Option.map_eq_some_iff.mp found
  by_cases selected : index = position
  · simp only [selected, ite_true] at same
    subst x
    exact updated before (by simpa only [selected] using lookup)
  · simp only [selected, ite_false] at same
    subst x
    exact original before (List.mem_of_getElem? lookup)

private def Ordered (branches : List (List Entry)) : Prop :=
  ∀ ledger ∈ branches, ledger.Pairwise (fun left right => left.view ≤ right.view)

private theorem committed_views {state : State}
    (reachable : transitionSystem.Reachable state) {left right : TxID}
    (first : left ∈ statusIDs state.history .committed)
    (second : right ∈ statusIDs state.history .committed)
    (bound : left.seqno ≤ right.seqno)
    : left.view ≤ right.view := by
  have at_of_pos {α : Type} {xs : List α} {index : Nat} (positive : 0 < index)
      : at? xs index = xs[index - 1]? :=
    ite_eq_right (Nat.ne_of_gt positive)
  have entry_views {ledger : List Entry}
      (ordered : ledger.Pairwise (fun left right => left.view ≤ right.view))
      {leftSeq rightSeq : Nat} {left right : Entry}
      (first : at? ledger leftSeq = some left) (second : at? ledger rightSeq = some right)
      (bound : leftSeq ≤ rightSeq)
      : left.view ≤ right.view := by
    by_cases same : leftSeq = rightSeq
    · rw [same, second] at first
      cases first
      exact Nat.le_refl _
    · have firstLookup : ledger[leftSeq - 1]? = some left :=
        (at_of_pos (at_bounds first).1).symm.trans first
      have secondLookup : ledger[rightSeq - 1]? = some right :=
        (at_of_pos (at_bounds second).1).symm.trans second
      obtain ⟨leftBound, leftValue⟩ := List.getElem?_eq_some_iff.mp firstLookup
      obtain ⟨rightBound, rightValue⟩ := List.getElem?_eq_some_iff.mp secondLookup
      have related := ordered.rel_getElem_of_lt leftBound rightBound
        (Nat.sub_lt_sub_right (at_bounds first).1 (Nat.lt_of_le_of_ne bound same))
      rw [leftValue, rightValue] at related
      exact related
  have ordered_reachable {state : State} (reachable : transitionSystem.Reachable state)
      : Ordered state.branches := by
    have ordered_modify (branches : List (List Entry)) (ordered : Ordered branches)
        (anchored : Anchored branches) (branch : Nat) (entry : Entry)
        (view : entry.view = branch) (positive : 0 < branch)
        : Ordered (branches.modify (branch - 1) (· ++ [entry])) := by
      apply forall_modify_at _ _ _ _ ordered
      intro ledger found
      have atLedger : at? branches branch = some ledger := by
        simpa only [at?, Nat.ne_of_gt positive, ↓reduceIte] using found
      apply List.pairwise_append.mpr
      refine ⟨
        ordered ledger (List.mem_of_getElem? found),
        by
          simp only [List.pairwise_cons, List.not_mem_nil, forall_false, implies_true, List.Pairwise.nil, and_self],
        ?_
      ⟩
      intro left member right singleton
      have equal := List.mem_singleton.mp singleton
      subst right
      obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp member
      have atEntry : at? ledger (index + 1) = some left := by simpa only [at?, Nat.add_eq_zero_iff, Nat.succ_ne_self, and_false, ↓reduceIte, Nat.add_one_sub_one] using lookup
      rw [view]
      exact (anchored _ _ atLedger _ _ atEntry).1
    have ordered_elect (branches : List (List Entry)) (ordered : Ordered branches)
        {ledger : List Entry} (member : ledger ∈ branches) (count : Nat)
        : Ordered (branches ++ [ledger.take count]) := by
      intro candidate listed
      rcases List.mem_append.mp listed with old | new
      · exact ordered candidate old
      · have same := List.mem_singleton.mp new
        subst candidate
        exact (ordered ledger member).sublist (List.take_sublist _ _)
    have step_ordered (before after : State) (action : Action)
        (ordered : Ordered before.branches) (anchored : Anchored before.branches)
        (transition : step before action = some after)
        : Ordered after.branches := by
      cases action with
      | request =>
          rw [Structural.request_some transition]
          exact ordered
      | execute =>
          obtain ⟨_, rfl, _, active, _⟩ := Structural.execute_some transition
          exact ordered_modify _ ordered anchored _ _ rfl (active_positive before active)
      | respond =>
          obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
          exact ordered
      | read =>
          obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
          exact ordered
      | commit =>
          obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
          exact ordered
      | invalidate =>
          obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
          exact ordered
      | appendOther =>
          obtain ⟨rfl, active⟩ := Structural.appendOther_some transition
          exact ordered_modify _ ordered anchored _ _ rfl (active_positive before active)
      | elect =>
          obtain ⟨_, rfl, found, _, _, _⟩ := Structural.elect_some transition
          exact ordered_elect _ ordered (mem_of_at? found) _
    induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
    | @initial state initialized =>
        change state = initialState at initialized
        subst state
        exact fun ledger member => (List.mem_replicate.mp member).2 ▸ List.Pairwise.nil
    | @step before after action reachable transition ih =>
        exact step_ordered before after action ih (anchored_reachable reachable) transition
  have current := current_reachable reachable
  obtain ⟨leftLedger, leftFound, leftEntry, leftAt, leftView⟩ := current left first
  obtain ⟨rightLedger, rightFound, rightEntry, rightAt, rightView⟩ := current right second
  rw [leftFound] at rightFound
  cases rightFound
  have ordered := ordered_reachable reachable leftLedger (mem_of_at? leftFound)
  simpa only [ge_iff_le, leftView, rightView]
    using entry_views ordered leftAt rightAt bound

end consistency.Proofs.ViewOrder

namespace consistency.Proofs.RealTime

open Model Properties Observations LedgerIdentity Commitment

private theorem write_in_prefix {ledger : List Entry} {seqno count : Nat} {entry : Entry}
    {tx : TxContent} (found : at? ledger seqno = some entry) (value : entry.tx = some tx)
    (bound : seqno ≤ count)
    : tx ∈ writes (ledger.take count) :=
  List.mem_filterMap.mpr ⟨entry, mem_of_at? (at_take_of_le found bound), value⟩

private theorem committed_sequence_order {state : State}
    (reachable : transitionSystem.Reachable state)
    {earlier later : Nat × Response}
    (first : earlier ∈ committedResponses state.history .rw)
    (second : later ∈ committedResponses state.history .rw)
    {request : Nat × (TxType × TxContent)} (sent : request ∈ requests state.history)
    (matchesRequest : later.2.tx = request.2.2) (beforeRequest : earlier.1 < request.1)
    : earlier.2.txid.seqno < later.2.txid.seqno := by
  apply Nat.lt_of_not_le
  intro notLater
  obtain ⟨leftLedger, leftFound, leftObs, _⟩ := committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, _, rightEntry, rightAt, rightTx⟩ :=
    committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  have observed : later.2.tx ∈ earlier.2.observed := by
    rw [leftObs]
    exact write_in_prefix rightAt rightTx notLater
  have firstLookup := ((History.mem_responsesOf_iff _ _ _).mp
    (List.mem_filter.mp first).1).2
  obtain ⟨index, prior, lookup⟩ :=
    ((safe_reachable reachable).2 _ _ _ _ _ firstLookup).2 later.2.tx observed
  have requestLookup := (History.mem_requests_iff _ _ _ _).mp sent
  have sameIndex := (History.requests_reachable reachable).2
    _ _ _ _ _ _ lookup requestLookup matchesRequest
  rw [sameIndex] at prior
  exact Nat.lt_asymm prior beforeRequest

theorem all_committed_observed
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ earlier ∈ committedResponses state.history .rw,
          ∀ request ∈ committedRequests state.history .rw,
          ∀ later ∈ committedResponses state.history .rw,
            later.2.tx = request.2.2
            → earlier.1 < request.1
            → earlier.2.tx ∈ later.2.observed := by
  intro trace state member earlier first request sent later second same before
  have reachable := trace.reachable member
  have bound := committed_sequence_order reachable first second
    (List.mem_filter.mp sent).1 same before
  obtain ⟨leftLedger, leftFound, _, leftEntry, leftAt, leftTx⟩ :=
    committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, rightObs, _⟩ := committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  rw [rightObs]
  exact write_in_prefix leftAt leftTx (Nat.le_of_lt bound)

theorem committed_rw_ordered_real_time
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ earlier ∈ committedResponses state.history .rw,
          ∀ request ∈ committedRequests state.history .rw,
          ∀ later ∈ committedResponses state.history .rw,
            later.2.tx = request.2.2
            → earlier.1 < request.1
            → txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  intro trace state member earlier first request sent later second same before
  have reachable := trace.reachable member
  have seqno := committed_sequence_order reachable first second
    (List.mem_filter.mp sent).1 same before
  have earlierKnown : earlier.2.txid ∈ statusIDs state.history .committed := by
    simpa only [List.contains_eq_mem, decide_eq_true_eq]
      using (List.mem_filter.mp first).2
  have laterKnown : later.2.txid ∈ statusIDs state.history .committed := by
    simpa only [List.contains_eq_mem, decide_eq_true_eq]
      using (List.mem_filter.mp second).2
  have views := ViewOrder.committed_views reachable earlierKnown laterKnown (Nat.le_of_lt seqno)
  rcases Nat.lt_or_eq_of_le views with strict | equal
  · exact Or.inl strict
  · exact Or.inr ⟨equal, seqno⟩

end consistency.Proofs.RealTime

namespace consistency.Proofs.Ordered

open Model Properties Observations LedgerIdentity Commitment

private theorem adjacent (history : List Event) {pair : Response × Response}
    (listed
      : pair ∈ (committedRwResponses history).zip (committedRwResponses history).tail)
    : pair.1 ∈ committedRwResponses history
      ∧ pair.2 ∈ committedRwResponses history
      ∧ pair.1 ≠ pair.2
      ∧ ¬txIDStrictlyLessThan pair.2.txid pair.1.txid := by
  have nodup_erase (bound : Nat)
      : ∀ (xs : List Response), xs.length ≤ bound → xs.eraseDups.Nodup := by
    induction bound with
    | zero =>
        intro xs short
        cases xs with
        | nil => exact List.nodup_nil
        | cons head tail => exact absurd short (Nat.not_succ_le_zero _)
    | succ bound ih =>
        intro xs short
        cases xs with
        | nil => exact List.nodup_nil
        | cons head tail =>
            rw [List.eraseDups_cons]
            apply List.nodup_cons.mpr
            refine ⟨?_, ih _ ?_⟩
            · simp only [List.mem_eraseDups, List.mem_filter, BEq.rfl, Bool.not_true, Bool.false_eq_true, and_false, not_false_eq_true]
            · exact Nat.le_trans (List.length_filter_le (fun value => !value == head) tail)
                (Nat.le_of_succ_le_succ short)
  have sorted_responses (history : List Event)
      : (committedRwResponses history).Pairwise
          (fun left right => ¬txIDStrictlyLessThan right.txid left.txid) := by
    have transitive : ∀ (a b c : Response),
        decide (¬txIDStrictlyLessThan b.txid a.txid) →
        decide (¬txIDStrictlyLessThan c.txid b.txid) →
        decide (¬txIDStrictlyLessThan c.txid a.txid) := by
      intro a b c first second
      have firstOrder := of_decide_eq_true first
      have secondOrder := of_decide_eq_true second
      apply decide_eq_true
      intro h
      have ab : a.txid.view ≤ b.txid.view :=
        Nat.le_of_not_lt (fun lt => firstOrder (Or.inl lt))
      have bc : b.txid.view ≤ c.txid.view :=
        Nat.le_of_not_lt (fun lt => secondOrder (Or.inl lt))
      rcases h with lt | ⟨eq, lt⟩
      · exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_trans ab bc))
      · have ba : b.txid.view = a.txid.view :=
          Nat.le_antisymm (Nat.le_trans bc (Nat.le_of_eq eq)) ab
        have cb : c.txid.view = b.txid.view := eq.trans ba.symm
        have abs : a.txid.seqno ≤ b.txid.seqno :=
          Nat.le_of_not_lt (fun lt => firstOrder (Or.inr ⟨ba, lt⟩))
        have bcs : b.txid.seqno ≤ c.txid.seqno :=
          Nat.le_of_not_lt (fun lt => secondOrder (Or.inr ⟨cb, lt⟩))
        exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_trans abs bcs))
    have total : ∀ (a b : Response),
        decide (¬txIDStrictlyLessThan b.txid a.txid) ||
        decide (¬txIDStrictlyLessThan a.txid b.txid) := by
      intro a b
      simp only [Bool.or_eq_true]
      by_cases first : ¬txIDStrictlyLessThan b.txid a.txid
      · exact Or.inl (decide_eq_true first)
      right
      apply decide_eq_true
      intro h
      apply first
      intro h2
      rcases h with lt | ⟨eq, lt⟩ <;> rcases h2 with lt2 | ⟨eq2, lt2⟩
      · exact Nat.lt_asymm lt lt2
      · exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_of_eq eq2))
      · exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt2 (Nat.le_of_eq eq))
      · exact Nat.lt_asymm lt lt2
    exact (List.pairwise_mergeSort transitive total _).imp (by
      intro left right related
      exact of_decide_eq_true related)
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp listed
  obtain ⟨first, tailLookup⟩ := List.getElem?_zip_eq_some.mp lookup
  have second : (committedRwResponses history)[index + 1]? = some pair.2 := by
    simpa only [List.getElem?_tail] using tailLookup
  obtain ⟨firstBound, firstValue⟩ := List.getElem?_eq_some_iff.mp first
  obtain ⟨secondBound, secondValue⟩ := List.getElem?_eq_some_iff.mp second
  have nodup : (committedRwResponses history).Nodup :=
    (List.mergeSort_perm _ _).nodup_iff.mpr (nodup_erase _ _ (Nat.le_refl _))
  have distinct := nodup.rel_getElem_of_lt firstBound secondBound (Nat.lt_succ_self index)
  have ordered := (sorted_responses history).rel_getElem_of_lt firstBound secondBound
    (Nat.lt_succ_self index)
  exact ⟨
    List.mem_of_getElem? first,
    List.mem_of_getElem? second,
    by simpa only [ne_eq, firstValue, secondValue] using distinct,
    by simpa only [secondValue, firstValue] using ordered
  ⟩

theorem committed_rw_ordered_serializable
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ pair ∈
            (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail,
            pair.1.observed <+: pair.2.observed
            ∧ pair.1.observed.length < pair.2.observed.length
            ∧ pair.2.observed.getLast? = some pair.2.tx := by
  have mem_ordered (history : List Event) {response : Response}
      (member : response ∈ committedRwResponses history)
      : ∃ indexed ∈ committedResponses history .rw, indexed.2 = response := by
    simpa only [committedRwResponses, List.mem_mergeSort, List.mem_eraseDups,
      List.mem_map]
      using member
  have sequence_order {state : State}
      (reachable : transitionSystem.Reachable state) {left right : TxID}
      (first : left ∈ statusIDs state.history .committed)
      (second : right ∈ statusIDs state.history .committed)
      (different : left ≠ right) (ordered : ¬txIDStrictlyLessThan right left)
      : left.seqno < right.seqno := by
    apply Nat.lt_of_not_le
    intro notLater
    have views := ViewOrder.committed_views reachable second first notLater
    have sameView : left.view = right.view :=
      Nat.le_antisymm (Nat.le_of_not_lt (fun lt => ordered (Or.inl lt))) views
    have sameSeq : left.seqno = right.seqno :=
      Nat.le_antisymm (Nat.le_of_not_lt (fun lt => ordered (Or.inr ⟨sameView.symm, lt⟩)))
        notLater
    exact different (congr (congrArg TxID.mk sameView) sameSeq)
  have through_entry {α : Type} {xs : List α} {index : Nat} {value : α}
      (found : at? xs index = some value)
      : xs.take index = xs.take (index - 1) ++ [value] := by
    have nonzero := Nat.ne_of_gt (at_bounds found).1
    obtain ⟨bound, actual⟩ :=
      List.getElem?_eq_some_iff.mp ((ite_eq_right nonzero).symm.trans found)
    have same := List.take_succ_eq_append_getElem bound
    rw [Nat.sub_one_add_one nonzero, actual] at same
    exact same
  have strict_observations {ledger : List Entry} {leftSeq rightSeq : Nat}
      {entry : Entry} {tx : TxContent} (rightAt : at? ledger rightSeq = some entry)
      (value : entry.tx = some tx) (bound : leftSeq < rightSeq)
      : writes (ledger.take leftSeq) <+: writes (ledger.take rightSeq)
        ∧ (writes (ledger.take leftSeq)).length < (writes (ledger.take rightSeq)).length
        ∧ (writes (ledger.take rightSeq)).getLast? = some tx := by
    have through : writes (ledger.take rightSeq) =
        writes (ledger.take (rightSeq - 1)) ++ [tx] := by
      rw [through_entry rightAt]
      simp only [writes, List.filterMap_append, value, Option.some.injEq, List.filterMap_cons_some, List.filterMap_nil]
    have before : writes (ledger.take leftSeq) <+: writes (ledger.take (rightSeq - 1)) :=
      (List.take_prefix_take_left (l := ledger) (Nat.le_sub_one_of_lt bound)).filterMap Entry.tx
    refine ⟨
      (List.take_prefix_take_left (l := ledger) (Nat.le_of_lt bound)).filterMap Entry.tx,
      ?_,
      ?_
    ⟩
    · have length := before.length_le
      rw [through, List.length_append, List.length_singleton]
      exact Nat.lt_succ_of_le length
    · simp only [through, List.getLast?_append, List.getLast?_singleton, Option.some_or]
  intro trace state member pair listed
  have reachable := trace.reachable member
  obtain ⟨firstListed, secondListed, different, ordered⟩ := adjacent state.history listed
  obtain ⟨first, firstMember, firstPayload⟩ := mem_ordered state.history firstListed
  obtain ⟨second, secondMember, secondPayload⟩ := mem_ordered state.history secondListed
  have distinctIDs : first.2.txid ≠ second.2.txid := by
    intro same
    have firstResponse := (List.mem_filter.mp firstMember).1
    have secondResponse := (List.mem_filter.mp secondMember).1
    have tx := LedgerIdentity.unique_txs trace state member
      first firstResponse second secondResponse same
    have obs := LedgerIdentity.same_observations trace state member
      first (List.mem_filter.mp firstResponse).1
      second (List.mem_filter.mp secondResponse).1 same
    have firstKind := ((History.mem_responsesOf_iff _ _ _).mp firstResponse).1
    have secondKind := ((History.mem_responsesOf_iff _ _ _).mp secondResponse).1
    have equal : first.2 = second.2 := by
      change Response.mk first.2.kind first.2.tx first.2.observed first.2.txid =
        Response.mk second.2.kind second.2.tx second.2.observed second.2.txid
      rw [firstKind, secondKind, tx, obs, same]
    exact different (firstPayload.symm.trans (equal.trans secondPayload))
  have firstKnown : first.2.txid ∈ statusIDs state.history .committed := by
    simpa only [List.contains_eq_mem, decide_eq_true_eq]
      using (List.mem_filter.mp firstMember).2
  have secondKnown : second.2.txid ∈ statusIDs state.history .committed := by
    simpa only [List.contains_eq_mem, decide_eq_true_eq]
      using (List.mem_filter.mp secondMember).2
  have seqno :=
    sequence_order reachable firstKnown secondKnown distinctIDs
      (by simpa only [secondPayload, firstPayload] using ordered)
  obtain ⟨firstLedger, firstFound, firstObs, _⟩ := committed_snapshot reachable firstMember
  obtain ⟨secondLedger, secondFound, secondObs, secondEntry, secondAt, secondTx⟩ :=
    committed_snapshot reachable secondMember
  rw [firstFound] at secondFound
  cases secondFound
  rw [← firstPayload, ← secondPayload, firstObs, secondObs]
  exact strict_observations secondAt secondTx seqno

end consistency.Proofs.Ordered
