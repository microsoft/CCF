module

public import consistency.Properties.History
public import CCF.Execution

/-!
Status separation and invalid-observation proofs.

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
    have snapshot := snapshot_source branches anchored found (at_last last) .ro tx (by simp only [reduceCtorEq, IsEmpty.forall_iff])
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
  simpa only [List.take_take, min_self] using (take_of_prefix isPrefix seqno bound).symm

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
          simp only [List.pairwise_cons, List.not_mem_nil, IsEmpty.forall_iff, implies_true, List.Pairwise.nil, and_self],
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

namespace consistency.Proofs.Statuses

open Model Properties Observations LedgerIdentity Commitment

private theorem last_of_at {α : Type} {xs : List α} {value : α}
    (found : at? xs xs.length = some value)
    : xs.getLast? = some value := by
  cases xs with
  | nil => cases found
  | cons head tail =>
      exact List.getLast?_eq_getElem?.trans ((ite_eq_right (Nat.succ_ne_zero _)).symm.trans found)

private theorem status_ids_snoc (history : List Event) (event : Event) (txid : TxID)
    (status : Status)
    : txid ∈ statusIDs (history ++ [event]) status
      ↔ txid ∈ statusIDs history status ∨ event = .status txid status := by
  unfold statusIDs
  rw [List.filterMap_append, List.mem_append]
  apply or_congr_right
  cases event with
  | request =>
      simp only [List.filterMap_cons, List.filterMap_nil, List.not_mem_nil, reduceCtorEq]
  | response =>
      simp only [List.filterMap_cons, List.filterMap_nil, List.not_mem_nil, reduceCtorEq]
  | status id value =>
      by_cases same : value = status
      · subst same
        simp only [List.filterMap_cons, List.filterMap_nil, ite_true, List.mem_singleton,
          Event.status.injEq, and_true]
        exact eq_comm
      · simp only [List.filterMap_cons, List.filterMap_nil, same, ite_false, List.not_mem_nil,
          false_iff]
        intro equal
        cases equal
        exact same rfl

private def Separated (history : List Event) : Prop :=
  ∀ committed ∈ statusIDs history .committed,
  ∀ invalid ∈ statusIDs history .invalid,
    invalid.view = committed.view → committed.seqno < invalid.seqno

private theorem separated_snoc (history : List Event) (event : Event)
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
    · simp_all only [Event.status.injEq, and_true, forall_eq', reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]

private theorem separated_invalidate (state : State) (separated : Separated state.history)
    (anchored : Anchored state.branches) (current : Current state.branches state.history)
    (snapshots : Snapshots state.branches state.history) {index : Nat}
    {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (response : at? state.history index = some (.response .rw tx observed txid))
    (allowed : mayInvalidate state txid = true)
    : Separated (state.history ++ [Event.status txid .invalid]) := by
  have cannot_invalidate (state : State) (anchored : Anchored state.branches)
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
    simp only [mayInvalidate, last_of_at latestFound, ge_iff_le, actual, invalidView, bne_self_eq_false, Bool.and_false, gt_iff_lt, Nat.not_lt.mpr frontier, decide_false, Bool.false_and, Bool.or_self]
  apply separated_snoc _ _ separated
  · simp only [Event.status.injEq, reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]
  · intro _ same
    cases same
    intro committed known sameView
    apply Nat.lt_of_not_le
    intro notLater
    have lookup : state.history[index - 1]? = some (.response .rw tx observed txid) :=
      (ite_eq_right (Nat.ne_of_gt (at_bounds response).1)).symm.trans response
    have denied := cannot_invalidate state anchored current known
      (snapshots _ _ _ _ _ lookup) sameView notLater
    simp only [denied, Bool.false_eq_true] at allowed

private theorem separated_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Separated state.history := by
  have separated_commit (history : List Event) (separated : Separated history)
      (txid : TxID)
      (allowed
        : ∀ invalid ∈ statusIDs history .invalid,
            invalid.view = txid.view → txid.seqno < invalid.seqno)
      : Separated (history ++ [Event.status txid .committed]) := by
    apply separated_snoc _ _ separated
    · intro _ same
      cases same
      exact allowed
    · simp only [Event.status.injEq, reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]
  have step_separated (before after : State) (action : Action)
      (separated : Separated before.history) (anchored : Anchored before.branches)
      (current : Current before.branches before.history)
      (snapshots : Snapshots before.branches before.history)
      (transition : step before action = some after)
      : Separated after.history := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact separated_snoc _ _ separated
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact separated
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact separated_snoc _ _ separated
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact separated_snoc _ _ separated
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | commit =>
        obtain ⟨_, rfl, ⟨_, _, _, _, _, _, _, _, allowed, _⟩⟩ := Structural.commit_some transition
        exact separated_commit _ separated _ allowed
    | invalidate =>
        obtain ⟨_, rfl, ⟨_, _, found, allowed⟩⟩ := Structural.invalidate_some transition
        exact separated_invalidate before separated anchored current snapshots found allowed
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact separated
    | elect =>
        obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
        exact separated
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      exact fun _ member => (List.not_mem_nil member).elim
  | @step before after action reachable transition ih =>
      exact step_separated before after action ih (anchored_reachable reachable)
        (current_reachable reachable) (snapshots_reachable reachable) transition

private theorem mem_statuses_iff (history : List Event) (txid : TxID) (status : Status)
    : (txid, status) ∈ statuses history ↔ txid ∈ statusIDs history status := by
  simp only [statuses, statusIDs, List.mem_filterMap]
  constructor
  · rintro ⟨event, listed, mapped⟩
    refine ⟨event, listed, ?_⟩
    cases event with
    | status id value =>
        cases mapped
        exact ite_eq_left rfl
    | _ => cases mapped
  · rintro ⟨event, listed, mapped⟩
    refine ⟨event, listed, ?_⟩
    cases event with
    | status id value =>
        dsimp only at mapped
        by_cases same : value = status
        · rw [ite_eq_left same] at mapped
          cases mapped
          cases same
          rfl
        · rw [ite_eq_right same] at mapped
          cases mapped
    | _ => cases mapped

theorem committed_or_invalid
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  intro trace state member txid committed invalid
  have impossible := separated_reachable (trace.reachable member)
    txid committed txid invalid rfl
  exact Nat.lt_irrefl _ impossible

theorem once_committed_prev_committed
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .committed
            → left.1.view = right.1.view
            → right.1.seqno ≤ left.1.seqno
            → right.2 = .committed := by
  intro trace state member left first right second leftCommitted sameView bound
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftCommitted] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed => rfl
  | invalid =>
      rw [value] at secondKnown
      have impossible := separated_reachable (trace.reachable member)
        left.1 firstKnown right.1 secondKnown sameView.symm
      exact absurd bound (Nat.not_le.mpr impossible)

theorem once_invalid_next_invalid
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .invalid
            → left.1.view = right.1.view
            → left.1.seqno ≤ right.1.seqno
            → right.2 = .invalid := by
  intro trace state member left first right second leftInvalid sameView bound
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftInvalid] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed =>
      rw [value] at secondKnown
      have impossible := separated_reachable (trace.reachable member)
        right.1 secondKnown left.1 firstKnown sameView
      exact absurd bound (Nat.not_le.mpr impossible)
  | invalid => rfl

theorem once_committed_next_invalid
    : forall (trace : CCF.Execution.Trace transitionSystem) (state : State),
        (state ∈ trace)
        → ∀ left ∈ statuses state.history,
          ∀ right ∈ statuses state.history,
            left.2 = .committed
            → left.1.seqno ≤ right.1.seqno
            → right.1.view < left.1.view
            → right.2 = .invalid := by
  intro trace state member left first right second leftCommitted bound older
  have firstKnown := (mem_statuses_iff _ _ _).mp first
  rw [leftCommitted] at firstKnown
  have secondKnown := (mem_statuses_iff _ _ _).mp second
  cases value : right.2 with
  | committed =>
      rw [value] at secondKnown
      have impossible := ViewOrder.committed_views (trace.reachable member)
        firstKnown secondKnown bound
      exact absurd impossible (Nat.not_le.mpr older)
  | invalid => rfl

end consistency.Proofs.Statuses

namespace consistency.Proofs.InvalidObservations

open Model Properties Observations LedgerIdentity Commitment Statuses

private def UniqueWrites (branches : List (List Entry)) : Prop :=
  ∀ left ∈ branches,
  ∀ right ∈ branches,
    ∀ (leftSeq rightSeq : Nat) (leftEntry rightEntry : Entry) (tx : TxContent),
      at? left leftSeq = some leftEntry
      → at? right rightSeq = some rightEntry
      → leftEntry.tx = some tx
      → rightEntry.tx = some tx
      → leftEntry.view = rightEntry.view ∧ leftSeq = rightSeq

private theorem unique_modify (branches : List (List Entry))
    (unique : UniqueWrites branches) (branch : Nat) (target : List Entry) (entry : Entry)
    (found : at? branches branch = some target)
    (fresh
      : ∀ tx, entry.tx = some tx → ∀ ledger ∈ branches, ∀ old ∈ ledger, old.tx ≠ some tx)
    : UniqueWrites (branches.modify (branch - 1) (· ++ [entry])) := by
  have modified_location (branches : List (List Entry)) (branch : Nat)
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
          simpa only [at?, Nat.ne_of_gt (at_bounds found).1, ↓reduceIte] using found
        rw [oldLookup] at lookup
        cases lookup
        exact Or.inr rfl
    rcases classification ledger member with old | changed
    · exact Or.inl ⟨ledger, old, atEntry⟩
    · rw [changed] at atEntry
      rcases at_snoc atEntry with old | last
      · exact Or.inl ⟨target, mem_of_at? found, old⟩
      · exact Or.inr last
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

private theorem unique_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : UniqueWrites state.branches := by
  have active_ledger (state : State) {branch : Nat}
      (active : activeBranch state branch = true)
      : ∃ ledger, at? state.branches branch = some ledger := by
    have positive := active_positive state active
    have bound : branch ≤ state.branches.length := by
      simp only [activeBranch, Bool.and_eq_true, decide_eq_true_eq] at active
      exact active.2
    have inside : branch - 1 < state.branches.length := Nat.sub_one_lt_of_le positive bound
    exact ⟨
      state.branches[branch - 1]'inside,
      (ite_eq_right (Nat.ne_of_gt positive)).trans (List.getElem?_eq_getElem inside)
    ⟩
  have unique_write (state : State)
      (unique : UniqueWrites state.branches) (branch : Nat) (tx : TxContent)
      (active : activeBranch state branch = true)
      (fresh : ∀ ledger ∈ state.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx)
      : UniqueWrites (appendEntry state branch ⟨branch, some tx⟩).branches := by
    obtain ⟨ledger, found⟩ := active_ledger state active
    apply unique_modify _ unique _ ledger _ found
    intro _ same
    cases same
    exact fresh
  have unique_other (state : State)
      (unique : UniqueWrites state.branches) (branch : Nat)
      (active : activeBranch state branch = true)
      : UniqueWrites (appendEntry state branch ⟨branch, none⟩).branches := by
    obtain ⟨ledger, found⟩ := active_ledger state active
    apply unique_modify _ unique _ ledger _ found
    simp only [reduceCtorEq, ne_eq, IsEmpty.forall_iff, implies_true]
  have elected_location (branches : List (List Entry)) {target : List Entry}
      (targetMember : target ∈ branches) (count : Nat) {ledger : List Entry}
      (member : ledger ∈ branches ++ [target.take count]) {seqno : Nat} {entry : Entry}
      (found : at? ledger seqno = some entry)
      : ∃ source ∈ branches, at? source seqno = some entry := by
    rcases List.mem_append.mp member with old | new
    · exact ⟨ledger, old, found⟩
    · have same := List.mem_singleton.mp new
      subst ledger
      exact ⟨target, targetMember, at_prefix (List.take_prefix _ _) found⟩
  have unique_elect (branches : List (List Entry)) (unique : UniqueWrites branches)
      {ledger : List Entry} (member : ledger ∈ branches) (count : Nat)
      : UniqueWrites (branches ++ [ledger.take count]) := by
    intro left first right second leftSeq rightSeq leftEntry rightEntry tx leftAt rightAt leftTx rightTx
    obtain ⟨oldLeft, oldLeftMember, oldLeftAt⟩ := elected_location branches member count first leftAt
    obtain ⟨oldRight, oldRightMember, oldRightAt⟩ := elected_location branches member count second rightAt
    exact unique _ oldLeftMember _ oldRightMember _ _ _ _ _ oldLeftAt oldRightAt leftTx rightTx
  have step_unique (before after : State) (action : Action)
      (unique : UniqueWrites before.branches)
      (transition : step before action = some after)
      : UniqueWrites after.branches := by
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact unique
    | execute =>
        obtain ⟨_, rfl, _, active, fresh⟩ := Structural.execute_some transition
        exact unique_write before unique _ _ active fresh
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact unique
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact unique
    | commit =>
        obtain ⟨_, rfl, -⟩ := Structural.commit_some transition
        exact unique
    | invalidate =>
        obtain ⟨_, rfl, -⟩ := Structural.invalidate_some transition
        exact unique
    | appendOther =>
        obtain ⟨rfl, active⟩ := Structural.appendOther_some transition
        exact unique_other before unique _ active
    | elect =>
        obtain ⟨_, rfl, found, _, _, _⟩ := Structural.elect_some transition
        exact unique_elect _ unique (mem_of_at? found) _
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      intro left first _ _ _ _ _ _ _ leftAt
      rw [(List.mem_replicate.mp first).2] at leftAt
      cases mem_of_at? leftAt
  | @step before after action _ transition ih =>
      exact step_unique before after action ih transition

private def Excludes (branches : List (List Entry)) (committed invalid : TxID) : Prop :=
  ∀ origin,
    at? branches committed.view = some origin
    → ∀ entry,
        at? origin invalid.seqno = some entry
        → invalid.seqno ≤ committed.seqno
        → entry.view ≠ invalid.view

private def Clean (branches : List (List Entry)) (history : List Event) : Prop :=
  ∀ committed ∈ statusIDs history .committed,
  ∀ invalid ∈ statusIDs history .invalid, Excludes branches committed invalid

private theorem clean_snoc (branches : List (List Entry)) (history : List Event)
    (event : Event) (clean : Clean branches history)
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
    · simp_all only [Event.status.injEq, and_true, forall_eq', reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]

private theorem origin_entry_in_branch (branches : List (List Entry))
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

private theorem clean_invalidate (state : State)
    (clean : Clean state.branches state.history) (anchored : Anchored state.branches)
    (current : Current state.branches state.history) (txid : TxID)
    (allowed : mayInvalidate state txid = true)
    : Clean state.branches (state.history ++ [Event.status txid .invalid]) := by
  apply clean_snoc _ _ _ clean
  · simp only [Event.status.injEq, reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]
  · intro _ same
    cases same
    intro committed known origin originFound entry entryFound bound sameView
    obtain ⟨latest, latestFound, endpoint, endpointFound, view⟩ := current committed known
    have actual := origin_entry_in_branch state.branches anchored latestFound
      endpointFound view originFound entryFound bound
    have frontier := Nat.le_trans bound (frontier_bound state.history known)
    have denied : mayInvalidate state txid = false := by
      simp only [mayInvalidate, last_of_at latestFound, ge_iff_le, actual, sameView, bne_self_eq_false, Bool.and_false, gt_iff_lt, Nat.not_lt.mpr frontier, decide_false, Bool.false_and, Bool.or_self]
    simp only [denied, Bool.false_eq_true] at allowed

private theorem clean_reachable {state : State}
    (reachable : transitionSystem.Reachable state)
    : Clean state.branches state.history := by
  have committed_origin (branches : List (List Entry)) (history : List Event)
      (current : Current branches history) (anchored : Anchored branches) {txid : TxID}
      (known : txid ∈ statusIDs history .committed)
      : ∃ origin,
          at? branches txid.view = some origin
          ∧ ∃ entry, at? origin txid.seqno = some entry := by
    obtain ⟨latest, latestFound, entry, atEntry, view⟩ := current txid known
    obtain ⟨_, origin, found, isPrefix⟩ := anchored _ _ latestFound _ _ atEntry
    exact ⟨origin, by simpa only [view] using found, entry, at_prefix isPrefix (at_take atEntry)⟩
  have at_of_prefix {α : Type} {before after : List α} (isPrefix : before <+: after)
      {index : Nat} {value : α} (found : at? after index = some value)
      (bound : index ≤ before.length)
      : at? before index = some value := by
    have positive := (at_bounds found).1
    have nonzero := Nat.ne_of_gt positive
    obtain ⟨tail, rfl⟩ := isPrefix
    exact (ite_eq_right nonzero).trans
      ((List.getElem?_append_left (Nat.sub_one_lt_of_le positive bound)).symm.trans
        ((ite_eq_right nonzero).symm.trans found))
  have clean_mono (before after : List (List Entry)) (history : List Event)
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
  have clean_commit (state : State) (clean : Clean state.branches state.history)
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
      : Clean state.branches (state.history ++ [Event.status txid .committed]) := by
    apply clean_snoc _ _ _ clean
    · intro _ same
      cases same
      intro invalid known origin originFound entry entryFound bound sameView
      have actual := origin_entry_in_branch state.branches anchored (at_last latest)
        endpointFound view originFound entryFound bound
      have denied := allowed invalid known bound
      simp only [actual, sameView, BEq.rfl, Bool.true_eq_false] at denied
    · simp only [Event.status.injEq, reduceCtorEq, and_false, IsEmpty.forall_iff, implies_true]
  have step_clean (before after : State) (action : Action)
      (clean : Clean before.branches before.history) (anchored : Anchored before.branches)
      (current : Current before.branches before.history)
      (transition : step before action = some after)
      : Clean after.branches after.history := by
    have extension := Structural.step_branches before after action transition
    cases action with
    | request =>
        rw [Structural.request_some transition]
        exact clean_snoc _ _ _ clean
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | execute =>
        obtain ⟨_, rfl, -⟩ := Structural.execute_some transition
        exact clean_mono _ _ _ clean current anchored extension
    | respond =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.respond_some transition
        exact clean_snoc _ _ _ clean
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | read =>
        obtain ⟨_, _, _, rfl, -⟩ := Structural.read_some transition
        exact clean_snoc _ _ _ clean
          (by intro _ same; cases same)
          (by intro _ same; cases same)
    | commit =>
        obtain ⟨txid, rfl, ⟨_, _, _, _, _, latestFound, entryFound, view, _, copied⟩⟩ := Structural.commit_some transition
        apply clean_commit before clean anchored txid latestFound entryFound view
        intro invalid member bound
        split
        · rename_i predecessor predecessorFound
          exact beq_false_of_ne (copied invalid member bound predecessor predecessorFound)
        · rfl
    | invalidate =>
        obtain ⟨txid, rfl, ⟨_, _, _, allowed⟩⟩ := Structural.invalidate_some transition
        exact clean_invalidate before clean anchored current txid allowed
    | appendOther =>
        obtain ⟨rfl, -⟩ := Structural.appendOther_some transition
        exact clean_mono _ _ _ clean current anchored extension
    | elect =>
        obtain ⟨_, rfl, -⟩ := Structural.elect_some transition
        exact clean_mono _ _ _ clean current anchored extension
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | @initial state initialized =>
      change state = initialState at initialized
      subst state
      intro _ known
      cases known
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
      some observedEntry := by
    rw [at?, ite_eq_right (Nat.succ_ne_zero index)]
    exact lookup
  have observerAt := at_prefix (List.take_prefix _ _) prefixAt
  have bound : index + 1 ≤ observer.2.txid.seqno :=
    Nat.le_trans (at_bounds prefixAt).2 (List.length_take_le _ _)
  obtain ⟨sameView, sameSeq⟩ := unique_reachable reachable
    invalidOrigin (mem_of_at? invalidFound) observerOrigin (mem_of_at? observerFound)
    _ _ _ _ _ invalidAt observerAt (invalidTx invalidKind) observedTx
  have committed : observer.2.txid ∈ statusIDs state.history .committed := by
    exact List.contains_iff_mem.mp (List.mem_filter.mp second).2
  have excluded := clean_reachable reachable observer.2.txid committed
    invalid.2.txid invalidKnown observerOrigin observerFound observedEntry
    (by rw [sameSeq]; exact observerAt) (Nat.le_trans (Nat.le_of_eq sameSeq) bound)
  exact excluded (sameView.symm.trans invalidView)

end consistency.Proofs.InvalidObservations
