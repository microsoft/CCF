module

public import consistency.Properties.History
public import CCF.Execution

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Structural

open Model

theorem at_of_pos {α : Type} {xs : List α} {index : Nat} (positive : 0 < index)
    : at? xs index = xs[index - 1]? :=
  ite_eq_right (Nat.ne_of_gt positive)

def BranchExtension (before after : List (List Entry)) : Prop :=
  ∀ index ledger,
    at? before index = some ledger
    → ∃ extended, at? after index = some extended ∧ ledger <+: extended

theorem branches_refl (branches : List (List Entry))
    : BranchExtension branches branches := by
  intro index ledger found
  exact ⟨ledger, found, List.prefix_refl _⟩

theorem branches_modify (branches : List (List Entry)) (position : Nat) (entry : Entry)
    : BranchExtension branches (branches.modify position (· ++ [entry])) := by
  intro index ledger found
  have nonzero : index ≠ 0 := by
    rintro rfl
    simp [at?] at found
  have lookup : branches[index - 1]? = some ledger := by simpa [at?, nonzero] using found
  by_cases same : position = index - 1
  · refine ⟨ledger ++ [entry], ?_, by simp⟩
    simp [at?, nonzero, List.getElem?_modify, lookup, same]
  · refine ⟨ledger, ?_, List.prefix_refl _⟩
    simp [at?, nonzero, List.getElem?_modify, lookup, same]

theorem branches_append (branches extra : List (List Entry))
    : BranchExtension branches (branches ++ extra) := by
  intro index ledger found
  have nonzero : index ≠ 0 := by
    rintro rfl
    simp [at?] at found
  have lookup : branches[index - 1]? = some ledger := by simpa [at?, nonzero] using found
  refine ⟨ledger, ?_, List.prefix_refl _⟩
  simp [at?, nonzero, List.getElem?_append_left (List.getElem?_eq_some_iff.mp lookup).1,
    lookup]

/-! Inversion lemmas: what each enabled action does, stated once for all invariants. -/

private theorem guard_bind_some {α : Type} {p : Prop} [Decidable p] {f : Unit → Option α}
    {a : α} (bound : ((if p then pure () else failure : Option Unit) >>= f) = some a)
    : p ∧ f () = some a := by
  by_cases holds : p
  · rw [ite_eq_left holds] at bound
    exact ⟨holds, bound⟩
  · rw [ite_eq_right holds] at bound
    cases bound

theorem request_some {before after : State} {kind : TxType}
    (transition : step before (.request kind) = some after)
    : after = appendEvent before (.request kind (nextRequestId before.history)) :=
  (Option.some.inj transition).symm

theorem execute_some {before after : State} {requestIndex branch : Nat}
    (transition : step before (.execute requestIndex branch) = some after)
    : ∃ tx,
        at? before.history requestIndex = some (.request .rw tx)
        ∧ activeBranch before branch = true
        ∧ (∀ ledger ∈ before.branches, ∀ entry ∈ ledger, entry.tx ≠ some tx)
        ∧ after = appendEntry before branch ⟨branch, some tx⟩ := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  split at rest
  · rename_i tx
    simp only [guard] at rest
    obtain ⟨active, rest⟩ := guard_bind_some rest
    obtain ⟨fresh, rest⟩ := guard_bind_some rest
    refine ⟨tx, found, active, ?_, (Option.some.inj rest).symm⟩
    rw [Bool.not_eq_true'] at fresh
    intro ledger member entry inLedger same
    apply List.any_eq_false.mp fresh ledger member
    exact List.any_eq_true.mpr ⟨entry, inLedger, beq_iff_eq.mpr same⟩
  · cases rest

theorem respond_some {before after : State} {requestIndex branch seqno : Nat}
    (transition : step before (.respond requestIndex branch seqno) = some after)
    : ∃ tx ledger entry,
        at? before.history requestIndex = some (.request .rw tx)
        ∧ responded before.history requestIndex .rw tx = false
        ∧ activeBranch before branch = true
        ∧ at? before.branches branch = some ledger
        ∧ at? ledger seqno = some entry
        ∧ entry.tx = some tx
        ∧ after
          = appendEvent before
              (.response .rw tx (writes (ledger.take seqno)) ⟨entry.view, seqno⟩) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  split at rest
  · rename_i tx
    simp only [guard] at rest
    obtain ⟨unanswered, rest⟩ := guard_bind_some rest
    obtain ⟨active, rest⟩ := guard_bind_some rest
    obtain ⟨ledger, ledgerFound, rest⟩ := Option.bind_eq_some_iff.mp rest
    obtain ⟨entry, entryFound, rest⟩ := Option.bind_eq_some_iff.mp rest
    obtain ⟨txMatches, rest⟩ := guard_bind_some rest
    exact ⟨tx, ledger, entry, found, by simpa using unanswered, active, ledgerFound,
      entryFound, eq_of_beq txMatches, (Option.some.inj rest).symm⟩
  · cases rest

theorem read_some {before after : State} {requestIndex branch : Nat}
    (transition : step before (.read requestIndex branch) = some after)
    : ∃ tx ledger entry,
        at? before.history requestIndex = some (.request .ro tx)
        ∧ responded before.history requestIndex .ro tx = false
        ∧ activeBranch before branch = true
        ∧ at? before.branches branch = some ledger
        ∧ ledger.getLast? = some entry
        ∧ after
          = appendEvent before
              (.response .ro tx (writes ledger) ⟨entry.view, ledger.length⟩) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  split at rest
  · rename_i tx
    simp only [guard] at rest
    obtain ⟨unanswered, rest⟩ := guard_bind_some rest
    obtain ⟨active, rest⟩ := guard_bind_some rest
    obtain ⟨ledger, ledgerFound, rest⟩ := Option.bind_eq_some_iff.mp rest
    obtain ⟨entry, last, rest⟩ := Option.bind_eq_some_iff.mp rest
    exact ⟨tx, ledger, entry, found, by simpa using unanswered, active, ledgerFound, last,
      (Option.some.inj rest).symm⟩
  · cases rest

theorem commit_some {before after : State} {responseIndex : Nat}
    (transition : step before (.commit responseIndex) = some after)
    : ∃ tx observed txid latest entry,
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
                → predecessor.view ≠ invalid.view)
        ∧ after = appendEvent before (.status txid .committed) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  split at rest
  · rename_i tx observed txid
    obtain ⟨latest, latestFound, rest⟩ := Option.bind_eq_some_iff.mp rest
    obtain ⟨entry, entryFound, rest⟩ := Option.bind_eq_some_iff.mp rest
    simp only [guard] at rest
    obtain ⟨view, rest⟩ := guard_bind_some rest
    obtain ⟨sameView, rest⟩ := guard_bind_some rest
    obtain ⟨copied, rest⟩ := guard_bind_some rest
    rw [Bool.not_eq_true'] at sameView copied
    refine ⟨tx, observed, txid, latest, entry, found, latestFound, entryFound, eq_of_beq view,
      ?_, ?_, (Option.some.inj rest).symm⟩
    · intro invalid member same
      have denied := List.any_eq_false.mp sameView invalid member
      simp only [same, beq_self_eq_true, Bool.true_and, decide_eq_true_eq] at denied
      exact Nat.lt_of_not_le denied
    · intro invalid member bound predecessor predecessorFound same
      apply List.any_eq_false.mp copied invalid member
      simp only [bound, predecessorFound, same, decide_true, beq_self_eq_true, Bool.true_and]
  · cases rest

theorem invalidate_some {before after : State} {responseIndex : Nat}
    (transition : step before (.invalidate responseIndex) = some after)
    : ∃ tx observed txid,
        at? before.history responseIndex = some (.response .rw tx observed txid)
        ∧ mayInvalidate before txid = true
        ∧ after = appendEvent before (.status txid .invalid) := by
  obtain ⟨event, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  split at rest
  · rename_i tx observed txid
    simp only [guard] at rest
    obtain ⟨allowed, rest⟩ := guard_bind_some rest
    exact ⟨tx, observed, txid, found, allowed, (Option.some.inj rest).symm⟩
  · cases rest

theorem appendOther_some {before after : State} {branch : Nat}
    (transition : step before (.appendOther branch) = some after)
    : activeBranch before branch = true
      ∧ after = appendEntry before branch ⟨branch, none⟩ := by
  simp only [step, appendOther, guard] at transition
  obtain ⟨active, rest⟩ := guard_bind_some transition
  exact ⟨active, (Option.some.inj rest).symm⟩

theorem elect_some {before after : State} {branch prefixLength : Nat}
    (transition : step before (.elect branch prefixLength) = some after)
    : ∃ ledger,
        at? before.branches branch = some ledger
        ∧ hasCommittedPrefix before ledger = true
        ∧ commitSeqno before.history ≤ prefixLength
        ∧ prefixLength ≤ ledger.length
        ∧ after
          = {
            before with
              branches := before.branches ++ [ledger.take prefixLength]
          } := by
  obtain ⟨ledger, found, rest⟩ := Option.bind_eq_some_iff.mp transition
  simp only [guard] at rest
  obtain ⟨compatible, rest⟩ := guard_bind_some rest
  obtain ⟨bounds, rest⟩ := guard_bind_some rest
  simp only [Bool.and_eq_true, decide_eq_true_eq] at bounds
  exact ⟨ledger, found, compatible, bounds.1, bounds.2, (Option.some.inj rest).symm⟩

theorem step_branches (before after : State) (action : Action)
    (transition : step before action = some after)
    : BranchExtension before.branches after.branches := by
  cases action with
  | request => rw [request_some transition]; exact branches_refl _
  | execute =>
      obtain ⟨_, _, _, _, rfl⟩ := execute_some transition
      exact branches_modify _ _ _
  | respond =>
      obtain ⟨_, _, _, _, _, _, _, _, _, rfl⟩ := respond_some transition
      exact branches_refl _
  | read =>
      obtain ⟨_, _, _, _, _, _, _, _, rfl⟩ := read_some transition
      exact branches_refl _
  | commit =>
      obtain ⟨_, _, _, _, _, _, _, _, _, _, _, rfl⟩ := commit_some transition
      exact branches_refl _
  | invalidate =>
      obtain ⟨_, _, _, _, _, rfl⟩ := invalidate_some transition
      exact branches_refl _
  | appendOther =>
      obtain ⟨_, rfl⟩ := appendOther_some transition
      exact branches_modify _ _ _
  | elect =>
      obtain ⟨_, _, _, _, _, rfl⟩ := elect_some transition
      exact branches_append _ _

end consistency.Proofs.Structural
