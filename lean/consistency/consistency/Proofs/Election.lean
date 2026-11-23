module

public import consistency.Model.Transitions

@[expose] public section

namespace consistency.Proofs.Election

open Model

/-- An election preserves the history and extends existing ledgers.
Its only new nonempty ledger is the prefix copied into the elected view. -/
structure ElectionEffect (before after : State) (view source count : Nat) where
  ledger : List Entry
  found : at? before.branches source = some ledger
  earlier : source < view
  history : after.history = before.history
  extendsBranch
    : ∀ index old,
        at? before.branches index = some old
        → ∃ extended, at? after.branches index = some extended ∧ old <+: extended
  origin
    : ∀ index branch,
        at? after.branches index = some branch
        → at? before.branches index = some branch
          ∨ branch = []
          ∨ (index = view ∧ branch = ledger.take count)
  newest
    : at? after.branches after.branches.length
        = at? before.branches before.branches.length
      ∨ (at? after.branches after.branches.length = some (ledger.take count)
          ∧ hasCommittedPrefix before ledger = true
          ∧ commitSeqno before.history ≤ count)

private theorem guard_some {α : Type} {p : Prop} [Decidable p] {f : Unit → Option α}
    {a : α} (bound : ((if p then pure () else failure : Option Unit) >>= f) = some a)
    : p ∧ f () = some a := by
  by_cases holds : p
  · rw [ite_eq_left holds] at bound
    exact ⟨holds, bound⟩
  · rw [ite_eq_right holds] at bound
    cases bound

theorem elect_effect {before after : State} {view source count : Nat}
    (transition : step before (.elect view source count) = some after)
    : Nonempty (ElectionEffect before after view source count) := by
  unfold step elect at transition
  obtain ⟨allowed, transition⟩ := guard_some transition
  simp only [Bool.and_eq_true, decide_eq_true_eq] at allowed
  have earlier := allowed.1
  obtain ⟨ledger, found, transition⟩ := Option.bind_eq_some_iff.mp transition
  obtain ⟨_, transition⟩ := guard_some transition
  dsimp only at transition
  split at transition
  next advances =>
    obtain ⟨compatible, transition⟩ := guard_some transition
    obtain ⟨retained, transition⟩ := guard_some transition
    cases transition
    refine ⟨⟨ledger, found, earlier, rfl, ?_, ?_, Or.inr ⟨?_, compatible, retained⟩⟩⟩
    · intro index old lookup
      refine ⟨old, ?_, List.prefix_refl _⟩
      have nz : index ≠ 0 := by
        rintro rfl
        cases lookup
      simp only [at?, ite_eq_right nz] at lookup ⊢
      rw [List.getElem?_append_left ((List.getElem?_eq_some_iff.mp lookup).1)]
      exact lookup
    · intro index branch lookup
      by_cases nz : index = 0
      · subst index
        cases lookup
      simp only [at?, ite_eq_right nz] at lookup ⊢
      rw [List.getElem?_append] at lookup
      split at lookup
      · exact Or.inl lookup
      · rw [List.getElem?_append] at lookup
        simp only [List.length_replicate] at lookup
        split at lookup
        · simp_all
        · simp only [List.getElem?_cons] at lookup
          split at lookup
          · exact Or.inr (Or.inr ⟨by omega, Option.some.inj lookup.symm⟩)
          · cases lookup
    · have length : (before.branches ++
          (List.replicate (view - before.branches.length - 1) [] ++ [ledger.take count])).length =
          view := by
        simp only [List.length_append, List.length_replicate, List.length_cons, List.length_nil]
        omega
      change at? _ (before.branches ++
        (List.replicate (view - before.branches.length - 1) [] ++ [ledger.take count])).length = _
      rw [length, at?, ite_eq_right (by omega : view ≠ 0), List.getElem?_append_right (by omega),
        show view - 1 - before.branches.length = view - before.branches.length - 1 by omega,
        List.getElem?_append_right (by simp), List.length_replicate, Nat.sub_self]
      rfl
  next =>
    obtain ⟨openSlot, transition⟩ := guard_some transition
    obtain ⟨late, empty⟩ := (show view < before.branches.length ∧ at? before.branches view = some [] by
      simpa only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] using openSlot)
    obtain ⟨⟨_, frontier⟩, _, transition⟩ := Option.bind_eq_some_iff.mp transition
    obtain ⟨_, _, transition⟩ := Option.bind_eq_some_iff.mp transition
    obtain ⟨_, transition⟩ := guard_some transition
    cases transition
    have viewPos : view ≠ 0 := by
      rintro rfl
      cases empty
    have unchanged {index : Nat} (other : index ≠ view) :
        at? (before.branches.set (view - 1) (ledger.take count)) index =
          at? before.branches index := by
      by_cases nz : index = 0
      · simp [at?, nz]
      · simp only [at?, ite_eq_right nz, List.getElem?_set_ne (by omega : view - 1 ≠ index - 1)]
    have filled : at? (before.branches.set (view - 1) (ledger.take count)) view =
        some (ledger.take count) := by
      rw [at?, ite_eq_right viewPos, List.getElem?_set_self (by omega)]
    refine ⟨⟨ledger, found, earlier, rfl, ?_, ?_, Or.inl ?_⟩⟩
    · intro index old lookup
      by_cases same : index = view
      · subst index
        rw [empty] at lookup
        cases lookup
        exact ⟨ledger.take count, filled, List.nil_prefix⟩
      · exact ⟨old, (unchanged same).trans lookup, List.prefix_refl _⟩
    · intro index branch lookup
      by_cases same : index = view
      · subst index
        exact Or.inr (Or.inr ⟨rfl, Option.some.inj (lookup.symm.trans filled)⟩)
      · exact Or.inl ((unchanged same).symm.trans lookup)
    · simp only [List.length_set]
      exact unchanged (by omega)

theorem ElectionEffect.ledger_mem {before after : State} {view source count : Nat}
    (effect : ElectionEffect before after view source count) {branch : List Entry}
    (member : branch ∈ after.branches)
    : ∃ old ∈ before.branches, branch <+: old := by
  have mem_at {ledgers : List (List Entry)} {i : Nat} {value : List Entry}
      (lookup : at? ledgers i = some value) : value ∈ ledgers := by
    by_cases zero : i = 0
    · simp [at?, zero] at lookup
    · exact List.mem_of_getElem? (by simpa [at?, zero] using lookup)
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp member
  have atBranch : at? after.branches (index + 1) = some branch := by simp [at?, lookup]
  have sourceMem := mem_at effect.found
  rcases effect.origin _ _ atBranch with old | empty | ⟨_, copied⟩
  · exact ⟨branch, mem_at old, List.prefix_refl _⟩
  · exact ⟨effect.ledger, sourceMem, empty ▸ List.nil_prefix⟩
  · exact ⟨effect.ledger, sourceMem, copied ▸ List.take_prefix _ _⟩

end consistency.Proofs.Election
