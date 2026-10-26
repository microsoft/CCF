module

public import consistency.Proofs.Commitment

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.ViewOrder

open Model Properties Observations LedgerIdentity Commitment

theorem forall_modify_at {α : Type} (xs : List α) (index : Nat) (f : α → α)
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
    exact updated before (by simpa [selected] using lookup)
  · simp only [selected, ite_false] at same
    subst x
    exact original before (List.mem_of_getElem? lookup)

def Ordered (branches : List (List Entry)) : Prop :=
  ∀ ledger ∈ branches, ledger.Pairwise (fun left right => left.view ≤ right.view)

theorem ordered_modify (branches : List (List Entry)) (ordered : Ordered branches)
    (anchored : Anchored branches) (branch : Nat) (entry : Entry)
    (view : entry.view = branch) (positive : 0 < branch)
    : Ordered (branches.modify (branch - 1) (· ++ [entry])) := by
  apply forall_modify_at _ _ _ _ ordered
  intro ledger found
  have atLedger : at? branches branch = some ledger := by
    simpa [at?, Nat.ne_of_gt positive] using found
  apply List.pairwise_append.mpr
  refine ⟨ordered ledger (List.mem_of_getElem? found), by simp, ?_⟩
  intro left member right singleton
  have equal := List.mem_singleton.mp singleton
  subst right
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp member
  have atEntry : at? ledger (index + 1) = some left := by simpa [at?] using lookup
  rw [view]
  exact (anchored _ _ atLedger _ _ atEntry).1

theorem ordered_elect (branches : List (List Entry)) (ordered : Ordered branches)
    {ledger : List Entry} (member : ledger ∈ branches) (count : Nat)
    : Ordered (branches ++ [ledger.take count]) := by
  intro candidate listed
  rcases List.mem_append.mp listed with old | new
  · exact ordered candidate old
  · have same := List.mem_singleton.mp new
    subst candidate
    exact (ordered ledger member).sublist (List.take_sublist _ _)

theorem step_ordered (config : Config) (before after : State) (action : Action)
    (ordered : Ordered before.branches) (anchored : Anchored before.branches)
    (transition : step config before action = some after)
    : Ordered after.branches := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact ordered)
      | (solve | apply ordered_modify _ ordered anchored _ _ rfl; apply active_positive config before; assumption)
      | (solve | apply ordered_elect _ ordered; apply mem_of_at?; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem ordered_reachable (config : Config) {state : State}
    (reachable : (transitionSystem config).Reachable state)
    : Ordered state.branches := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | @initial state initialized =>
      change state = initialState config at initialized
      subst state
      simp [Ordered, initialState, List.mem_replicate]
  | @step before after action reachable transition ih =>
      exact step_ordered config before after action ih (anchored_reachable config reachable) transition

theorem entry_views {ledger : List Entry}
    (ordered : ledger.Pairwise (fun left right => left.view ≤ right.view))
    {leftSeq rightSeq : Nat} {left right : Entry}
    (first : at? ledger leftSeq = some left) (second : at? ledger rightSeq = some right)
    (bound : leftSeq ≤ rightSeq)
    : left.view ≤ right.view := by
  by_cases same : leftSeq = rightSeq
  · rw [same, second] at first
    cases first
    exact Nat.le_refl _
  · have firstLookup : ledger[leftSeq - 1]? = some left := by
      simpa [at?, Nat.ne_of_gt (at_bounds first).1] using first
    have secondLookup : ledger[rightSeq - 1]? = some right := by
      simpa [at?, Nat.ne_of_gt (at_bounds second).1] using second
    obtain ⟨leftBound, leftValue⟩ := List.getElem?_eq_some_iff.mp firstLookup
    obtain ⟨rightBound, rightValue⟩ := List.getElem?_eq_some_iff.mp secondLookup
    have related := ordered.rel_getElem_of_lt leftBound rightBound (by
      have := (at_bounds first).1
      omega)
    simpa [leftValue, rightValue] using related

theorem committed_views (config : Config) {state : State}
    (reachable : (transitionSystem config).Reachable state) {left right : TxID}
    (first : left ∈ statusIDs state.history .committed)
    (second : right ∈ statusIDs state.history .committed)
    (bound : left.seqno ≤ right.seqno)
    : left.view ≤ right.view := by
  have current := current_reachable config reachable
  obtain ⟨leftLedger, leftFound, leftEntry, leftAt, leftView⟩ := current left first
  obtain ⟨rightLedger, rightFound, rightEntry, rightAt, rightView⟩ := current right second
  rw [leftFound] at rightFound
  cases rightFound
  have ordered := ordered_reachable config reachable leftLedger (mem_of_at? leftFound)
  simpa [leftView, rightView] using entry_views ordered leftAt rightAt bound

end consistency.Proofs.ViewOrder
