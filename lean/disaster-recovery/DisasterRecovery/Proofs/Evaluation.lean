module

public import DisasterRecovery.Properties.Utils
public import CCF.Proofs.Execution

@[expose] public section

/-!
Helpers for checking concrete executions by evaluation. `List.merge` and `List.mergeSort`
are defined by well-founded recursion, so the kernel cannot evaluate `insertGossip` or
`insertVote`. `insertGossip_eval` and `insertVote_eval` restate them with structurally
recursive equivalents; after rewriting with `evalSimps`, concrete steps close by `rfl`.
-/

namespace DisasterRecovery.Proofs.Evaluation

open CCF
open Model.Local

/-- `List.merge` by structural recursion on fuel, so the kernel can evaluate it. -/
def mergeFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α -> List α
  | 0, xs, ys => xs ++ ys
  | _ + 1, [], ys => ys
  | _ + 1, x :: xs, [] => x :: xs
  | fuel + 1, x :: xs, y :: ys =>
      if le x y then
        x :: mergeFuel le fuel xs (y :: ys)
      else
        y :: mergeFuel le fuel (x :: xs) ys

theorem merge_eq_mergeFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs ys : List α),
        xs.length + ys.length <= fuel -> List.merge xs ys le = mergeFuel le fuel xs ys
  | 0, [], [], _ => by simp [mergeFuel]
  | 0, _ :: _, _, h | 0, [], _ :: _, h => by simp at h
  | _ + 1, [], _, _ => by simp [mergeFuel]
  | _ + 1, _ :: _, [], _ => by simp [mergeFuel]
  | fuel + 1, x :: xs, y :: ys, h => by
      rw [List.cons_merge_cons, mergeFuel]
      split
      · rw [merge_eq_mergeFuel le fuel xs (y :: ys) (by simp at h ⊢; omega)]
      · rw [merge_eq_mergeFuel le fuel (x :: xs) ys (by simp at h ⊢; omega)]

/-- `List.mergeSort` by structural recursion on fuel, so the kernel can evaluate it. -/
def mergeSortFuel {α : Type} (le : α -> α -> Bool) : Nat -> List α -> List α
  | 0, xs => xs
  | fuel + 1, xs =>
      if xs.length < 2 then
        xs
      else
        mergeFuel le xs.length (mergeSortFuel le fuel (xs.take ((xs.length + 1) / 2)))
          (mergeSortFuel le fuel (xs.drop ((xs.length + 1) / 2)))

theorem mergeSort_eq_mergeSortFuel {α : Type} (le : α -> α -> Bool)
    : forall (fuel : Nat) (xs : List α),
        xs.length <= fuel -> xs.mergeSort le = mergeSortFuel le fuel xs
  | 0, [], _ => by simp [mergeSortFuel]
  | 0, _ :: _, h => by simp at h
  | fuel + 1, xs, h => by
      rw [mergeSortFuel]
      split
      · match xs, ‹xs.length < 2› with
        | [], _ => simp
        | [_], _ => simp
      · conv => lhs; rw [← List.take_append_drop ((xs.length + 1) / 2) xs]
        rw [List.mergeSort_append _ _ (by simp; omega) (by simp; omega),
          merge_eq_mergeFuel le xs.length _ _ (by simp; omega),
          mergeSort_eq_mergeSortFuel le fuel (xs.take _) (by simp; omega),
          mergeSort_eq_mergeSortFuel le fuel (xs.drop _) (by simp; omega)]

theorem insertGossip_eval (source : Location) (txid : TxID)
    (gossips : List (Location × TxID))
    : insertGossip source txid gossips
      = if gossips.any (fun entry => entry.1 == source) then
          gossips
        else
          mergeSortFuel (fun left right => decide (left.1 <= right.1))
            (gossips.length + 1) ((source, txid) :: gossips) := by
  unfold insertGossip
  rw [mergeSort_eq_mergeSortFuel _ (gossips.length + 1) _ (by simp)]

theorem insertVote_eval (source : Location) (votes : List Location)
    : insertVote source votes
      = if votes.contains source then
          votes
        else
          mergeSortFuel (fun left right => decide (left <= right)) (votes.length + 1)
            (source :: votes) := by
  unfold insertVote
  rw [mergeSort_eq_mergeSortFuel _ (votes.length + 1) _ (by simp)]

/-- Each recorded action leads from the previous state to the state paired with it. -/
def StepsFrom (system : TransitionSystem)
    : system.State -> List (system.Action × system.State) -> Prop
  | _, [] => True
  | before, (action, after) :: rest =>
      system.step before action = some after /\ StepsFrom system after rest

theorem stepsFrom_getElem? {system : TransitionSystem}
    : forall (initial : system.State) (steps : List (system.Action × system.State)),
        StepsFrom system initial steps
        -> forall (n : Nat) (before : system.State) (action : system.Action),
            (initial :: steps.map Prod.snd)[n]? = some before
            -> (steps.map Prod.fst)[n]? = some action
            -> system.step before action = (steps.map Prod.snd)[n]?
  | _, [], _, _, _, _, _, chosen => by simp at chosen
  | _, (_, _) :: _, ⟨step, _⟩, 0, _, _, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_zero, Option.some.injEq] at first chosen ⊢
      subst first chosen
      exact step
  | _, (_, after) :: rest, ⟨_, valid⟩, n + 1, before, action, first, chosen => by
      simp only [List.map_cons, List.getElem?_cons_succ] at first chosen ⊢
      exact stepsFrom_getElem? after rest valid n before action first chosen

/-- The finite trace that starts at `initial` and records `steps`. -/
def ofSteps {system : TransitionSystem} (initial : system.State)
    (steps : List (system.Action × system.State)) (initialized : system.init initial)
    (valid : StepsFrom system initial steps)
    : Execution.Trace system :=
  ⟨
    { init := initial, steps := CCF.Seq.ofList steps },
    initialized,
    by
      intro n before action first chosen
      simp only [CCF.Seq.map_get?, CCF.Seq.ofList_get?] at chosen ⊢
      rw [← List.getElem?_map] at chosen ⊢
      refine stepsFrom_getElem? initial steps valid n before action ?_ chosen
      cases n <;>
        simpa only [CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ,
          CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_cons_zero,
          List.getElem?_cons_succ, List.getElem?_map] using first
  ⟩

theorem ofSteps_stateAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).stateAt n
      = (initial :: steps.map Prod.snd)[n]? := by
  cases n <;>
    simp only [ofSteps, Execution.Trace.stateAt, Execution.Trace.states,
      CCF.Seq.get?_cons_zero, CCF.Seq.get?_cons_succ, CCF.Seq.map_get?,
      CCF.Seq.ofList_get?, List.getElem?_cons_zero, List.getElem?_cons_succ,
      List.getElem?_map]

theorem ofSteps_actionAt {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} (n : Nat)
    : (ofSteps initial steps initialized valid).actionAt n
      = (steps.map Prod.fst)[n]? := by
  simp only [ofSteps, Execution.Trace.actionAt, Execution.Trace.actions,
    CCF.Seq.map_get?, CCF.Seq.ofList_get?, List.getElem?_map]

theorem mem_ofSteps {system : TransitionSystem} {initial : system.State}
    {steps : List (system.Action × system.State)} {initialized : system.init initial}
    {valid : StepsFrom system initial steps} {state : system.State}
    : state ∈ ofSteps initial steps initialized valid
      <-> state ∈ initial :: steps.map Prod.snd := by
  rw [Execution.Trace.mem_iff_exists_stateAt]
  simp only [ofSteps_stateAt]
  constructor
  · rintro ⟨n, found⟩
    exact List.mem_of_getElem? found.symm
  · intro member
    obtain ⟨n, bound, rfl⟩ := List.getElem_of_mem member
    exact ⟨n, (List.getElem?_eq_getElem bound).symm⟩

end DisasterRecovery.Proofs.Evaluation
