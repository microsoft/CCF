module

public import CCFRaft.Proofs.Safety.Lists

@[expose] public section

/-!
# Sequences and logs for replication progress

Facts about index sequences that hold infinitely often or are eventually
constant, the length of the agreeing prefix of two logs, and the retry index a
rejection selects.
-/

namespace CCFRaft.Proofs.Replication

open Model.Node

/-! ## Infinitely often -/

/-! ## Agreeing prefixes -/

/-- The length of the longest common prefix. -/
def agree {α : Type} [DecidableEq α] : List α -> List α -> Nat
  | x :: xs, y :: ys => if x = y then agree xs ys + 1 else 0
  | _, _ => 0

section Agree

variable {α : Type} [DecidableEq α]

theorem take_agree
    : forall (xs ys : List α), xs.take (agree xs ys) = ys.take (agree xs ys)
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · rename_i same
        subst same
        simp [take_agree xs ys]
      · simp
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem agree_le_left : forall (xs ys : List α), agree xs ys <= xs.length
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · have := agree_le_left xs ys
        simp
        omega
      · exact Nat.zero_le _
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem agree_le_right : forall (xs ys : List α), agree xs ys <= ys.length
  | x :: xs, y :: ys => by
      simp only [agree]
      split
      · have := agree_le_right xs ys
        simp
        omega
      · exact Nat.zero_le _
  | [], _ => by simp [agree]
  | _ :: _, [] => by simp [agree]

theorem le_agree
    : forall (xs ys : List α) (n : Nat),
        n <= xs.length -> n <= ys.length -> xs.take n = ys.take n -> n <= agree xs ys
  | _, _, 0, _, _, _ => Nat.zero_le _
  | x :: xs, y :: ys, n + 1, left, right, same => by
      simp only [List.take_succ_cons, List.cons.injEq] at same
      simp only [agree, same.1, ↓reduceIte]
      have := le_agree xs ys n (by simpa using left) (by simpa using right) same.2
      omega
  | [], _, n + 1, left, _, _ => by simp at left
  | _ :: _, [], n + 1, _, right, _ => by simp at right

theorem agree_mono {xs ys zs : List α} (sub : ys <+: zs)
    : agree xs ys <= agree xs zs := by
  have bound := agree_le_right xs ys
  refine le_agree _ _ _ (agree_le_left xs ys) (bound.trans sub.length_le) ?_
  rw [take_agree, CCFRaft.Proofs.Safety.take_eq_of_prefix sub bound]

theorem agree_of_prefix {xs ys : List α} (sub : xs <+: ys) : agree xs ys = xs.length :=
  le_antisymm (agree_le_left xs ys)
    (le_agree _ _ _ le_rfl sub.length_le
      (by rw [CCFRaft.Proofs.Safety.take_eq_of_prefix sub le_rfl]))

end Agree

/-! ## Retry indices -/

/-- The largest item satisfying `Q`, or `init` if larger. -/
def maxWhere (Q : Nat -> Prop) [DecidablePred Q] (items : List Nat) (init : Nat) : Nat :=
  items.foldl (fun best c => if Q c then max best c else best) init

theorem maxWhere_spec (Q : Nat -> Prop) [DecidablePred Q]
    : forall (items : List Nat) (init : Nat),
        init <= maxWhere Q items init
        /\ (forall c, c ∈ items -> Q c -> c <= maxWhere Q items init)
        /\ (maxWhere Q items init = init
            \/ (maxWhere Q items init ∈ items /\ Q (maxWhere Q items init)))
  | [], init => by simp [maxWhere]
  | item :: items, init => by
      have unfold : maxWhere Q (item :: items) init
          = maxWhere Q items (if Q item then max init item else init) := rfl
      rw [unfold]
      by_cases holds : Q item
      · rw [ite_eq_left holds]
        obtain ⟨grows, covers, chosen⟩ := maxWhere_spec Q items (max init item)
        refine ⟨by omega, fun c member holds' => ?_, ?_⟩
        · rcases List.mem_cons.mp member with rfl | member
          · omega
          · exact covers c member holds'
        · rcases chosen with same | ⟨member, holds'⟩
          · rcases Nat.le_total init item with le | le
            · have picked : maxWhere Q items (max init item) = item := by omega
              rw [picked]
              exact Or.inr ⟨List.mem_cons.mpr (Or.inl rfl), holds⟩
            · exact Or.inl (by omega)
          · exact Or.inr ⟨List.mem_cons_of_mem _ member, holds'⟩
      · rw [ite_eq_right holds]
        obtain ⟨grows, covers, chosen⟩ := maxWhere_spec Q items init
        refine ⟨grows, fun c member holds' => ?_, ?_⟩
        · rcases List.mem_cons.mp member with rfl | member
          · exact absurd holds' holds
          · exact covers c member holds'
        · rcases chosen with same | ⟨member, holds'⟩
          · exact Or.inl same
          · exact Or.inr ⟨List.mem_cons_of_mem _ member, holds'⟩

section Retry

variable {log : List Entry} {index term : Nat}

theorem fhpm_eq
    : findHighestPossibleMatch log index term
      = maxWhere (fun c => 0 < c /\ termAt log c <= term)
          (List.range (min index log.length + 1)) 0 :=
  rfl

theorem fhpm_le : findHighestPossibleMatch log index term <= min index log.length := by
  rw [fhpm_eq]
  rcases (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
      (List.range (min index log.length + 1)) 0).2.2 with same | ⟨member, _⟩
  · rw [same]
    exact Nat.zero_le _
  · exact Nat.lt_succ_iff.mp (List.mem_range.mp member)

theorem le_fhpm {c : Nat} (positive : 0 < c) (le : c <= index) (bound : c <= log.length)
    (holds : termAt log c <= term)
    : c <= findHighestPossibleMatch log index term := by
  rw [fhpm_eq]
  exact (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
          (List.range (min index log.length + 1)) 0).2.1
    c (List.mem_range.mpr (by omega)) ⟨positive, holds⟩

theorem fhpm_chosen
    : findHighestPossibleMatch log index term = 0
      \/ (0 < findHighestPossibleMatch log index term
          /\ termAt log (findHighestPossibleMatch log index term) <= term) := by
  rw [fhpm_eq]
  rcases (maxWhere_spec (fun c => 0 < c /\ termAt log c <= term)
      (List.range (min index log.length + 1)) 0).2.2 with same | ⟨_, holds⟩
  · exact Or.inl same
  · exact Or.inr holds

end Retry

end CCFRaft.Proofs.Replication
