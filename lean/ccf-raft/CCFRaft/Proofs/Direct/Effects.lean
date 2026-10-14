module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Concrete

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Results of local effects

`Keeps P m` says every successful run of `m`, from any outputs, returns a value
satisfying `P`. Sends only change outputs, so a handler keeps a state predicate
when each of its state updates does.
-/

namespace CCFRaft.Proofs.Direct

open CCF

variable {Node Message Notification : Type}

/-- Every successful run of `m` returns a value satisfying `P`. -/
def Keeps {α : Type} (P : α -> Prop) (m : Effect Node Message Notification α) : Prop :=
  forall outputs result after, m.run outputs = some (result, after) -> P result

namespace Keeps

variable {α β : Type}

theorem pure' {P : α -> Prop} {value : α} (holds : P value)
    : Keeps (Node := Node) (Message := Message) (Notification := Notification) P
        (pure value) := by
  intro _ _ _ ran
  cases ran
  exact holds

theorem trivial' (m : Effect Node Message Notification α) : Keeps (fun _ => True) m :=
  fun _ _ _ _ => True.intro

theorem bind' {Q : α -> Prop} {P : β -> Prop} {m : Effect Node Message Notification α}
    {f : α -> Effect Node Message Notification β}
    (first : Keeps Q m) (rest : forall value, Q value -> Keeps P (f value))
    : Keeps P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  cases ranFirst : m.run outputs with
  | none => simp [ranFirst] at ran
  | some pair =>
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      exact rest value (first _ _ _ ranFirst) _ _ _ ran

theorem seq' {P : β -> Prop} {m : Effect Node Message Notification α}
    {f : α -> Effect Node Message Notification β}
    (rest : forall value, Keeps P (f value))
    : Keeps P (m >>= f) :=
  bind' (trivial' m) fun value _ => rest value

theorem mono {P Q : α -> Prop} {m : Effect Node Message Notification α}
    (kept : Keeps P m) (weaker : forall value, P value -> Q value)
    : Keeps Q m :=
  fun outputs result after ran => weaker _ (kept outputs result after ran)

theorem and' {P Q : α -> Prop} {m : Effect Node Message Notification α}
    (left : Keeps P m) (right : Keeps Q m)
    : Keeps (fun value => P value /\ Q value) m :=
  fun _ _ _ ran => ⟨left _ _ _ ran, right _ _ _ ran⟩

theorem ite' {P : α -> Prop} {c : Prop} [Decidable c]
    {m n : Effect Node Message Notification α}
    (yes : c -> Keeps P m) (no : Not c -> Keeps P n)
    : Keeps P (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

theorem failure' {P : α -> Prop}
    : Keeps (Node := Node) (Message := Message) (Notification := Notification) P
        failure := by
  intro _ _ _ ran
  simp at ran

/-- A guard either fails or establishes its condition. -/
theorem guard' {c : Prop} [Decidable c]
    : Keeps (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ => c) (guard c) := by
  intro _ _ _ ran
  by_contra absent
  simp [guard, absent] at ran

theorem foldlM' {γ : Type} {P : α -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step : forall value item, P value -> Keeps P (f value item))
    : forall (items : List γ) (init : α), P init -> Keeps P (items.foldlM f init)
  | [], _, holds => by simpa using pure' holds
  | item :: items, init, holds => by
      simp only [List.foldlM_cons]
      exact bind' (step init item holds) fun value kept => foldlM' step items value kept

end Keeps

end CCFRaft.Proofs.Direct
