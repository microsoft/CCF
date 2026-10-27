module

public import CCFRaft.Proofs.Concrete

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Results and sends of local effects

`Sends P m` says every successful run of `m` appends some envelopes `new` to
the outgoing messages and returns a value `r` with `P r new`. Unlike
`Direct.Keeps`, this records what a handler sends as well as what it returns.
-/

namespace CCFRaft.Proofs.Safety

open CCF

variable {Node Message Notification : Type}

/-- Every successful run of `m` appends `new` to the outgoing envelopes and
returns `result` with `P result new`. -/
def Sends {α : Type} (P : α -> List (Envelope Node Message) -> Prop)
    (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after,
    m.run outputs = some (result, after)
    -> exists new, after.outgoing = outputs.outgoing ++ new /\ P result new

namespace Sends

variable {α β γ : Type}

theorem pure' {P : α -> List (Envelope Node Message) -> Prop} {value : α}
    (holds : P value [])
    : Sends (Notification := Notification) P (pure value) := by
  intro outputs _ _ ran
  cases ran
  exact ⟨[], by simp, holds⟩

theorem bind' {Q : α -> List (Envelope Node Message) -> Prop}
    {P : β -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Sends Q m)
    (rest
      : forall value sent,
          Q value sent -> Sends (fun result later => P result (sent ++ later)) (f value))
    : Sends P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  cases ranFirst : m.run outputs with
  | none => simp [ranFirst] at ran
  | some pair =>
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      obtain ⟨sent, sentEq, holds⟩ := first _ _ _ ranFirst
      obtain ⟨later, laterEq, done⟩ := rest value sent holds _ _ _ ran
      exact ⟨sent ++ later, by rw [laterEq, sentEq, List.append_assoc], done⟩

theorem mono {P Q : α -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} (sends : Sends P m)
    (weaker : forall value sent, P value sent -> Q value sent)
    : Sends Q m := by
  intro outputs result after ran
  obtain ⟨sent, eq, holds⟩ := sends _ _ _ ran
  exact ⟨sent, eq, weaker _ _ holds⟩

theorem and' {P Q : α -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} (left : Sends P m) (right : Sends Q m)
    : Sends (fun value sent => P value sent /\ Q value sent) m := by
  intro outputs result after ran
  obtain ⟨sent, eq, holds⟩ := left _ _ _ ran
  obtain ⟨sent', eq', holds'⟩ := right _ _ _ ran
  rw [eq] at eq'
  rw [← List.append_cancel_left eq'] at holds'
  exact ⟨sent, eq, holds, holds'⟩

theorem ite' {P : α -> List (Envelope Node Message) -> Prop} {c : Prop} [Decidable c]
    {m n : Effect Node Message Notification α}
    (yes : c -> Sends P m) (no : Not c -> Sends P n)
    : Sends P (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

theorem guard' {c : Prop} [Decidable c]
    : Sends (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ sent => c /\ sent = []) (guard c) := by
  intro outputs _ after ran
  by_cases holds : c
  · simp [guard, holds] at ran
    obtain ⟨_, rfl⟩ := ran
    exact ⟨[], by simp, holds, rfl⟩
  · simp [guard, holds] at ran

theorem guard_bind {P : α -> List (Envelope Node Message) -> Prop} {c : Prop}
    [Decidable c] {m : Effect Node Message Notification α} (rest : c -> Sends P m)
    : Sends P (guard c >>= fun _ => m) :=
  bind' guard'
    fun _ _ ⟨holds, empty⟩ => by
      subst empty
      exact mono (rest holds) fun _ _ done => by simpa using done

theorem send (source target : Node) (payload : Message)
    : Sends (Notification := Notification)
        (fun _ sent => sent = [{ source, target, payload }])
        ((Capabilities.record source).send payload target) := by
  intro outputs _ after ran
  simp only [Capabilities.record, modify, modifyGet, StateT.run] at ran
  cases ran
  exact ⟨_, rfl, rfl⟩

/-- A loop whose bodies each only send envelopes satisfying `R`. -/
theorem forM' {items : List γ} {f : γ -> Effect Node Message Notification PUnit}
    {R : Envelope Node Message -> Prop}
    (each
      : forall item,
          item ∈ items -> Sends (fun _ sent => forall e, e ∈ sent -> R e) (f item))
    : Sends (fun _ sent => forall e, e ∈ sent -> R e) (items.forM f) := by
  induction items with
  | nil =>
      exact pure' (P := fun _ sent => forall e, e ∈ sent -> R e) (by simp)
  | cons head tail ih =>
      rw [show (head :: tail).forM f = (f head >>= fun _ => tail.forM f) from rfl]
      refine bind' (each head List.mem_cons_self) fun _ sent first => ?_
      refine mono (ih fun item member => each item (List.mem_cons_of_mem _ member))
        fun _ later rest => ?_
      intro e member
      rcases List.mem_append.mp member with old | new
      · exact first e old
      · exact rest e new

/-- A `for` loop whose bodies each only send envelopes satisfying `R`. -/
theorem forIn' {β : Type} {items : List γ} {init : β}
    {f : γ -> β -> Effect Node Message Notification (ForInStep β)}
    {R : Envelope Node Message -> Prop}
    (each
      : forall item value,
          item ∈ items -> Sends (fun _ sent => forall e, e ∈ sent -> R e) (f item value))
    : Sends (fun _ sent => forall e, e ∈ sent -> R e) (forIn items init f) := by
  induction items generalizing init with
  | nil =>
      simpa using pure' (P := fun (_ : β) sent => forall e, e ∈ sent -> R e) (by simp)
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine bind' (each head init List.mem_cons_self) fun step sent first => ?_
      cases step with
      | done value => exact pure' fun e member => first e (by simpa using member)
      | yield value =>
          refine mono (ih fun item value member => each item value (List.mem_cons_of_mem _ member))
            fun _ later rest e member => ?_
          rcases List.mem_append.mp member with old | new
          · exact first e old
          · exact rest e new

/-- A fold that keeps `I` of its accumulator and everything sent so far. -/
theorem foldlM' {I : α -> List (Envelope Node Message) -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step
      : forall value sent item,
          I value sent -> Sends (fun next later => I next (sent ++ later)) (f value item))
    : forall (items : List γ) (init : α) (sent : List (Envelope Node Message)),
        I init sent
        -> Sends (fun result later => I result (sent ++ later)) (items.foldlM f init)
  | [], _, _, holds => by simpa using pure' (P := fun result later => I result (_ ++ later)) (by simpa using holds)
  | item :: items, init, sent, holds => by
      simp only [List.foldlM_cons]
      refine bind' (step init sent item holds) fun value later kept => ?_
      refine mono (foldlM' step items value (sent ++ later) kept) fun _ rest done => ?_
      simpa [List.append_assoc] using done

end Sends

end CCFRaft.Proofs.Safety
