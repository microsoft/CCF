module

public import DisasterRecovery.Proofs.Evaluation
public import CCF.Proofs.OCC

@[expose] public section

namespace DisasterRecovery.Proofs.Transactions

open Model.Local CCF.OCC

private abbrev Gossip := Location × TxID

private theorem select_comm (x y : Gossip) : selectMaximum x y = selectMaximum y x := by
  rcases x with ⟨a, ⟨av, as'⟩⟩
  rcases y with ⟨b, ⟨bv, bs⟩⟩
  simp [selectMaximum, txScoreGreater]
  grind

private theorem select_swap (z x y : Gossip)
    : selectMaximum (selectMaximum z x) y = selectMaximum (selectMaximum z y) x := by
  rcases x with ⟨a, ⟨av, as'⟩⟩
  rcases y with ⟨b, ⟨bv, bs⟩⟩
  rcases z with ⟨c, ⟨cv, cs⟩⟩
  simp only [selectMaximum]
  split <;> split <;> simp [txScoreGreater] at * <;> grind

private def accumulate : Option Gossip → Gossip → Option Gossip
  | none, x => some x
  | some z, x => some (selectMaximum z x)

private theorem fold_some (xs : List Gossip) (x : Gossip)
    : xs.foldl accumulate (some x) = some (xs.foldl selectMaximum x) := by
  induction xs generalizing x with
  | nil => rfl
  | cons _ _ ih => apply ih

private theorem maximum_perm (xs ys : List Gossip) (perm : xs.Perm ys)
    : maximumGossip xs = maximumGossip ys := by
  have fold (l : List Gossip) : maximumGossip l = l.foldl accumulate none := by
    cases l with
    | nil => rfl
    | cons _ _ => exact (fold_some _ _).symm
  rw [fold, fold]
  apply perm.foldl_eq'
  intro x _ y _ z
  cases z with
  | none => exact congrArg some (select_comm x y)
  | some z => exact congrArg some (select_swap z x y)

private theorem bind_respects {α β : Type} (p : Tx α) (f : α → Tx β)
    (hp : p.Respects) (hf : ∀ x, (f x).Respects)
    : (p >>= f).Respects := by
  change (p.bind f).Respects
  induction p with
  | done x => exact hf x
  | fail => trivial
  | get _ _ ih => exact fun v => ih v (hp v)
  | put _ _ _ ih | output _ _ ih => exact ih hp
  | scan _ _ ih =>
      exact ⟨fun xs ys h => congrArg (·.bind f) (hp.1 xs ys h), fun xs => ih xs (hp.2 xs)⟩

private theorem readPhase_respects (table : Table) : (readPhase table).Respects := by
  intro value
  cases value with
  | none => trivial
  | some v => cases v <;> trivial

private theorem advance_respects (config : Config) (timeout : Bool)
    : (advance config timeout).Respects := by
  unfold advance
  apply bind_respects _ _ (readPhase_respects _)
  intro phase
  apply bind_respects _ _ (readPhase_respects _)
  intro lane
  cases phase with
  | gossiping =>
      constructor
      · intro xs ys perm
        have hp : (gossipEntries xs).Perm (gossipEntries ys) := perm.filterMap _
        dsimp [Program.bind]
        rw [hp.length_eq, maximum_perm _ _ hp]
      · intro xs
        dsimp [Program.bind]
        split
        · split <;> cases timeout <;> cases lane <;> trivial
        · cases timeout <;> cases lane <;> trivial
  | voting =>
      constructor
      · intro xs ys perm
        have hp : (voteEntries xs).Perm (voteEntries ys) := perm.filterMap _
        dsimp [Program.bind]
        rw [hp.length_eq, hp.isEmpty_eq]
      · intro xs
        dsimp [Program.bind]
        split
        · split <;> cases timeout <;> cases lane <;> trivial
        · cases timeout <;> cases lane <;> trivial
  | joining =>
      apply bind_respects
      · intro value; cases value with
        | none => trivial
        | some v => cases v <;> trivial
      · intro chosen; cases chosen <;> cases timeout <;> cases lane <;> trivial
  | opening | «open» => cases timeout <;> cases lane <;> trivial

theorem transaction_respects (config : Config) (event : Event)
    : (transaction config event).Respects := by
  cases event with
  | timeout => exact advance_respects _ _
  | retry => trivial
  | receiveVote _ valid =>
      cases valid with
      | rejected => trivial
      | accepted => exact advance_respects _ _
  | receiveGossip _ _ valid =>
      cases valid with
      | rejected => trivial
      | accepted =>
          unfold transaction
          apply bind_respects
          · intro v; cases v with
            | none => trivial
            | some v => cases v <;> trivial
          · intro chosen
            split
            · trivial
            · apply bind_respects
              · intro _; trivial
              · intro read
                split <;> exact advance_respects _ _
  | receiveIAmOpen _ valid =>
      cases valid with
      | rejected => trivial
      | accepted =>
          unfold transaction
          apply bind_respects _ _ (readPhase_respects _)
          intro phase
          cases phase <;> first | exact advance_respects _ _ | trivial

private def IsRestart : Output → Prop
  | .notify (.restart _) => True
  | _ => False

private def BeforeWrite {α : Type} : Tx α → Prop
  | .done _ | .fail _ | .put .. => True
  | .get _ next => ∀ x, BeforeWrite (next x)
  | .scan _ next => ∀ xs, BeforeWrite (next xs)
  | .output o next => IsRestart o ∧ BeforeWrite next

private theorem beforeWrite_bind {α β : Type} (p : Tx α) (f : α → Tx β)
    (hp : BeforeWrite p) (hf : ∀ x, BeforeWrite (f x))
    : BeforeWrite (p >>= f) := by
  induction p with
  | done x => exact hf x
  | fail | put => trivial
  | get _ _ ih | scan _ _ ih => exact fun x => ih x (hp x)
  | output _ _ ih => exact ⟨hp.1, ih hp.2⟩

private theorem advance_beforeWrite (config : Config) (timeout : Bool)
    : BeforeWrite (advance config timeout) := by
  unfold advance
  apply beforeWrite_bind
  · intro v; cases v with
    | none => trivial
    | some v => cases v <;> trivial
  intro phase
  apply beforeWrite_bind
  · intro v; cases v with
    | none => trivial
    | some v => cases v <;> trivial
  intro lane
  cases phase with
  | gossiping =>
      intro xs
      dsimp [Program.bind]
      split
      · split <;> trivial
      · cases timeout <;> cases lane <;> trivial
  | voting =>
      intro xs
      dsimp [Program.bind]
      split
      · split <;> cases timeout <;> trivial
      · cases timeout <;> cases lane <;> trivial
  | joining =>
      apply beforeWrite_bind
      · intro v; cases v with
        | none => trivial
        | some v => cases v <;> trivial
      · intro chosen
        cases chosen with
        | none => trivial
        | some _ => exact ⟨trivial, by cases timeout <;> cases lane <;> trivial⟩
  | opening | «open» => cases timeout <;> cases lane <;> trivial

private theorem beforeWrite_event (config : Config) (e : Event)
    : BeforeWrite (transaction config e) := by
  cases e with
  | timeout => exact advance_beforeWrite _ _
  | retry => trivial
  | receiveVote _ v => cases v <;> trivial
  | receiveGossip _ _ v =>
      cases v with
      | rejected => trivial
      | accepted =>
          unfold transaction
          apply beforeWrite_bind
          · intro v; cases v with
            | none => trivial
            | some v => cases v <;> trivial
          · intro chosen
            split
            · trivial
            · intro value
              dsimp [Program.bind]
              split <;> first | trivial | exact advance_beforeWrite _ _
  | receiveIAmOpen _ v =>
      cases v with
      | rejected => trivial
      | accepted =>
          unfold transaction
          apply beforeWrite_bind
          · intro v; cases v with
            | none => trivial
            | some v => cases v <;> trivial
          · intro phase; cases phase <;> trivial

private theorem empty_prefix {α : Type} (p : Tx α) (db : Store)
    (n : Normal Table Key Value) (outs : List Output)
    (empty : (p.execFrom db n outs).normal.writes = [])
    : n.writes = [] := by
  induction p generalizing n outs with
  | done | fail => exact empty
  | get _ _ ih | scan _ _ ih => have h := ih _ _ _ empty; exact h
  | output _ _ ih => exact ih _ _ empty
  | put _ _ _ ih => have h := ih _ _ empty; contradiction

private theorem readOnly_outputs {α : Type} (p : Tx α) (db : Store)
    (n : Normal Table Key Value) (outs : List Output) (ok : BeforeWrite p)
    (hs : ∀ x ∈ outs, IsRestart x) (empty : (p.execFrom db n outs).normal.writes = [])
    : ∀ x ∈ (p.execFrom db n outs).outputs, IsRestart x := by
  induction p generalizing n outs with
  | done | fail => exact hs
  | get _ _ ih | scan _ _ ih => exact ih _ _ _ (ok _) hs empty
  | output o _ ih =>
      apply ih _ _ ok.2 _ empty
      intro x mem
      rcases List.mem_append.mp mem with old | new
      · exact hs x old
      · exact List.mem_singleton.mp new ▸ ok.1
  | put _ _ rest _ => have h := empty_prefix rest db _ _ empty; contradiction

/-- A pending read-only transaction may commit against a different state without
validation, but it can neither send a message nor announce opening or completion. -/
theorem readOnly_only_restart (config : Config) (event : Event) (db : Store)
    (empty : ((transaction config event).exec db).normal.writes = [])
    (o : Output) (member : o ∈ ((transaction config event).exec db).outputs)
    : ∃ node, o = .notify (.restart node) := by
  have h := readOnly_outputs _ db {} [] (beforeWrite_event config event) (by simp) empty o member
  cases o with
  | send => contradiction
  | notify n => cases n <;> first | contradiction | exact ⟨_,rfl⟩

end DisasterRecovery.Proofs.Transactions
