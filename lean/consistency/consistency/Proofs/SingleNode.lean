module

public import consistency.Proofs.LedgerIdentity

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.SingleNode

open Model Properties Observations LedgerIdentity

def Single (config : Config) (state : State) : Prop :=
  state.branches.length = config.firstBranch
  ∧ ∀ ledger ∈ state.branches, ∀ entry ∈ ledger, entry.view = config.firstBranch

theorem active_index (config : Config) (state : State) (single : Single config state)
    {branch : Nat} (active : activeBranch config state branch = true)
    : branch = config.firstBranch := by
  have length := single.1
  simp [activeBranch] at active
  omega

theorem single_modify (config : Config) (state : State) (single : Single config state)
    (branch : Nat) (entry : Entry) (view : entry.view = branch)
    (active : activeBranch config state branch = true)
    : Single config (appendEntry state branch entry) := by
  refine ⟨by simpa [appendEntry] using single.1, ?_⟩
  apply forall_modify _ _ _ _ single.2
  intro ledger member value listed
  rcases List.mem_append.mp listed with old | new
  · exact single.2 ledger member value old
  · have same := List.mem_singleton.mp new
    subst value
    exact view.trans (active_index config state single active)

theorem step_single (config : Config) (singleNode : config.multiNode = false)
    (before after : State) (action : Action) (single : Single config before)
    (transition : step config before action = some after)
    : Single config after := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact single)
      | (solve | apply single_modify config before single _ _ rfl; assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff, Single])

theorem single_reachable (config : Config) (singleNode : config.multiNode = false)
    {state : State} (reachable : (transitionSystem config).Reachable state)
    : Single config state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | @initial state initialized =>
      change state = initialState config at initialized
      subst state
      simp [Single, initialState, List.mem_replicate]
  | @step before after action _ transition ih =>
      exact step_single config singleNode before after action ih transition

theorem snapshot_view (config : Config) (state : State) (single : Single config state)
    {kind : TxType} {tx : TxContent} {observed : List TxContent} {txid : TxID}
    (snapshot : Snapshot state.branches kind tx observed txid)
    : txid.view = config.firstBranch := by
  obtain ⟨ledger, found, _, entry, atEntry, view, _⟩ := snapshot
  exact view.symm.trans (single.2 ledger (mem_of_at? found) entry (mem_of_at? atEntry))

theorem unique_seq_nums
    : forall (config : Config) (trace : CCF.Execution.Trace State) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        → ∀ left ∈ responsesOf state.history .rw,
          ∀ right ∈ responsesOf state.history .rw,
            left.2.txid.seqno = right.2.txid.seqno → left.2.tx = right.2.tx := by
  intro config trace state ⟨singleNode, valid, member⟩ left first right second seqno
  have reachable := valid.reachable member
  have single := single_reachable config singleNode reachable
  have snapshots := snapshots_reachable config reachable
  have leftView := snapshot_view config state single
    (snapshots _ _ _ _ _ ((History.mem_responsesOf_iff _ _ _).mp first).2)
  have rightView := snapshot_view config state single
    (snapshots _ _ _ _ _ ((History.mem_responsesOf_iff _ _ _).mp second).2)
  have same : left.2.txid = right.2.txid :=
    congrArg₂ TxID.mk (leftView.trans rightView.symm) seqno
  exact LedgerIdentity.unique_txs config trace state ⟨valid, member⟩ left first right second same

theorem rw_serializable
    : forall (config : Config) (trace : CCF.Execution.Trace State) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        → ∀ left ∈ responsesOf state.history .rw,
          ∀ right ∈ responsesOf state.history .rw,
            left.2.observed <+: right.2.observed
            ∨ right.2.observed <+: left.2.observed := by
  intro config trace state ⟨singleNode, valid, member⟩ left first right second
  have reachable := valid.reachable member
  have single := single_reachable config singleNode reachable
  have snapshots := snapshots_reachable config reachable
  have firstSnapshot := snapshots _ _ _ _ _
    ((History.mem_responsesOf_iff _ _ _).mp first).2
  have secondSnapshot := snapshots _ _ _ _ _
    ((History.mem_responsesOf_iff _ _ _).mp second).2
  have leftView := snapshot_view config state single firstSnapshot
  have rightView := snapshot_view config state single secondSnapshot
  obtain ⟨firstLedger, firstFound, firstObs, _⟩ := firstSnapshot
  obtain ⟨secondLedger, secondFound, secondObs, _⟩ := secondSnapshot
  rw [leftView] at firstFound
  rw [rightView, firstFound] at secondFound
  cases secondFound
  rw [firstObs, secondObs]
  rcases Nat.le_total left.2.txid.seqno right.2.txid.seqno with bound | bound
  · exact Or.inl ((List.take_prefix_take_left (l := firstLedger) bound).filterMap Entry.tx)
  · exact Or.inr ((List.take_prefix_take_left (l := firstLedger) bound).filterMap Entry.tx)

end consistency.Proofs.SingleNode
