module

public import consistency.Proofs.SingleNode

@[expose] public section

set_option linter.unusedSimpArgs false

namespace consistency.Proofs.Reads

open Model Properties Observations LedgerIdentity SingleNode

def Predecessors (history : List Event) : Prop :=
  ∀ (readIndex : Nat) (readTx : TxContent) (observed : List TxContent) (readID : TxID),
    history[readIndex]? = some (.response .ro readTx observed readID)
    → ∀ (writeIndex : Nat) (writeTx : TxContent) (writeObserved : List TxContent)
        (writeID : TxID),
        history[writeIndex]? = some (.response .rw writeTx writeObserved writeID)
        → writeIndex < readIndex
        → writeTx ∈ observed

theorem predecessors_snoc (history : List Event) (event : Event)
    (predecessors : Predecessors history)
    (newRead
      : ∀ (tx : TxContent) (observed : List TxContent) (txid : TxID),
          event = .response .ro tx observed txid
          → ∀ (index : Nat) (write : TxContent) (writeObserved : List TxContent)
              (writeID : TxID),
              history[index]? = some (.response .rw write writeObserved writeID)
              → write ∈ observed)
    : Predecessors (history ++ [event]) := by
  intro readIndex readTx observed readID readFound writeIndex writeTx writeObserved writeID writeFound before
  rcases History.lookup_snoc readFound with ⟨readBound, oldRead⟩ | ⟨readLast, newResponse⟩
  · rcases History.lookup_snoc writeFound with ⟨_, oldWrite⟩ | ⟨writeLast, _⟩
    · exact predecessors _ _ _ _ oldRead _ _ _ _ oldWrite before
    · omega
  · rcases History.lookup_snoc writeFound with ⟨_, oldWrite⟩ | ⟨writeLast, _⟩
    · exact newRead _ _ _ newResponse _ _ _ _ oldWrite
    · omega

theorem prior_writes (config : Config) (state : State) (single : Single config state)
    (snapshots : Snapshots state.branches state.history) {branch : Nat}
    {ledger : List Entry} (found : at? state.branches branch = some ledger)
    (active : activeBranch config state branch = true)
    : ∀ (index : Nat) (tx : TxContent) (observed : List TxContent) (txid : TxID),
        state.history[index]? = some (.response .rw tx observed txid)
        → tx ∈ writes ledger := by
  intro index tx observed txid response
  have snapshot := snapshots _ _ _ _ _ response
  have view := snapshot_view config state single snapshot
  obtain ⟨origin, originFound, _, entry, atEntry, _, txMatches⟩ := snapshot
  have branchIndex := active_index config state single active
  rw [branchIndex] at found
  rw [view, found] at originFound
  cases originFound
  exact List.mem_filterMap.mpr ⟨entry, mem_of_at? atEntry, txMatches rfl⟩

theorem predecessors_read (config : Config) (state : State) (single : Single config state)
    (snapshots : Snapshots state.branches state.history)
    (predecessors : Predecessors state.history) {branch : Nat} {ledger : List Entry}
    (tx : TxContent) (txid : TxID) (found : at? state.branches branch = some ledger)
    (active : activeBranch config state branch = true)
    : Predecessors (state.history ++ [.response .ro tx (writes ledger) txid]) := by
  apply predecessors_snoc _ _ predecessors
  intro _ _ _ same
  cases same
  exact prior_writes config state single snapshots found active

theorem step_predecessors (config : Config) (singleNode : config.multiNode = false)
    (before after : State) (action : Action) (single : Single config before)
    (snapshots : Snapshots before.branches before.history)
    (predecessors : Predecessors before.history)
    (transition : step config before action = some after)
    : Predecessors after.history := by
  cases action <;>
    simp only [step, request, execute, respond, Model.read, commit, invalidate, appendOther, elect]
      at transition
  all_goals
    simp_all [Option.bind_eq_some_iff, guard]
    repeat' first
      | (rcases transition with ⟨condition, transition⟩)
      | (split at transition)
      | (exact predecessors)
      | (solve | apply predecessors_snoc _ _ predecessors; simp)
      | (solve | apply predecessors_read config before single snapshots predecessors <;> assumption)
      | (simp_all [appendEvent, appendEntry, Option.bind_eq_some_iff])

theorem predecessors_reachable (config : Config) (singleNode : config.multiNode = false)
    {state : State} (reachable : (transitionSystem config).Reachable state)
    : Predecessors state.history := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | @initial state initialized =>
      change state = initialState config at initialized
      subst state
      simp [Predecessors, initialState]
  | @step before after action reachable transition ih =>
      exact step_predecessors config singleNode before after action
        (single_reachable config singleNode reachable) (snapshots_reachable config reachable) ih transition

theorem all_committed_observed_ro
    : forall (config : Config) (trace : CCF.Execution.Trace State) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        → ∀ earlier ∈ committedResponses state.history .rw,
          ∀ request ∈ committedRequests state.history .ro,
          ∀ later ∈ committedResponses state.history .ro,
            later.2.tx = request.2.2
            → earlier.1 < request.1
            → earlier.2.tx ∈ later.2.observed := by
  intro config trace state ⟨singleNode, valid, member⟩ earlier first request sent later second same before
  have reachable := valid.reachable member
  obtain ⟨firstKind, firstLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp
    (List.mem_filter.mp first).1
  obtain ⟨secondKind, secondLookup⟩ := (History.mem_responsesOf_iff _ _ _).mp
    (List.mem_filter.mp second).1
  rw [firstKind] at firstLookup
  rw [secondKind] at secondLookup
  obtain ⟨requestIndex, prior, requestLookup⟩ :=
    History.causal_reachable config reachable _ _ _ _ _ secondLookup
  have sentLookup := (History.mem_requests_iff _ _ _ _).mp (List.mem_filter.mp sent).1
  have sameIndex := (History.requests_reachable config reachable).2
    _ _ _ _ _ _ requestLookup sentLookup same
  exact predecessors_reachable config singleNode reachable _ _ _ _ secondLookup
    _ _ _ _ firstLookup (by omega)

end consistency.Proofs.Reads
