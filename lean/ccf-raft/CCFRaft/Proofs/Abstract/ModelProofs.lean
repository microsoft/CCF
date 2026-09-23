-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.Model

import CCFRaft.Proofs.Abstract.Support

open CCFRaft.Proofs.Abstract CCFRaft.Proofs.Abstract.Model CCFRaft.Proofs.Abstract.Safety CCFRaft.Proofs.Abstract.Support
open CCFRaft.Model.Local (BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm messageEntries refreshRetirementState retiredCommittedIndexFrom retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom retirementCommittableIndexInLog retirementCompletedNodes retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt updateIndex)

set_option autoImplicit false

/-!
# Model proof helpers

Bootstrap, state-update, retirement, and reachability lemmas kept outside the
manual model-review boundary.
-/

namespace CCFRaft.Proofs.Abstract.ModelProofs

/-- Every valid bootstrap configuration contains its selected leader. -/
lemma initialLeader_mem_initialConfiguration
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Membership.mem
      (INITIAL_CONFIGURATION (Node := Node))
      (INITIAL_LEADER (Node := Node)) :=
  bootstrap.leader_mem

/-- Every valid bootstrap configuration is nonempty. -/
lemma initialConfiguration_nonempty
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    (INITIAL_CONFIGURATION (Node := Node)).Nonempty := by
  exact
    Exists.intro
      (INITIAL_LEADER (Node := Node))
      (initialLeader_mem_initialConfiguration (Node := Node))

variable {Node TxId : Type}

namespace NodeStore

open CCFRaft.Proofs.Abstract.Model.NodeStore

variable [DecidableEq Node]

@[simp]
lemma node?_set_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    (nodes.set node value).node? node = some value := by
  simp [node?, CCFRaft.Proofs.Abstract.Model.NodeStore.set]

@[simp]
lemma node?_set_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    (nodes.set node value).node? candidate = nodes.node? candidate := by
  simp [node?, CCFRaft.Proofs.Abstract.Model.NodeStore.set, Finmap.lookup_insert_of_ne, different]

@[simp]
lemma get_set_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    nodes.set node value node = value := by
  simp [CCFRaft.Proofs.Abstract.Model.NodeStore.get]

@[simp]
lemma get_set_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    nodes.set node value candidate = nodes candidate := by
  simp [CCFRaft.Proofs.Abstract.Model.NodeStore.get, node?_set_of_ne, different]

@[simp]
lemma node?_ofFinset_of_mem
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node)
    (member : node ∈ keys) :
    (ofFinset keys value).node? node = some (value node) := by
  rw [node?, Finmap.lookup_eq_some_iff]
  simp [ofFinset, member]

@[simp]
lemma node?_ofFinset_of_not_mem
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node)
    (notMember : node ∉ keys) :
    (ofFinset keys value).node? node = none := by
  rw [node?, Finmap.lookup_eq_none]
  simpa [ofFinset, Finmap.mem_def, Multiset.keys] using notMember

@[simp]
lemma get_ofFinset
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId)
    (node : Node) :
    ofFinset keys value node =
      if node ∈ keys then value node else freshNodeState := by
  simp only [CCFRaft.Proofs.Abstract.Model.NodeStore.get]
  split <;> simp_all

@[simp]
lemma node?_allocate_of_allocated
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node)
    (allocated : nodes.allocated node) :
    (nodes.allocate added).node? node = nodes.node? node := by
  change (nodes.node? node).isSome at allocated
  rw [Option.isSome_iff_exists] at allocated
  rcases allocated with ⟨value, found⟩
  simp only [node?, allocate]
  rw [Finmap.lookup_union_left (Finmap.mem_of_lookup_eq_some found)]

@[simp]
lemma node?_allocate_of_not_allocated_of_mem
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node)
    (notAllocated : Not (nodes.allocated node))
    (member : node ∈ added) :
    (nodes.allocate added).node? node = some freshNodeState := by
  have missing : nodes.node? node = none := by
    cases found : nodes.node? node <;>
      simp_all [NodeStore.allocated]
  have notIn : node ∉ nodes.entries := by
    rw [← Finmap.lookup_eq_none]
    exact missing
  simp only [node?, allocate]
  rw [Finmap.lookup_union_right notIn]
  exact node?_ofFinset_of_mem added (fun _ => freshNodeState) node member

@[simp]
lemma allocate_empty (nodes : NodeStore Node TxId) :
    nodes.allocate ∅ = nodes := by
  cases nodes with
  | mk entries =>
      change NodeStore.mk (entries ∪ (∅ : Finmap (fun _ : Node => NodeState Node TxId))) =
        NodeStore.mk entries
      rw [Finmap.union_empty]

end NodeStore

variable [DecidableEq Node]

/-- Reading the node just updated returns the new value. -/
@[simp]
lemma updateNode_same
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    updateNode nodes node value node = value := by
  simp [updateNode]

/-- Reading another node after an update returns its old value. -/
@[simp]
lemma updateNode_of_ne
    (nodes : NodeStore Node TxId)
    (node candidate : Node)
    (value : NodeState Node TxId)
    (different : Not (candidate = node)) :
    updateNode nodes node value candidate = nodes candidate := by
  simp [updateNode, different]

/-- Reading the updated peer index returns the new value. -/
@[simp]
lemma updateIndex_same
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    updateIndex indices node value node = value := by
  simp [updateIndex]

/-- Updating one peer index leaves all other peer indices unchanged. -/
@[simp]
lemma updateIndex_of_ne
    (indices : Node -> Nat)
    (node candidate : Node)
    (value : Nat)
    (different : Not (candidate = node)) :
    updateIndex indices node value candidate = indices candidate := by
  simp [updateIndex, different]

/-- Reading the replaced destination queue returns the new queue. -/
@[simp]
lemma updateQueue_same
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId)) :
    updateQueue network destination queue destination = queue := by
  simp [updateQueue]

/-- Replacing one destination queue leaves other queues unchanged. -/
@[simp]
lemma updateQueue_of_ne
    (network : Node -> List (Message Node TxId))
    (destination candidate : Node)
    (queue : List (Message Node TxId))
    (different : Not (candidate = destination)) :
    updateQueue network destination queue candidate = network candidate := by
  simp [updateQueue, different]

/-- Selecting a packet only removes an occurrence from the original queue. -/
lemma takeOccurrenceFrom_sublist
    (source : Node)
    (occurrence : Nat)
    (queue remaining : List (Message Node TxId))
    (selected : Message Node TxId)
    (removed : takeOccurrenceFrom source occurrence queue = some (selected, remaining)) :
    remaining.Sublist queue := by
  induction queue generalizing occurrence remaining with
  | nil => simp [takeOccurrenceFrom] at removed
  | cons head tail inductionHypothesis =>
      by_cases same : head.source = source
      · cases occurrence with
        | zero =>
            simp only [takeOccurrenceFrom, ite_eq_left same, Option.some.injEq,
              Prod.mk.injEq] at removed
            rcases removed with ⟨_, rfl⟩
            exact List.Sublist.cons _ (List.Sublist.refl _)
        | succ occurrence =>
            cases found : takeOccurrenceFrom source occurrence tail with
            | none => simp [takeOccurrenceFrom, same, found] at removed
            | some result =>
                rcases result with ⟨packet, rest⟩
                simp [takeOccurrenceFrom, same, found] at removed
                rcases removed with ⟨rfl, rfl⟩
                exact (inductionHypothesis occurrence rest found).cons_cons head
      · cases found : takeOccurrenceFrom source occurrence tail with
        | none => simp [takeOccurrenceFrom, same, found] at removed
        | some result =>
            rcases result with ⟨packet, rest⟩
            simp [takeOccurrenceFrom, same, found] at removed
            rcases removed with ⟨rfl, rfl⟩
            exact (inductionHypothesis occurrence rest found).cons_cons head

section
omit [DecidableEq Node]

@[simp] lemma protocolNodeState_idempotent
    (state : NodeState Node TxId) :
    protocolNodeState (protocolNodeState state) = protocolNodeState state := by
  simp [protocolNodeState]

@[simp] lemma protocolNodeState_set_votedFor
    (state : NodeState Node TxId)
    (votedFor : Option Node) :
    protocolNodeState { state with votedFor } =
      { protocolNodeState state with votedFor } := by
  simp [protocolNodeState]

@[simp] lemma protocolNodeState_set_sentIndex
    (state : NodeState Node TxId)
    (sentIndex : Node -> Nat) :
    protocolNodeState { state with sentIndex } =
      { protocolNodeState state with sentIndex } := by
  simp [protocolNodeState]

@[simp] lemma protocolNodeState_idempotent_set_votedFor
    (state : NodeState Node TxId)
    (votedFor : Option Node) :
    protocolNodeState { protocolNodeState state with votedFor } =
      { protocolNodeState state with votedFor } := by
  simp [protocolNodeState]

end

variable [Bootstrap Node] [DecidableEq TxId]

@[simp] lemma refreshRetirementState_role
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).role = state.role := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_currentTerm
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).currentTerm = state.currentTerm := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_log
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).log = state.log := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_commitIndex
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).commitIndex = state.commitIndex := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_sentIndex
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).sentIndex = state.sentIndex := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_matchIndex
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).matchIndex = state.matchIndex := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_isNewFollower
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).isNewFollower =
      state.isNewFollower := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_votedFor
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).votedFor = state.votedFor := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_votesGranted
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).votesGranted =
      state.votesGranted := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_preVotesGranted
    (node : Node)
    (state : NodeState Node TxId) :
    (refreshRetirementState node state).preVotesGranted =
      state.preVotesGranted := by
  simp [refreshRetirementState]

@[simp] lemma refreshRetirementState_idempotent
    (node : Node)
    (state : NodeState Node TxId) :
    refreshRetirementState node (refreshRetirementState node state) =
      refreshRetirementState node state := by
  have repeatOr (left right : Option Nat) :
      (left.or right).or right = left.or right := by
    cases left <;> cases right <;> rfl
  simp [refreshRetirementState, repeatOr]

@[simp] lemma protocolNodeState_refreshRetirementState
    (node : Node)
    (state : NodeState Node TxId) :
    protocolNodeState (refreshRetirementState node state) =
      protocolNodeState state := by
  simp [protocolNodeState]

namespace Reachable

/-- The Raft initial state is reachable. -/
lemma initial :
    Reachable (initialState : State Node TxId) :=
  ExecutableTransitionSystem.Reachable.initial

/-- Taking an enabled action from a reachable state preserves reachability. -/
lemma step
    {state : State Node TxId}
    (reachable : Reachable state)
    {action : Action Node TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

/-- A successfully executed action list ends in a reachable state. -/
lemma runActionsReachable
    {start final : State Node TxId}
    {actions : List (Action Node TxId)}
    (startReachable : Reachable start)
    (ran : runActions start actions = some final) :
    Reachable final := by
  induction actions generalizing start final with
  | nil =>
      simp [runActions] at ran
      subst final
      exact startReachable
  | cons action actions inductionHypothesis =>
      unfold runActions at ran
      cases applied : system.applyAction start action with
      | none =>
          simp [applied] at ran
      | some nextState =>
          have enabled : Enabled start action := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · assumption
            · contradiction
          have nextEq : next start action = nextState := by
            unfold ExecutableTransitionSystem.applyAction at applied
            split at applied
            · exact Option.some.inj applied
            · contradiction
          have nextReachable : Reachable nextState := by
            rw [← nextEq]
            exact step startReachable enabled
          exact
            inductionHypothesis nextReachable
              (by simpa [applied] using ran)

end Reachable

end CCFRaft.Proofs.Abstract.ModelProofs
