-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Concrete
import CCFRaft.Proofs.Abstract.ReconfigurationPreservation

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-!
# Correspondence between the network model and the abstract model

`Corr concrete abstract` relates a `Model.State` to an
`Abstract.Model.State`. Node states agree. Each abstract destination queue is
a permutation of the concrete envelopes to that destination, so a concrete
delivery of any envelope can be matched by reordering one abstract queue.
The abstract retirement snapshots equal the values every node derives from
its own log. Every envelope's endpoints are allocated in the abstract store.
-/

namespace CCFRaft.Proofs.Refinement

open Shared Shared.MultiNodeTransitionSystem
open Model.Local (NodeState Bootstrap Role Entry INITIAL_CONFIGURATION INITIAL_LEADER
  INITIAL_PRE_VOTE_STATUS BOOTSTRAP_TERM initialNodeState retirementCompletedNodes
  allConfigurations activeNodeUnion currentConfigurationAt configurationsInLog
  configurationsInLogFrom implicitConfiguration retiredCommittedNodesUpTo Configuration)
open Abstract.Model (NodeStore freshNodeState updateNode updateQueue enqueue)
open Abstract.Invariant (SystemInductiveInvariant JoinedCarrierFacts
  AllocatedNodesExactlyJoined)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

/-- The abstract message a concrete envelope stands for. -/
def toAbstract (envelope : Model.Envelope Node TxId) : Abstract.Model.Message Node TxId :=
  let source := envelope.source
  let destination := envelope.target
  match envelope.payload with
  | .appendEntriesRequest request =>
      .appendEntriesRequest
        { term := request.term
          prevLogIndex := request.prevLogIndex
          prevLogTerm := request.prevLogTerm
          entries := request.entries
          leaderCommit := request.leaderCommit
          source
          destination }
  | .appendEntriesResponse response =>
      .appendEntriesResponse
        { term := response.term
          success := response.success
          lastLogIndex := response.lastLogIndex
          source
          destination }
  | .requestVoteRequest request =>
      .requestVoteRequest
        { term := request.term
          lastCommittableTerm := request.lastCommittableTerm
          lastCommittableIndex := request.lastCommittableIndex
          source
          destination }
  | .requestVoteResponse response =>
      .requestVoteResponse
        { term := response.term
          voteGranted := response.voteGranted
          source
          destination }
  | .requestPreVote request =>
      .requestPreVote
        { term := request.term
          lastCommittableTerm := request.lastCommittableTerm
          lastCommittableIndex := request.lastCommittableIndex
          source
          destination }
  | .requestPreVoteResponse response =>
      .requestPreVoteResponse
        { term := response.term
          voteGranted := response.voteGranted
          source
          destination }
  | .proposeVoteRequest term =>
      .proposeVoteRequest { term, source, destination }

@[simp]
theorem toAbstract_source (envelope : Model.Envelope Node TxId) :
    (toAbstract envelope).source = envelope.source := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

@[simp]
theorem toAbstract_destination (envelope : Model.Envelope Node TxId) :
    (toAbstract envelope).destination = envelope.target := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

@[simp]
theorem toAbstract_term (envelope : Model.Envelope Node TxId) :
    (toAbstract envelope).term = envelope.payload.term := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

theorem toAbstract_injective :
    Function.Injective (toAbstract (Node := Node) (TxId := TxId)) := by
  rintro ⟨source, target, payload⟩ ⟨source', target', payload'⟩ same
  cases payload <;> cases payload' <;> simp [toAbstract] at same ⊢
  all_goals first
    | exact ⟨same.2.1, same.2.2, same.1⟩
    | (rename_i first second; cases first; cases second; simp_all)

/-- The abstract queue for `target`: its concrete envelopes, oldest first. -/
def absQueue (network : List (Model.Envelope Node TxId)) (target : Node) :
    List (Abstract.Model.Message Node TxId) :=
  (network.filter fun envelope => envelope.target = target).map toAbstract

theorem absQueue_append (first second : List (Model.Envelope Node TxId)) (target : Node) :
    absQueue (first ++ second) target = absQueue first target ++ absQueue second target := by
  simp [absQueue]

theorem absQueue_nil (target : Node) : absQueue ([] : List (Model.Envelope Node TxId)) target = [] :=
  rfl

theorem absQueue_singleton (envelope : Model.Envelope Node TxId) (target : Node) :
    absQueue [envelope] target =
      if envelope.target = target then [toAbstract envelope] else [] := by
  by_cases same : envelope.target = target <;> simp [absQueue, same]

theorem removeOne_eq_erase (value : Model.Envelope Node TxId) (values : List (Model.Envelope Node TxId)) :
    removeOne value values = values.erase value := by
  induction values with
  | nil => rfl
  | cons head tail ih =>
      simp only [removeOne, List.erase_cons]
      split <;> simp_all

theorem absQueue_erase
    (envelope : Model.Envelope Node TxId) (network : List (Model.Envelope Node TxId))
    (target : Node) :
    absQueue (network.erase envelope) target =
      if envelope.target = target then (absQueue network target).erase (toAbstract envelope)
      else absQueue network target := by
  unfold absQueue
  induction network with
  | nil => split <;> rfl
  | cons head tail ih =>
      by_cases same : head = envelope
      · subst head
        by_cases here : envelope.target = target <;> simp [here]
      · have different : (head == envelope) = false := by simpa using same
        have image : Not (toAbstract head = toAbstract envelope) :=
          fun equal => same (toAbstract_injective equal)
        rw [List.erase_cons, different]
        by_cases headHere : head.target = target <;>
          by_cases here : envelope.target = target <;>
            simp_all

/-- The node state and network relation between the models. -/
structure Corr [Bootstrap Node]
    (concrete : Model.State Node TxId) (abstract : Abstract.Model.State Node TxId) : Prop where
  keys : (concrete.nodes.map Prod.fst).Nodup
  nodes : forall node state, (node, state) ∈ concrete.nodes -> abstract.nodes node = state
  network : forall target, (abstract.network target).Perm (absQueue concrete.network target)
  preVoteStatus : abstract.preVoteStatus = INITIAL_PRE_VOTE_STATUS
  retirementCompleted :
    forall node,
      abstract.retirementCompleted node =
        retirementCompletedNodes (abstract.nodes node).log (abstract.nodes node).commitIndex
  endpoints :
    forall envelope, envelope ∈ concrete.network ->
      abstract.allocated envelope.source /\ abstract.allocated envelope.target

/-- Some abstract state satisfying the invariant corresponds to `concrete`. -/
def Refines [Bootstrap Node] (concrete : Model.State Node TxId) : Prop :=
  exists abstract, SystemInductiveInvariant abstract /\ Corr concrete abstract

variable [Bootstrap Node]

theorem joinedCarriers {abstract : Abstract.Model.State Node TxId}
    (invariant : SystemInductiveInvariant abstract) : JoinedCarrierFacts abstract := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant
  exact facts.joinedCarriers

theorem allocatedJoined {abstract : Abstract.Model.State Node TxId}
    (invariant : SystemInductiveInvariant abstract) : AllocatedNodesExactlyJoined abstract := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant
  exact facts.allocatedNodesExactlyJoined

theorem get_of_not_allocated {abstract : Abstract.Model.State Node TxId} {node : Node}
    (absent : Not (abstract.allocated node)) : abstract.nodes node = freshNodeState := by
  simp only [Abstract.Model.State.allocated, Abstract.Model.NodeStore.allocated] at absent
  simp only [Abstract.Model.NodeStore.get]
  cases found : abstract.nodes.node? node <;> simp_all

theorem allocated_of_role {abstract : Abstract.Model.State Node TxId} {node : Node}
    (role : Not ((abstract.nodes node).role = .none)) : abstract.allocated node := by
  by_contra absent
  exact role (by rw [get_of_not_allocated absent]; rfl)

theorem allocated_of_activeNodeUnion {abstract : Abstract.Model.State Node TxId}
    (invariant : SystemInductiveInvariant abstract) {node member : Node}
    (active : member ∈ activeNodeUnion (abstract.nodes node)) : abstract.allocated member :=
  (allocatedJoined invariant member).mpr ((joinedCarriers invariant).activeNodes node active)

theorem mem_foldl_union {P : Configuration Node -> Prop} [DecidablePred P]
    (configurations : List (Configuration Node)) (init : Finset Node) (member : Node)
    (found : member ∈ configurations.foldl
      (fun nodes configuration => if P configuration then nodes ∪ configuration.nodes else nodes)
      init) :
    member ∈ init \/ ∃ configuration ∈ configurations, member ∈ configuration.nodes := by
  induction configurations generalizing init with
  | nil => exact Or.inl found
  | cons head tail ih =>
      rcases ih _ found with inner | ⟨configuration, listed, inside⟩
      · by_cases chosen : P head
        · simp only [chosen, ite_true, Finset.mem_union] at inner
          rcases inner with old | here
          · exact Or.inl old
          · exact Or.inr ⟨head, by simp, here⟩
        · simp only [chosen, ite_false] at inner
          exact Or.inl inner
      · exact Or.inr ⟨configuration, by simp [listed], inside⟩

theorem retirementCompletedNodes_configured {log : List (Entry Node TxId)} {commitIndex : Nat}
    {member : Node} (found : member ∈ retirementCompletedNodes log commitIndex) :
    ∃ configuration ∈ allConfigurations log, member ∈ configuration.nodes := by
  unfold retirementCompletedNodes at found
  simp only [Finset.mem_filter, Finset.mem_sdiff] at found
  rcases mem_foldl_union _ _ _ found.1.1.1 with empty | configured
  · simp at empty
  · exact configured

theorem allocated_of_retirementCompleted {abstract : Abstract.Model.State Node TxId}
    (invariant : SystemInductiveInvariant abstract) {node member : Node}
    (found : member ∈ retirementCompletedNodes (abstract.nodes node).log
      (abstract.nodes node).commitIndex) :
    abstract.allocated member := by
  obtain ⟨configuration, listed, inside⟩ := retirementCompletedNodes_configured found
  exact (allocatedJoined invariant member).mpr
    ((joinedCarriers invariant).configurationNodes node configuration listed inside)

theorem initialNodeState_of_not_mem {node : Node} (absent : node ∉ INITIAL_CONFIGURATION) :
    (initialNodeState node : NodeState Node TxId) = freshNodeState := by
  have notLeader : Not (node = INITIAL_LEADER) := by
    rintro rfl
    exact absent (Bootstrap.leader_mem)
  simp [initialNodeState, freshNodeState, absent, notLeader]

theorem retirementCompletedNodes_nil :
    retirementCompletedNodes ([] : List (Entry Node TxId)) 0 = ∅ := by
  simp [retirementCompletedNodes, currentConfigurationAt, configurationsInLog,
    configurationsInLogFrom, allConfigurations, implicitConfiguration]

theorem corr_initial {nodes : List Node} {concrete : Model.State Node TxId}
    (initialized : (Model.transitionSystem nodes).init concrete) :
    Corr concrete Abstract.Model.initialState := by
  obtain ⟨distinct, keys, _, _, empty, initial⟩ := initialized
  refine ⟨keys ▸ distinct, ?_, ?_, rfl, ?_, ?_⟩
  · intro node state member
    have : state = initialNodeState node := initial (node, state) member
    subst this
    simp only [Abstract.Model.initialState, Abstract.Model.initialNodes,
      Abstract.ModelProofs.NodeStore.get_ofFinset]
    split
    · rfl
    · rename_i absent
      exact (initialNodeState_of_not_mem absent).symm
  · intro target
    simp [Abstract.Model.initialState, empty, absQueue]
  · intro node
    simp only [Abstract.Model.initialState, Abstract.Model.initialNodes,
      Abstract.ModelProofs.NodeStore.get_ofFinset]
    split <;> simp [initialNodeState, freshNodeState, retirementCompletedNodes_nil]
  · intro envelope member
    simp [empty] at member

theorem mem_replaceNode {nodes : List (Node × NodeState Node TxId)} {node member : Node}
    {value state : NodeState Node TxId}
    (found : (member, state) ∈ replaceNode nodes node value) :
    (member = node /\ state = value) \/ (Not (member = node) /\ (member, state) ∈ nodes) := by
  simp only [replaceNode, List.mem_map] at found
  obtain ⟨⟨key, old⟩, listed, same⟩ := found
  by_cases here : key = node
  · simp only [here, beq_self_eq_true, ite_true, Prod.mk.injEq] at same
    exact Or.inl ⟨same.1.symm, same.2.symm⟩
  · have different : (key == node) = false := by simpa using here
    simp only [different, Bool.false_eq_true, ite_false, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact Or.inr ⟨here, listed⟩

theorem replaceNode_keys (nodes : List (Node × NodeState Node TxId)) (node : Node)
    (value : NodeState Node TxId) :
    (replaceNode nodes node value).map Prod.fst = nodes.map Prod.fst := by
  simp only [replaceNode, List.map_map]
  congr 1
  funext entry
  by_cases here : entry.1 = node <;> simp [here]

theorem mem_of_nodeState {concrete : Model.State Node TxId} {node : Node}
    {state : NodeState Node TxId} (found : nodeState concrete node = some state) :
    (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

/--
Build the correspondence after one node changes. The acting node takes
`value`, every other abstract node is unchanged, and the caller supplies the
network, retirement, and endpoint facts.
-/
theorem Corr.update {concrete : Model.State Node TxId}
    {abstract after : Abstract.Model.State Node TxId} {node : Node}
    {value : NodeState Node TxId} {network : List (Model.Envelope Node TxId)}
    (corr : Corr concrete abstract)
    (nodesEq : forall member, after.nodes member = if member = node then value else abstract.nodes member)
    (networkPerm : forall target, (after.network target).Perm (absQueue network target))
    (preVote : after.preVoteStatus = abstract.preVoteStatus)
    (retirement : forall member,
      after.retirementCompleted member =
        retirementCompletedNodes (after.nodes member).log (after.nodes member).commitIndex)
    (endpoints : forall envelope, envelope ∈ network ->
      after.allocated envelope.source /\ after.allocated envelope.target) :
    Corr { concrete with nodes := replaceNode concrete.nodes node value, network } after where
  keys := by simpa [replaceNode_keys] using corr.keys
  nodes := by
    intro member state found
    rcases mem_replaceNode found with ⟨rfl, rfl⟩ | ⟨different, listed⟩
    · simp [nodesEq]
    · simp [nodesEq, different, corr.nodes member state listed]
  network := networkPerm
  preVoteStatus := preVote.trans corr.preVoteStatus
  retirementCompleted := retirement
  endpoints := endpoints

end CCFRaft.Proofs.Refinement
