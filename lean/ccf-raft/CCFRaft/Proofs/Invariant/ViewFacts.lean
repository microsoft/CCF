-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Safety
import CCFRaft.Proofs.Invariant.NodeFacts
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION
    INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role
    activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes
    becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom
    currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch
    hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration
    initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm
    latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm
    messageEntries refreshRetirementState retiredCommittedIndexFrom
    retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom
    retirementCommittableIndexInLog retirementCompletedNodes
    retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt
    updateIndex
  )
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

open Shared Shared.MultiNodeTransitionSystem Concrete

@[simp]
theorem toMessage_source (envelope : Model.Envelope Node TxId)
    : (toMessage envelope).source = envelope.source := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

@[simp]
theorem toMessage_destination (envelope : Model.Envelope Node TxId)
    : (toMessage envelope).destination = envelope.target := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

@[simp]
theorem toMessage_term (envelope : Model.Envelope Node TxId)
    : (toMessage envelope).term = envelope.payload.term := by
  rcases envelope with ⟨source, target, payload⟩
  cases payload <;> rfl

theorem toMessage_injective
    : Function.Injective (toMessage (Node := Node) (TxId := TxId)) := by
  rintro ⟨source, target, payload⟩ ⟨source', target', payload'⟩ same
  cases payload <;> cases payload' <;> simp [toMessage] at same ⊢
  all_goals first
    | exact ⟨same.2.1, same.2.2, same.1⟩
    | (rename_i first second; cases first; cases second; simp_all)

/-- The endpoint-annotated queue for `target`: its concrete envelopes, oldest first. -/
def messagesAt (network : List (Model.Envelope Node TxId)) (target : Node)
    : List (Message Node TxId) :=
  (network.filter fun envelope => envelope.target = target).map toMessage

theorem messagesAt_append (first second : List (Model.Envelope Node TxId)) (target : Node)
    : messagesAt (first ++ second) target
      = messagesAt first target ++ messagesAt second target := by
  simp [messagesAt]

theorem messagesAt_nil (target : Node)
    : messagesAt ([] : List (Model.Envelope Node TxId)) target = [] :=
  rfl

theorem messagesAt_singleton (envelope : Model.Envelope Node TxId) (target : Node)
    : messagesAt [envelope] target
      = if envelope.target = target then [toMessage envelope] else [] := by
  by_cases same : envelope.target = target <;> simp [messagesAt, same]

theorem removeOne_eq_erase (value : Model.Envelope Node TxId)
    (values : List (Model.Envelope Node TxId))
    : removeOne value values = values.erase value := by
  induction values with
  | nil => rfl
  | cons head tail ih =>
      simp only [removeOne, List.erase_cons]
      split <;> simp_all

theorem messagesAt_erase
    (envelope : Model.Envelope Node TxId) (network : List (Model.Envelope Node TxId))
    (target : Node)
    : messagesAt (network.erase envelope) target
      = if envelope.target = target then
          (messagesAt network target).erase (toMessage envelope)
        else
          messagesAt network target := by
  unfold messagesAt
  induction network with
  | nil => split <;> rfl
  | cons head tail ih =>
      by_cases same : head = envelope
      · subst head
        by_cases here : envelope.target = target <;> simp [here]
      · have different : (head == envelope) = false := by simpa using same
        have image : Not (toMessage head = toMessage envelope) :=
          fun equal => same (toMessage_injective equal)
        rw [List.erase_cons, different]
        by_cases headHere : head.target = target <;>
          by_cases here : envelope.target = target <;>
            simp_all

theorem mem_foldl_union {P : Configuration Node -> Prop} [DecidablePred P]
    (configurations : List (Configuration Node)) (init : Finset Node) (member : Node)
    (found
      : member
        ∈ configurations.foldl
            (fun nodes configuration =>
              if P configuration then nodes ∪ configuration.nodes else nodes)
            init)
    : member ∈ init
      \/ ∃ configuration ∈ configurations, member ∈ configuration.nodes := by
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

theorem retirementCompletedNodes_configured {log : List (Entry Node TxId)}
    {commitIndex : Nat} {member : Node}
    (found : member ∈ retirementCompletedNodes log commitIndex)
    : ∃ configuration ∈ allConfigurations log, member ∈ configuration.nodes := by
  unfold retirementCompletedNodes at found
  simp only [Finset.mem_filter, Finset.mem_sdiff] at found
  rcases mem_foldl_union _ _ _ found.1.1.1 with empty | configured
  · simp at empty
  · exact configured

theorem initialNodeState_of_not_mem {node : Node} (absent : node ∉ INITIAL_CONFIGURATION)
    : (initialNodeState node : NodeState Node TxId) = freshNodeState := by
  have notLeader : Not (node = INITIAL_LEADER) := by
    rintro rfl
    exact absent (Bootstrap.leader_mem)
  simp [initialNodeState, freshNodeState, absent, notLeader]

theorem retirementCompletedNodes_nil
    : retirementCompletedNodes ([] : List (Entry Node TxId)) 0 = ∅ := by
  simp [retirementCompletedNodes, currentConfigurationAt, configurationsInLog,
    configurationsInLogFrom, allConfigurations, implicitConfiguration]

theorem enqueue_apply (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) (target : Node)
    : enqueue network message target
      = network target ++ (if message.destination = target then [message] else []) := by
  by_cases same : message.destination = target
  · subst target
    simp [enqueue, updateQueue]
  · simp [enqueue, updateQueue, same, Ne.symm same]

theorem enqueue_toMessage (network : Node -> List (Message Node TxId))
    (envelope : Model.Envelope Node TxId) (target : Node)
    : enqueue network (toMessage envelope) target
      = network target ++ messagesAt [envelope] target := by
  rw [enqueue_apply, messagesAt_singleton, toMessage_destination]

theorem updateQueue_updateQueue
    (network : Node -> List (Message Node TxId)) (destination : Node)
    (first second : List (Message Node TxId))
    : updateQueue (updateQueue network destination first) destination second
      = updateQueue network destination second := by
  simp [updateQueue]

theorem updateQueue_apply (network : Node -> List (Message Node TxId))
    (destination target : Node) (queue : List (Message Node TxId))
    : updateQueue network destination queue target
      = if target = destination then queue else network target := by
  by_cases same : target = destination
  · subst target
    simp [updateQueue]
  · simp [updateQueue, same]

theorem observeTerm_eq_updateTerm (state : NodeState Node TxId)
    (message : Model.Local.Message Node TxId)
    : Model.Local.observeTerm state message = state
      \/ (Model.Local.observeTerm state message
            = Model.Local.updateTerm state message.term
          /\ state.currentTerm < message.term
          /\ (forall term, Not (message = .proposeVoteRequest term))
          /\ (forall response,
                message = .appendEntriesResponse response -> state.role = .leader)) := by
  have update : forall term, Model.Local.updateTerm state term = state \/
      (state.currentTerm < term) := by
    intro term
    unfold Model.Local.updateTerm
    split_ifs with newer
    · exact Or.inr newer
    · exact Or.inl rfl
  cases message
  case proposeVoteRequest term => exact Or.inl rfl
  case appendEntriesResponse response =>
    by_cases leader : state.role = .leader
    · rcases update response.term with same | newer
      · left
        simp [Model.Local.observeTerm, leader, same]
      · right
        refine ⟨by simp [Model.Local.observeTerm, leader, Model.Local.Message.term], newer,
          by simp, fun _ _ => leader⟩
    · left
      simp [Model.Local.observeTerm, leader]
  case appendEntriesRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteRequest payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVote payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩
  case requestPreVoteResponse payload =>
    rcases update payload.term with same | newer
    · exact Or.inl same
    · exact Or.inr ⟨rfl, newer, by simp, by simp⟩

@[ext]
theorem View.ext {left right : View Node TxId}
    (nodes : left.nodes = right.nodes) (network : left.network = right.network)
    (joined : left.hasJoined = right.hasJoined)
    : left = right := by
  cases left
  cases right
  cases nodes
  cases network
  cases joined
  rfl

theorem view_node {state : Model.State Node TxId} {joined : Finset Node}
    {node : Node} {local_ : NodeState Node TxId}
    (found : nodeState state node = some local_)
    : (view state joined).nodes node = local_ := by
  simp [view, found]

theorem nodeState_replaceNode_other (state : Model.State Node TxId)
    (node member : Node) (value : NodeState Node TxId) (different : member ≠ node)
    : nodeState { state with nodes := replaceNode state.nodes node value } member
      = nodeState state member := by
  simp only [nodeState, replaceNode]
  induction state.nodes with
  | nil => rfl
  | cons head tail ih =>
      rcases head with ⟨key, old⟩
      by_cases here : key = node
      · subst key
        simpa [different, Ne.symm different] using ih
      · by_cases queried : key = member
        · simp [here, queried, different]
        · simpa [here, queried] using ih

theorem view_replaceNode {state : Model.State Node TxId} {joined joined' : Finset Node}
    {node : Node} {old : NodeState Node TxId}
    (distinct : (state.nodes.map Prod.fst).Nodup)
    (found : nodeState state node = some old)
    (value : NodeState Node TxId) (network : List (Model.Envelope Node TxId))
    : view { state with nodes := replaceNode state.nodes node value, network } joined'
      = {
        nodes := updateNode (view state joined).nodes node value
        network := messagesAt network
        hasJoined := joined'
      } := by
  apply View.ext
  · funext member
    by_cases here : member = node
    · subst member
      have listed : (node, value) ∈ replaceNode state.nodes node value := by
        apply List.mem_map.mpr
        exact ⟨(node, old), mem_of_nodeState found, by simp⟩
      have keys : ((replaceNode state.nodes node value).map Prod.fst).Nodup := by
        simpa [replaceNode_keys] using distinct
      have updated := Direct.nodeState_of_mem (state :=
        { state with nodes := replaceNode state.nodes node value, network }) keys listed
      simp [view, updated]
    · have unchanged := nodeState_replaceNode_other state node member value here
      simpa [view, updateNode, here, nodeState]
        using congrArg (fun s => s.getD (initialNodeState member)) unchanged
  · rfl
  · rfl

theorem view_initial {nodes : List Node} {state : Model.State Node TxId}
    (initialized : (Model.transitionSystem nodes).init state)
    : view state INITIAL_CONFIGURATION
      = {
        nodes := initialNodeState,
        network := fun _ => [],
        hasJoined := INITIAL_CONFIGURATION
      } := by
  apply View.ext
  · funext node
    cases found : nodeState state node with
    | none => simp [view, found]
    | some local_ =>
        have initial : local_ = initialNodeState node :=
          initialized.2.2.2.2.2 (node, local_) (mem_of_nodeState found)
        simp [view, found, initial]
  · simp [view, initialized.2.2.2.2.1]
  · rfl

theorem mem_view_network {state : Model.State Node TxId} {joined : Finset Node}
    {envelope : Model.Envelope Node TxId} (queued : envelope ∈ state.network)
    : toMessage envelope ∈ (view state joined).network envelope.target := by
  simp only [view, List.mem_map, List.mem_filter]
  exact ⟨envelope, ⟨queued, by simp⟩, rfl⟩

theorem messagesAt_erase_eq (network : List (Model.Envelope Node TxId))
    (envelope : Model.Envelope Node TxId)
    : messagesAt (removeOne envelope network)
      = updateQueue (messagesAt network) envelope.target
          ((messagesAt network envelope.target).erase (toMessage envelope)) := by
  funext target
  rw [removeOne_eq_erase, messagesAt_erase, updateQueue_apply]
  by_cases here : envelope.target = target
  · simp [here]
  · simp [here, Ne.symm here]

theorem ViewInvariant.joinedCarriers {state : View Node TxId}
    (invariant : ViewInvariant state)
    : JoinedCarrierFacts state := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant.safety
  exact facts.joinedCarriers

theorem ViewInvariant.joined_of_role {state : View Node TxId}
    (invariant : ViewInvariant state) {node : Node}
    (active : (state.nodes node).role ≠ .none)
    : node ∈ state.hasJoined := by
  by_contra absent
  have outside : node ∉ INITIAL_CONFIGURATION := fun member => absent (invariant.initialJoined member)
  rw [invariant.unjoined node absent, initialNodeState_of_not_mem outside] at active
  exact active rfl

theorem ViewInvariant.activeJoined {state : View Node TxId}
    (invariant : ViewInvariant state) {node member : Node}
    (active : member ∈ activeNodeUnion (state.nodes node))
    : member ∈ state.hasJoined :=
  invariant.joinedCarriers.activeNodes node active

theorem ViewInvariant.retiredJoined {state : View Node TxId}
    (invariant : ViewInvariant state) {node member : Node}
    (retired : member ∈ (state.nodes node).retirementCompleted)
    : member ∈ state.hasJoined := by
  obtain ⟨configuration, listed, member⟩ := retirementCompletedNodes_configured retired
  exact invariant.joinedCarriers.configurationNodes node configuration listed member

theorem ViewInvariant.update {state : View Node TxId} (invariant : ViewInvariant state)
    {node : Node} {value : NodeState Node TxId}
    {network : Node -> List (Message Node TxId)} {joined : Finset Node}
    (nodeJoined : node ∈ state.hasJoined) (mono : state.hasJoined ⊆ joined)
    (safety
      : SystemInductiveInvariant
          { nodes := updateNode state.nodes node value, network, hasJoined := joined })
    (endpoints
      : forall destination message,
          message ∈ network destination
          -> message.source ∈ joined /\ message.destination ∈ joined)
    : ViewInvariant
        { nodes := updateNode state.nodes node value, network, hasJoined := joined } where
  safety := safety
  initialJoined := Finset.Subset.trans invariant.initialJoined mono
  unjoined := by
    intro member absent
    have different : member ≠ node := by
      rintro rfl
      exact absent (mono nodeJoined)
    simpa [updateNode, different]
      using invariant.unjoined member (fun old => absent (mono old))
  endpoints := endpoints

theorem ViewInvariant.sentEndpoints {state : View Node TxId}
    (invariant : ViewInvariant state) {joined : Finset Node}
    (mono : state.hasJoined ⊆ joined) {sends : List (Model.Envelope Node TxId)}
    (sent
      : forall envelope,
          envelope ∈ sends -> envelope.source ∈ joined /\ envelope.target ∈ joined)
    : forall destination message,
        message ∈ state.network destination ++ messagesAt sends destination
        -> message.source ∈ joined /\ message.destination ∈ joined := by
  intro destination message member
  rcases List.mem_append.mp member with old | outgoing
  · obtain ⟨source, target⟩ := invariant.endpoints destination message old
    exact ⟨mono source, mono target⟩
  · obtain ⟨envelope, listed, rfl⟩ := List.mem_map.mp outgoing
    simpa using sent envelope (List.mem_filter.mp listed).1

theorem ViewInvariant.erasedEndpoints {state : View Node TxId}
    (invariant : ViewInvariant state) (destination : Node) (message : Message Node TxId)
    : forall target queued,
        queued
          ∈ updateQueue state.network destination
              ((state.network destination).erase message) target
        -> queued.source ∈ state.hasJoined /\ queued.destination ∈ state.hasJoined := by
  intro target queued member
  by_cases here : target = destination
  · subst target
    exact invariant.endpoints destination queued
      (List.mem_of_mem_erase (by simpa using member))
  · exact invariant.endpoints target queued (by simpa [updateQueue, here] using member)

end CCFRaft.Proofs.Invariant
