-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Refinement.Moves

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-!
# Simulating inputs

Each local input of `Model.Local.act` is matched by the abstract action with
the same name, taken by the same node.
-/

namespace CCFRaft.Proofs.Refinement

open Shared Shared.MultiNodeTransitionSystem
open Model.Local (NodeState Bootstrap Role Entry retirementCompletedNodes activeNodeUnion updateIndex
  refreshRetirementState INITIAL_PRE_VOTE_STATUS)
open Abstract.Model (NodeStore updateNode updateQueue enqueue)
open Abstract.Invariant (SystemInductiveInvariant)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

theorem get_updateNode (nodes : NodeStore Node TxId) (node member : Node)
    (value : NodeState Node TxId) :
    updateNode nodes node value member = if member = node then value else nodes member := by
  by_cases same : member = node
  · subst member
    simp [updateNode]
  · simp [updateNode, same, Abstract.ModelProofs.NodeStore.get_set_of_ne]

theorem allocated_updateNode {nodes : NodeStore Node TxId} {node member : Node}
    {value : NodeState Node TxId} (allocated : nodes.allocated member) :
    (updateNode nodes node value).allocated member := by
  by_cases same : member = node
  · subst member
    simp [updateNode, NodeStore.allocated, Abstract.ModelProofs.NodeStore.node?_set_same]
  · simpa [updateNode, NodeStore.allocated,
      Abstract.ModelProofs.NodeStore.node?_set_of_ne, same] using allocated

theorem enqueue_apply (network : Node -> List (Abstract.Model.Message Node TxId))
    (message : Abstract.Model.Message Node TxId) (target : Node) :
    enqueue network message target =
      network target ++ (if message.destination = target then [message] else []) := by
  by_cases same : message.destination = target
  · subst target
    simp [enqueue, Abstract.Model.updateQueue]
  · simp [enqueue, Abstract.Model.updateQueue, same, Ne.symm same]

theorem enqueue_toAbstract (network : Node -> List (Abstract.Model.Message Node TxId))
    (envelope : Model.Envelope Node TxId) (target : Node) :
    enqueue network (toAbstract envelope) target = network target ++ absQueue [envelope] target := by
  rw [enqueue_apply, absQueue_singleton, toAbstract_destination]

/--
The correspondence after node `node` takes `value` and sends `sends`, when
the abstract step changed only that node, appended the same messages, and
refreshed its retirement snapshot.
-/
theorem Corr.local {concrete : Model.State Node TxId}
    {abstract after : Abstract.Model.State Node TxId} {node : Node}
    {value : NodeState Node TxId} {sends : List (Model.Envelope Node TxId)}
    (corr : Corr concrete abstract)
    (nodesEq : forall member,
      after.nodes member = if member = node then value else abstract.nodes member)
    (networkEq : forall target, after.network target = abstract.network target ++ absQueue sends target)
    (preVote : after.preVoteStatus = abstract.preVoteStatus)
    (allocatedMono : forall member, abstract.allocated member -> after.allocated member)
    (retirementHere : after.retirementCompleted node = retirementCompletedNodes value.log value.commitIndex)
    (retirementOther : forall member, Not (member = node) ->
      after.retirementCompleted member = abstract.retirementCompleted member)
    (sendsAllocated : forall envelope, envelope ∈ sends ->
      after.allocated envelope.source /\ after.allocated envelope.target) :
    Corr { concrete with
      nodes := replaceNode concrete.nodes node value
      network := concrete.network ++ sends } after := by
  apply corr.update nodesEq _ preVote _ _
  · intro target
    rw [networkEq, absQueue_append]
    exact (corr.network target).append_right _
  · intro member
    by_cases same : member = node
    · subst member
      simp [retirementHere, nodesEq]
    · rw [retirementOther member same, corr.retirementCompleted member, nodesEq member]
      simp [same]
  · intro envelope member
    rcases List.mem_append.mp member with old | new
    · obtain ⟨source, target⟩ := corr.endpoints envelope old
      exact ⟨allocatedMono _ source, allocatedMono _ target⟩
    · exact sendsAllocated envelope new

/-- The acting node's local state is the abstract state of that node. -/
theorem Corr.state {concrete : Model.State Node TxId} {abstract : Abstract.Model.State Node TxId}
    (corr : Corr concrete abstract) {node : Node} {state : NodeState Node TxId}
    (found : nodeState concrete node = some state) : abstract.nodes node = state :=
  corr.nodes node state (mem_of_nodeState found)

theorem guard_holds {p : Prop} [Decidable p] {done : Unit}
    (holds : (if p then pure () else failure : Option Unit) = some done) : p := by
  by_contra absent
  simp [absent] at holds

set_option hygiene false in
/-- Split an enabled `act` into its guard `enabled` and its effect. -/
macro "extract_guard" : tactic => `(tactic| (
  simp only [Model.Local.act, guard, bind, Option.bind] at acted
  split at acted
  · simp at acted
  rename_i _ _ _ condition
  have enabled := guard_holds condition
  have acted := Option.some.inj acted
  subst acted))

theorem highestCommittableIndex_eq (abstract : Abstract.Model.State Node TxId) (node : Node) :
    Abstract.Model.highestCommittableIndex abstract node =
      Model.Local.highestCommittableIndex (abstract.nodes node) node :=
  rfl

theorem advanceCommit_eq (abstract : Abstract.Model.State Node TxId) (node : Node) :
    refreshRetirementState node
        { abstract.nodes node with
          commitIndex := Abstract.Model.highestCommittableIndex abstract node } =
      Model.Local.advanceCommit (abstract.nodes node) node :=
  rfl

theorem retirementCompleted_eq {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} (corr : Corr concrete abstract) (node : Node) :
    abstract.retirementCompleted node = (abstract.nodes node).retirementCompleted :=
  corr.retirementCompleted node

theorem candidateTransitionEnabled_iff {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId} (corr : Corr concrete abstract) (node : Node) :
    Abstract.Model.candidateTransitionEnabled abstract node <->
      abstract.allocated node /\
        Model.Local.candidateTransitionEnabled (abstract.nodes node) node := by
  simp only [Abstract.Model.candidateTransitionEnabled, Model.Local.candidateTransitionEnabled,
    retirementCompleted_eq corr]

theorem get_allocate (nodes : NodeStore Node TxId) (added : Finset Node) (member : Node) :
    nodes.allocate added member = nodes member := by
  by_cases allocated : nodes.allocated member
  · simp [Abstract.Model.NodeStore.get,
      Abstract.ModelProofs.NodeStore.node?_allocate_of_allocated _ _ _ allocated]
  · have missing : nodes.node? member = none := by
      simpa [NodeStore.allocated] using allocated
    by_cases fresh : member ∈ added
    · simp [Abstract.Model.NodeStore.get, missing,
        Abstract.ModelProofs.NodeStore.node?_allocate_of_not_allocated_of_mem _ _ _ allocated fresh]
    · have stillMissing : (nodes.allocate added).node? member = none := by
        simp only [NodeStore.node?, NodeStore.allocate]
        rw [Finmap.lookup_eq_none, Finmap.mem_union, not_or]
        refine ⟨by simpa [NodeStore.node?, Finmap.lookup_eq_none] using missing, ?_⟩
        rw [← Finmap.lookup_eq_none]
        exact Abstract.ModelProofs.NodeStore.node?_ofFinset_of_not_mem added _ member fresh
      simp [Abstract.Model.NodeStore.get, missing, stillMissing]

theorem allocated_allocate {nodes : NodeStore Node TxId} {added : Finset Node} {member : Node}
    (allocated : nodes.allocated member) : (nodes.allocate added).allocated member := by
  simpa [NodeStore.allocated,
    Abstract.ModelProofs.NodeStore.node?_allocate_of_allocated _ _ _ allocated] using allocated

/-- The shape of an abstract step simulating one local input. -/
def Simulates (concrete : Model.State Node TxId) (abstract : Abstract.Model.State Node TxId)
    (node : Node) (value : NodeState Node TxId) (sends : List (Model.Envelope Node TxId)) : Prop :=
  exists after, Moves abstract after /\
    Corr { concrete with
      nodes := replaceNode concrete.nodes node value
      network := concrete.network ++ sends } after

theorem simulate_appendEntries {concrete : Model.State Node TxId}
    {abstract : Abstract.Model.State Node TxId}
    (invariant : SystemInductiveInvariant abstract) (corr : Corr concrete abstract)
    {node destination : Node} {batchEnd : Nat} {state : NodeState Node TxId}
    {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state
      (.appendEntries destination batchEnd) = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, distinct, target, sentBound, batchBound, sameTerm, progress⟩ := enabled
  let request := Model.Local.makeAppendEntriesRequest state destination batchEnd
  let envelope : Model.Envelope Node TxId :=
    { source := node, target := destination, payload := .appendEntriesRequest request }
  let value := { state with sentIndex := updateIndex state.sentIndex destination batchEnd }
  show Simulates concrete abstract node value [envelope]
  have sourceAllocated : abstract.allocated node :=
    allocated_of_role (by rw [here, leader]; decide)
  have destinationAllocated : abstract.allocated destination := by
    rcases target with active | retired
    · exact allocated_of_activeNodeUnion invariant (node := node) (by rw [here]; exact active)
    · exact allocated_of_retirementCompleted invariant (node := node) (by rw [here]; exact retired)
  refine ⟨_, Moves.single (action := .appendEntries node destination batchEnd) ?_, ?_⟩
  · refine ⟨sourceAllocated, destinationAllocated, ?_⟩
    simp only [here]
    refine ⟨leader, distinct, ?_, sentBound, batchBound, sameTerm, progress⟩
    rw [corr.retirementCompleted node, here]
    exact target
  · apply corr.local
    · intro member
      simp [Abstract.Model.next, get_updateNode, here, value]
    · intro target
      have message : toAbstract envelope =
          .appendEntriesRequest
            (Abstract.Model.makeAppendEntriesRequest abstract node destination batchEnd) := by
        simp [toAbstract, envelope, request, Abstract.Model.makeAppendEntriesRequest,
          Model.Local.makeAppendEntriesRequest, here]
      simp only [Abstract.Model.next]
      rw [← message, enqueue_toAbstract]
    · rfl
    · intro member allocated
      exact allocated_updateNode allocated
    · simp [Abstract.Model.next, corr.retirementCompleted node, here, value]
    · intro member _
      rfl
    · intro sent member
      simp only [List.mem_singleton] at member
      subst member
      exact ⟨allocated_updateNode sourceAllocated, allocated_updateNode destinationAllocated⟩


variable {concrete : Model.State Node TxId} {abstract : Abstract.Model.State Node TxId}
  {node : Node} {state : NodeState Node TxId}
  {execute : Model.Local.NodeEffect Node TxId (NodeState Node TxId)}

/-- Leader appends are simulated by the abstract append with the same content. -/
theorem simulate_leaderAppend
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    (content : Model.Local.EntryContent Node TxId)
    (action : Abstract.Model.Action Node TxId)
    (enabled : Abstract.Model.Enabled abstract action)
    (nextEq : Abstract.Model.next abstract action =
      { abstract with
        nodes := updateNode abstract.nodes node (Model.Local.appendEntry state node content)
        submittedTxIds := (Abstract.Model.next abstract action).submittedTxIds
        retirementCompleted :=
          Abstract.Model.refreshRetirementCompleted abstract.retirementCompleted node
            (Model.Local.appendEntry state node content) }) :
    Simulates concrete abstract node (Model.Local.appendEntry state node content) [] := by
  have here := corr.state found
  refine ⟨_, Moves.single enabled, ?_⟩
  apply corr.local
  · intro member
    rw [nextEq, get_updateNode]
  · intro target
    rw [nextEq]
    simp [absQueue]
  · rw [nextEq]
  · intro member allocated
    rw [nextEq]
    exact allocated_updateNode allocated
  · rw [nextEq]
    simp [Abstract.Model.refreshRetirementCompleted]
  · intro member different
    rw [nextEq]
    simp [Abstract.Model.refreshRetirementCompleted, different]
  · simp

theorem simulate_clientRequest (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state) {txId : TxId}
    (acted : Model.Local.act (Capabilities.record node) node state (.clientRequest txId) =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, active, stays⟩ := enabled
  show Simulates concrete abstract node (Model.Local.appendEntry state node (.transaction txId)) []
  apply simulate_leaderAppend corr found _ (.clientRequest node txId)
  · refine ⟨allocated_of_role (by rw [here, leader]; decide), ?_⟩
    simp only [here]
    exact ⟨leader, active, stays⟩
  · simp [Abstract.Model.next, here, Model.Local.appendEntry]

theorem simulate_appendRetiredCommitted (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .appendRetiredCommitted =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, active, pending, stays⟩ := enabled
  have pendingEq : Abstract.Model.pendingRetiredCommittedNodes abstract node =
      state.retirementCompleted \ Model.Local.allRetiredCommittedNodes state.log := by
    simp [Abstract.Model.pendingRetiredCommittedNodes, retirementCompleted_eq corr, here]
  show Simulates concrete abstract node
    (Model.Local.appendEntry state node
      (.retiredCommitted
        (state.retirementCompleted \ Model.Local.allRetiredCommittedNodes state.log))) []
  apply simulate_leaderAppend corr found _ (.appendRetiredCommitted node)
  · refine ⟨allocated_of_role (by rw [here, leader]; decide), ?_⟩
    simp only [here, pendingEq]
    exact ⟨leader, active, pending, stays⟩
  · simp [Abstract.Model.next, here, pendingEq, Model.Local.appendEntry]

theorem simulate_signCommittableMessages (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .signCommittableMessages =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, active, nonempty, stays⟩ := enabled
  show Simulates concrete abstract node (Model.Local.appendEntry state node .signature) []
  apply simulate_leaderAppend corr found _ (.signCommittableMessages node)
  · refine ⟨allocated_of_role (by rw [here, leader]; decide), ?_⟩
    simp only [here]
    exact ⟨leader, active, nonempty, stays⟩
  · simp [Abstract.Model.next, here, Model.Local.appendEntry]


/-- A step that changes only the acting node, not its log or commit index. -/
theorem simulate_nodeUpdate
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    (action : Abstract.Model.Action Node TxId)
    (enabled : Abstract.Model.Enabled abstract action)
    (value : NodeState Node TxId)
    (nextEq : Abstract.Model.next abstract action =
      { abstract with nodes := updateNode abstract.nodes node value })
    (retirementEq : retirementCompletedNodes value.log value.commitIndex =
      retirementCompletedNodes state.log state.commitIndex) :
    Simulates concrete abstract node value [] := by
  have here := corr.state found
  refine ⟨_, Moves.single enabled, ?_⟩
  apply corr.local
  · intro member
    rw [nextEq, get_updateNode]
  · intro target
    rw [nextEq]
    simp [absQueue]
  · rw [nextEq]
  · intro member allocated
    rw [nextEq]
    exact allocated_updateNode allocated
  · rw [nextEq, corr.retirementCompleted node, here]
    simpa [get_updateNode] using retirementEq.symm
  · intro member different
    rw [nextEq]
  · simp

/-- A step that only sends one message from the acting node. -/
theorem simulate_send
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    (action : Abstract.Model.Action Node TxId)
    (enabled : Abstract.Model.Enabled abstract action)
    (envelope : Model.Envelope Node TxId)
    (sourceAllocated : abstract.allocated envelope.source)
    (targetAllocated : abstract.allocated envelope.target)
    (nextEq : Abstract.Model.next abstract action =
      { abstract with network := enqueue abstract.network (toAbstract envelope) }) :
    Simulates concrete abstract node state [envelope] := by
  have here := corr.state found
  refine ⟨_, Moves.single enabled, ?_⟩
  apply corr.local
  · intro member
    rw [nextEq]
    by_cases same : member = node
    · subst member
      simp [here]
    · simp [same]
  · intro target
    rw [nextEq]
    exact enqueue_toAbstract _ _ _
  · rw [nextEq]
  · intro member allocated
    rw [nextEq]
    exact allocated
  · rw [nextEq, corr.retirementCompleted node, here]
  · intro member different
    rw [nextEq]
  · intro sent member
    simp only [List.mem_singleton] at member
    subst member
    rw [nextEq]
    exact ⟨sourceAllocated, targetAllocated⟩

theorem simulate_timeout (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .timeout = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨eligible, capable⟩ := enabled
  show Simulates concrete abstract node (Model.Local.becomeCandidateNodeState state node) []
  have allocated : abstract.allocated node :=
    allocated_of_role (by rw [here]; rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
  apply simulate_nodeUpdate corr found (.timeout node)
  · refine ⟨allocated, ?_⟩
    simp only [here, retirementCompleted_eq corr, corr.preVoteStatus]
    exact ⟨eligible.1, eligible.2.1, eligible.2.2, capable⟩
  · simp [Abstract.Model.next, here]
  · rfl

theorem simulate_becomePreVoteCandidate (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .becomePreVoteCandidate =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨eligible, capable⟩ := enabled
  show Simulates concrete abstract node
    { state with role := .preVoteCandidate, preVotesGranted := {node} } []
  have allocated : abstract.allocated node :=
    allocated_of_role (by rw [here]; rcases eligible.1 with role | role | role <;> rw [role] <;> decide)
  apply simulate_nodeUpdate corr found (.becomePreVoteCandidate node)
  · refine ⟨allocated, ?_⟩
    simp only [here, retirementCompleted_eq corr, corr.preVoteStatus]
    exact ⟨eligible.1, eligible.2.1, eligible.2.2, capable⟩
  · simp [Abstract.Model.next, here]
  · rfl

theorem simulate_becomeCandidate (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .becomeCandidate =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨role, eligible, capable, majority⟩ := enabled
  show Simulates concrete abstract node (Model.Local.becomeCandidateNodeState state node) []
  have allocated : abstract.allocated node := allocated_of_role (by rw [here, role]; decide)
  apply simulate_nodeUpdate corr found (.becomeCandidate node)
  · refine ⟨allocated, ?_⟩
    simp only [here, retirementCompleted_eq corr, corr.preVoteStatus]
    refine ⟨role, eligible.2.1, eligible.2.2, capable, ?_⟩
    unfold Abstract.Model.hasPreVoteMajority
    rw [here]
    exact majority
  · simp [Abstract.Model.next, here]
  · rfl

theorem simulate_checkQuorum (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .checkQuorum = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, others⟩ := enabled
  show Simulates concrete abstract node { state with role := .follower, isNewFollower := true } []
  apply simulate_nodeUpdate corr found (.checkQuorum node)
  · refine ⟨allocated_of_role (by rw [here, leader]; decide), ?_⟩
    simp only [here]
    refine ⟨leader, ?_⟩
    unfold Abstract.Model.hasOtherActiveReplica
    rw [here]
    exact others
  · simp [Abstract.Model.next, Abstract.Model.stepDownState, here]
  · rfl

theorem simulate_requestVote (invariant : SystemInductiveInvariant abstract)
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    {destination : Node}
    (acted : Model.Local.act (Capabilities.record node) node state (.requestVote destination) =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨candidate, distinct, active⟩ := enabled
  let envelope : Model.Envelope Node TxId :=
    { source := node, target := destination
      payload := .requestVoteRequest (Model.Local.makeRequestVoteRequest state) }
  show Simulates concrete abstract node state [envelope]
  have sourceAllocated : abstract.allocated node := allocated_of_role (by rw [here, candidate]; decide)
  have targetAllocated : abstract.allocated destination :=
    allocated_of_activeNodeUnion invariant (node := node) (by rw [here]; exact active)
  refine simulate_send corr found (.requestVote node destination) ?enabled envelope sourceAllocated
    targetAllocated ?next
  case enabled =>
    refine ⟨sourceAllocated, targetAllocated, ?_⟩
    simp only [here]
    exact ⟨candidate, distinct, active⟩
  case next =>
    simp [Abstract.Model.next, envelope, toAbstract, Abstract.Model.makeRequestVoteRequest,
      Model.Local.makeRequestVoteRequest, here]

theorem simulate_requestPreVote (invariant : SystemInductiveInvariant abstract)
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    {destination : Node}
    (acted : Model.Local.act (Capabilities.record node) node state (.requestPreVote destination) =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨candidate, distinct, active⟩ := enabled
  let envelope : Model.Envelope Node TxId :=
    { source := node, target := destination
      payload := .requestPreVote (Model.Local.makeRequestVoteRequest state) }
  show Simulates concrete abstract node state [envelope]
  have sourceAllocated : abstract.allocated node := allocated_of_role (by rw [here, candidate]; decide)
  have targetAllocated : abstract.allocated destination :=
    allocated_of_activeNodeUnion invariant (node := node) (by rw [here]; exact active)
  refine simulate_send corr found (.requestPreVote node destination) ?enabled envelope sourceAllocated
    targetAllocated ?next
  case enabled =>
    refine ⟨sourceAllocated, targetAllocated, ?_⟩
    simp only [here]
    exact ⟨candidate, distinct, active⟩
  case next =>
    simp [Abstract.Model.next, envelope, toAbstract, Abstract.Model.makeRequestPreVote,
      Model.Local.makeRequestVoteRequest, here]

theorem simulate_proposeVote (invariant : SystemInductiveInvariant abstract)
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    {destination : Node}
    (acted : Model.Local.act (Capabilities.record node) node state (.proposeVote destination) =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, successor⟩ := enabled
  let envelope : Model.Envelope Node TxId :=
    { source := node, target := destination, payload := .proposeVoteRequest state.currentTerm }
  show Simulates concrete abstract node state [envelope]
  have sourceAllocated : abstract.allocated node := allocated_of_role (by rw [here, leader]; decide)
  have targetAllocated : abstract.allocated destination :=
    allocated_of_activeNodeUnion invariant (node := node)
      (by rw [here]; exact Finset.mem_of_mem_erase successor.1)
  refine simulate_send corr found (.proposeVote node destination) ?enabled envelope sourceAllocated
    targetAllocated ?next
  case enabled =>
    refine ⟨sourceAllocated, targetAllocated, ?_⟩
    simp only [here]
    refine ⟨leader, ?_⟩
    unfold Abstract.Model.plausibleSuccessor
    rw [here]
    exact successor
  case next =>
    simp [Abstract.Model.next, envelope, toAbstract, Abstract.Model.makeProposeVoteRequest, here]


theorem retirementCompletedNodes_zero_singleton (entry : Entry Node TxId) :
    retirementCompletedNodes [entry] 0 = ∅ := by
  rcases entry with ⟨term, content⟩
  cases content <;>
    simp [retirementCompletedNodes, Model.Local.currentConfigurationAt,
      Model.Local.configurationsInLog, Model.Local.configurationsInLogFrom,
      Model.Local.allConfigurations, Model.Local.implicitConfiguration]

theorem simulate_initializeConfiguration (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .initializeConfiguration =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨initial, leader, term, empty, zero, active⟩ := enabled
  let entry : Entry Node TxId :=
    { term := state.currentTerm, content := .reconfiguration Model.Local.INITIAL_CONFIGURATION }
  show Simulates concrete abstract node { state with log := [entry] } []
  apply simulate_nodeUpdate corr found (.initializeConfiguration node)
  · refine ⟨initial, allocated_of_role (by rw [here, leader]; decide), ?_⟩
    simp only [here]
    exact ⟨leader, term, empty, zero, active⟩
  · simp [Abstract.Model.next, here, entry]
  · simp [empty, zero, retirementCompletedNodes_zero_singleton, retirementCompletedNodes_nil]

theorem refresh_sentIndex (self : Node) (value : NodeState Node TxId) (sentIndex : Node -> Nat) :
    { refreshRetirementState self value with sentIndex } =
      refreshRetirementState self { value with sentIndex } :=
  rfl

theorem simulate_changeConfiguration (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state) {newConfiguration : Finset Node}
    (acted : Model.Local.act (Capabilities.record node) node state
      (.changeConfiguration newConfiguration) = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, active, nonempty, changed, stays⟩ := enabled
  let added := newConfiguration \ (Model.Local.latestConfiguration state).nodes
  let value :=
    { Model.Local.appendEntry state node (.reconfiguration newConfiguration) with
      sentIndex := fun peer => if peer ∈ added then state.log.length else state.sentIndex peer }
  show Simulates concrete abstract node value []
  have allocated : abstract.allocated node := allocated_of_role (by rw [here, leader]; decide)
  have nextEq : Abstract.Model.next abstract (.changeConfiguration node newConfiguration) =
      { abstract with
        nodes := updateNode (abstract.nodes.allocate added) node value
        hasJoined := abstract.hasJoined ∪ added
        retirementCompleted :=
          Abstract.Model.refreshRetirementCompleted abstract.retirementCompleted node value } := by
    simp only [Abstract.Model.next, here, value, added, Model.Local.appendEntry, refresh_sentIndex]
  refine ⟨_, Moves.single (action := .changeConfiguration node newConfiguration) ?_, ?_⟩
  · refine ⟨allocated, ?_⟩
    simp only [here]
    exact ⟨leader, active, nonempty, changed, stays⟩
  · apply corr.local
    · intro member
      rw [nextEq]
      simp only [get_updateNode, get_allocate]
    · intro target
      rw [nextEq]
      simp [absQueue]
    · rw [nextEq]
    · intro member old
      rw [nextEq]
      exact allocated_updateNode (allocated_allocate old)
    · rw [nextEq]
      simp [Abstract.Model.refreshRetirementCompleted]
    · intro member different
      rw [nextEq]
      simp [Abstract.Model.refreshRetirementCompleted, different]
    · simp

theorem updateNode_updateNode (nodes : NodeStore Node TxId) (node : Node)
    (first second : NodeState Node TxId) :
    updateNode (updateNode nodes node first) node second = updateNode nodes node second := by
  simp [updateNode, NodeStore.set, Finmap.insert_insert]

theorem advanced_eq (abstract : Abstract.Model.State Node TxId) (node : Node) :
    Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node) node =
      { abstract with
        nodes := updateNode abstract.nodes node
          (Model.Local.demoteRetiredCommitted (Model.Local.advanceCommit (abstract.nodes node) node))
        retirementCompleted :=
          Abstract.Model.refreshRetirementCompleted abstract.retirementCompleted node
            (Model.Local.advanceCommit (abstract.nodes node) node) } := by
  simp only [Abstract.Model.demoteRetiredCommitted, Abstract.Model.advanceCommitState,
    advanceCommit_eq, Abstract.ModelProofs.updateNode_same, Model.Local.demoteRetiredCommitted]
  split_ifs <;> simp [updateNode_updateNode]

theorem advanced_nodes (abstract : Abstract.Model.State Node TxId) (node member : Node) :
    (Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node)
        node).nodes member =
      if member = node then
        Model.Local.demoteRetiredCommitted (Model.Local.advanceCommit (abstract.nodes node) node)
      else abstract.nodes member := by
  rw [advanced_eq, get_updateNode]

theorem advanced_retirementCompleted (abstract : Abstract.Model.State Node TxId) (node : Node) :
    (Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node)
        node).retirementCompleted =
      Abstract.Model.refreshRetirementCompleted abstract.retirementCompleted node
        (Model.Local.advanceCommit (abstract.nodes node) node) := by
  rw [advanced_eq]

theorem advanced_network (abstract : Abstract.Model.State Node TxId) (node : Node) :
    (Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node)
        node).network = abstract.network := by
  rw [advanced_eq]

theorem advanced_preVoteStatus (abstract : Abstract.Model.State Node TxId) (node : Node) :
    (Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node)
        node).preVoteStatus = abstract.preVoteStatus := by
  rw [advanced_eq]

theorem advanced_allocated (abstract : Abstract.Model.State Node TxId) (node member : Node)
    (allocated : abstract.allocated member) :
    (Abstract.Model.demoteRetiredCommitted (Abstract.Model.advanceCommitState abstract node)
        node).allocated member := by
  rw [advanced_eq]
  exact allocated_updateNode allocated

theorem demote_retirementCompleted (value : NodeState Node TxId) :
    retirementCompletedNodes (Model.Local.demoteRetiredCommitted value).log
        (Model.Local.demoteRetiredCommitted value).commitIndex =
      retirementCompletedNodes value.log value.commitIndex := by
  unfold Model.Local.demoteRetiredCommitted
  split <;> rfl

theorem advanceCommit_enabled (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (progress : state.commitIndex < Model.Local.highestCommittableIndex state node) :
    (abstract.nodes node).commitIndex < Abstract.Model.highestCommittableIndex abstract node := by
  rw [highestCommittableIndex_eq, corr.state found]
  exact progress

theorem terminal_iff (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state) :
    Abstract.Model.terminalRetirementCommit abstract node <->
      Model.Local.terminalRetirementCommit state node := by
  show (refreshRetirementState node
      { abstract.nodes node with
        commitIndex := Abstract.Model.highestCommittableIndex abstract node }).membershipState = _ <-> _
  rw [advanceCommit_eq, corr.state found]
  rfl

theorem simulate_advanceCommitIndex (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .advanceCommitIndex =
      some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, progress, notTerminal⟩ := enabled
  show Simulates concrete abstract node
    (Model.Local.demoteRetiredCommitted (Model.Local.advanceCommit state node)) []
  refine ⟨_, Moves.single (action := .advanceCommitIndex node) ?_, ?_⟩
  · refine ⟨allocated_of_role (by rw [here, leader]; decide), by rw [here]; exact leader,
      advanceCommit_enabled corr found progress, fun terminal => notTerminal ?_⟩
    exact (terminal_iff corr found).mp terminal
  · apply corr.local
    · intro member
      simp only [Abstract.Model.next]
      rw [advanced_nodes, here]
    · intro target
      simp only [Abstract.Model.next]
      rw [advanced_network]
      simp [absQueue]
    · simp only [Abstract.Model.next]
      exact advanced_preVoteStatus _ _
    · intro member allocated
      exact advanced_allocated _ _ _ allocated
    · simp only [Abstract.Model.next]
      rw [advanced_retirementCompleted, here, demote_retirementCompleted]
      simp [Abstract.Model.refreshRetirementCompleted]
    · intro member different
      simp only [Abstract.Model.next]
      rw [advanced_retirementCompleted]
      simp [Abstract.Model.refreshRetirementCompleted, different]
    · simp

theorem simulate_advanceCommitIndexAndProposeVote (invariant : SystemInductiveInvariant abstract)
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    {destination : Node}
    (acted : Model.Local.act (Capabilities.record node) node state
      (.advanceCommitIndexAndProposeVote destination) = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨leader, progress, terminal, successor⟩ := enabled
  let envelope : Model.Envelope Node TxId :=
    { source := node, target := destination, payload := .proposeVoteRequest state.currentTerm }
  show Simulates concrete abstract node
    (Model.Local.demoteRetiredCommitted (Model.Local.advanceCommit state node)) [envelope]
  have sourceAllocated : abstract.allocated node := allocated_of_role (by rw [here, leader]; decide)
  have targetAllocated : abstract.allocated destination :=
    allocated_of_activeNodeUnion invariant (node := node)
      (by rw [here]; exact Finset.mem_of_mem_erase successor.1)
  refine ⟨_, Moves.single (action := .advanceCommitIndexAndProposeVote node destination) ?_, ?_⟩
  · refine ⟨sourceAllocated, targetAllocated, by rw [here]; exact leader,
      advanceCommit_enabled corr found progress, (terminal_iff corr found).mpr terminal, ?_⟩
    unfold Abstract.Model.plausibleSuccessor
    rw [here]
    exact successor
  · have message : toAbstract envelope =
        .proposeVoteRequest (Abstract.Model.makeProposeVoteRequest abstract node destination) := by
      simp [envelope, toAbstract, Abstract.Model.makeProposeVoteRequest, here]
    apply corr.local
    · intro member
      simp only [Abstract.Model.next]
      rw [advanced_nodes, here]
    · intro target
      simp only [Abstract.Model.next]
      rw [← message, enqueue_toAbstract, advanced_network]
    · simp only [Abstract.Model.next]
      exact advanced_preVoteStatus _ _
    · intro member allocated
      exact advanced_allocated _ _ _ allocated
    · simp only [Abstract.Model.next]
      rw [advanced_retirementCompleted, here, demote_retirementCompleted]
      simp [Abstract.Model.refreshRetirementCompleted]
    · intro member different
      simp only [Abstract.Model.next]
      rw [advanced_retirementCompleted]
      simp [Abstract.Model.refreshRetirementCompleted, different]
    · intro sent member
      simp only [List.mem_singleton] at member
      subst member
      exact ⟨advanced_allocated _ _ _ sourceAllocated, advanced_allocated _ _ _ targetAllocated⟩

theorem simulate_becomeLeader (corr : Corr concrete abstract)
    (found : nodeState concrete node = some state)
    (acted : Model.Local.act (Capabilities.record node) node state .becomeLeader = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  have here := corr.state found
  extract_guard
  obtain ⟨candidate, active, majority, stays⟩ := enabled
  let log := state.log.take (Model.Local.maxCommittableIndex state.log)
  let value := refreshRetirementState node
    { state with
      log
      role := .leader
      sentIndex := fun _ => log.length
      matchIndex := fun _ => 0 }
  show Simulates concrete abstract node value []
  have nextEq : Abstract.Model.next abstract (.becomeLeader node) =
      { abstract with
        nodes := updateNode abstract.nodes node value
        retirementCompleted :=
          Abstract.Model.refreshRetirementCompleted abstract.retirementCompleted node value } := by
    simp only [Abstract.Model.next, here, value, log]
  refine ⟨_, Moves.single (action := .becomeLeader node) ?_, ?_⟩
  · refine ⟨allocated_of_role (by rw [here, candidate]; decide), ?_⟩
    simp only [here]
    refine ⟨candidate, active, ?_, stays⟩
    unfold Abstract.Model.hasElectionMajority
    rw [here]
    exact majority
  · apply corr.local
    · intro member
      rw [nextEq, get_updateNode]
    · intro target
      rw [nextEq]
      simp [absQueue]
    · rw [nextEq]
    · intro member allocated
      rw [nextEq]
      exact allocated_updateNode allocated
    · rw [nextEq]
      simp [Abstract.Model.refreshRetirementCompleted]
    · intro member different
      rw [nextEq]
      simp [Abstract.Model.refreshRetirementCompleted, different]
    · simp

/-- Every enabled local input is simulated by abstract moves. -/
theorem simulate_act (invariant : SystemInductiveInvariant abstract)
    (corr : Corr concrete abstract) (found : nodeState concrete node = some state)
    {input : Model.Local.Input Node TxId}
    (acted : Model.Local.act (Capabilities.record node) node state input = some execute) :
    Simulates concrete abstract node (execute.run {}).1 (execute.run {}).2.outgoing := by
  cases input with
  | initializeConfiguration => exact simulate_initializeConfiguration corr found acted
  | clientRequest => exact simulate_clientRequest corr found acted
  | changeConfiguration => exact simulate_changeConfiguration corr found acted
  | appendRetiredCommitted => exact simulate_appendRetiredCommitted corr found acted
  | signCommittableMessages => exact simulate_signCommittableMessages corr found acted
  | appendEntries => exact simulate_appendEntries invariant corr found acted
  | advanceCommitIndex => exact simulate_advanceCommitIndex corr found acted
  | timeout => exact simulate_timeout corr found acted
  | becomePreVoteCandidate => exact simulate_becomePreVoteCandidate corr found acted
  | becomeCandidate => exact simulate_becomeCandidate corr found acted
  | requestVote => exact simulate_requestVote invariant corr found acted
  | requestPreVote => exact simulate_requestPreVote invariant corr found acted
  | checkQuorum => exact simulate_checkQuorum corr found acted
  | becomeLeader => exact simulate_becomeLeader corr found acted
  | proposeVote => exact simulate_proposeVote invariant corr found acted
  | advanceCommitIndexAndProposeVote =>
      exact simulate_advanceCommitIndexAndProposeVote invariant corr found acted

end CCFRaft.Proofs.Refinement
