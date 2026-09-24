-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Direct.Framework

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

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
# Safety from the invariant

The invariant's commit evidence makes committed logs comparable, and its term
ownership makes leaders unique per term. Both carry over from the view to the
node states of a network state.
-/

namespace CCFRaft.Proofs.Invariant

open Shared Shared.MultiNodeTransitionSystem

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety (state : View Node TxId) : Prop :=
  forall left right,
    (state.nodes left).role = .leader
    -> (state.nodes right).role = .leader
    -> (state.nodes left).currentTerm = (state.nodes right).currentTerm
    -> left = right

/-- Any two node-local committed logs are prefix-comparable. -/
def CommittedLogsPrefix (state : View Node TxId) : Prop :=
  forall left right,
    (state.nodes left).committedLog <+: (state.nodes right).committedLog
    \/ (state.nodes right).committedLog <+: (state.nodes left).committedLog

variable [Bootstrap Node]

lemma commitEvidenceCommittedLogsPrefix
    {state : View Node TxId}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {nodeEvidence : NodeCommitEvidence Node TxId}
    {requestEvidence : RequestCommitEvidence Node TxId}
    {elections : ElectionHistory Node TxId}
    {activations : ActivationHistory Node TxId}
    (evidenceFacts : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence)
    (activationEvidence
      : ActivationEvidenceFacts
          state appendHistory responseHistory nodeEvidence requestEvidence
          elections activations)
    : CommittedLogsPrefix state := by
  intro left right
  by_cases leftZero : (state.nodes left).commitIndex = 0
  · left
    simp [NodeState.committedLog, leftZero]
  by_cases rightZero : (state.nodes right).commitIndex = 0
  · right
    simp [NodeState.committedLog, rightZero]
  have leftPositive : 0 < (state.nodes left).commitIndex :=
    Nat.pos_of_ne_zero leftZero
  have rightPositive : 0 < (state.nodes right).commitIndex :=
    Nat.pos_of_ne_zero rightZero
  rcases evidenceFacts.nodePositive left leftPositive with
    ⟨leftEvidence, leftStored, leftValid, _, _⟩
  rcases evidenceFacts.nodePositive right rightPositive with
    ⟨rightEvidence, rightStored, rightValid, _, _⟩
  have leftKnown :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          leftEvidence (state.nodes left).committedLog :=
    Or.inl ⟨left, leftPositive, leftStored, rfl⟩
  have rightKnown :
      KnownCommitEvidence
        state appendHistory nodeEvidence requestEvidence
          rightEvidence (state.nodes right).committedLog :=
    Or.inl ⟨right, rightPositive, rightStored, rfl⟩
  rcases
      activationEvidence.supportedPrefixesComparable
        leftEvidence (state.nodes left).committedLog leftKnown
        rightEvidence (state.nodes right).committedLog rightKnown with
    leftBefore | rightBefore
  · exact Or.inl (by
      rw [← leftValid.2.2.2.1, ← rightValid.2.2.2.1]
      exact leftBefore)
  · exact Or.inr (by
      rw [← rightValid.2.2.2.1, ← leftValid.2.2.2.1]
      exact rightBefore)

lemma invariantFactsCommittedLogsPrefixFromActivation
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : CommittedLogsPrefix state := by
  rcases facts.historicalSafety with
    ⟨_owners, _canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, _ownership, _electionFacts,
      _configurationFacts, _voteCanonicalFacts, _ackerCurrentFacts,
      _ackerVoteFacts, _activationVoteFacts, _ackerElectionFacts,
      _ackerActivationFacts,
      _electionQueuedFacts,
      _activationProgress, _activationQuorums, evidenceFacts, _prospectiveFacts,
      activationEvidence, _activationCanonical, _activationElections,
      _configurationActivations⟩
  exact
    commitEvidenceCommittedLogsPrefix
      (elections := elections) (activations := activations)
      evidenceFacts activationEvidence

lemma invariantFactsElectionSafetyFromOwnership
    {state : View Node TxId}
    {votes : VoteHistory Node}
    {appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId)}
    {responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId)}
    {voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId)}
    {voteCandidateHistory voteVoterHistory
      : RequestVoteResponse Node -> List (Entry Node TxId)}
    (facts
      : InvariantFacts
          state votes appendHistory responseHistory voteRequestHistory
          voteCandidateHistory voteVoterHistory)
    : ElectionSafety state := by
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, _elections, _activations,
      _nodeEvidence, _requestEvidence, ownership, _⟩
  intro left right leftRole rightRole sameTerm
  have leftOwned := ownership.activeLeader left leftRole
  have rightOwned := ownership.activeLeader right rightRole
  rw [sameTerm] at leftOwned
  exact Option.some.inj (leftOwned.symm.trans rightOwned)

theorem systemInductiveInvariant_electionSafety {state : View Node TxId}
    (invariant : SystemInductiveInvariant state)
    : ElectionSafety state := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant
  exact invariantFactsElectionSafetyFromOwnership facts

theorem systemInductiveInvariant_committedLogsPrefix {state : View Node TxId}
    (invariant : SystemInductiveInvariant state)
    : CommittedLogsPrefix state := by
  obtain ⟨_, _, _, _, _, _, facts⟩ := invariant
  exact invariantFactsCommittedLogsPrefixFromActivation facts

theorem view_nodes_of_mem {state : Model.State Node TxId} {joined : Finset Node}
    {node : Node} {local_ : NodeState Node TxId}
    (distinct : (state.nodes.map Prod.fst).Nodup) (member : (node, local_) ∈ state.nodes)
    : (view state joined).nodes node = local_ := by
  simp [view, Direct.nodeState_of_mem distinct member]

/-- Two leaders of one term in a network state satisfying `Inv` are the same node. -/
theorem inv_electionSafety {state : Model.State Node TxId} (inv : Inv state)
    (distinct : (state.nodes.map Prod.fst).Nodup) {left right : Node}
    {leftState rightState : NodeState Node TxId}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    (leftLeader : leftState.role = .leader) (rightLeader : rightState.role = .leader)
    (sameTerm : leftState.currentTerm = rightState.currentTerm)
    : left = right := by
  obtain ⟨joined, invariant⟩ := inv
  have leftEq := view_nodes_of_mem (joined := joined) distinct leftMember
  have rightEq := view_nodes_of_mem (joined := joined) distinct rightMember
  exact systemInductiveInvariant_electionSafety invariant.safety left right
    (by rw [leftEq]; exact leftLeader)
    (by rw [rightEq]; exact rightLeader)
    (by rw [leftEq, rightEq]; exact sameTerm)

/-- Committed logs of two nodes in a network state satisfying `Inv` are comparable. -/
theorem inv_committedLogsPrefix {state : Model.State Node TxId} (inv : Inv state)
    (distinct : (state.nodes.map Prod.fst).Nodup) {left right : Node}
    {leftState rightState : NodeState Node TxId}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog := by
  obtain ⟨joined, invariant⟩ := inv
  have := systemInductiveInvariant_committedLogsPrefix invariant.safety left right
  rwa [view_nodes_of_mem distinct leftMember, view_nodes_of_mem distinct rightMember] at this

end CCFRaft.Proofs.Invariant
