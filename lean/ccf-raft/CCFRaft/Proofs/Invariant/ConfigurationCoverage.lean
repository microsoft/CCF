-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Invariant.HandlerFacts
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
variable {joined : Finset Node}

omit [DecidableEq Node] [DecidableEq TxId] in
private lemma entryAtTake_of_le
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    : entryAt? (log.take count) index = entryAt? log index := by
  by_cases zero : index = 0
  · simp [entryAt?, zero]
  · unfold entryAt?
    simp only [zero, ↓reduceIte]
    rw [List.getElem?_take]
    split
    · rfl
    · omega

omit [DecidableEq TxId] in
/--
A covered candidate node covers an equivalent frozen election ballot.
-/
lemma ConfigurationCoverageWitness.ballotConfigurationCoverage
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    (role : ((nodeOf state) node).role = .candidate)
    (ballotLog : record.ballotLog = ((nodeOf state) node).log)
    (ballotCommitIndex : record.ballotCommitIndex = ((nodeOf state) node).commitIndex)
    (ballotTerm : term = ((nodeOf state) node).currentTerm)
    : BallotConfigurationCoverage activations term record := by
  intro _positive
  refine ⟨witness.activationIndex, witness.activation, witness.stored, ?_, ?_, ?_, ?_⟩
  · simpa [
      currentConfiguration, ballotLog, ballotCommitIndex
    ] using witness.configurationCovered
  · simpa [ballotTerm] using witness.candidateTermStrict role
  · simpa [
      currentConfiguration, ballotLog, ballotCommitIndex
    ] using witness.configurationIndexBound
  · simpa [ballotLog, ballotCommitIndex] using witness.historyAgreement

omit [DecidableEq TxId] in
/-- Frame coverage through actions which preserve the covered log frontier. -/
lemma configurationCoverageFrame
    {state after : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : ConfigurationCoverageFacts state activations)
    (currentConfigurationEq
      : forall node,
          currentConfiguration ((nodeOf after) node)
          = currentConfiguration ((nodeOf state) node))
    (termMonotone
      : forall node,
          ((nodeOf state) node).currentTerm <= ((nodeOf after) node).currentTerm)
    (commitEq
      : forall node,
          ((nodeOf after) node).commitIndex = ((nodeOf state) node).commitIndex)
    (logTakeEq
      : forall node frontier,
          frontier <= ((nodeOf state) node).commitIndex
          -> ((nodeOf after) node).log.take frontier
              = ((nodeOf state) node).log.take frontier)
    (candidateTermStrictAfter
      : forall node (witness : ConfigurationCoverageWitness state activations node),
          ((nodeOf after) node).role = .candidate
          -> witness.activation.activationTerm < ((nodeOf after) node).currentTerm)
    : ConfigurationCoverageFacts after activations := by
  intro node positive
  have oldPositive :
      0 < (currentConfiguration ((nodeOf state) node)).index := by
    simpa [currentConfigurationEq node] using positive
  rcases facts node oldPositive with ⟨witness⟩
  let shared :=
    min ((nodeOf state) node).commitIndex
      witness.activation.activationFrontier
  have sharedBound :
      shared <= ((nodeOf state) node).commitIndex :=
    Nat.min_le_left _ _
  refine ⟨⟨
            witness.activationIndex,
            witness.activation,
            witness.stored,
            by simpa [currentConfigurationEq node] using witness.configurationCovered,
            witness.activationTermBound.trans (termMonotone node),
            by
              simpa [currentConfigurationEq node, commitEq node]
                using witness.configurationIndexBound,
            ?_,
            ?_,
            ?_,
            ?_,
            ?_
          ⟩⟩
  calc
    witness.activation.history.take
          (min ((nodeOf after) node).commitIndex witness.activation.activationFrontier)
        = witness.activation.history.take shared := by
      simp [shared, commitEq node]
    _ = ((nodeOf state) node).log.take shared := by
      simpa [shared] using witness.historyAgreement
    _ = ((nodeOf after) node).log.take shared :=
      (logTakeEq node shared sharedBound).symm
    _ = ((nodeOf after) node).log.take
          (min ((nodeOf after) node).commitIndex
            witness.activation.activationFrontier) := by
      simp [shared, commitEq node]
  · intro higherIndex higher stored order
    have oldOrder :
        (currentConfiguration ((nodeOf state) node)).index <
          higher.newConfiguration.index := by
      simpa [currentConfigurationEq node] using order
    simpa [commitEq node] using witness.higherAuthority higherIndex higher stored oldOrder
  · intro lowerIndex lower stored order
    have oldOrder :
        lower.newConfiguration.index <
          (currentConfiguration ((nodeOf state) node)).index := by
      simpa [currentConfigurationEq node] using order
    simpa [commitEq node] using witness.lowerAuthority lowerIndex lower stored oldOrder
  · intro sameIndex same stored sameConfigurationIndex
    have oldConfigurationIndex :
        same.newConfiguration.index =
          (currentConfiguration ((nodeOf state) node)).index := by
      simpa [currentConfigurationEq node] using sameConfigurationIndex
    exact (witness.sameAuthority sameIndex same stored oldConfigurationIndex).trans
      (currentConfigurationEq node).symm
  · exact candidateTermStrictAfter node witness

omit [DecidableEq TxId] in
/-- Coverage ignores every state field except the node records. -/
lemma configurationCoverageFrameNodesEq
    {state after : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : ConfigurationCoverageFacts state activations)
    (nodesEq : (nodeOf after) = (nodeOf state))
    : ConfigurationCoverageFacts after activations := by
  apply configurationCoverageFrame
    facts
    (fun node => by rw [nodesEq])
    (fun node => by rw [nodesEq])
    (fun node => by rw [nodesEq])
    (fun node frontier _ => by rw [nodesEq])
    (fun node witness role => by
      simpa [nodesEq] using witness.candidateTermStrict (by simpa [nodesEq] using role))

namespace ConfigurationCoverageWitness

/-- Frontier shared by the covered node and its immutable activation event. -/
def sharedFrontier
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : Nat :=
  min ((nodeOf state) node).commitIndex witness.activation.activationFrontier

/-- Stable signed prefix shared by the node and its covering activation event. -/
def sharedPrefix
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : List (Entry Node TxId) :=
  witness.activation.history.take witness.sharedFrontier

/-- The activation event retained by a coverage witness is valid. -/
lemma activationValid
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.activation.Valid :=
  historyFacts.valid witness.activationIndex witness.activation witness.stored

omit [DecidableEq TxId] in
/-- The shared coverage frontier is committed by the covered node. -/
lemma sharedFrontier_le_commitIndex
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedFrontier <= ((nodeOf state) node).commitIndex :=
  Nat.min_le_left _ _

omit [DecidableEq TxId] in
/-- The shared coverage frontier lies inside the activation event. -/
lemma sharedFrontier_le_activationFrontier
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedFrontier <= witness.activation.activationFrontier :=
  Nat.min_le_right _ _

omit [DecidableEq TxId] in
/-- The shared prefix is exactly the node log at the shared frontier. -/
lemma sharedPrefix_eq_nodeLogTake
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedPrefix = ((nodeOf state) node).log.take witness.sharedFrontier := by
  exact witness.historyAgreement

omit [DecidableEq TxId] in
/-- The shared prefix is a restriction of the full activation prefix. -/
lemma sharedPrefix_prefix_activationPrefix
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedPrefix
      <+: witness.activation.history.take witness.activation.activationFrontier := by
  rw [List.prefix_take_iff]
  exact ⟨
    List.take_prefix _ _,
    by
      simp [
        sharedPrefix, sharedFrontier,
        List.length_take
      ]
  ⟩

/-- The covered current configuration occurs in the event's shared prefix. -/
lemma configuration_mem_activationHistoryTake
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : currentConfiguration ((nodeOf state) node)
      ∈ allConfigurations (witness.activation.history.take witness.sharedFrontier) := by
  let sharedFrontier := witness.sharedFrontier
  have valid := witness.activationValid historyFacts
  have known :
      currentConfiguration ((nodeOf state) node) ∈
        allConfigurations witness.activation.history := by
    have covered := witness.configurationCovered
    rw [valid.2.2.2.2.2.2.1] at covered
    exact (List.mem_filter.mp covered).1
  exact allConfigurations_mem_take_of_index_le
    witness.activation.history sharedFrontier
    (witness.sharedFrontier_le_activationFrontier.trans valid.2.1)
    known
    (by
      change (currentConfiguration ((nodeOf state) node)).index
      <= min ((nodeOf state) node).commitIndex witness.activation.activationFrontier
      exact witness.configurationIndexBound)

/-- A covered current configuration is no later than the event it belongs to. -/
lemma configurationIndex_le_activationConfiguration
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : (currentConfiguration ((nodeOf state) node)).index
      <= witness.activation.newConfiguration.index := by
  have valid := witness.activationValid historyFacts
  have covered := witness.configurationCovered
  rw [valid.2.2.2.2.2.2.1] at covered
  have known :
      currentConfiguration ((nodeOf state) node) ∈
        allConfigurations witness.activation.history :=
    (List.mem_filter.mp covered).1
  have within :
      (currentConfiguration ((nodeOf state) node)).index <=
        witness.activation.activationFrontier :=
    (of_decide_eq_true (List.mem_filter.mp covered).2).2
  let activationState : NodeState Node TxId :=
    { (nodeOf state) node with
      log := witness.activation.history
      commitIndex := witness.activation.activationFrontier }
  have ordered :=
    configuration_index_le_currentConfiguration
      activationState
      (currentConfiguration ((nodeOf state) node))
      (by simpa [activationState] using known)
      (by simpa [activationState] using within)
  simpa [activationState, currentConfiguration, valid.2.2.2.1] using ordered

omit [DecidableEq TxId] in
/-- The stable shared prefix precedes every strictly higher activation event. -/
lemma sharedPrefix_prefix_higherAuthority
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {higherIndex : ActivationKey Node}
    {higher : ActivationRecord Node TxId}
    (stored : activations higherIndex = some higher)
    (order
      : (currentConfiguration ((nodeOf state) node)).index
        < higher.newConfiguration.index)
    : witness.sharedPrefix <+: higher.history.take higher.activationFrontier := by
  simpa [sharedPrefix, sharedFrontier]
    using witness.higherAuthority higherIndex higher stored order

omit [DecidableEq TxId] in
/-- Every strictly lower activation event precedes the stable shared prefix. -/
lemma lowerAuthority_prefix_sharedPrefix
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {lowerIndex : ActivationKey Node}
    {lower : ActivationRecord Node TxId}
    (stored : activations lowerIndex = some lower)
    (order
      : lower.newConfiguration.index < (currentConfiguration ((nodeOf state) node)).index)
    : lower.history.take lower.activationFrontier <+: witness.sharedPrefix := by
  simpa [sharedPrefix, sharedFrontier]
    using witness.lowerAuthority lowerIndex lower stored order

omit [DecidableEq TxId] in
/-- Equal activation indices identify the covered configuration. -/
lemma sameAuthority_configurationEq
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {sameIndex : ActivationKey Node}
    {same : ActivationRecord Node TxId}
    (stored : activations sameIndex = some same)
    (sameConfigurationIndex
      : same.newConfiguration.index = (currentConfiguration ((nodeOf state) node)).index)
    : same.newConfiguration = currentConfiguration ((nodeOf state) node) :=
  witness.sameAuthority sameIndex same stored sameConfigurationIndex

omit [DecidableEq TxId] in
/-- The event term retained by a coverage witness is locally observed. -/
lemma activationTerm_le_currentTerm
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.activation.activationTerm <= ((nodeOf state) node).currentTerm :=
  witness.activationTermBound

omit [DecidableEq TxId] in
/-- The covering activation term is strictly below a covered candidate term. -/
lemma activationTerm_lt_candidateTerm
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    (role : ((nodeOf state) node).role = .candidate)
    : witness.activation.activationTerm < ((nodeOf state) node).currentTerm :=
  witness.candidateTermStrict role

end ConfigurationCoverageWitness

/--
Equal positive current-configuration indices identify the same configuration
across covered nodes.
-/
lemma configurationCoverageCurrentIndexUnique
    {state : Model.State Node TxId}
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {left right : Node}
    (leftPositive : 0 < (currentConfiguration ((nodeOf state) left)).index)
    (rightPositive : 0 < (currentConfiguration ((nodeOf state) right)).index)
    (sameIndex
      : (currentConfiguration ((nodeOf state) left)).index
        = (currentConfiguration ((nodeOf state) right)).index)
    : currentConfiguration ((nodeOf state) left)
      = currentConfiguration ((nodeOf state) right) := by
  rcases coverage left leftPositive with ⟨leftWitness⟩
  rcases coverage right rightPositive with ⟨rightWitness⟩
  have leftKnownShared :=
    leftWitness.configuration_mem_activationHistoryTake historyFacts
  have rightKnownShared :=
    rightWitness.configuration_mem_activationHistoryTake historyFacts
  have leftKnownOwn :
      currentConfiguration ((nodeOf state) left) ∈
        allConfigurations leftWitness.activation.history := by
    apply
      CCFRaft.Proofs.Invariant.memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix
            leftWitness.sharedFrontier
            leftWitness.activation.history))
    simpa [ConfigurationCoverageWitness.sharedFrontier] using leftKnownShared
  have rightKnownOwn :
      currentConfiguration ((nodeOf state) right) ∈
        allConfigurations rightWitness.activation.history := by
    apply
      CCFRaft.Proofs.Invariant.memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix
            rightWitness.sharedFrontier
            rightWitness.activation.history))
    simpa [ConfigurationCoverageWitness.sharedFrontier] using rightKnownShared
  rcases Nat.lt_trichotomy
      leftWitness.activation.newConfiguration.index
      rightWitness.activation.newConfiguration.index with
    leftBefore | sameActivationIndex | rightBefore
  · have leftCurrentBeforeRight :
        (currentConfiguration ((nodeOf state) left)).index <
          rightWitness.activation.newConfiguration.index :=
      (leftWitness.configurationIndex_le_activationConfiguration
        historyFacts).trans_lt leftBefore
    have leftPrefixInRight :=
      leftWitness.sharedPrefix_prefix_higherAuthority
        rightWitness.stored leftCurrentBeforeRight
    have leftKnownRight :
        currentConfiguration ((nodeOf state) left) ∈
          allConfigurations rightWitness.activation.history := by
      apply
        CCFRaft.Proofs.Invariant.memOfPrefix
          (allConfigurations_mono_prefix
            (leftPrefixInRight.trans
              (List.take_prefix
                rightWitness.activation.activationFrontier
                rightWitness.activation.history)))
      simpa [
        ConfigurationCoverageWitness.sharedPrefix,
        ConfigurationCoverageWitness.sharedFrontier
      ] using leftKnownShared
    exact
      allConfigurations_index_unique
        (TxId := TxId) rightWitness.activation.history
        leftKnownRight rightKnownOwn sameIndex
  · rcases
        historyFacts.sameConfigurationComparable
          leftWitness.activationIndex leftWitness.activation
          rightWitness.activationIndex rightWitness.activation
          leftWitness.stored rightWitness.stored sameActivationIndex with
      leftBeforeRight | rightBeforeLeft
    · have leftKnownRight :
          currentConfiguration ((nodeOf state) left) ∈
            allConfigurations rightWitness.activation.history := by
        apply
          CCFRaft.Proofs.Invariant.memOfPrefix
            (allConfigurations_mono_prefix
              (leftWitness.sharedPrefix_prefix_activationPrefix.trans
                (leftBeforeRight.trans
                  (List.take_prefix
                    rightWitness.activation.activationFrontier
                    rightWitness.activation.history))))
        exact leftKnownShared
      exact
        allConfigurations_index_unique
          (TxId := TxId) rightWitness.activation.history
          leftKnownRight rightKnownOwn sameIndex
    · have rightKnownLeft :
          currentConfiguration ((nodeOf state) right) ∈
            allConfigurations leftWitness.activation.history := by
        apply
          CCFRaft.Proofs.Invariant.memOfPrefix
            (allConfigurations_mono_prefix
              (rightWitness.sharedPrefix_prefix_activationPrefix.trans
                (rightBeforeLeft.trans
                  (List.take_prefix
                    leftWitness.activation.activationFrontier
                    leftWitness.activation.history))))
        exact rightKnownShared
      exact
        allConfigurations_index_unique
          (TxId := TxId) leftWitness.activation.history
          leftKnownOwn rightKnownLeft sameIndex
  · have rightCurrentBeforeLeft :
        (currentConfiguration ((nodeOf state) right)).index <
          leftWitness.activation.newConfiguration.index :=
      (rightWitness.configurationIndex_le_activationConfiguration
        historyFacts).trans_lt rightBefore
    have rightPrefixInLeft :=
      rightWitness.sharedPrefix_prefix_higherAuthority
        leftWitness.stored rightCurrentBeforeLeft
    have rightKnownLeft :
        currentConfiguration ((nodeOf state) right) ∈
          allConfigurations leftWitness.activation.history := by
      apply
        CCFRaft.Proofs.Invariant.memOfPrefix
          (allConfigurations_mono_prefix
            (rightPrefixInLeft.trans
              (List.take_prefix
                leftWitness.activation.activationFrontier
                leftWitness.activation.history)))
      simpa [
        ConfigurationCoverageWitness.sharedPrefix,
        ConfigurationCoverageWitness.sharedFrontier
      ] using rightKnownShared
    exact
      allConfigurations_index_unique
        (TxId := TxId) leftWitness.activation.history
        leftKnownOwn rightKnownLeft sameIndex

end CCFRaft.Proofs.Invariant
