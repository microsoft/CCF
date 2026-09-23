-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.Invariant
import CCFRaft.Proofs.Abstract.HandlerProofs
import CCFRaft.Proofs.Abstract.Support

open CCFRaft.Proofs.Abstract CCFRaft.Proofs.Abstract.Model CCFRaft.Proofs.Abstract.Safety
  CCFRaft.Proofs.Abstract.Support CCFRaft.Proofs.Abstract.ModelProofs
  CCFRaft.Proofs.Abstract.Invariant CCFRaft.Proofs.Abstract.HandlerProofs
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

namespace CCFRaft.Proofs.Abstract.Invariant

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

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

variable [Bootstrap Node]

omit [DecidableEq TxId] in
/--
A covered candidate node covers an equivalent frozen election ballot.
-/
lemma ConfigurationCoverageWitness.ballotConfigurationCoverage
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {term : Nat}
    {record : ElectionRecord Node TxId}
    (role : (state.nodes node).role = .candidate)
    (ballotLog : record.ballotLog = (state.nodes node).log)
    (ballotCommitIndex : record.ballotCommitIndex = (state.nodes node).commitIndex)
    (ballotTerm : term = (state.nodes node).currentTerm)
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
    {state after : State Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : ConfigurationCoverageFacts state activations)
    (currentConfigurationEq
      : forall node,
          currentConfiguration (after.nodes node)
          = currentConfiguration (state.nodes node))
    (termMonotone
      : forall node, (state.nodes node).currentTerm <= (after.nodes node).currentTerm)
    (commitEq
      : forall node, (after.nodes node).commitIndex = (state.nodes node).commitIndex)
    (logTakeEq
      : forall node frontier,
          frontier <= (state.nodes node).commitIndex
          -> (after.nodes node).log.take frontier = (state.nodes node).log.take frontier)
    (candidateTermStrictAfter
      : forall node (witness : ConfigurationCoverageWitness state activations node),
          (after.nodes node).role = .candidate
          -> witness.activation.activationTerm < (after.nodes node).currentTerm)
    : ConfigurationCoverageFacts after activations := by
  intro node positive
  have oldPositive :
      0 < (currentConfiguration (state.nodes node)).index := by
    simpa [currentConfigurationEq node] using positive
  rcases facts node oldPositive with ⟨witness⟩
  let shared :=
    min (state.nodes node).commitIndex
      witness.activation.activationFrontier
  have sharedBound :
      shared <= (state.nodes node).commitIndex :=
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
          (min (after.nodes node).commitIndex witness.activation.activationFrontier)
        = witness.activation.history.take shared := by
      simp [shared, commitEq node]
    _ = (state.nodes node).log.take shared := by
      simpa [shared] using witness.historyAgreement
    _ = (after.nodes node).log.take shared :=
      (logTakeEq node shared sharedBound).symm
    _ = (after.nodes node).log.take
          (min (after.nodes node).commitIndex witness.activation.activationFrontier) := by
      simp [shared, commitEq node]
  · intro higherIndex higher stored order
    have oldOrder :
        (currentConfiguration (state.nodes node)).index <
          higher.newConfiguration.index := by
      simpa [currentConfigurationEq node] using order
    simpa [commitEq node] using witness.higherAuthority higherIndex higher stored oldOrder
  · intro lowerIndex lower stored order
    have oldOrder :
        lower.newConfiguration.index <
          (currentConfiguration (state.nodes node)).index := by
      simpa [currentConfigurationEq node] using order
    simpa [commitEq node] using witness.lowerAuthority lowerIndex lower stored oldOrder
  · intro sameIndex same stored sameConfigurationIndex
    have oldConfigurationIndex :
        same.newConfiguration.index =
          (currentConfiguration (state.nodes node)).index := by
      simpa [currentConfigurationEq node] using sameConfigurationIndex
    exact (witness.sameAuthority sameIndex same stored oldConfigurationIndex).trans
      (currentConfigurationEq node).symm
  · exact candidateTermStrictAfter node witness

omit [DecidableEq TxId] in
/-- Coverage ignores every state field except the node records. -/
lemma configurationCoverageFrameNodesEq
    {state after : State Node TxId}
    {activations : ActivationHistory Node TxId}
    (facts : ConfigurationCoverageFacts state activations)
    (nodesEq : after.nodes = state.nodes)
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
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : Nat :=
  min (state.nodes node).commitIndex witness.activation.activationFrontier

/-- Stable signed prefix shared by the node and its covering activation event. -/
def sharedPrefix
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : List (Entry Node TxId) :=
  witness.activation.history.take witness.sharedFrontier

/-- The activation event retained by a coverage witness is valid. -/
lemma activationValid
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.activation.Valid :=
  historyFacts.valid witness.activationIndex witness.activation witness.stored

omit [DecidableEq TxId] in
/-- The shared coverage frontier is committed by the covered node. -/
lemma sharedFrontier_le_commitIndex
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedFrontier <= (state.nodes node).commitIndex :=
  Nat.min_le_left _ _

omit [DecidableEq TxId] in
/-- The shared coverage frontier lies inside the activation event. -/
lemma sharedFrontier_le_activationFrontier
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedFrontier <= witness.activation.activationFrontier :=
  Nat.min_le_right _ _

omit [DecidableEq TxId] in
/-- The shared prefix is exactly the node log at the shared frontier. -/
lemma sharedPrefix_eq_nodeLogTake
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedPrefix = (state.nodes node).log.take witness.sharedFrontier := by
  exact witness.historyAgreement

/-- The shared prefix has the full shared-frontier length. -/
lemma sharedPrefix_length
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.sharedPrefix.length = witness.sharedFrontier := by
  have valid := witness.activationValid historyFacts
  simp [
    sharedPrefix, List.length_take,
    Nat.min_eq_left
      (witness.sharedFrontier_le_activationFrontier.trans valid.2.1)
  ]

omit [DecidableEq TxId] in
/-- The shared prefix is a restriction of the full activation prefix. -/
lemma sharedPrefix_prefix_activationPrefix
    {state : State Node TxId}
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

/-- Every positive shared prefix ends at a signature. -/
lemma sharedPrefix_signature
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (committedSignature : CommittedFrontierIsSignature state)
    (witness : ConfigurationCoverageWitness state activations node)
    (positive : 0 < witness.sharedFrontier)
    : isSignatureAt witness.activation.history witness.sharedFrontier = true := by
  have valid := witness.activationValid historyFacts
  by_cases commitBefore :
      (state.nodes node).commitIndex <=
        witness.activation.activationFrontier
  · have sharedEq :
        witness.sharedFrontier = (state.nodes node).commitIndex := by
      simp [sharedFrontier, Nat.min_eq_left commitBefore]
    have nodeSignature :
        isSignatureAt
            (state.nodes node).log witness.sharedFrontier = true := by
      rw [sharedEq]
      exact committedSignature node (by simpa [sharedEq] using positive)
    have nodeTakeSignature :
        isSignatureAt
            ((state.nodes node).log.take witness.sharedFrontier)
            witness.sharedFrontier = true :=
      isSignatureAt_take_of_le le_rfl nodeSignature
    have activationTakeSignature :
        isSignatureAt witness.sharedPrefix witness.sharedFrontier = true := by
      rw [witness.sharedPrefix_eq_nodeLogTake]
      exact nodeTakeSignature
    exact
      isSignatureAt_of_prefix
        (List.take_prefix
          witness.sharedFrontier witness.activation.history)
        activationTakeSignature
  · have activationBefore :
        witness.activation.activationFrontier <=
          (state.nodes node).commitIndex := by
      omega
    have sharedEq :
        witness.sharedFrontier =
          witness.activation.activationFrontier := by
      simp [sharedFrontier, Nat.min_eq_right activationBefore]
    simpa [sharedEq] using valid.2.2.2.2.2.1

/-- The covered current configuration occurs in the event's shared prefix. -/
lemma configuration_mem_activationHistoryTake
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : currentConfiguration (state.nodes node)
      ∈ allConfigurations (witness.activation.history.take witness.sharedFrontier) := by
  let sharedFrontier := witness.sharedFrontier
  have valid := witness.activationValid historyFacts
  have known :
      currentConfiguration (state.nodes node) ∈
        allConfigurations witness.activation.history := by
    have covered := witness.configurationCovered
    rw [valid.2.2.2.2.2.2.1] at covered
    exact (List.mem_filter.mp covered).1
  exact allConfigurations_mem_take_of_index_le
    witness.activation.history sharedFrontier
    (witness.sharedFrontier_le_activationFrontier.trans valid.2.1)
    known
    (by
      change (currentConfiguration (state.nodes node)).index
      <= min (state.nodes node).commitIndex witness.activation.activationFrontier
      exact witness.configurationIndexBound)

/-- The covered current configuration occurs in the node's shared prefix. -/
lemma configuration_mem_nodeLogTake
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : currentConfiguration (state.nodes node)
      ∈ allConfigurations ((state.nodes node).log.take witness.sharedFrontier) := by
  have covered :=
    witness.configuration_mem_activationHistoryTake historyFacts
  have agreement :
      witness.activation.history.take witness.sharedFrontier =
        (state.nodes node).log.take witness.sharedFrontier := by
    simpa [sharedFrontier] using witness.historyAgreement
  rw [agreement] at covered
  exact covered

/-- A covered current configuration is no later than the event it belongs to. -/
lemma configurationIndex_le_activationConfiguration
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (historyFacts : ActivationHistoryFacts activations)
    (witness : ConfigurationCoverageWitness state activations node)
    : (currentConfiguration (state.nodes node)).index
      <= witness.activation.newConfiguration.index := by
  have valid := witness.activationValid historyFacts
  have covered := witness.configurationCovered
  rw [valid.2.2.2.2.2.2.1] at covered
  have known :
      currentConfiguration (state.nodes node) ∈
        allConfigurations witness.activation.history :=
    (List.mem_filter.mp covered).1
  have within :
      (currentConfiguration (state.nodes node)).index <=
        witness.activation.activationFrontier :=
    (of_decide_eq_true (List.mem_filter.mp covered).2).2
  let activationState : NodeState Node TxId :=
    { state.nodes node with
      log := witness.activation.history
      commitIndex := witness.activation.activationFrontier }
  have ordered :=
    configuration_index_le_currentConfiguration
      activationState
      (currentConfiguration (state.nodes node))
      (by simpa [activationState] using known)
      (by simpa [activationState] using within)
  simpa [activationState, currentConfiguration, valid.2.2.2.1] using ordered

omit [DecidableEq TxId] in
/-- The stable shared prefix precedes every strictly higher activation event. -/
lemma sharedPrefix_prefix_higherAuthority
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {higherIndex : ActivationKey Node}
    {higher : ActivationRecord Node TxId}
    (stored : activations higherIndex = some higher)
    (order
      : (currentConfiguration (state.nodes node)).index < higher.newConfiguration.index)
    : witness.sharedPrefix <+: higher.history.take higher.activationFrontier := by
  simpa [sharedPrefix, sharedFrontier]
    using witness.higherAuthority higherIndex higher stored order

omit [DecidableEq TxId] in
/-- Every strictly lower activation event precedes the stable shared prefix. -/
lemma lowerAuthority_prefix_sharedPrefix
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {lowerIndex : ActivationKey Node}
    {lower : ActivationRecord Node TxId}
    (stored : activations lowerIndex = some lower)
    (order
      : lower.newConfiguration.index < (currentConfiguration (state.nodes node)).index)
    : lower.history.take lower.activationFrontier <+: witness.sharedPrefix := by
  simpa [sharedPrefix, sharedFrontier]
    using witness.lowerAuthority lowerIndex lower stored order

omit [DecidableEq TxId] in
/-- Equal activation indices identify the covered configuration. -/
lemma sameAuthority_configurationEq
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    {sameIndex : ActivationKey Node}
    {same : ActivationRecord Node TxId}
    (stored : activations sameIndex = some same)
    (sameConfigurationIndex
      : same.newConfiguration.index = (currentConfiguration (state.nodes node)).index)
    : same.newConfiguration = currentConfiguration (state.nodes node) :=
  witness.sameAuthority sameIndex same stored sameConfigurationIndex

omit [DecidableEq TxId] in
/-- The event term retained by a coverage witness is locally observed. -/
lemma activationTerm_le_currentTerm
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    : witness.activation.activationTerm <= (state.nodes node).currentTerm :=
  witness.activationTermBound

omit [DecidableEq TxId] in
/-- The covering activation term is strictly below a covered candidate term. -/
lemma activationTerm_lt_candidateTerm
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    {node : Node}
    (witness : ConfigurationCoverageWitness state activations node)
    (role : (state.nodes node).role = .candidate)
    : witness.activation.activationTerm < (state.nodes node).currentTerm :=
  witness.candidateTermStrict role

end ConfigurationCoverageWitness

/--
Equal positive current-configuration indices identify the same configuration
across covered nodes.
-/
lemma configurationCoverageCurrentIndexUnique
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {left right : Node}
    (leftPositive : 0 < (currentConfiguration (state.nodes left)).index)
    (rightPositive : 0 < (currentConfiguration (state.nodes right)).index)
    (sameIndex
      : (currentConfiguration (state.nodes left)).index
        = (currentConfiguration (state.nodes right)).index)
    : currentConfiguration (state.nodes left)
      = currentConfiguration (state.nodes right) := by
  rcases coverage left leftPositive with ⟨leftWitness⟩
  rcases coverage right rightPositive with ⟨rightWitness⟩
  have leftKnownShared :=
    leftWitness.configuration_mem_activationHistoryTake historyFacts
  have rightKnownShared :=
    rightWitness.configuration_mem_activationHistoryTake historyFacts
  have leftKnownOwn :
      currentConfiguration (state.nodes left) ∈
        allConfigurations leftWitness.activation.history := by
    apply
      CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
        (allConfigurations_mono_prefix
          (List.take_prefix
            leftWitness.sharedFrontier
            leftWitness.activation.history))
    simpa [ConfigurationCoverageWitness.sharedFrontier] using leftKnownShared
  have rightKnownOwn :
      currentConfiguration (state.nodes right) ∈
        allConfigurations rightWitness.activation.history := by
    apply
      CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
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
        (currentConfiguration (state.nodes left)).index <
          rightWitness.activation.newConfiguration.index :=
      (leftWitness.configurationIndex_le_activationConfiguration
        historyFacts).trans_lt leftBefore
    have leftPrefixInRight :=
      leftWitness.sharedPrefix_prefix_higherAuthority
        rightWitness.stored leftCurrentBeforeRight
    have leftKnownRight :
        currentConfiguration (state.nodes left) ∈
          allConfigurations rightWitness.activation.history := by
      apply
        CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
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
          currentConfiguration (state.nodes left) ∈
            allConfigurations rightWitness.activation.history := by
        apply
          CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
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
          currentConfiguration (state.nodes right) ∈
            allConfigurations leftWitness.activation.history := by
        apply
          CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
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
        (currentConfiguration (state.nodes right)).index <
          leftWitness.activation.newConfiguration.index :=
      (rightWitness.configurationIndex_le_activationConfiguration
        historyFacts).trans_lt rightBefore
    have rightPrefixInLeft :=
      rightWitness.sharedPrefix_prefix_higherAuthority
        leftWitness.stored rightCurrentBeforeLeft
    have rightKnownLeft :
        currentConfiguration (state.nodes right) ∈
          allConfigurations leftWitness.activation.history := by
      apply
        CCFRaft.Proofs.Abstract.HandlerProofs.memOfPrefix
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

/--
Return the covering activation event for a positive current configuration,
together with the facts available at its shared frontier.
-/
lemma currentConfigurationCoverageAtSharedFrontier
    {state : State Node TxId}
    {activations : ActivationHistory Node TxId}
    (historyFacts : ActivationHistoryFacts activations)
    (coverage : ConfigurationCoverageFacts state activations)
    {node : Node}
    (positive : 0 < (currentConfiguration (state.nodes node)).index)
    : Exists
        fun witness : ConfigurationCoverageWitness state activations node =>
          witness.activation.Valid
          /\ min (state.nodes node).commitIndex witness.activation.activationFrontier
              <= (state.nodes node).commitIndex
          /\ min (state.nodes node).commitIndex witness.activation.activationFrontier
              <= witness.activation.activationFrontier
          /\ currentConfiguration (state.nodes node)
              ∈ allConfigurations
                  (witness.activation.history.take
                    (min
                      (state.nodes node).commitIndex
                      witness.activation.activationFrontier))
          /\ currentConfiguration (state.nodes node)
              ∈ allConfigurations
                  ((state.nodes node).log.take
                    (min
                      (state.nodes node).commitIndex
                      witness.activation.activationFrontier))
          /\ witness.activation.activationTerm <= (state.nodes node).currentTerm
          /\ (forall higherIndex higher,
                activations higherIndex = some higher
                -> (currentConfiguration (state.nodes node)).index
                    < higher.newConfiguration.index
                -> witness.sharedPrefix <+: higher.history.take higher.activationFrontier)
          /\ (forall lowerIndex lower,
                activations lowerIndex = some lower
                -> lower.newConfiguration.index
                    < (currentConfiguration (state.nodes node)).index
                -> lower.history.take lower.activationFrontier <+: witness.sharedPrefix)
          /\ (forall sameIndex same,
                activations sameIndex = some same
                -> same.newConfiguration.index
                    = (currentConfiguration (state.nodes node)).index
                -> same.newConfiguration = currentConfiguration (state.nodes node))
          /\ ((state.nodes node).role = .candidate
              -> witness.activation.activationTerm < (state.nodes node).currentTerm) := by
  rcases coverage node positive with ⟨witness⟩
  exact ⟨
    witness,
    witness.activationValid historyFacts,
    witness.sharedFrontier_le_commitIndex,
    witness.sharedFrontier_le_activationFrontier,
    witness.configuration_mem_activationHistoryTake historyFacts,
    witness.configuration_mem_nodeLogTake historyFacts,
    witness.activationTerm_le_currentTerm,
    fun _ _ stored order =>
      witness.sharedPrefix_prefix_higherAuthority stored order,
    fun _ _ stored order =>
      witness.lowerAuthority_prefix_sharedPrefix stored order,
    fun _ _ stored sameConfigurationIndex =>
      witness.sameAuthority_configurationEq stored sameConfigurationIndex,
    witness.activationTerm_lt_candidateTerm
  ⟩

end CCFRaft.Proofs.Abstract.Invariant
