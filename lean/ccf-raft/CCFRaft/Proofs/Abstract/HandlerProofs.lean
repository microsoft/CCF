-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.ModelProofs

import CCFRaft.Proofs.Abstract.Support

open CCFRaft.Proofs.Abstract CCFRaft.Proofs.Abstract.Model CCFRaft.Proofs.Abstract.Safety CCFRaft.Proofs.Abstract.Support CCFRaft.Proofs.Abstract.ModelProofs
open CCFRaft.Model.Local (BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm messageEntries refreshRetirementState retiredCommittedIndexFrom retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom retirementCommittableIndexInLog retirementCompletedNodes retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt updateIndex)

set_option autoImplicit false

/-!
# Reusable handler proofs

Common log lookup and AppendEntries handler facts.
-/

namespace CCFRaft.Proofs.Abstract.HandlerProofs

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

/-! ## Generic list, quorum, and message facts -/

/-- Every list is a prefix of itself. -/
lemma prefixRefl {Alpha : Type} (values : List Alpha) :
    values <+: values :=
  ⟨[], by simp⟩

/-- Taking the length of a known prefix recovers that prefix. -/
lemma prefixEqTake
    {Alpha : Type}
    {head values : List Alpha}
    (isPrefix : head <+: values) :
    values.take head.length = head := by
  rw [List.prefix_iff_eq_take] at isPrefix
  exact isPrefix.symm

/-- Two lists agree through any index lying inside their shared prefix. -/
lemma takeEqOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {count : Nat}
    (within : count <= left.length) :
    left.take count = right.take count := by
  rw [List.prefix_iff_eq_take] at isPrefix
  rw [isPrefix, List.take_take, Nat.min_eq_left within]

/-- Two prefixes of the same list are prefixes of each other. -/
lemma prefixesComparable
    {Alpha : Type}
    {left right common : List Alpha}
    (leftPrefix : left <+: common)
    (rightPrefix : right <+: common) :
    left <+: right \/ right <+: left := by
  by_cases leftShorter : left.length <= right.length
  · left
    have leftEq : right.take left.length = left := by
      calc
        right.take left.length =
            common.take left.length :=
          takeEqOfPrefix rightPrefix leftShorter
        _ = left := prefixEqTake leftPrefix
    have takenPrefix := List.take_prefix left.length right
    rwa [leftEq] at takenPrefix
  · right
    have rightShorter : right.length <= left.length := by omega
    have rightEq : left.take right.length = right := by
      calc
        left.take right.length =
            common.take right.length :=
          takeEqOfPrefix leftPrefix rightShorter
        _ = right := prefixEqTake rightPrefix
    have takenPrefix := List.take_prefix right.length left
    rwa [rightEq] at takenPrefix

/--
Two strict majorities of the same configuration share a configuration member.
-/
lemma configurationMajoritiesIntersect
    {configuration : Configuration Node}
    {left right : Finset Node}
    (leftMajority : hasConfigurationMajority left configuration)
    (rightMajority : hasConfigurationMajority right configuration) :
    Exists fun node =>
      node ∈ configuration.nodes /\
        node ∈ left /\
        node ∈ right := by
  let leftMembers := left ∩ configuration.nodes
  let rightMembers := right ∩ configuration.nodes
  have leftStrict :
      leftMembers.card * 2 > configuration.nodes.card :=
    leftMajority
  have rightStrict :
      rightMembers.card * 2 > configuration.nodes.card :=
    rightMajority
  have common : (leftMembers ∩ rightMembers).Nonempty := by
    by_contra noCommon
    have intersectionEmpty :
        leftMembers ∩ rightMembers = ∅ :=
      Finset.not_nonempty_iff_eq_empty.mp noCommon
    have disjoint : Disjoint leftMembers rightMembers :=
      Finset.disjoint_iff_inter_eq_empty.mpr intersectionEmpty
    have unionCard :
        (leftMembers ∪ rightMembers).card =
          leftMembers.card + rightMembers.card :=
      Finset.card_union_of_disjoint disjoint
    have unionSubset :
        leftMembers ∪ rightMembers ⊆ configuration.nodes := by
      intro node member
      rcases Finset.mem_union.mp member with leftMember | rightMember
      · exact (Finset.mem_inter.mp leftMember).2
      · exact (Finset.mem_inter.mp rightMember).2
    have unionBound :
        (leftMembers ∪ rightMembers).card <= configuration.nodes.card :=
      Finset.card_le_card unionSubset
    omega
  rcases common with ⟨node, member⟩
  have leftMember := (Finset.mem_inter.mp member).1
  have rightMember := (Finset.mem_inter.mp member).2
  exact
    ⟨node,
      (Finset.mem_inter.mp leftMember).2,
      (Finset.mem_inter.mp leftMember).1,
      (Finset.mem_inter.mp rightMember).1⟩

/-- Enlarging a support set preserves a strict majority in one configuration. -/
lemma hasConfigurationMajority_mono
    {configuration : Configuration Node}
    {smaller larger : Finset Node}
    (subset : smaller ⊆ larger)
    (majority : hasConfigurationMajority smaller configuration) :
    hasConfigurationMajority larger configuration := by
  unfold hasConfigurationMajority at majority ⊢
  have intersectionSubset :
      smaller ∩ configuration.nodes ⊆
        larger ∩ configuration.nodes := by
    intro node member
    exact
      Finset.mem_inter.mpr
        ⟨subset (Finset.mem_inter.mp member).1,
          (Finset.mem_inter.mp member).2⟩
  have cardBound := Finset.card_le_card intersectionSubset
  omega

/-- A strict configuration majority contains a member of that configuration. -/
lemma configurationMajorityNonempty
    {configuration : Configuration Node}
    {support : Finset Node}
    (majority : hasConfigurationMajority support configuration) :
    Exists fun node =>
      node ∈ configuration.nodes /\ node ∈ support := by
  have common :=
    configurationMajoritiesIntersect majority majority
  rcases common with ⟨node, configurationMember, supportMember, _⟩
  exact ⟨node, configurationMember, supportMember⟩

/-! ## Log-derived configuration facts -/

omit [DecidableEq Node] [DecidableEq TxId] in
/-- Projecting configurations distributes over log concatenation. -/
lemma configurationsInLogFrom_append
    (start : Nat)
    (left right : List (Entry Node TxId)) :
    configurationsInLogFrom start (left ++ right) =
      configurationsInLogFrom start left ++
        configurationsInLogFrom (start + left.length) right := by
  induction left generalizing start with
  | nil =>
      simp [configurationsInLogFrom]
  | cons entry entries inductionHypothesis =>
      cases content : entry.content with
      | transaction txId =>
          simp [
            configurationsInLogFrom, content,
            inductionHypothesis, Nat.add_assoc, Nat.add_comm
          ]
      | signature =>
          simp [
            configurationsInLogFrom, content,
            inductionHypothesis, Nat.add_assoc, Nat.add_comm
          ]
      | retiredCommitted nodes =>
          simp [
            configurationsInLogFrom, content,
            inductionHypothesis, Nat.add_assoc, Nat.add_comm
          ]
      | reconfiguration nodes =>
          simp [
            configurationsInLogFrom, content,
            inductionHypothesis, Nat.add_assoc, Nat.add_comm
          ]

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A log prefix retains every projected physical configuration. -/
lemma configurationsInLogFrom_mono_prefix
    (start : Nat)
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right) :
    configurationsInLogFrom start left <+:
      configurationsInLogFrom start right := by
  rcases isPrefix with ⟨suffix, rfl⟩
  rw [configurationsInLogFrom_append]
  exact List.prefix_append _ _

section Bootstrap

variable [Bootstrap Node]
omit [DecidableEq TxId]

/-- A log prefix retains every known implicit or physical configuration. -/
lemma allConfigurations_mono_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right) :
    allConfigurations left <+: allConfigurations right := by
  unfold allConfigurations configurationsInLog
  rcases configurationsInLogFrom_mono_prefix 1 isPrefix with
    ⟨suffix, agreed⟩
  exact ⟨suffix, by simp [agreed]⟩

omit [Bootstrap Node] in
/-- Once a removal index is found, extending the configuration history keeps it. -/
lemma retirementIndexFromConfigurations_some_append
    (node : Node)
    (previouslyIncluded : Bool)
    (configurations suffix : List (Configuration Node))
    (index : Nat)
    (found :
      retirementIndexFromConfigurations
        node previouslyIncluded configurations = some index) :
    retirementIndexFromConfigurations
      node previouslyIncluded (configurations ++ suffix) = some index := by
  induction configurations generalizing previouslyIncluded with
  | nil =>
      simp [retirementIndexFromConfigurations] at found
  | cons configuration remaining inductionHypothesis =>
      by_cases member : node ∈ configuration.nodes
      · simp [retirementIndexFromConfigurations, member] at found ⊢
        exact inductionHypothesis true found
      · by_cases included : previouslyIncluded
        · simp [retirementIndexFromConfigurations, member, included] at found ⊢
          exact found
        · simp [retirementIndexFromConfigurations, member, included] at found ⊢
          exact inductionHypothesis false found

/-- A log extension preserves an already discovered retirement index. -/
lemma retirementIndexInLog_some_of_prefix
    (node : Node)
    {left right : List (Entry Node TxId)}
    {index : Nat}
    (isPrefix : left <+: right)
    (found : retirementIndexInLog node left = some index) :
    retirementIndexInLog node right = some index := by
  unfold retirementIndexInLog at found ⊢
  rcases allConfigurations_mono_prefix (TxId := TxId) isPrefix with
    ⟨suffix, configurationsEq⟩
  rw [← configurationsEq]
  exact
    retirementIndexFromConfigurations_some_append
      node false (allConfigurations left) suffix index found

/-- A log extension preserves existence of committed removal evidence. -/
lemma retirementIndexInLog_isSome_of_prefix
    (node : Node)
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    (found : (retirementIndexInLog node left).isSome) :
    (retirementIndexInLog node right).isSome := by
  rw [Option.isSome_iff_exists] at found ⊢
  rcases found with ⟨index, indexFound⟩
  exact
    ⟨index,
      retirementIndexInLog_some_of_prefix
        (TxId := TxId) node isPrefix indexFound⟩

/-- Every completed-retirement set member has a committed removal prefix. -/
lemma retirementCompletedNodes_hasRemoval
    (log : List (Entry Node TxId))
    (commitIndex : Nat)
    {node : Node}
    (member : node ∈ retirementCompletedNodes log commitIndex) :
    (retirementIndexInLog node (log.take commitIndex)).isSome := by
  simpa [retirementCompletedNodes] using (Finset.mem_filter.mp member).2

omit [DecidableEq Node] [Bootstrap Node] in
/-- Every projected physical configuration index lies in its source interval. -/
lemma configurationsInLogFrom_index_bounds
    (start : Nat)
    (log : List (Entry Node TxId))
    {configuration : Configuration Node}
    (member : configuration ∈ configurationsInLogFrom start log) :
    start <= configuration.index /\
      configuration.index < start + log.length := by
  induction log generalizing start with
  | nil =>
      simp [configurationsInLogFrom] at member
  | cons entry entries inductionHypothesis =>
      cases content : entry.content with
      | transaction txId =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by
                simpa [configurationsInLogFrom, content] using member)
          simp only [List.length_cons]
          omega
      | signature =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by
                simpa [configurationsInLogFrom, content] using member)
          simp only [List.length_cons]
          omega
      | retiredCommitted nodes =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by
                simpa [configurationsInLogFrom, content] using member)
          simp only [List.length_cons]
          omega
      | reconfiguration nodes =>
          have alternatives :
              configuration = { index := start, nodes := nodes } \/
                configuration ∈
                  configurationsInLogFrom (start + 1) entries := by
            simpa [configurationsInLogFrom, content] using member
          rcases alternatives with head | tail
          · subst configuration
            simp
          · have bounds :=
              inductionHypothesis (start := start + 1) tail
            simp only [List.length_cons]
            omega

omit [DecidableEq Node] [Bootstrap Node] in
/-- Physical configuration indices are strictly increasing in log order. -/
lemma configurationsInLogFrom_pairwise_index_lt
    (start : Nat)
    (log : List (Entry Node TxId)) :
    (configurationsInLogFrom start log).Pairwise
      (fun left right => left.index < right.index) := by
  induction log generalizing start with
  | nil =>
      simp [configurationsInLogFrom]
  | cons entry entries inductionHypothesis =>
      cases content : entry.content with
      | transaction txId =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | signature =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | retiredCommitted nodes =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | reconfiguration nodes =>
          rw [
            show configurationsInLogFrom start (entry :: entries) =
                { index := start, nodes := nodes } ::
                  configurationsInLogFrom (start + 1) entries by
              simp [configurationsInLogFrom, content],
            List.pairwise_cons
          ]
          constructor
          · intro configuration member
            have bounds :=
              configurationsInLogFrom_index_bounds
                (TxId := TxId) (start + 1) entries member
            simp only
            omega
          · exact inductionHypothesis (start := start + 1)

omit [DecidableEq Node] [Bootstrap Node] in
/-- Every physical configuration index is positive and within the log. -/
lemma configurationsInLog_index_bounds
    (log : List (Entry Node TxId))
    {configuration : Configuration Node}
    (member : configuration ∈ configurationsInLog log) :
    0 < configuration.index /\
      configuration.index <= log.length := by
  have bounds :=
    configurationsInLogFrom_index_bounds
      (TxId := TxId) 1 log (by simpa [configurationsInLog] using member)
  omega

/-- A known configuration within a frontier is retained by the log take. -/
lemma allConfigurations_mem_take_of_index_le
    (log : List (Entry Node TxId))
    (frontier : Nat)
    {configuration : Configuration Node}
    (frontierBound : frontier <= log.length)
    (known : configuration ∈ allConfigurations log)
    (within : configuration.index <= frontier) :
    configuration ∈ allConfigurations (log.take frontier) := by
  rw [allConfigurations] at known ⊢
  rcases List.mem_cons.mp known with implicit | physical
  · exact List.mem_cons.mpr (Or.inl implicit)
  · right
    have split :
        configurationsInLog log =
          configurationsInLog (log.take frontier) ++
            configurationsInLogFrom
              (1 + (log.take frontier).length)
              (log.drop frontier) := by
      simpa [
        configurationsInLog,
        List.take_append_drop
      ] using
        configurationsInLogFrom_append
          (TxId := TxId) 1
          (log.take frontier) (log.drop frontier)
    rw [split] at physical
    rcases List.mem_append.mp physical with retained | suffix
    · exact retained
    · have suffixBounds :=
        configurationsInLogFrom_index_bounds
          (TxId := TxId)
          (1 + (log.take frontier).length)
          (log.drop frontier) suffix
      have takeLength :
          (log.take frontier).length = frontier := by
        simp [Nat.min_eq_left frontierBound]
      rw [takeLength] at suffixBounds
      omega

omit [DecidableEq Node] [Bootstrap Node] in
/-- Physical configuration indices are strictly increasing. -/
lemma configurationsInLog_pairwise_index_lt
    (log : List (Entry Node TxId)) :
    (configurationsInLog log).Pairwise
      (fun left right => left.index < right.index) := by
  simpa [configurationsInLog] using
    configurationsInLogFrom_pairwise_index_lt (TxId := TxId) 1 log

/-- The implicit index zero precedes every physical configuration index. -/
lemma allConfigurations_pairwise_index_lt
    (log : List (Entry Node TxId)) :
    (allConfigurations log).Pairwise
      (fun left right => left.index < right.index) := by
  rw [allConfigurations, List.pairwise_cons]
  constructor
  · intro configuration member
    have positive :=
      (configurationsInLog_index_bounds
        (TxId := TxId) log member).1
    simpa [implicitConfiguration] using positive
  · exact configurationsInLog_pairwise_index_lt (TxId := TxId) log

omit [DecidableEq Node] [Bootstrap Node] in
/-- Physical configuration indices contain no duplicates. -/
lemma configurationsInLog_indices_nodup
    (log : List (Entry Node TxId)) :
    ((configurationsInLog log).map fun configuration =>
      configuration.index).Nodup := by
  have ordered :
      ((configurationsInLog log).map fun configuration =>
        configuration.index).Pairwise (fun left right => left < right) :=
    List.pairwise_map.mpr
      (configurationsInLog_pairwise_index_lt (TxId := TxId) log)
  exact ordered.nodup

/-- Known configuration indices, including implicit index zero, are unique. -/
lemma allConfigurations_indices_nodup
    (log : List (Entry Node TxId)) :
    ((allConfigurations log).map fun configuration =>
      configuration.index).Nodup := by
  have ordered :
      ((allConfigurations log).map fun configuration =>
        configuration.index).Pairwise (fun left right => left < right) :=
    List.pairwise_map.mpr
      (allConfigurations_pairwise_index_lt (TxId := TxId) log)
  exact ordered.nodup

omit [Bootstrap Node] in
/-- A strictly index-ordered configuration list has unique index ownership. -/
private lemma pairwiseConfigurationIndex_unique
    {configurations : List (Configuration Node)}
    (ordered :
      configurations.Pairwise
        (fun left right => left.index < right.index))
    {left right : Configuration Node}
    (leftMember : left ∈ configurations)
    (rightMember : right ∈ configurations)
    (sameIndex : left.index = right.index) :
    left = right := by
  induction configurations generalizing left right with
  | nil =>
      simp at leftMember
  | cons head tail inductionHypothesis =>
      rw [List.pairwise_cons] at ordered
      rcases List.mem_cons.mp leftMember with leftHead | leftTail
      · subst left
        rcases List.mem_cons.mp rightMember with rightHead | rightTail
        · exact rightHead.symm
        · have strictlyLater := ordered.1 right rightTail
          omega
      · rcases List.mem_cons.mp rightMember with rightHead | rightTail
        · subst right
          have strictlyLater := ordered.1 left leftTail
          omega
        · exact
            inductionHypothesis ordered.2 leftTail rightTail sameIndex

omit [Bootstrap Node] in
/-- A physical log index identifies at most one configuration. -/
lemma configurationsInLog_index_unique
    (log : List (Entry Node TxId))
    {left right : Configuration Node}
    (leftMember : left ∈ configurationsInLog log)
    (rightMember : right ∈ configurationsInLog log)
    (sameIndex : left.index = right.index) :
    left = right :=
  pairwiseConfigurationIndex_unique
    (configurationsInLog_pairwise_index_lt (TxId := TxId) log)
    leftMember rightMember sameIndex

/-- Every known configuration, including the implicit one, has a unique index. -/
lemma allConfigurations_index_unique
    (log : List (Entry Node TxId))
    {left right : Configuration Node}
    (leftMember : left ∈ allConfigurations log)
    (rightMember : right ∈ allConfigurations log)
    (sameIndex : left.index = right.index) :
    left = right :=
  pairwiseConfigurationIndex_unique
    (allConfigurations_pairwise_index_lt (TxId := TxId) log)
    leftMember rightMember sameIndex

omit [DecidableEq Node] [Bootstrap Node] in
/-- Physical configurations contain no duplicate records. -/
lemma configurationsInLog_nodup
    (log : List (Entry Node TxId)) :
    (configurationsInLog log).Nodup := by
  rw [List.nodup_iff_pairwise_ne]
  exact
    (configurationsInLog_pairwise_index_lt (TxId := TxId) log).imp
      (by
        intro left right ordered same
        subst right
        omega)

/-- Known configurations contain no duplicate records. -/
lemma allConfigurations_nodup
    (log : List (Entry Node TxId)) :
    (allConfigurations log).Nodup := by
  rw [List.nodup_iff_pairwise_ne]
  exact
    (allConfigurations_pairwise_index_lt (TxId := TxId) log).imp
      (by
        intro left right ordered same
        subst right
        omega)

omit [DecidableEq Node] [Bootstrap Node] in
/-- Appending a non-reconfiguration entry does not add a configuration. -/
lemma configurationsInLogFrom_append_nonreconfiguration
    (start : Nat)
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (notReconfiguration :
      forall nodes,
        Not (entry.content = .reconfiguration nodes)) :
    configurationsInLogFrom start (log ++ [entry]) =
      configurationsInLogFrom start log := by
  induction log generalizing start with
  | nil =>
      cases content : entry.content with
      | transaction txId =>
          simp [configurationsInLogFrom, content]
      | signature =>
          simp [configurationsInLogFrom, content]
      | retiredCommitted nodes =>
          simp [configurationsInLogFrom, content]
      | reconfiguration nodes =>
          exact False.elim (notReconfiguration nodes content)
  | cons head tail inductionHypothesis =>
      cases content : head.content with
      | transaction txId =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | signature =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | retiredCommitted nodes =>
          simpa [configurationsInLogFrom, content] using
            inductionHypothesis (start := start + 1)
      | reconfiguration nodes =>
          simp [
            configurationsInLogFrom, content,
            inductionHypothesis (start := start + 1)
          ]

omit [DecidableEq Node] [Bootstrap Node] in
/-- Appending a non-reconfiguration entry preserves projected configurations. -/
lemma configurationsInLog_append_nonreconfiguration
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (notReconfiguration :
      forall nodes,
        Not (entry.content = .reconfiguration nodes)) :
    configurationsInLog (log ++ [entry]) =
      configurationsInLog log := by
  exact
    configurationsInLogFrom_append_nonreconfiguration
      (TxId := TxId) 1 log entry notReconfiguration

/-- Appending a non-reconfiguration entry preserves the current authority. -/
lemma currentConfigurationAt_append_nonreconfiguration
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (commitIndex : Nat)
    (notReconfiguration :
      forall nodes,
        Not (entry.content = .reconfiguration nodes)) :
    currentConfigurationAt (log ++ [entry]) commitIndex =
      currentConfigurationAt log commitIndex := by
  simp [
    currentConfigurationAt,
    configurationsInLog_append_nonreconfiguration
      (TxId := TxId) log entry notReconfiguration
  ]

/-- Appending a non-reconfiguration entry preserves all active authorities. -/
lemma activeConfigurations_append_nonreconfiguration
    (state : NodeState Node TxId)
    (entry : Entry Node TxId)
    (notReconfiguration :
      forall nodes,
        Not (entry.content = .reconfiguration nodes)) :
    activeConfigurations { state with log := state.log ++ [entry] } =
      activeConfigurations state := by
  simp [
    activeConfigurations, currentConfiguration,
    allConfigurations,
    configurationsInLog_append_nonreconfiguration
      (TxId := TxId) state.log entry notReconfiguration,
    currentConfigurationAt_append_nonreconfiguration
      (TxId := TxId) state.log entry state.commitIndex
        notReconfiguration
  ]
  rfl

/-- Select a configuration exactly when its physical index is committed. -/
private def selectConfiguration
    (commitIndex : Nat)
    (current configuration : Configuration Node) :
    Configuration Node :=
  if configuration.index <= commitIndex then configuration else current

omit [DecidableEq Node] [Bootstrap Node] in
/-- Selecting from a list returns the fallback or a member of the list. -/
private lemma foldlSelectConfiguration_mem
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node) :
    configurations.foldl (selectConfiguration commitIndex) fallback =
        fallback \/
      configurations.foldl (selectConfiguration commitIndex) fallback ∈
        configurations := by
  induction configurations generalizing fallback with
  | nil =>
      simp
  | cons head tail inductionHypothesis =>
      simp only [List.foldl_cons]
      by_cases committed : head.index <= commitIndex
      · rw [selectConfiguration, ite_eq_left committed]
        rcases inductionHypothesis (fallback := head) with same | member
        · exact Or.inr (List.mem_cons.mpr (Or.inl same))
        · exact Or.inr (List.mem_cons_of_mem head member)
      · rw [selectConfiguration, ite_eq_right committed]
        rcases inductionHypothesis (fallback := fallback) with same | member
        · exact Or.inl same
        · exact Or.inr (List.mem_cons_of_mem head member)

omit [DecidableEq Node] [Bootstrap Node] in
/-- A bounded fallback keeps the selected configuration within the frontier. -/
private lemma foldlSelectConfiguration_index_le
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node)
    (fallbackBound : fallback.index <= commitIndex) :
    (configurations.foldl
      (selectConfiguration commitIndex) fallback).index <= commitIndex := by
  induction configurations generalizing fallback with
  | nil =>
      exact fallbackBound
  | cons head tail inductionHypothesis =>
      simp only [List.foldl_cons]
      by_cases committed : head.index <= commitIndex
      · rw [selectConfiguration, ite_eq_left committed]
        exact inductionHypothesis head committed
      · rw [selectConfiguration, ite_eq_right committed]
        exact inductionHypothesis fallback fallbackBound

omit [DecidableEq Node] [Bootstrap Node] in
/-- Selection through an ordered suffix never moves behind its fallback. -/
private lemma foldlSelectConfiguration_index_ge
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node)
    (afterFallback :
      forall configuration,
        configuration ∈ configurations ->
          fallback.index < configuration.index)
    (ordered :
      configurations.Pairwise
        (fun left right => left.index < right.index)) :
    fallback.index <=
      (configurations.foldl
        (selectConfiguration commitIndex) fallback).index := by
  induction configurations generalizing fallback with
  | nil =>
      simp
  | cons head tail inductionHypothesis =>
      rw [List.pairwise_cons] at ordered
      simp only [List.foldl_cons]
      by_cases committed : head.index <= commitIndex
      · rw [selectConfiguration, ite_eq_left committed]
        have fallbackBeforeHead :
            fallback.index < head.index :=
          afterFallback head (by simp)
        exact
          (Nat.le_of_lt fallbackBeforeHead).trans
            (inductionHypothesis
              head ordered.1 ordered.2)
      · rw [selectConfiguration, ite_eq_right committed]
        exact
          inductionHypothesis
            fallback
            (by
              intro configuration member
              exact
                afterFallback configuration
                  (List.mem_cons_of_mem head member))
            ordered.2

omit [DecidableEq Node] [Bootstrap Node] in
/-- Every committed member of an ordered suffix is no later than its selection. -/
private lemma foldlSelectConfiguration_greatest
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node)
    (afterFallback :
      forall configuration,
        configuration ∈ configurations ->
          fallback.index < configuration.index)
    (ordered :
      configurations.Pairwise
        (fun left right => left.index < right.index))
    {configuration : Configuration Node}
    (member : configuration ∈ configurations)
    (committed : configuration.index <= commitIndex) :
    configuration.index <=
      (configurations.foldl
        (selectConfiguration commitIndex) fallback).index := by
  induction configurations generalizing fallback with
  | nil =>
      simp at member
  | cons head tail inductionHypothesis =>
      rw [List.pairwise_cons] at ordered
      rcases List.mem_cons.mp member with headEq | tailMember
      · subst configuration
        simp only [List.foldl_cons]
        rw [
          selectConfiguration,
          ite_eq_left committed
        ]
        exact
          foldlSelectConfiguration_index_ge
            commitIndex tail head ordered.1 ordered.2
      · simp only [List.foldl_cons]
        by_cases headCommitted : head.index <= commitIndex
        · rw [selectConfiguration, ite_eq_left headCommitted]
          exact
            inductionHypothesis
              head ordered.1 ordered.2 tailMember
        · rw [selectConfiguration, ite_eq_right headCommitted]
          exact
            inductionHypothesis
              fallback
              (by
                intro candidate candidateMember
                exact
                  afterFallback candidate
                    (List.mem_cons_of_mem head candidateMember))
              ordered.2 tailMember

omit [DecidableEq Node] [Bootstrap Node] in
/-- If every list member is pending, selection preserves its fallback. -/
private lemma foldlSelectConfiguration_eq_of_all_after
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node)
    (pending :
      forall configuration,
        configuration ∈ configurations ->
          commitIndex < configuration.index) :
    configurations.foldl (selectConfiguration commitIndex) fallback =
      fallback := by
  induction configurations generalizing fallback with
  | nil =>
      rfl
  | cons head tail inductionHypothesis =>
      have headPending : commitIndex < head.index :=
        pending head (by simp)
      have headNotCommitted : Not (head.index <= commitIndex) := by
        omega
      simp only [
        List.foldl_cons,
        selectConfiguration,
        ite_eq_right headNotCommitted
      ]
      exact
        inductionHypothesis
          fallback
          (by
            intro configuration member
            exact
              pending configuration
                (List.mem_cons_of_mem head member))

/--
The current configuration is either implicit or one of the physical
configurations projected from the log.
-/
lemma currentConfiguration_eq_implicit_or_mem_configurationsInLog
    (state : NodeState Node TxId) :
    currentConfiguration state = implicitConfiguration \/
      currentConfiguration state ∈ configurationsInLog state.log := by
  exact
    foldlSelectConfiguration_mem
      state.commitIndex
      (configurationsInLog state.log)
      implicitConfiguration

/-- The current configuration is always known from the local log. -/
lemma currentConfiguration_mem_allConfigurations
    (state : NodeState Node TxId) :
    currentConfiguration state ∈ allConfigurations state.log := by
  rcases
      currentConfiguration_eq_implicit_or_mem_configurationsInLog state with
    implicit | physical
  · simp [allConfigurations, implicit]
  · simp [allConfigurations, physical]

/-- The current configuration index never exceeds the local commit frontier. -/
lemma currentConfiguration_index_le_commitIndex
    (state : NodeState Node TxId) :
    (currentConfiguration state).index <= state.commitIndex := by
  exact
    foldlSelectConfiguration_index_le
      state.commitIndex
      (configurationsInLog state.log)
      implicitConfiguration
      (by simp [implicitConfiguration])

/--
The current configuration has the greatest known configuration index at or
before the local commit frontier.
-/
lemma configuration_index_le_currentConfiguration
    (state : NodeState Node TxId)
    (configuration : Configuration Node)
    (known : configuration ∈ allConfigurations state.log)
    (committed : configuration.index <= state.commitIndex) :
    configuration.index <= (currentConfiguration state).index := by
  rw [allConfigurations] at known
  rcases List.mem_cons.mp known with implicit | physical
  · subst configuration
    simp [implicitConfiguration]
  · have afterImplicit :
        forall candidate,
          candidate ∈ configurationsInLog state.log ->
            (implicitConfiguration (Node := Node)).index <
              candidate.index := by
      intro candidate member
      have positive :=
        (configurationsInLog_index_bounds
          (TxId := TxId) state.log member).1
      simpa [implicitConfiguration] using positive
    exact
      foldlSelectConfiguration_greatest
        state.commitIndex
        (configurationsInLog state.log)
        implicitConfiguration
        afterImplicit
        (configurationsInLog_pairwise_index_lt
          (TxId := TxId) state.log)
        physical
        committed

/--
The implicit configuration is current exactly when every physical
reconfiguration is still beyond the commit frontier.
-/
lemma currentConfiguration_eq_implicit_iff
    (state : NodeState Node TxId) :
    currentConfiguration state = implicitConfiguration <->
      forall configuration,
        configuration ∈ configurationsInLog state.log ->
          state.commitIndex < configuration.index := by
  constructor
  · intro currentImplicit configuration physical
    by_contra notPending
    have committed : configuration.index <= state.commitIndex := by
      omega
    have greatest :=
      configuration_index_le_currentConfiguration
        state configuration
        (by simp [allConfigurations, physical])
        committed
    have positive :=
      (configurationsInLog_index_bounds
        (TxId := TxId) state.log physical).1
    rw [currentImplicit] at greatest
    simp [implicitConfiguration] at greatest
    omega
  · intro pending
    exact
      foldlSelectConfiguration_eq_of_all_after
        state.commitIndex
        (configurationsInLog state.log)
        implicitConfiguration
        pending

/-- The current configuration is one of the active configurations. -/
lemma currentConfiguration_mem_activeConfigurations
    (state : NodeState Node TxId) :
    currentConfiguration state ∈ activeConfigurations state := by
  simp [
    activeConfigurations,
    currentConfiguration_mem_allConfigurations
  ]

/--
Unique commit authority: an active configuration whose index is committed is
the current configuration.

This lets proofs for an already-committed index reuse ordinary
single-configuration quorum arguments: every active authority governing that
index is definitionally the same current configuration.
-/
lemma activeConfigurationAtCommittedIndex_eq_current
    (state : NodeState Node TxId)
    (configuration : Configuration Node)
    (active : configuration ∈ activeConfigurations state)
    (committed : configuration.index <= state.commitIndex) :
    configuration = currentConfiguration state := by
  have activeFacts :
      configuration ∈ allConfigurations state.log /\
        (currentConfiguration state).index <= configuration.index := by
    simpa [activeConfigurations] using active
  have noLater :=
    configuration_index_le_currentConfiguration
      state configuration activeFacts.1 committed
  have sameIndex :
      configuration.index = (currentConfiguration state).index :=
    Nat.le_antisymm noLater activeFacts.2
  exact
    allConfigurations_index_unique
      (TxId := TxId)
      state.log
      activeFacts.1
      (currentConfiguration_mem_allConfigurations state)
      sameIndex

/-- Any two active configurations at committed indices are identical. -/
lemma activeConfigurationsAtCommittedIndices_unique
    (state : NodeState Node TxId)
    {left right : Configuration Node}
    (leftActive : left ∈ activeConfigurations state)
    (rightActive : right ∈ activeConfigurations state)
    (leftCommitted : left.index <= state.commitIndex)
    (rightCommitted : right.index <= state.commitIndex) :
    left = right := by
  rw [
    activeConfigurationAtCommittedIndex_eq_current
      state left leftActive leftCommitted,
    activeConfigurationAtCommittedIndex_eq_current
      state right rightActive rightCommitted
  ]

/--
At an already-committed log index, the only active configuration that can
govern that index is the current configuration.
-/
lemma activeConfigurationGoverningCommittedIndex_eq_current
    (state : NodeState Node TxId)
    {configuration : Configuration Node}
    {index : Nat}
    (active : configuration ∈ activeConfigurations state)
    (governs : configuration.index <= index)
    (committed : index <= state.commitIndex) :
    configuration = currentConfiguration state :=
  activeConfigurationAtCommittedIndex_eq_current
    state configuration active (governs.trans committed)

/--
Any decidable per-configuration obligation at an already-committed index
reduces to the current configuration. This local form avoids introducing a
global `State` into single-node quorum arguments.
-/
lemma activeConfigurations_all_at_committed_index_iff_current
    (state : NodeState Node TxId)
    (index : Nat)
    (committed : index <= state.commitIndex)
    (predicate : Configuration Node -> Prop)
    [DecidablePred predicate] :
    (activeConfigurations state).all
        (fun configuration =>
          decide (configuration.index <= index -> predicate configuration)) <->
      ((currentConfiguration state).index <= index ->
        predicate (currentConfiguration state)) := by
  constructor
  · intro allActive currentGoverns
    rw [List.all_eq_true] at allActive
    have currentRequired :=
      allActive
        (currentConfiguration state)
        (currentConfiguration_mem_activeConfigurations state)
    exact (of_decide_eq_true currentRequired) currentGoverns
  · intro currentRequired
    rw [List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    have currentEq :=
      activeConfigurationGoverningCommittedIndex_eq_current
        state active governs committed
    subst configuration
    exact currentRequired governs

/--
For an already-committed index, `hasMajorityAt` reduces to the current
configuration's strict-majority obligation (or no obligation before its
configuration index).
-/
lemma hasMajorityAt_committed_iff_currentConfiguration
    (state : State Node TxId)
    (leader : Node)
    (index : Nat)
    (committed : index <= (state.nodes leader).commitIndex) :
    hasMajorityAt state leader index <->
      ((currentConfiguration (state.nodes leader)).index <= index ->
        hasConfigurationMajority
          (acknowledgingNodes state leader index)
          (currentConfiguration (state.nodes leader))) := by
  unfold hasMajorityAt
  exact
    activeConfigurations_all_at_committed_index_iff_current
      (state.nodes leader)
      index
      committed
      (fun configuration =>
        hasConfigurationMajority
          (acknowledgingNodes state leader index)
          configuration)

end Bootstrap

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A successful one-based lookup proves the index lies within the log. -/
lemma entryAtSomeIndexBound
    {log : List (Entry Node TxId)}
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? log index = some entry) :
    index <= log.length := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    omega

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A successful one-based lookup is membership evidence. -/
lemma entryAt_mem
    {log : List (Entry Node TxId)}
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? log index = some entry) :
    entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, value⟩
    rw [← value]
    exact List.getElem_mem within

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A successful lookup is unchanged when the log is extended at the end. -/
lemma entryAt_of_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? left index = some entry) :
    entryAt? right index = some entry := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  unfold entryAt? at found ⊢
  by_cases zero : index = 0
  · simp [zero] at found
  · simp only [zero, ↓reduceIte] at found ⊢
    have within : index - 1 < left.length := by
      rw [List.getElem?_eq_some_iff] at found
      exact found.1
    rw [List.getElem?_append_left within]
    exact found

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A bounded AppendEntries batch has exactly `batchEnd - previousIndex` entries. -/
lemma messageEntriesLength
    (log : List (Entry Node TxId))
    {previousIndex batchEnd : Nat}
    (ordered : previousIndex <= batchEnd)
    (within : batchEnd <= log.length) :
    (messageEntries log previousIndex batchEnd).length =
      batchEnd - previousIndex := by
  rw [← Nat.sub_add_cancel ordered] at within ⊢
  simp [
    messageEntries,
    List.length_take,
    List.length_drop
  ]
  omega

omit [DecidableEq TxId] in
/-- A message after enqueue was either already present or is the new message. -/
lemma memEnqueue
    (network : Node -> List (Message Node TxId))
    (newMessage message : Message Node TxId)
    (destination : Node)
    (member : message ∈ enqueue network newMessage destination) :
    message ∈ network destination \/
      (destination = newMessage.destination /\ message = newMessage) := by
  unfold enqueue at member
  by_cases destinationEq : destination = newMessage.destination
  · subst destination
    simp at member
    rcases member with oldMember | newMember
    · exact Or.inl oldMember
    · exact Or.inr ⟨rfl, newMember⟩
  · have oldMember :
        message ∈ network destination := by
      simpa [updateQueue, Function.update, destinationEq] using member
    exact Or.inl oldMember

omit [DecidableEq TxId] in
/-- Selecting a source message returns that source and preserves queue membership. -/
lemma takeFirstFromSound
    {source : Node}
    {queue remaining : List (Message Node TxId)}
    {selected : Message Node TxId}
    (taken :
      takeFirstFrom source queue = some (selected, remaining)) :
    selected.source = source /\
      selected ∈ queue /\
      (forall message, message ∈ remaining -> message ∈ queue) := by
  induction queue generalizing selected remaining with
  | nil =>
      simp [takeFirstFrom] at taken
  | cons head tail inductionHypothesis =>
      unfold takeFirstFrom at taken
      split at taken
      · rename_i headSource
        simp at taken
        rcases taken with ⟨selectedEq, remainingEq⟩
        subst selected
        subst remaining
        refine ⟨headSource, by simp, ?_⟩
        intro message member
        exact List.mem_cons_of_mem head member
      · rename_i headNotSource
        split at taken
        · contradiction
        · rename_i selectedTail tailRemaining tailTaken
          simp at taken
          rcases taken with ⟨selectedEq, remainingEq⟩
          subst selected
          subst remaining
          have sound := inductionHypothesis tailTaken
          refine ⟨sound.1, by simp [sound.2.1], ?_⟩
          intro message member
          simp at member
          rcases member with headEq | tailMember
          · subst message
            simp
          · exact List.mem_cons_of_mem _ (sound.2.2 message tailMember)

/-- Every member of a prefix is also a member of the larger list. -/
lemma memOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {value : Alpha}
    (member : value ∈ left) :
    value ∈ right := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  simp [member]

/-! ## Generic commit-frontier facts -/

/-- A positive signature test identifies a concrete signature entry. -/
lemma isSignatureAtTrue
    {log : List (Entry Node TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true) :
    Exists fun entry =>
      entryAt? log index = some entry /\
        entry.content = .signature := by
  cases found : entryAt? log index with
  | none =>
      simp [isSignatureAt, found] at signature
  | some entry =>
      refine ⟨entry, rfl, ?_⟩
      simpa [isSignatureAt, found] using signature

/-- The latest signature index lies within the log. -/
lemma maxCommittableIndexBounded
    (log : List (Entry Node TxId)) :
    maxCommittableIndex log <= log.length := by
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best index =>
      if isSignatureAt log index then max best index else best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= log.length := by
    intro index member
    simp [candidates] at member
    omega
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values -> index <= log.length) ->
        best <= log.length ->
        values.foldl choose best <= log.length := by
    intro values
    induction values with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best valuesBound bestBound
        apply inductionHypothesis
        · intro index member
          exact valuesBound index (by simp [member])
        · have headBound := valuesBound head (by simp)
          simp only [choose]
          split <;> omega
  change candidates.foldl choose 0 <= log.length
  exact foldBounded candidates 0 allBounded (by omega)

/-- A positive latest committable index points to a signature. -/
lemma maxCommittableIndexPositiveIsSignature
    {log : List (Entry Node TxId)}
    (positive : 0 < maxCommittableIndex log) :
    isSignatureAt log (maxCommittableIndex log) = true := by
  unfold maxCommittableIndex at positive ⊢
  let valid := fun index => isSignatureAt log index = true
  let choose :=
    fun best index =>
      if valid index then max best index else best
  have foldValid :
      forall (values : List Nat) (best : Nat),
        (best = 0 \/ valid best) ->
        let result := values.foldl choose best
        result = 0 \/ valid result := by
    intro values
    induction values with
    | nil =>
        intro best bestValid
        exact bestValid
    | cons head tail inductionHypothesis =>
        intro best bestValid
        apply inductionHypothesis
        simp only [choose]
        by_cases headValid : valid head
        · simp [headValid]
          rcases bestValid with bestZero | bestIsValid
          · subst best
            exact Or.inr headValid
          · by_cases bestLeHead : best <= head
            · right
              simpa [max_eq_right bestLeHead] using headValid
            · right
              have headLeBest : head <= best := by omega
              simpa [max_eq_left headLeBest] using bestIsValid
        · simp [headValid, bestValid]
  have resultValid :=
    foldValid (List.range (log.length + 1)) 0 (Or.inl rfl)
  rcases resultValid with resultZero | resultValid
  · rw [resultZero] at positive
    omega
  · exact resultValid

/-- Every signature index is no later than the latest signature index. -/
lemma signatureIndex_le_maxCommittableIndex
    {log : List (Entry Node TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true) :
    index <= maxCommittableIndex log := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best candidate =>
      if isSignatureAt log candidate then
        max best candidate
      else
        best
  have foldAboveStart :
      forall (values : List Nat) (best : Nat),
        best <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        intro best
        exact le_rfl
    | cons head tail inductionHypothesis =>
        intro best
        apply le_trans (b := choose best head)
        · simp only [choose]
          split <;> omega
        · exact inductionHypothesis (choose best head)
  have foldContains :
      forall (values : List Nat) (best : Nat),
        index ∈ values ->
          index <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        simp
    | cons head tail inductionHypothesis =>
        intro best member
        simp only [List.foldl_cons]
        rcases List.mem_cons.mp member with headEq | tailMember
        · subst head
          have selected :
              choose best index = max best index := by
            simp [choose, signature]
          rw [selected]
          exact
            (le_max_right best index).trans
              (foldAboveStart tail (max best index))
        · exact
            inductionHypothesis
              (choose best head) tailMember
  change index <= candidates.foldl choose 0
  exact
    foldContains candidates 0
      (by
        simp [candidates]
        omega)

/-- There is no signature exactly when the latest committable index is zero. -/
lemma maxCommittableIndex_eq_zero_iff
    (log : List (Entry Node TxId)) :
    maxCommittableIndex log = 0 <->
      forall index, isSignatureAt log index = false := by
  constructor
  · intro zero index
    cases signature : isSignatureAt log index with
    | false =>
        rfl
    | true =>
        have bounded :=
          signatureIndex_le_maxCommittableIndex signature
        rw [zero] at bounded
        have indexZero : index = 0 := by omega
        subst index
        simp [isSignatureAt, entryAt?] at signature
  · intro noSignature
    by_contra nonzero
    have positive : 0 < maxCommittableIndex log :=
      Nat.pos_of_ne_zero nonzero
    have signature :=
      maxCommittableIndexPositiveIsSignature positive
    rw [noSignature] at signature
    exact Bool.noConfusion signature

/-- Extending a log preserves every earlier signature lookup. -/
lemma isSignatureAt_of_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true) :
    isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
lemma maxCommittableIndex_le_of_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right) :
    maxCommittableIndex left <= maxCommittableIndex right := by
  by_cases zero : maxCommittableIndex left = 0
  · omega
  · have positive : 0 < maxCommittableIndex left :=
      Nat.pos_of_ne_zero zero
    exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_of_prefix isPrefix
          (maxCommittableIndexPositiveIsSignature positive))

/-- Appending a signature makes it the latest committable entry. -/
lemma maxCommittableIndex_append_signature
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (signature : entry.content = .signature) :
    maxCommittableIndex (log ++ [entry]) = log.length + 1 := by
  have appendedSignature :
      isSignatureAt (log ++ [entry]) (log.length + 1) = true := by
    simp [isSignatureAt, entryAt?, signature]
  have lower :=
    signatureIndex_le_maxCommittableIndex appendedSignature
  have upper :=
    maxCommittableIndexBounded (log ++ [entry])
  simp only [List.length_append, List.length_cons, List.length_nil] at upper
  omega

/-- Taking a log prefix leaves lookups inside that prefix unchanged. -/
lemma isSignatureAt_take_of_le
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    (signature : isSignatureAt log index = true) :
    isSignatureAt (log.take count) index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have taken : entryAt? (log.take count) index = some entry := by
    by_cases zero : index = 0
    · subst index
      simp [entryAt?] at found
    · unfold entryAt? at found ⊢
      simp only [zero, ↓reduceIte] at found ⊢
      rw [List.getElem?_take]
      split
      · exact found
      · omega
  simp [isSignatureAt, taken, content]

/-- The bounded committable frontier does not exceed its supplied frontier. -/
lemma maxCommittableIndexUpTo_le_frontier
    (log : List (Entry Node TxId))
    (frontier : Nat) :
    maxCommittableIndexUpTo log frontier <= frontier := by
  unfold maxCommittableIndexUpTo
  exact
    (maxCommittableIndexBounded (log.take frontier)).trans
      (by simp)

/-- The bounded committable frontier does not exceed the complete log. -/
lemma maxCommittableIndexUpTo_le_length
    (log : List (Entry Node TxId))
    (frontier : Nat) :
    maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  omega

/-- Restricting the search frontier cannot reveal a later signature. -/
lemma maxCommittableIndexUpTo_le
    (log : List (Entry Node TxId))
    (frontier : Nat) :
    maxCommittableIndexUpTo log frontier <=
      maxCommittableIndex log := by
  unfold maxCommittableIndexUpTo
  exact
    maxCommittableIndex_le_of_prefix
      (List.take_prefix frontier log)

/-- A positive bounded committable frontier points to a signature in the log. -/
lemma maxCommittableIndexUpToPositiveIsSignature
    {log : List (Entry Node TxId)}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier) :
    isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

section BootstrapCommit

variable [Bootstrap Node]

/-- The computed commit frontier never exceeds the leader log length. -/
lemma highestCommittableIndexBounded
    (state : State Node TxId)
    (leader : Node) :
    highestCommittableIndex state leader <=
      (state.nodes leader).log.length := by
  unfold highestCommittableIndex
  let candidates := List.range ((state.nodes leader).log.length + 1)
  let choose :=
    fun best index =>
      if index > (state.nodes leader).commitIndex /\
          isSignatureAt (state.nodes leader).log index = true /\
          termAt (state.nodes leader).log index =
            (state.nodes leader).currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= (state.nodes leader).log.length := by
    intro index member
    simp [candidates] at member
    omega
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values ->
          index <= (state.nodes leader).log.length) ->
        best <= (state.nodes leader).log.length ->
        values.foldl choose best <=
          (state.nodes leader).log.length := by
    intro values
    induction values with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best valuesBound bestBound
        apply inductionHypothesis
        · intro index member
          exact valuesBound index (by simp [member])
        · have headBound := valuesBound head (by simp)
          simp only [choose]
          split <;> omega
  change candidates.foldl choose 0 <= (state.nodes leader).log.length
  exact foldBounded candidates 0 allBounded (by omega)

/-- A newly selected commit frontier satisfies every commit-selection guard. -/
lemma highestCommittableIndexFacts
    (state : State Node TxId)
    (leader : Node)
    (advances :
      (state.nodes leader).commitIndex <
        highestCommittableIndex state leader) :
    isSignatureAt
        (state.nodes leader).log
        (highestCommittableIndex state leader) = true /\
      termAt
        (state.nodes leader).log
        (highestCommittableIndex state leader) =
        (state.nodes leader).currentTerm /\
      hasMajorityAt state leader
          (highestCommittableIndex state leader) := by
  unfold highestCommittableIndex at advances ⊢
  let leaderState := state.nodes leader
  let valid :=
    fun index =>
      index > leaderState.commitIndex /\
        isSignatureAt leaderState.log index = true /\
        termAt leaderState.log index = leaderState.currentTerm /\
        hasMajorityAt state leader index
  let choose :=
    fun best index =>
      if valid index then max best index else best
  have foldValid :
      forall (values : List Nat) (best : Nat),
        (best = 0 \/ valid best) ->
        let result := values.foldl choose best
        result = 0 \/ valid result := by
    intro values
    induction values with
    | nil =>
        intro best bestValid
        exact bestValid
    | cons head tail inductionHypothesis =>
        intro best bestValid
        apply inductionHypothesis
        simp only [choose]
        by_cases headValid : valid head
        · simp [headValid]
          rcases bestValid with bestZero | bestIsValid
          · subst best
            exact Or.inr headValid
          · by_cases bestLeHead : best <= head
            · right
              simpa [max_eq_right bestLeHead] using headValid
            · right
              have headLeBest : head <= best := by omega
              simpa [max_eq_left headLeBest] using bestIsValid
        · simp [headValid, bestValid]
  have resultValid :=
    foldValid (List.range (leaderState.log.length + 1)) 0 (Or.inl rfl)
  rcases resultValid with resultZero | resultValid
  · rw [resultZero] at advances
    omega
  · exact
      ⟨resultValid.2.1, resultValid.2.2.1, resultValid.2.2.2⟩

/-- A newly selected commit frontier satisfies the term and majority guards. -/
lemma highestCommittableIndexValid
    (state : State Node TxId)
    (leader : Node)
    (advances :
      (state.nodes leader).commitIndex <
        highestCommittableIndex state leader) :
    termAt
        (state.nodes leader).log
        (highestCommittableIndex state leader) =
      (state.nodes leader).currentTerm /\
      hasMajorityAt state leader
        (highestCommittableIndex state leader) :=
  (highestCommittableIndexFacts state leader advances).2

/-- A newly selected positive commit frontier points to a signature. -/
lemma highestCommittableIndexIsSignature
    (state : State Node TxId)
    (leader : Node)
    (advances :
      (state.nodes leader).commitIndex <
        highestCommittableIndex state leader) :
    isSignatureAt
        (state.nodes leader).log
        (highestCommittableIndex state leader) = true :=
  (highestCommittableIndexFacts state leader advances).1

end BootstrapCommit

/-! ## Generic local-handler facts -/

variable [Bootstrap Node]

private def withProtocolNodeState
    (result : NodeState Node TxId × AppendEntriesResponse Node) :
    NodeState Node TxId × AppendEntriesResponse Node :=
  (protocolNodeState result.1, result.2)

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
lemma rejectAppendEntriesRequest_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    rejectAppendEntriesRequest? (protocolNodeState node) request =
      (rejectAppendEntriesRequest? node request).map
        withProtocolNodeState := by
  unfold rejectAppendEntriesRequest?
  simp only [protocolNodeState, logOk]
  split_ifs <;>
    simp_all [
      failureResponse, withProtocolNodeState, protocolNodeState
    ]

omit [Bootstrap Node] in
lemma appendEntriesAlreadyDone_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    appendEntriesAlreadyDone? (protocolNodeState node) request =
      (appendEntriesAlreadyDone? node request).map
        withProtocolNodeState := by
  unfold appendEntriesAlreadyDone?
  simp only [alreadyDone, protocolNodeState]
  split_ifs <;>
    simp_all [
      committedFromLeader, successResponse, withProtocolNodeState,
      protocolNodeState
    ]

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
lemma conflictAppendEntriesRequest_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    conflictAppendEntriesRequest? (protocolNodeState node) request =
      (conflictAppendEntriesRequest? node request).map
        protocolNodeState := by
  unfold conflictAppendEntriesRequest?
  simp only [hasTermConflict, overlapLength, protocolNodeState]
  split_ifs <;> simp_all [protocolNodeState]

/-- Retirement refresh preserves protocol observations, not erased result metadata. -/
lemma noConflictAppendEntriesRequest_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    (noConflictAppendEntriesRequest? (protocolNodeState node) request).map
        withProtocolNodeState =
      (noConflictAppendEntriesRequest? node request).map
        withProtocolNodeState := by
  unfold noConflictAppendEntriesRequest?
  simp only [noConflictExtension, protocolNodeState]
  split_ifs <;>
    simp_all [
      committedFromLeader, successResponse, withProtocolNodeState,
      protocolNodeState
    ]

lemma acceptAppendEntriesRequest_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    (acceptAppendEntriesRequest? (protocolNodeState node) request).map
        withProtocolNodeState =
      (acceptAppendEntriesRequest? node request).map
        withProtocolNodeState := by
  unfold acceptAppendEntriesRequest?
  by_cases accepted :
      request.term = node.currentTerm /\
        node.role = .follower /\
        logOk node request /\
        request.prevLogIndex >= node.commitIndex
  · have acceptedProtocol :
        request.term = (protocolNodeState node).currentTerm /\
          (protocolNodeState node).role = .follower /\
          logOk (protocolNodeState node) request /\
          request.prevLogIndex >=
            (protocolNodeState node).commitIndex := by
      simpa [protocolNodeState, logOk] using accepted
    rw [ite_eq_left acceptedProtocol, ite_eq_left accepted]
    rw [appendEntriesAlreadyDone_protocolNodeState]
    cases already : appendEntriesAlreadyDone? node request with
    | some result => simp [withProtocolNodeState]
    | none =>
      simp only [Option.map_none]
      have extension := noConflictAppendEntriesRequest_protocolNodeState node request
      cases extended : noConflictAppendEntriesRequest? node request <;>
        cases projected : noConflictAppendEntriesRequest? (protocolNodeState node) request <;>
        simp only [extended, projected, Option.map_none, Option.map_some,
          Option.some.injEq] at extension ⊢
      · rw [conflictAppendEntriesRequest_protocolNodeState]
        cases conflictResult : conflictAppendEntriesRequest? node request with
        | none => rfl
        | some truncated =>
          simp only [Option.map_some]
          rw [appendEntriesAlreadyDone_protocolNodeState]
          cases appendEntriesAlreadyDone? truncated request with
          | some result => simp [withProtocolNodeState]
          | none =>
            exact noConflictAppendEntriesRequest_protocolNodeState truncated request
      · contradiction
      · contradiction
      · exact extension
  · have rejectedProtocol :
        Not (
          request.term = (protocolNodeState node).currentTerm /\
            (protocolNodeState node).role = .follower /\
            logOk (protocolNodeState node) request /\
            request.prevLogIndex >=
              (protocolNodeState node).commitIndex) := by
      simpa [protocolNodeState, logOk] using accepted
    rw [ite_eq_right rejectedProtocol, ite_eq_right accepted]

lemma handleAppendEntriesRequest_protocolNodeState
    (node : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    (handleAppendEntriesRequest? (protocolNodeState node) request).map
        withProtocolNodeState =
      (handleAppendEntriesRequest? node request).map
        withProtocolNodeState := by
  unfold handleAppendEntriesRequest?
  rw [rejectAppendEntriesRequest_protocolNodeState]
  cases rejectAppendEntriesRequest? node request
  · exact acceptAppendEntriesRequest_protocolNodeState node request
  · simp [withProtocolNodeState]

/-- Erasing input metadata preserves the reply and every protocol state field. -/
lemma handleAppendEntriesRequest_protocolNodeState_some
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    Exists fun projectedAfter =>
      handleAppendEntriesRequest? (protocolNodeState before) request =
        some (projectedAfter, response) /\
      protocolNodeState projectedAfter = protocolNodeState after := by
  have observations := handleAppendEntriesRequest_protocolNodeState before request
  rw [handled] at observations
  cases projected :
      handleAppendEntriesRequest? (protocolNodeState before) request with
  | none => simp [projected] at observations
  | some result =>
    rcases result with ⟨projectedAfter, projectedResponse⟩
    simp only [projected, Option.map_some, Option.some.injEq,
      withProtocolNodeState, Prod.mk.injEq] at observations
    exact ⟨projectedAfter, by rw [observations.2], observations.1⟩

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Replies received after stepping down are consumed without changing state. -/
lemma handleAppendEntriesResponseNonLeaderUnchanged
    (before : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    (notLeader : before.role ≠ .leader) :
    handleAppendEntriesResponse? before response = some before := by
  simp [handleAppendEntriesResponse?, notLeader]

/-- Once recorded, a retirement commit frontier survives later refreshes. -/
lemma refreshRetirementState_retiredCommittedIndex_preserved
    (node : Node)
    (state : NodeState Node TxId)
    {frontier : Nat}
    (recorded : state.retiredCommittedIndex = some frontier) :
    (refreshRetirementState node state).retiredCommittedIndex =
      some frontier := by
  simp [refreshRetirementState, recorded]

/-- The first covering refresh records the commit frontier, not the marker index. -/
lemma refreshRetirementState_retiredCommittedIndex_first
    (node : Node)
    (state : NodeState Node TxId)
    {markerIndex : Nat}
    (unrecorded : state.retiredCommittedIndex = none)
    (marker : retiredCommittedIndexInLog node state.log = some markerIndex)
    (covered : markerIndex <= state.commitIndex) :
    (refreshRetirementState node state).retiredCommittedIndex =
      some state.commitIndex := by
  simp [refreshRetirementState, unrecorded, marker, covered]

/-- Facts guaranteed after tallying a RequestVote response. -/
structure VoteResponseHandlerPost
    (before after : NodeState Node TxId)
    (response : RequestVoteResponse Node) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  preVotesGrantedUnchanged :
    after.preVotesGranted = before.preVotesGranted
  membershipStateUnchanged :
    after.membershipState = before.membershipState
  retirementIndexUnchanged :
    after.retirementIndex = before.retirementIndex
  retirementCommittableIndexUnchanged :
    after.retirementCommittableIndex = before.retirementCommittableIndex
  retiredCommittedIndexUnchanged :
    after.retiredCommittedIndex = before.retiredCommittedIndex
  votesUpdate :
    after.votesGranted = before.votesGranted \/
      (response.voteGranted = true /\
        before.role = .candidate /\
        after.votesGranted =
          insert response.source before.votesGranted)

omit [DecidableEq TxId] [Bootstrap Node] in
/-- Tallying a response changes only the candidate's recorded vote set. -/
lemma handleRequestVoteResponsePreserves
    {before after : NodeState Node TxId}
    {response : RequestVoteResponse Node}
    (handled :
      handleRequestVoteResponse? before response = some after) :
    VoteResponseHandlerPost before after response := by
  unfold handleRequestVoteResponse? at handled
  split at handled
  · simp at handled
    subst after
    exact
      ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, Or.inl rfl⟩
  · split at handled
    · simp at handled
      subst after
      exact
        ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
          rfl, rfl, rfl, rfl, Or.inl rfl⟩
    · rename_i candidateRole
      split at handled
      · rename_i currentTerm
        split at handled
        · rename_i granted
          simp at handled
          subst after
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
              rfl, rfl, rfl, rfl,
              Or.inr ⟨granted, by simpa using candidateRole, rfl⟩⟩
        · simp at handled
          subst after
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
              rfl, rfl, rfl, rfl, Or.inl rfl⟩
      · contradiction

omit [Bootstrap Node] in
/-- RequestPreVote changes no local persistent or replication state. -/
lemma handleRequestPreVoteStateUnchanged
    {before after : NodeState Node TxId}
    {request : RequestPreVote Node}
    {response : RequestPreVoteResponse Node}
    (handled :
      handleRequestPreVote? before request = some (after, response)) :
    after = before := by
  unfold handleRequestPreVote? at handled
  split at handled
  · simp at handled
    exact handled.1.symm
  · contradiction

omit [Bootstrap Node] in
/-- RequestPreVote replies preserve the request's source and destination. -/
lemma handleRequestPreVoteResponseAddressed
    {before after : NodeState Node TxId}
    {request : RequestPreVote Node}
    {response : RequestPreVoteResponse Node}
    (handled :
      handleRequestPreVote? before request = some (after, response)) :
    response.source = request.destination /\
      response.destination = request.source := by
  unfold handleRequestPreVote? at handled
  split at handled
  · simp at handled
    rw [← handled.2]
    exact ⟨rfl, rfl⟩
  · contradiction

/-- Tallying a pre-vote response changes only the speculative vote set. -/
structure PreVoteResponseHandlerPost
    (before after : NodeState Node TxId)
    (response : RequestPreVoteResponse Node) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  isNewFollowerUnchanged : after.isNewFollower = before.isNewFollower
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  membershipStateUnchanged :
    after.membershipState = before.membershipState
  retirementIndexUnchanged :
    after.retirementIndex = before.retirementIndex
  retirementCommittableIndexUnchanged :
    after.retirementCommittableIndex = before.retirementCommittableIndex
  retiredCommittedIndexUnchanged :
    after.retiredCommittedIndex = before.retiredCommittedIndex
  preVotesUpdate :
    after.preVotesGranted = before.preVotesGranted \/
      (response.voteGranted = true /\
        response.term = before.currentTerm /\
        before.role = .preVoteCandidate /\
        after.preVotesGranted =
          insert response.source before.preVotesGranted)

omit [DecidableEq TxId] [Bootstrap Node] in
lemma handleRequestPreVoteResponsePreserves
    {before after : NodeState Node TxId}
    {response : RequestPreVoteResponse Node}
    (handled :
      handleRequestPreVoteResponse? before response = some after) :
    PreVoteResponseHandlerPost before after response := by
  unfold handleRequestPreVoteResponse? at handled
  split at handled
  · simp at handled
    subst after
    exact
      ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
        rfl, rfl, rfl, rfl, Or.inl rfl⟩
  · split at handled
    · simp at handled
      subst after
      exact
        ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
          rfl, rfl, rfl, rfl, Or.inl rfl⟩
    · rename_i preVoteCandidate
      split at handled
      · rename_i currentTerm
        split at handled
        · rename_i granted
          simp at handled
          subst after
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
              rfl, rfl, rfl, rfl,
              Or.inr
                ⟨granted, currentTerm,
                  by simpa using preVoteCandidate, rfl⟩⟩
        · simp at handled
          subst after
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
              rfl, rfl, rfl, rfl,
              Or.inl rfl⟩
      · contradiction

/--
A processed proposal either leaves the node unchanged, including when newer,
or performs the exact current-term ordinary-candidate transition.
-/
lemma handleProposeVoteRequestCases
    {state : State Node TxId}
    {destination : Node}
    {request : ProposeVoteRequest Node}
    {after : NodeState Node TxId}
    (handled :
      handleProposeVoteRequest? state destination request = some after) :
    after = state.nodes destination \/
        (request.term = (state.nodes destination).currentTerm /\
          candidateTransitionEnabled state destination /\
          after =
            becomeCandidateNodeState
              (state.nodes destination) destination) := by
  simp only [handleProposeVoteRequest?] at handled
  split at handled
  · rename_i eligible
    simp only [Option.some.injEq] at handled
    subst after
    exact Or.inr ⟨eligible.1, eligible.2, rfl⟩
  · simp only [Option.some.injEq] at handled
    exact Or.inl handled.symm

omit [DecidableEq TxId] [Bootstrap Node] in
/-- A successful newer-message lookup identifies the queued message and order. -/
lemma newerMessageSound
    {state : State Node TxId}
    {source destination : Node}
    {selected : Message Node TxId}
    (found : newerMessage? state source destination = some selected) :
    Exists fun remaining =>
      takeFirstFrom source (state.network destination) =
        some (selected, remaining) /\
      (state.nodes destination).currentTerm < selected.term := by
  unfold newerMessage? at found
  cases taken :
      takeFirstFrom source (state.network destination) with
  | none =>
      simp [taken] at found
  | some result =>
      rcases result with ⟨message, remaining⟩
      simp only [taken] at found
      dsimp only [Bind.bind, Option.bind] at found
      cases message <;> dsimp only at found
      all_goals
        first
        | contradiction
        | split at found
          · rename_i allowed
            have selectedEq := Option.some.inj found
            subst selected
            exact ⟨remaining, rfl, allowed.2⟩
          · contradiction

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Failure-response routing and the failure bit do not depend on its NACK index. -/
lemma failureResponseMetadata
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    (failureResponse before request).source = request.destination /\
      (failureResponse before request).destination = request.source /\
      (failureResponse before request).success = false := by
  unfold failureResponse
  split
  · exact ⟨rfl, rfl, rfl⟩
  · dsimp
    split
    · exact ⟨rfl, rfl, rfl⟩
    · split
      · exact ⟨rfl, rfl, rfl⟩
      · split <;> exact ⟨rfl, rfl, rfl⟩

omit [Bootstrap Node] in
/-- A follower commit learned from a request stays below the advertised
leader frontier, apart from an already committed local prefix. -/
lemma committedFromLeader_le_max_leaderCommit
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) :
    committedFromLeader before request newLog <=
    max before.commitIndex request.leaderCommit := by
  unfold committedFromLeader
  exact
    max_le_max_left before.commitIndex
      ((maxCommittableIndexUpTo_le_frontier
        newLog
        (min request.leaderCommit
          (request.prevLogIndex + request.entries.length))).trans
        (min_le_left
          request.leaderCommit
          (request.prevLogIndex + request.entries.length)))

omit [Bootstrap Node] in
/-- A follower commit learned from a request stays below the request's
verified end, apart from an already committed local prefix. -/
lemma committedFromLeader_le_max_requestEnd
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) :
    committedFromLeader before request newLog <=
    max before.commitIndex
      (request.prevLogIndex + request.entries.length) := by
  unfold committedFromLeader
  exact
    max_le_max_left before.commitIndex
      ((maxCommittableIndexUpTo_le_frontier
        newLog
        (min request.leaderCommit
          (request.prevLogIndex + request.entries.length))).trans
        (min_le_right
          request.leaderCommit
          (request.prevLogIndex + request.entries.length)))

omit [Bootstrap Node] in
/-- A follower commit learned from a request stays below the latest signature,
apart from an already committed local prefix. -/
lemma committedFromLeader_le_max_committable
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) :
    committedFromLeader before request newLog <=
      max before.commitIndex (maxCommittableIndex newLog) := by
  unfold committedFromLeader
  exact
    max_le_max_left before.commitIndex
      (maxCommittableIndexUpTo_le
        newLog
        (min request.leaderCommit
          (request.prevLogIndex + request.entries.length)))

omit [Bootstrap Node] in
/-- A follower commit learned from a request remains inside the resulting log
when the previous committed prefix is still present. -/
lemma committedFromLeader_bounded
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    (oldBound : before.commitIndex <= newLog.length) :
    committedFromLeader before request newLog <= newLog.length := by
  unfold committedFromLeader
  apply max_le oldBound
  exact
    maxCommittableIndexUpTo_le_length
      newLog
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length))

omit [Bootstrap Node] in
/-- A signature lookup is retained by any log containing the committed prefix. -/
lemma committedSignature_retained
    (before : NodeState Node TxId)
    (newLog : List (Entry Node TxId))
    (retainedPrefix : before.committedLog <+: newLog)
    (signature :
      isSignatureAt before.log before.commitIndex = true) :
    isSignatureAt newLog before.commitIndex = true := by
  apply isSignatureAt_of_prefix retainedPrefix
  unfold NodeState.committedLog
  exact isSignatureAt_take_of_le le_rfl signature

omit [Bootstrap Node] in
/-- Learning a follower commit preserves the signature-frontier invariant. -/
lemma committedFromLeader_isSignature
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    (oldSignature :
      0 < before.commitIndex ->
        isSignatureAt newLog before.commitIndex = true)
    (positive : 0 < committedFromLeader before request newLog) :
    isSignatureAt
      newLog
      (committedFromLeader before request newLog) = true := by
  unfold committedFromLeader at positive ⊢
  let learned :=
    maxCommittableIndexUpTo newLog
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length))
  by_cases oldDominates : learned <= before.commitIndex
  · rw [max_eq_left oldDominates]
    exact oldSignature (by omega)
  · have oldLeLearned : before.commitIndex <= learned := by omega
    rw [max_eq_right oldLeLearned]
    exact
      maxCommittableIndexUpToPositiveIsSignature
        (by omega)

/-- State facts needed from the AppendEntries request handler in both phases. -/
structure AppendRequestLocalPost
    (before after : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (response : AppendEntriesResponse Node) : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  logShape :
    after.log = before.log \/
      after.log = before.log.take request.prevLogIndex \/
      after.log = before.log.take request.prevLogIndex ++ request.entries
  logUnchangedOrPreviousBound :
    after.log = before.log \/
      request.prevLogIndex <= before.log.length
  logUnchangedOrPreviousMatches :
    after.log = before.log \/
      request.prevLogIndex = 0 \/
        termAt before.log request.prevLogIndex =
          request.prevLogTerm
  logUnchangedOrCurrentTerm :
    after.log = before.log \/
      request.term = before.currentTerm
  previousCommittedPrefix :
    before.committedLog <+: after.log
  commitIndexBounded :
    before.commitIndex <= before.log.length ->
      after.commitIndex <= after.log.length
  commitIndexMonotone :
    before.commitIndex <= after.commitIndex
  commitRequestEndBound :
    after.commitIndex <=
      max before.commitIndex
        (request.prevLogIndex + request.entries.length)
  commitUpperBound :
    after.commitIndex <= max before.commitIndex request.leaderCommit
  commitCommittableBound :
    after.commitIndex <=
      max before.commitIndex (maxCommittableIndex after.log)
  commitIndexSignature :
    (0 < before.commitIndex ->
      isSignatureAt before.log before.commitIndex = true) ->
    0 < after.commitIndex ->
      isSignatureAt after.log after.commitIndex = true
  responseSource : response.source = request.destination
  responseDestination : response.destination = request.source
  successfulIndexBound :
    response.success = true ->
      response.lastLogIndex <=
        request.prevLogIndex + request.entries.length
  successfulCurrentTerm :
    response.success = true ->
      request.term = before.currentTerm
  commitAdvancedSuccessful :
    before.commitIndex < after.commitIndex ->
      response.success = true
  successfulUnchangedEntryTerms :
    response.success = true ->
      after.log = before.log ->
        ((before.log.drop request.prevLogIndex).take
            request.entries.length).map Entry.term =
          request.entries.map Entry.term
  successfulLogOk :
    response.success = true ->
      logOk before request
  successfulResponseTerm :
    response.success = true ->
      response.term = before.currentTerm
  successfulIndexExact :
    response.success = true ->
      response.lastLogIndex =
        request.prevLogIndex + request.entries.length
  failedResponse :
    response.success = false ->
      response = failureResponse before request
  failedStateUnchanged :
    response.success = false ->
      after = before
  failedRequestNotNewer :
    response.success = false ->
      request.term <= before.currentTerm
  failedSameTermNotLogOk :
    response.success = false ->
      request.term = before.currentTerm ->
        Not (logOk before request)

/-- Every successful AppendEntries handler branch has the common local shape. -/
lemma handleAppendEntriesRequestLocalPost
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    AppendRequestLocalPost before after request response := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have afterEq := congrArg Prod.fst pairEq
      have responseEq := congrArg Prod.snd pairEq
      dsimp at afterEq responseEq
      subst after
      subst response
      have metadata := failureResponseMetadata before request
      exact
        ⟨rfl, rfl, rfl, rfl, rfl, rfl,
          Or.inl rfl, Or.inl rfl, Or.inl rfl,
          Or.inl rfl, List.take_prefix _ _,
          (by intro bound; exact bound),
          le_rfl,
          le_max_left _ _,
          le_max_left _ _,
          le_max_left _ _,
          (by intro oldSignature positive; exact oldSignature positive),
          metadata.1,
          metadata.2.1,
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro advanced; omega),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro succeeded; rw [metadata.2.2] at succeeded; contradiction),
          (by intro _; rfl),
          (by intro _; rfl),
          (by
            intro _
            rcases ‹request.term < before.currentTerm \/
                (request.term = before.currentTerm /\
                  before.role = .follower /\
                  Not (logOk before request))› with stale | same
            · omega
            · omega),
          (by
            intro _ equal
            rcases ‹request.term < before.currentTerm \/
                (request.term = before.currentTerm /\
                  before.role = .follower /\
                  Not (logOk before request))› with stale | same
            · omega
            · exact same.2.2)⟩
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      split at handled
      · rename_i alreadyState alreadyResponse already
        unfold appendEntriesAlreadyDone? at already
        split at already
        · rename_i truncatedAlreadyDone
          have pairEq :=
            (Option.some.inj already).trans (Option.some.inj handled)
          have afterEq := congrArg Prod.fst pairEq
          have responseEq := congrArg Prod.snd pairEq
          dsimp at afterEq responseEq
          subst after
          subst response
          simp only [committedFromLeader]
          exact
            ⟨rfl, rfl, rfl, rfl, rfl, rfl,
              Or.inl rfl, Or.inl rfl, Or.inl rfl,
              Or.inl rfl, List.take_prefix _ _,
              (by
                intro bound
                exact
                  committedFromLeader_bounded
                    before request before.log bound),
              le_max_left _ _,
              committedFromLeader_le_max_requestEnd
                before request before.log,
              committedFromLeader_le_max_leaderCommit
                before request before.log,
              committedFromLeader_le_max_committable
                before request before.log,
              (by
                intro oldSignature positive
                exact
                  committedFromLeader_isSignature
                    before request before.log oldSignature positive),
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by intro; exact accepted.1,
              by simp [successResponse],
              (by
                intro _ _
                have done : alreadyDone before request := by assumption
                rcases done with empty | represented
                · simp [empty]
                · exact represented.2),
              by intro; exact accepted.2.2.1,
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse],
              by simp [successResponse]⟩
        · contradiction
      · split at handled
        · rename_i extendedState extendedResponse extended
          unfold noConflictAppendEntriesRequest? at extended
          split at extended
          · have pairEq :=
              (Option.some.inj extended).trans (Option.some.inj handled)
            have afterEq := congrArg Prod.fst pairEq
            have responseEq := congrArg Prod.snd pairEq
            dsimp at afterEq responseEq
            subst after
            subst response
            simp only [committedFromLeader]
            exact
              ⟨rfl, rfl, rfl, rfl, rfl, rfl,
                Or.inr (Or.inr rfl),
                Or.inr ‹noConflictExtension before request›.2.1,
                Or.inr (by
                  rcases accepted.2.2.1 with zero | present
                  · exact Or.inl zero
                  · exact Or.inr present.2),
                Or.inr accepted.1,
                (by
                  unfold NodeState.committedLog
                  have first :
                      before.log.take before.commitIndex <+:
                        before.log.take request.prevLogIndex := by
                    rw [List.prefix_take_iff]
                    constructor
                    · exact List.take_prefix _ _
                    · simp only [List.length_take]
                      omega
                  exact first.trans
                    (List.prefix_append
                      (before.log.take request.prevLogIndex)
                      request.entries)),
                (by
                  intro bound
                  have previousBound :=
                    ‹noConflictExtension before request›.2.1
                  apply committedFromLeader_bounded
                  simp [List.length_take, previousBound]
                  omega),
                le_max_left _ _,
                committedFromLeader_le_max_requestEnd
                  before request
                    (before.log.take request.prevLogIndex ++
                      request.entries),
                committedFromLeader_le_max_leaderCommit
                  before request
                    (before.log.take request.prevLogIndex ++
                      request.entries),
                committedFromLeader_le_max_committable
                  before request
                    (before.log.take request.prevLogIndex ++
                      request.entries),
                (by
                  intro oldSignature positive
                  apply
                    committedFromLeader_isSignature
                      before request
                        (before.log.take request.prevLogIndex ++
                          request.entries)
                  · intro oldPositive
                    apply committedSignature_retained before
                    · unfold NodeState.committedLog
                      have first :
                          before.log.take before.commitIndex <+:
                            before.log.take request.prevLogIndex := by
                        rw [List.prefix_take_iff]
                        constructor
                        · exact List.take_prefix _ _
                        · simp only [List.length_take]
                          omega
                      exact first.trans
                        (List.prefix_append
                          (before.log.take request.prevLogIndex)
                          request.entries)
                    · exact oldSignature oldPositive
                  · exact positive),
                by simp [successResponse],
                by simp [successResponse],
                by
                  intro
                  simp only [successResponse]
                  have previousBound :=
                    ‹noConflictExtension before request›.2.1
                  simp [List.length_take, previousBound],
                by intro; exact accepted.1,
                by simp [successResponse],
                (by
                  intro _ same
                  have logEq :
                      before.log =
                        before.log.take request.prevLogIndex ++
                          request.entries := same.symm
                  nth_rewrite 1 [logEq]
                  simp [
                    ‹noConflictExtension before request›.2.1]),
                by intro; exact accepted.2.2.1,
                by simp [successResponse],
                (by
                  intro
                  simp [
                    successResponse, List.length_take,
                    ‹noConflictExtension before request›.2.1]),
                by simp [successResponse],
                by simp [successResponse],
                by simp [successResponse],
                by simp [successResponse]⟩
          · contradiction
        · split at handled
          · contradiction
          · rename_i truncated conflict
            unfold conflictAppendEntriesRequest? at conflict
            split at conflict
            · have truncatedEq := Option.some.inj conflict
              subst truncated
              split at handled
              · rename_i alreadyState alreadyResponse already
                unfold appendEntriesAlreadyDone? at already
                split at already
                · rename_i truncatedAlreadyDone
                  have pairEq :=
                    (Option.some.inj already).trans
                      (Option.some.inj handled)
                  have afterEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at afterEq responseEq
                  subst after
                  subst response
                  simp only [committedFromLeader]
                  exact
                    ⟨rfl, rfl, rfl, rfl, rfl, rfl,
                      Or.inr (Or.inl rfl),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · exact Or.inl zero
                        · exact Or.inr present.2),
                      Or.inr accepted.1,
                      (by
                        unfold NodeState.committedLog
                        rw [List.prefix_take_iff]
                        constructor
                        · exact List.take_prefix _ _
                        · simp [List.length_take]
                          omega),
                      (by
                        intro bound
                        apply committedFromLeader_bounded
                        simp [List.length_take]
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · omega),
                      le_max_left _ _,
                      committedFromLeader_le_max_requestEnd
                        before request
                          (before.log.take request.prevLogIndex),
                      committedFromLeader_le_max_leaderCommit
                        before request
                          (before.log.take request.prevLogIndex),
                      committedFromLeader_le_max_committable
                        before request
                          (before.log.take request.prevLogIndex),
                      (by
                        intro oldSignature positive
                        apply
                          committedFromLeader_isSignature
                            before request
                              (before.log.take request.prevLogIndex)
                        · intro oldPositive
                          apply committedSignature_retained before
                          · unfold NodeState.committedLog
                            rw [List.prefix_take_iff]
                            constructor
                            · exact List.take_prefix _ _
                            · simp [List.length_take]
                              omega
                          · exact oldSignature oldPositive
                        · exact positive),
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by intro; exact accepted.1,
                      by simp [successResponse],
                      (by
                        intro _ same
                        have done :
                            alreadyDone
                              { before with
                                log := before.log.take request.prevLogIndex
                                isNewFollower := false }
                              request := by
                          assumption
                        rcases done with empty | represented
                        · simp [empty]
                        · rw [← same]
                          exact represented.2),
                      by intro; exact accepted.2.2.1,
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse]⟩
                · contradiction
              · unfold noConflictAppendEntriesRequest? at handled
                split at handled
                · have pairEq := Option.some.inj handled
                  have afterEq := congrArg Prod.fst pairEq
                  have responseEq := congrArg Prod.snd pairEq
                  dsimp at afterEq responseEq
                  subst after
                  subst response
                  simp only [committedFromLeader]
                  refine
                    ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_,
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                      Or.inr (by
                        rcases accepted.2.2.1 with zero | present
                        · exact Or.inl zero
                        · exact Or.inr present.2),
                      Or.inr accepted.1,
                      (by
                        unfold NodeState.committedLog
                        simp only [List.take_take, Nat.min_self]
                        have first :
                            before.log.take before.commitIndex <+:
                              before.log.take request.prevLogIndex := by
                          rw [List.prefix_take_iff]
                          constructor
                          · exact List.take_prefix _ _
                          · simp only [List.length_take]
                            omega
                        exact first.trans
                          (List.prefix_append
                            (before.log.take request.prevLogIndex)
                            request.entries)),
                      (by
                        intro bound
                        apply committedFromLeader_bounded
                        simp [List.length_take, List.take_take]
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · omega),
                      le_max_left _ _,
                      committedFromLeader_le_max_requestEnd
                        before request
                          ((before.log.take request.prevLogIndex).take
                              request.prevLogIndex ++
                            request.entries),
                      committedFromLeader_le_max_leaderCommit
                        before request
                          ((before.log.take request.prevLogIndex).take
                              request.prevLogIndex ++
                            request.entries),
                      committedFromLeader_le_max_committable
                        before request
                          ((before.log.take request.prevLogIndex).take
                              request.prevLogIndex ++
                            request.entries),
                      (by
                        intro oldSignature positive
                        apply
                          committedFromLeader_isSignature
                            before request
                              ((before.log.take request.prevLogIndex).take
                                  request.prevLogIndex ++
                                request.entries)
                        · intro oldPositive
                          apply committedSignature_retained before
                          · unfold NodeState.committedLog
                            simp only [List.take_take, Nat.min_self]
                            have first :
                                before.log.take before.commitIndex <+:
                                  before.log.take
                                    request.prevLogIndex := by
                              rw [List.prefix_take_iff]
                              constructor
                              · exact List.take_prefix _ _
                              · simp only [List.length_take]
                                omega
                            exact first.trans
                              (List.prefix_append
                                (before.log.take request.prevLogIndex)
                                request.entries)
                          · exact oldSignature oldPositive
                        · exact positive),
                      by simp [successResponse],
                      by simp [successResponse],
                      by
                        intro
                        simp only [successResponse]
                        simp [List.length_take],
                      by intro; exact accepted.1,
                      by simp [successResponse],
                      (by
                        intro _ same
                        have logEq :
                            before.log =
                              (before.log.take request.prevLogIndex).take
                                  request.prevLogIndex ++ request.entries :=
                          same.symm
                        nth_rewrite 1 [logEq]
                        have previousBound :
                            request.prevLogIndex <= before.log.length := by
                          rcases accepted.2.2.1 with zero | present
                          · omega
                          · exact present.1
                        simp [
                          List.take_take, previousBound]),
                      by intro; exact accepted.2.2.1,
                      by simp [successResponse],
                      (by
                        intro
                        have previousBound :
                            request.prevLogIndex <= before.log.length := by
                          rcases accepted.2.2.1 with zero | present
                          · omega
                          · exact present.1
                        simp [
                          successResponse, List.take_take,
                          List.length_take, previousBound]),
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse],
                      by simp [successResponse]⟩
                  right
                  right
                  simp [List.take_take]
                · contradiction
            · contradiction
    · contradiction

/-- A node which is already a leader can only take a rejecting request branch. -/
lemma handleAppendEntriesRequestLeaderUnchanged
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (leader : before.role = .leader)
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    after = before := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      have beforeAfter := congrArg Prod.fst pairEq
      dsimp at beforeAfter
      exact beforeAfter.symm
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      exact Role.noConfusion (accepted.2.1.symm.trans leader)
    · contradiction

/-- A non-follower can only take the stale rejecting request branch. -/
lemma handleAppendEntriesRequestNonFollowerUnchanged
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse Node}
    (notFollower : Not (before.role = .follower))
    (handled :
      handleAppendEntriesRequest? before request = some (after, response)) :
    after = before := by
  unfold handleAppendEntriesRequest? at handled
  split at handled
  · rename_i rejectedState rejectedResponse rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · have pairEq :=
        (Option.some.inj rejected).trans (Option.some.inj handled)
      exact (congrArg Prod.fst pairEq).symm
    · contradiction
  · unfold acceptAppendEntriesRequest? at handled
    split at handled
    · rename_i accepted
      exact False.elim (notFollower accepted.2.1)
    · contradiction

section RetirementExamples

local instance : Bootstrap Bool where
  configuration := {false, true}
  leader := true
  leader_mem := by simp

private def retirementExampleNode : NodeState Bool Unit :=
  { freshNodeState with role := .follower, currentTerm := 1 }

private def retirementExampleRequest : AppendEntriesRequest Bool Unit where
  term := 1
  prevLogIndex := 0
  prevLogTerm := 0
  entries :=
    [ ⟨1, .reconfiguration {true}⟩,
      ⟨1, .retiredCommitted {false}⟩,
      ⟨1, .signature⟩,
      ⟨1, .signature⟩ ]
  leaderCommit := 4
  source := true
  destination := false

-- Marker 2 is first covered at signature 3, even when the batch commits to 4.
example :
    (handleAppendEntriesRequest? retirementExampleNode retirementExampleRequest).map
        (fun result =>
          (result.1.retiredCommittedIndex, result.1.commitIndex,
            result.1.membershipState)) =
      some (some 3, 4, .retiredCommitted) := by
  decide

-- The old unprojected-result equality incorrectly erased freshly derived metadata.
example :
    handleAppendEntriesRequest? (protocolNodeState retirementExampleNode)
        retirementExampleRequest ≠
      (handleAppendEntriesRequest? retirementExampleNode retirementExampleRequest).map
        withProtocolNodeState := by
  intro commutes
  have membership := congrArg
    (fun result => result.map (fun pair => pair.1.membershipState)) commutes
  change some MembershipState.retiredCommitted = some MembershipState.active at membership
  contradiction

example :
    (handleProposeVoteRequest? (initialState : State Bool Unit) false
        { term := BOOTSTRAP_TERM + 1, source := true, destination := false }).map
        (fun node => node.currentTerm) = some BOOTSTRAP_TERM := by
  decide

end RetirementExamples

end CCFRaft.Proofs.Abstract.HandlerProofs
