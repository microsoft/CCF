-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.NodeFacts
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

/-! ## Generic list, quorum, and message facts -/

/-- Every list is a prefix of itself. -/
lemma prefixRefl {Alpha : Type} (values : List Alpha) : values <+: values :=
  ⟨[], by simp⟩

/-- Taking the length of a known prefix recovers that prefix. -/
lemma prefixEqTake {Alpha : Type} {head values : List Alpha} (isPrefix : head <+: values)
    : values.take head.length = head := by
  rw [List.prefix_iff_eq_take] at isPrefix
  exact isPrefix.symm

/-- Two lists agree through any index lying inside their shared prefix. -/
lemma takeEqOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {count : Nat}
    (within : count <= left.length)
    : left.take count = right.take count := by
  rw [List.prefix_iff_eq_take] at isPrefix
  rw [isPrefix, List.take_take, Nat.min_eq_left within]

/-- Two prefixes of the same list are prefixes of each other. -/
lemma prefixesComparable
    {Alpha : Type}
    {left right common : List Alpha}
    (leftPrefix : left <+: common)
    (rightPrefix : right <+: common)
    : left <+: right \/ right <+: left := by
  by_cases leftShorter : left.length <= right.length
  · left
    have leftEq : right.take left.length = left := by
      calc
        right.take left.length = common.take left.length :=
          takeEqOfPrefix rightPrefix leftShorter
        _ = left := prefixEqTake leftPrefix
    have takenPrefix := List.take_prefix left.length right
    rwa [leftEq] at takenPrefix
  · right
    have rightShorter : right.length <= left.length := by omega
    have rightEq : left.take right.length = right := by
      calc
        left.take right.length = common.take right.length :=
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
    (rightMajority : hasConfigurationMajority right configuration)
    : Exists
        fun node =>
          node ∈ configuration.nodes /\ node ∈ left /\ node ∈ right := by
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
  exact ⟨
    node,
    (Finset.mem_inter.mp leftMember).2,
    (Finset.mem_inter.mp leftMember).1,
    (Finset.mem_inter.mp rightMember).1
  ⟩

/-- Enlarging a support set preserves a strict majority in one configuration. -/
lemma hasConfigurationMajority_mono
    {configuration : Configuration Node}
    {smaller larger : Finset Node}
    (subset : smaller ⊆ larger)
    (majority : hasConfigurationMajority smaller configuration)
    : hasConfigurationMajority larger configuration := by
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
    (majority : hasConfigurationMajority support configuration)
    : Exists
        fun node =>
          node ∈ configuration.nodes /\ node ∈ support := by
  have common :=
    configurationMajoritiesIntersect majority majority
  rcases common with ⟨node, configurationMember, supportMember, _⟩
  exact ⟨node, configurationMember, supportMember⟩

/-! ## Log-derived configuration facts -/

omit [DecidableEq Node] [DecidableEq TxId] in
/-- Projecting configurations distributes over log concatenation. -/
lemma configurationsInLogFrom_append (start : Nat) (left right : List (Entry Node TxId))
    : configurationsInLogFrom start (left ++ right)
      = configurationsInLogFrom start left
        ++ configurationsInLogFrom (start + left.length) right := by
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
    (isPrefix : left <+: right)
    : configurationsInLogFrom start left <+: configurationsInLogFrom start right := by
  rcases isPrefix with ⟨suffix, rfl⟩
  rw [configurationsInLogFrom_append]
  exact List.prefix_append _ _

section Bootstrap

variable [Bootstrap Node]
omit [DecidableEq TxId]

/-- A log prefix retains every known implicit or physical configuration. -/
lemma allConfigurations_mono_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    : allConfigurations left <+: allConfigurations right := by
  unfold allConfigurations configurationsInLog
  rcases configurationsInLogFrom_mono_prefix 1 isPrefix with
    ⟨suffix, agreed⟩
  exact ⟨suffix, by simp [agreed]⟩

omit [DecidableEq Node] [Bootstrap Node] in
/-- Every projected physical configuration index lies in its source interval. -/
lemma configurationsInLogFrom_index_bounds
    (start : Nat)
    (log : List (Entry Node TxId))
    {configuration : Configuration Node}
    (member : configuration ∈ configurationsInLogFrom start log)
    : start <= configuration.index /\ configuration.index < start + log.length := by
  induction log generalizing start with
  | nil =>
      simp [configurationsInLogFrom] at member
  | cons entry entries inductionHypothesis =>
      cases content : entry.content with
      | transaction txId =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by simpa [configurationsInLogFrom, content] using member)
          simp only [List.length_cons]
          omega
      | signature =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by simpa [configurationsInLogFrom, content] using member)
          simp only [List.length_cons]
          omega
      | retiredCommitted nodes =>
          have bounds :=
            inductionHypothesis (start := start + 1)
              (by simpa [configurationsInLogFrom, content] using member)
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
    (log : List (Entry Node TxId))
    : (configurationsInLogFrom start log).Pairwise
        (fun left right => left.index < right.index) := by
  induction log generalizing start with
  | nil =>
      simp [configurationsInLogFrom]
  | cons entry entries inductionHypothesis =>
      cases content : entry.content with
      | transaction txId =>
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
      | signature =>
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
      | retiredCommitted nodes =>
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
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
    (member : configuration ∈ configurationsInLog log)
    : 0 < configuration.index /\ configuration.index <= log.length := by
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
    (within : configuration.index <= frontier)
    : configuration ∈ allConfigurations (log.take frontier) := by
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
      simpa [configurationsInLog, List.take_append_drop]
        using configurationsInLogFrom_append
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
lemma configurationsInLog_pairwise_index_lt (log : List (Entry Node TxId))
    : (configurationsInLog log).Pairwise
        (fun left right => left.index < right.index) := by
  simpa [configurationsInLog]
    using configurationsInLogFrom_pairwise_index_lt (TxId := TxId) 1 log

/-- The implicit index zero precedes every physical configuration index. -/
lemma allConfigurations_pairwise_index_lt (log : List (Entry Node TxId))
    : (allConfigurations log).Pairwise (fun left right => left.index < right.index) := by
  rw [allConfigurations, List.pairwise_cons]
  constructor
  · intro configuration member
    have positive :=
      (configurationsInLog_index_bounds
        (TxId := TxId) log member).1
    simpa [implicitConfiguration] using positive
  · exact configurationsInLog_pairwise_index_lt (TxId := TxId) log

omit [Bootstrap Node] in
/-- A strictly index-ordered configuration list has unique index ownership. -/
private lemma pairwiseConfigurationIndex_unique
    {configurations : List (Configuration Node)}
    (ordered : configurations.Pairwise (fun left right => left.index < right.index))
    {left right : Configuration Node}
    (leftMember : left ∈ configurations)
    (rightMember : right ∈ configurations)
    (sameIndex : left.index = right.index)
    : left = right := by
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

/-- Every known configuration, including the implicit one, has a unique index. -/
lemma allConfigurations_index_unique
    (log : List (Entry Node TxId))
    {left right : Configuration Node}
    (leftMember : left ∈ allConfigurations log)
    (rightMember : right ∈ allConfigurations log)
    (sameIndex : left.index = right.index)
    : left = right :=
  pairwiseConfigurationIndex_unique
    (allConfigurations_pairwise_index_lt (TxId := TxId) log)
    leftMember rightMember sameIndex

omit [DecidableEq Node] [Bootstrap Node] in
/-- Appending a non-reconfiguration entry does not add a configuration. -/
lemma configurationsInLogFrom_append_nonreconfiguration
    (start : Nat)
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (notReconfiguration : forall nodes, Not (entry.content = .reconfiguration nodes))
    : configurationsInLogFrom start (log ++ [entry])
      = configurationsInLogFrom start log := by
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
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
      | signature =>
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
      | retiredCommitted nodes =>
          simpa [configurationsInLogFrom, content]
            using inductionHypothesis (start := start + 1)
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
    (notReconfiguration : forall nodes, Not (entry.content = .reconfiguration nodes))
    : configurationsInLog (log ++ [entry]) = configurationsInLog log := by
  exact
    configurationsInLogFrom_append_nonreconfiguration
      (TxId := TxId) 1 log entry notReconfiguration

/-- Appending a non-reconfiguration entry preserves the current authority. -/
lemma currentConfigurationAt_append_nonreconfiguration
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (commitIndex : Nat)
    (notReconfiguration : forall nodes, Not (entry.content = .reconfiguration nodes))
    : currentConfigurationAt (log ++ [entry]) commitIndex
      = currentConfigurationAt log commitIndex := by
  simp [
    currentConfigurationAt,
    configurationsInLog_append_nonreconfiguration
      (TxId := TxId) log entry notReconfiguration
  ]

/-- Select a configuration exactly when its physical index is committed. -/
private def selectConfiguration
    (commitIndex : Nat)
    (current configuration : Configuration Node)
    : Configuration Node :=
  if configuration.index <= commitIndex then configuration else current

omit [DecidableEq Node] [Bootstrap Node] in
/-- Selecting from a list returns the fallback or a member of the list. -/
private lemma foldlSelectConfiguration_mem
    (commitIndex : Nat)
    (configurations : List (Configuration Node))
    (fallback : Configuration Node)
    : configurations.foldl (selectConfiguration commitIndex) fallback = fallback
      \/ configurations.foldl (selectConfiguration commitIndex) fallback
          ∈ configurations := by
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
    (fallbackBound : fallback.index <= commitIndex)
    : (configurations.foldl (selectConfiguration commitIndex) fallback).index
      <= commitIndex := by
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
    (afterFallback
      : forall configuration,
          configuration ∈ configurations -> fallback.index < configuration.index)
    (ordered : configurations.Pairwise (fun left right => left.index < right.index))
    : fallback.index
      <= (configurations.foldl (selectConfiguration commitIndex) fallback).index := by
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
        exact (Nat.le_of_lt fallbackBeforeHead).trans
          (inductionHypothesis head ordered.1 ordered.2)
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
    (afterFallback
      : forall configuration,
          configuration ∈ configurations -> fallback.index < configuration.index)
    (ordered : configurations.Pairwise (fun left right => left.index < right.index))
    {configuration : Configuration Node}
    (member : configuration ∈ configurations)
    (committed : configuration.index <= commitIndex)
    : configuration.index
      <= (configurations.foldl (selectConfiguration commitIndex) fallback).index := by
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

/--
The current configuration is either implicit or one of the physical
configurations projected from the log.
-/
lemma currentConfiguration_eq_implicit_or_mem_configurationsInLog
    (state : NodeState Node TxId)
    : currentConfiguration state = implicitConfiguration
      \/ currentConfiguration state ∈ configurationsInLog state.log := by
  exact
    foldlSelectConfiguration_mem
      state.commitIndex
      (configurationsInLog state.log)
      implicitConfiguration

/-- The current configuration is always known from the local log. -/
lemma currentConfiguration_mem_allConfigurations (state : NodeState Node TxId)
    : currentConfiguration state ∈ allConfigurations state.log := by
  rcases
      currentConfiguration_eq_implicit_or_mem_configurationsInLog state with
    implicit | physical
  · simp [allConfigurations, implicit]
  · simp [allConfigurations, physical]

/-- The current configuration index never exceeds the local commit frontier. -/
lemma currentConfiguration_index_le_commitIndex (state : NodeState Node TxId)
    : (currentConfiguration state).index <= state.commitIndex := by
  exact foldlSelectConfiguration_index_le
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
    (committed : configuration.index <= state.commitIndex)
    : configuration.index <= (currentConfiguration state).index := by
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

/-- The current configuration is one of the active configurations. -/
lemma currentConfiguration_mem_activeConfigurations (state : NodeState Node TxId)
    : currentConfiguration state ∈ activeConfigurations state := by
  simp [
    activeConfigurations,
    currentConfiguration_mem_allConfigurations
  ]

end Bootstrap

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A bounded AppendEntries batch has exactly `batchEnd - previousIndex` entries. -/
lemma messageEntriesLength
    (log : List (Entry Node TxId))
    {previousIndex batchEnd : Nat}
    (ordered : previousIndex <= batchEnd)
    (within : batchEnd <= log.length)
    : (messageEntries log previousIndex batchEnd).length = batchEnd - previousIndex := by
  rw [← Nat.sub_add_cancel ordered] at within ⊢
  simp [
    messageEntries,
    List.length_take,
    List.length_drop
  ]
  omega

/-- Every member of a prefix is also a member of the larger list. -/
lemma memOfPrefix
    {Alpha : Type}
    {left right : List Alpha}
    (isPrefix : left <+: right)
    {value : Alpha}
    (member : value ∈ left)
    : value ∈ right := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  simp [member]

/-! ## Generic commit-frontier facts -/

section BootstrapCommit

variable [Bootstrap Node]

/-- The computed commit frontier never exceeds the leader log length. -/
lemma highestCommittableIndexBounded (state : Model.State Node TxId) (leader : Node)
    : highestCommittableIndex (nodeOf state leader) leader <= ((nodeOf state) leader).log.length := by
  unfold highestCommittableIndex
  let candidates := List.range (((nodeOf state) leader).log.length + 1)
  let choose :=
    fun best index =>
      if index > ((nodeOf state) leader).commitIndex /\
          isSignatureAt ((nodeOf state) leader).log index = true /\
          termAt ((nodeOf state) leader).log index =
            ((nodeOf state) leader).currentTerm /\
          hasMajorityAt (nodeOf state leader) leader index then
        max best index
      else
        best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= ((nodeOf state) leader).log.length := by
    intro index member
    simp [candidates] at member
    omega
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values ->
          index <= ((nodeOf state) leader).log.length) ->
        best <= ((nodeOf state) leader).log.length ->
        values.foldl choose best <=
          ((nodeOf state) leader).log.length := by
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
  change candidates.foldl choose 0 <= ((nodeOf state) leader).log.length
  exact foldBounded candidates 0 allBounded (by omega)

/-- A newly selected commit frontier satisfies every commit-selection guard. -/
lemma highestCommittableIndexFacts
    (state : Model.State Node TxId)
    (leader : Node)
    (advances : ((nodeOf state) leader).commitIndex < highestCommittableIndex (nodeOf state leader) leader)
    : isSignatureAt ((nodeOf state) leader).log (highestCommittableIndex (nodeOf state leader) leader) = true
      /\ termAt ((nodeOf state) leader).log (highestCommittableIndex (nodeOf state leader) leader)
          = ((nodeOf state) leader).currentTerm
      /\ hasMajorityAt (nodeOf state leader) leader (highestCommittableIndex (nodeOf state leader) leader) := by
  unfold highestCommittableIndex at advances ⊢
  let leaderState := (nodeOf state) leader
  let valid :=
    fun index =>
      index > leaderState.commitIndex /\
        isSignatureAt leaderState.log index = true /\
        termAt leaderState.log index = leaderState.currentTerm /\
        hasMajorityAt (nodeOf state leader) leader index
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
  · exact ⟨resultValid.2.1, resultValid.2.2.1, resultValid.2.2.2⟩

/-- A newly selected commit frontier satisfies the term and majority guards. -/
lemma highestCommittableIndexValid
    (state : Model.State Node TxId)
    (leader : Node)
    (advances : ((nodeOf state) leader).commitIndex < highestCommittableIndex (nodeOf state leader) leader)
    : termAt ((nodeOf state) leader).log (highestCommittableIndex (nodeOf state leader) leader)
        = ((nodeOf state) leader).currentTerm
      /\ hasMajorityAt (nodeOf state leader) leader (highestCommittableIndex (nodeOf state leader) leader) :=
  (highestCommittableIndexFacts state leader advances).2

/-- A newly selected positive commit frontier points to a signature. -/
lemma highestCommittableIndexIsSignature
    (state : Model.State Node TxId)
    (leader : Node)
    (advances : ((nodeOf state) leader).commitIndex < highestCommittableIndex (nodeOf state leader) leader)
    : isSignatureAt ((nodeOf state) leader).log (highestCommittableIndex (nodeOf state leader) leader)
      = true :=
  (highestCommittableIndexFacts state leader advances).1

end BootstrapCommit

/-! ## Generic local-handler facts -/

variable [Bootstrap Node]

omit [DecidableEq TxId] [Bootstrap Node] in
lemma handleAppendEntriesResponseNonLeaderUnchanged
    (before : NodeState Node TxId) (source : Node)
    (response : AppendEntriesResponse) (notLeader : before.role ≠ .leader)
    : handleAppendEntriesResponse before source response = before := by
  simp [handleAppendEntriesResponse, notLeader]

/-- Facts guaranteed after tallying a RequestVote response. -/
structure VoteResponseHandlerPost
    (before after : NodeState Node TxId)
    (source : Node) (response : RequestVoteResponse)
    : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  preVotesGrantedUnchanged : after.preVotesGranted = before.preVotesGranted
  membershipStateUnchanged : after.membershipState = before.membershipState
  retirementIndexUnchanged : after.retirementIndex = before.retirementIndex
  retirementCommittableIndexUnchanged
    : after.retirementCommittableIndex = before.retirementCommittableIndex
  retiredCommittedIndexUnchanged
    : after.retiredCommittedIndex = before.retiredCommittedIndex
  votesUpdate
    : after.votesGranted = before.votesGranted
      \/ (response.voteGranted = true
          /\ before.role = .candidate
          /\ after.votesGranted = insert source before.votesGranted)

omit [DecidableEq TxId] [Bootstrap Node] in
lemma handleRequestVoteResponsePreserves
    {before after : NodeState Node TxId} {source : Node}
    {response : RequestVoteResponse}
    (handled : handleRequestVoteResponse before source response = after)
    : VoteResponseHandlerPost before after source response := by
  subst after
  unfold handleRequestVoteResponse
  split_ifs with granted
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
      Or.inr ⟨granted.2.2, granted.1, rfl⟩⟩
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩

/-- Tallying a pre-vote response changes only the speculative vote set. -/
structure PreVoteResponseHandlerPost
    (before after : NodeState Node TxId)
    (source : Node) (response : RequestVoteResponse)
    : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  logUnchanged : after.log = before.log
  commitIndexUnchanged : after.commitIndex = before.commitIndex
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  isNewFollowerUnchanged : after.isNewFollower = before.isNewFollower
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  membershipStateUnchanged : after.membershipState = before.membershipState
  retirementIndexUnchanged : after.retirementIndex = before.retirementIndex
  retirementCommittableIndexUnchanged
    : after.retirementCommittableIndex = before.retirementCommittableIndex
  retiredCommittedIndexUnchanged
    : after.retiredCommittedIndex = before.retiredCommittedIndex
  preVotesUpdate
    : after.preVotesGranted = before.preVotesGranted
      \/ (response.voteGranted = true
          /\ response.term = before.currentTerm
          /\ before.role = .preVoteCandidate
          /\ after.preVotesGranted = insert source before.preVotesGranted)

omit [DecidableEq TxId] [Bootstrap Node] in
lemma handleRequestPreVoteResponsePreserves
    {before after : NodeState Node TxId} {source : Node}
    {response : RequestVoteResponse}
    (handled : handleRequestPreVoteResponse before source response = after)
    : PreVoteResponseHandlerPost before after source response := by
  subst after
  unfold handleRequestPreVoteResponse
  split_ifs with granted
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl,
      Or.inr ⟨granted.2.2, granted.2.1, granted.1, rfl⟩⟩
  · exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl⟩

lemma handleProposeVoteRequestCases
    (state : NodeState Node TxId) (destination : Node) (term : Nat)
    : handleProposeVoteRequest state destination term = state
      ∨ (term = state.currentTerm
        ∧ candidateTransitionEnabled state destination
        ∧ handleProposeVoteRequest state destination term
            = becomeCandidateNodeState state destination) := by
  unfold handleProposeVoteRequest
  split_ifs with eligible
  · exact Or.inr ⟨eligible.1, eligible.2, rfl⟩
  · exact Or.inl rfl

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
lemma failureResponseMetadata (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : (failureResponse before request).success = false := by
  unfold failureResponse
  split
  · rfl
  · dsimp
    split
    · rfl
    · split
      · rfl
      · split <;> rfl

omit [Bootstrap Node] in
/-- A follower commit learned from a request stays below the advertised
leader frontier, apart from an already committed local prefix. -/
lemma committedFromLeader_le_max_leaderCommit
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    : committedFromLeader before request newLog
      <= max before.commitIndex request.leaderCommit := by
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
    (newLog : List (Entry Node TxId))
    : committedFromLeader before request newLog
      <= max before.commitIndex (request.prevLogIndex + request.entries.length) := by
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
    (newLog : List (Entry Node TxId))
    : committedFromLeader before request newLog
      <= max before.commitIndex (maxCommittableIndex newLog) := by
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
    (oldBound : before.commitIndex <= newLog.length)
    : committedFromLeader before request newLog <= newLog.length := by
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
    (signature : isSignatureAt before.log before.commitIndex = true)
    : isSignatureAt newLog before.commitIndex = true := by
  apply isSignatureAt_of_prefix retainedPrefix
  unfold NodeState.committedLog
  exact isSignatureAt_take_of_le le_rfl signature

omit [Bootstrap Node] in
/-- Learning a follower commit preserves the signature-frontier invariant. -/
lemma committedFromLeader_isSignature
    (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId))
    (oldSignature
      : 0 < before.commitIndex -> isSignatureAt newLog before.commitIndex = true)
    (positive : 0 < committedFromLeader before request newLog)
    : isSignatureAt newLog (committedFromLeader before request newLog) = true := by
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
    (response : AppendEntriesResponse)
    : Prop where
  roleUnchanged : after.role = before.role
  currentTermUnchanged : after.currentTerm = before.currentTerm
  sentIndexUnchanged : after.sentIndex = before.sentIndex
  matchIndexUnchanged : after.matchIndex = before.matchIndex
  votedForUnchanged : after.votedFor = before.votedFor
  votesGrantedUnchanged : after.votesGranted = before.votesGranted
  logShape
    : after.log = before.log
      \/ after.log = before.log.take request.prevLogIndex
      \/ after.log = before.log.take request.prevLogIndex ++ request.entries
  logUnchangedOrPreviousBound
    : after.log = before.log \/ request.prevLogIndex <= before.log.length
  logUnchangedOrPreviousMatches
    : after.log = before.log
      \/ request.prevLogIndex = 0
      \/ termAt before.log request.prevLogIndex = request.prevLogTerm
  logUnchangedOrCurrentTerm : after.log = before.log \/ request.term = before.currentTerm
  previousCommittedPrefix : before.committedLog <+: after.log
  commitIndexBounded
    : before.commitIndex <= before.log.length -> after.commitIndex <= after.log.length
  commitIndexMonotone : before.commitIndex <= after.commitIndex
  commitRequestEndBound
    : after.commitIndex
      <= max before.commitIndex (request.prevLogIndex + request.entries.length)
  commitUpperBound : after.commitIndex <= max before.commitIndex request.leaderCommit
  commitCommittableBound
    : after.commitIndex <= max before.commitIndex (maxCommittableIndex after.log)
  commitIndexSignature
    : (0 < before.commitIndex -> isSignatureAt before.log before.commitIndex = true)
      -> 0 < after.commitIndex -> isSignatureAt after.log after.commitIndex = true
  successfulIndexBound
    : response.success = true
      -> response.lastLogIndex <= request.prevLogIndex + request.entries.length
  successfulCurrentTerm : response.success = true -> request.term = before.currentTerm
  commitAdvancedSuccessful
    : before.commitIndex < after.commitIndex -> response.success = true
  successfulUnchangedEntryTerms
    : response.success = true -> after.log = before.log
      -> ((before.log.drop request.prevLogIndex).take request.entries.length).map
            Entry.term
          = request.entries.map Entry.term
  successfulLogOk : response.success = true -> logOk before request
  successfulResponseTerm : response.success = true -> response.term = before.currentTerm
  successfulIndexExact
    : response.success = true
      -> response.lastLogIndex = request.prevLogIndex + request.entries.length
  failedResponse : response.success = false -> response = failureResponse before request
  failedStateUnchanged : response.success = false -> after = before
  failedRequestNotNewer : response.success = false -> request.term <= before.currentTerm
  failedSameTermNotLogOk
    : response.success = false -> request.term = before.currentTerm
      -> Not (logOk before request)

/-- Every successful AppendEntries handler branch has the common local shape. -/
lemma handleAppendEntriesRequestLocalPost
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse}
    (notStepped : ¬ (request.term = before.currentTerm
      ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)))
    (handled : handleAppendEntriesRequest? self before request = some (after, response))
    : AppendRequestLocalPost before after request response := by
  simp only [handleAppendEntriesRequest?, notStepped, ite_false] at handled
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
      exact ⟨
        rfl,
        rfl,
        rfl,
        rfl,
        rfl,
        rfl,
        Or.inl rfl,
        Or.inl rfl,
        Or.inl rfl,
        Or.inl rfl,
        List.take_prefix _ _,
        (by intro bound; exact bound),
        le_rfl,
        le_max_left _ _,
        le_max_left _ _,
        le_max_left _ _,
        (by intro oldSignature positive; exact oldSignature positive),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
        (by intro advanced; omega),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
        (by intro succeeded; rw [metadata] at succeeded; contradiction),
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
          · exact same.2.2)
      ⟩
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
          exact ⟨
            rfl,
            rfl,
            rfl,
            rfl,
            rfl,
            rfl,
            Or.inl rfl,
            Or.inl rfl,
            Or.inl rfl,
            Or.inl rfl,
            List.take_prefix _ _,
            (by
              intro bound
              exact
                committedFromLeader_bounded
                  before request before.log bound),
            le_max_left _ _,
            committedFromLeader_le_max_requestEnd before request before.log,
            committedFromLeader_le_max_leaderCommit before request before.log,
            committedFromLeader_le_max_committable before request before.log,
            (by
              intro oldSignature positive
              exact
                committedFromLeader_isSignature
                  before request before.log oldSignature positive),
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
            by simp [successResponse]
          ⟩
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
            exact ⟨
              rfl,
              rfl,
              rfl,
              rfl,
              rfl,
              rfl,
              Or.inr (Or.inr rfl),
              Or.inr ‹noConflictExtension before request›.2.1,
              Or.inr
                (by
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
                (before.log.take request.prevLogIndex ++ request.entries),
              committedFromLeader_le_max_leaderCommit
                before request
                (before.log.take request.prevLogIndex ++ request.entries),
              committedFromLeader_le_max_committable
                before request
                (before.log.take request.prevLogIndex ++ request.entries),
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
              by simp [successResponse]
            ⟩
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
                  exact ⟨
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    Or.inr (Or.inl rfl),
                    Or.inr
                      (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                    Or.inr
                      (by
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
                    by simp [successResponse]
                  ⟩
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
                  refine ⟨
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    rfl,
                    ?_,
                    Or.inr
                      (by
                        rcases accepted.2.2.1 with zero | present
                        · omega
                        · exact present.1),
                    Or.inr
                      (by
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
                      ((before.log.take request.prevLogIndex).take request.prevLogIndex
                        ++ request.entries),
                    committedFromLeader_le_max_leaderCommit
                      before request
                      ((before.log.take request.prevLogIndex).take request.prevLogIndex
                        ++ request.entries),
                    committedFromLeader_le_max_committable
                      before request
                      ((before.log.take request.prevLogIndex).take request.prevLogIndex
                        ++ request.entries),
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
                    by simp [successResponse]
                  ⟩
                  right
                  right
                  simp [List.take_take]
                · contradiction
            · contradiction
    · contradiction

/-- A node which is already a leader can only take a rejecting request branch. -/
lemma handleAppendEntriesRequestLeaderUnchanged
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : AppendEntriesResponse}
    (leader : before.role = .leader)
    (notStepped : ¬ (request.term = before.currentTerm
      ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)))
    (handled : handleAppendEntriesRequest? self before request = some (after, response))
    : after = before := by
  simp only [handleAppendEntriesRequest?, notStepped, ite_false] at handled
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


lemma handleAppendEntriesRequest_successfulCurrentTerm
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (handled : handleAppendEntriesRequest? self before request = some (after, response))
    (success : response.success = true)
    : request.term = before.currentTerm := by
  by_cases stepping : request.term = before.currentTerm
      ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)
  · exact stepping.1
  · exact (handleAppendEntriesRequestLocalPost stepping handled).successfulCurrentTerm success

lemma acceptAppendEntriesRequest_conditions
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted : acceptAppendEntriesRequest? self before request = some (after, response))
    : request.term = before.currentTerm ∧ before.role = .follower
      ∧ logOk before request ∧ before.commitIndex ≤ request.prevLogIndex := by
  unfold acceptAppendEntriesRequest? at accepted
  split at accepted
  · assumption
  · contradiction

lemma acceptAppendEntriesRequest_handled
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted : acceptAppendEntriesRequest? self before request = some (after, response))
    : handleAppendEntriesRequest? self before request = some (after, response) := by
  obtain ⟨term, role, matching, _⟩ := acceptAppendEntriesRequest_conditions accepted
  simpa [handleAppendEntriesRequest?, rejectAppendEntriesRequest?, term, role, matching] using accepted

lemma acceptAppendEntriesRequestLocalPost
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted : acceptAppendEntriesRequest? self before request = some (after, response))
    : AppendRequestLocalPost before after request response := by
  have follower := (acceptAppendEntriesRequest_conditions accepted).2.1
  exact handleAppendEntriesRequestLocalPost (by simp [follower])
    (acceptAppendEntriesRequest_handled accepted)

end CCFRaft.Proofs.Invariant
