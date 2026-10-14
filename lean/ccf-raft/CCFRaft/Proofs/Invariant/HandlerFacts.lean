module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Invariant.NodeFacts
public import CCFRaft.Proofs.Ledger

@[expose] public section

set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node
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

section InitialConfig

variable [InitialConfig Node]
omit [DecidableEq TxId]

/-- A log prefix retains every known implicit or physical configuration. -/
lemma allConfigurations_mono_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    : allConfigurations (inferInstance) left
      <+: allConfigurations (inferInstance) right := by
  unfold allConfigurations configurationsInLog
  rcases configurationsInLogFrom_mono_prefix 1 isPrefix with
    ⟨suffix, agreed⟩
  exact ⟨suffix, by simp [agreed]⟩

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
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
    (known : configuration ∈ allConfigurations (inferInstance) log)
    (within : configuration.index <= frontier)
    : configuration ∈ allConfigurations (inferInstance) (log.take frontier) := by
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

omit [DecidableEq Node] [InitialConfig Node] in
/-- Physical configuration indices are strictly increasing. -/
lemma configurationsInLog_pairwise_index_lt (log : List (Entry Node TxId))
    : (configurationsInLog log).Pairwise
        (fun left right => left.index < right.index) := by
  simpa [configurationsInLog]
    using configurationsInLogFrom_pairwise_index_lt (TxId := TxId) 1 log

/-- The implicit index zero precedes every physical configuration index. -/
lemma allConfigurations_pairwise_index_lt (log : List (Entry Node TxId))
    : (allConfigurations (inferInstance) log).Pairwise
        (fun left right => left.index < right.index) := by
  rw [allConfigurations, List.pairwise_cons]
  constructor
  · intro configuration member
    have positive :=
      (configurationsInLog_index_bounds
        (TxId := TxId) log member).1
    simpa [implicitConfiguration] using positive
  · exact configurationsInLog_pairwise_index_lt (TxId := TxId) log

omit [InitialConfig Node] in
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
    (leftMember : left ∈ allConfigurations (inferInstance) log)
    (rightMember : right ∈ allConfigurations (inferInstance) log)
    (sameIndex : left.index = right.index)
    : left = right :=
  pairwiseConfigurationIndex_unique
    (allConfigurations_pairwise_index_lt (TxId := TxId) log)
    leftMember rightMember sameIndex

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
/-- Appending a non-reconfiguration entry preserves projected configurations. -/
lemma configurationsInLog_append_nonreconfiguration
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (notReconfiguration : forall nodes, Not (entry.content = .reconfiguration nodes))
    : configurationsInLog (log ++ [entry]) = configurationsInLog log := by
  exact
    configurationsInLogFrom_append_nonreconfiguration
      (TxId := TxId) 1 log entry notReconfiguration

omit [DecidableEq Node] [InitialConfig Node] in
/-- Every projected configuration comes from a reconfiguration entry of the log. -/
lemma configurationsInLogFrom_entry {start : Nat} {log : List (Entry Node TxId)}
    {configuration : Configuration Node}
    (member : configuration ∈ configurationsInLogFrom start log)
    : ∃ entry ∈ log, entry.content = .reconfiguration configuration.nodes := by
  induction log generalizing start with
  | nil => simp [configurationsInLogFrom] at member
  | cons head tail inductionHypothesis =>
      unfold configurationsInLogFrom at member
      split at member
      · rename_i nodes content
        rcases List.mem_cons.mp member with rfl | rest
        · exact ⟨head, List.mem_cons_self, content⟩
        · obtain ⟨entry, inTail, eq⟩ := inductionHypothesis rest
          exact ⟨entry, List.mem_cons_of_mem _ inTail, eq⟩
      · obtain ⟨entry, inTail, eq⟩ := inductionHypothesis member
        exact ⟨entry, List.mem_cons_of_mem _ inTail, eq⟩

omit [DecidableEq Node] [InitialConfig Node] in
/-- Every reconfiguration entry of the log is projected to a configuration. -/
lemma configurationsInLogFrom_of_entry {start : Nat} {log : List (Entry Node TxId)}
    {entry : Entry Node TxId} {nodes : Finset Node}
    (member : entry ∈ log) (content : entry.content = .reconfiguration nodes)
    : ∃ configuration ∈ configurationsInLogFrom start log,
        configuration.nodes = nodes := by
  induction log generalizing start with
  | nil => simp at member
  | cons head tail inductionHypothesis =>
      rcases List.mem_cons.mp member with rfl | rest
      · exact ⟨{ index := start, nodes }, by simp [configurationsInLogFrom, content], rfl⟩
      · obtain ⟨configuration, inTail, eq⟩ := inductionHypothesis (start := start + 1) rest
        refine ⟨configuration, ?_, eq⟩
        unfold configurationsInLogFrom
        split <;> simp [inTail]

/-- Appending a non-reconfiguration entry preserves the current authority. -/
lemma currentConfigurationAt_append_nonreconfiguration
    (log : List (Entry Node TxId))
    (entry : Entry Node TxId)
    (commitIndex : Nat)
    (notReconfiguration : forall nodes, Not (entry.content = .reconfiguration nodes))
    : currentConfigurationAt (inferInstance) (log ++ [entry]) commitIndex
      = currentConfigurationAt (inferInstance) log commitIndex := by
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

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
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

omit [DecidableEq Node] [InitialConfig Node] in
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
    : currentConfiguration (inferInstance) state = implicitConfiguration (inferInstance)
      \/ currentConfiguration (inferInstance) state ∈ configurationsInLog state.log := by
  exact
    foldlSelectConfiguration_mem
      state.commitIndex
      (configurationsInLog state.log)
      (implicitConfiguration (inferInstance))

/-- The current configuration is always known from the local log. -/
lemma currentConfiguration_mem_allConfigurations (state : NodeState Node TxId)
    : currentConfiguration (inferInstance) state
      ∈ allConfigurations (inferInstance) state.log := by
  rcases
      currentConfiguration_eq_implicit_or_mem_configurationsInLog state with
    implicit | physical
  · simp [allConfigurations, implicit]
  · simp [allConfigurations, physical]

/-- The current configuration index never exceeds the local commit frontier. -/
lemma currentConfiguration_index_le_commitIndex (state : NodeState Node TxId)
    : (currentConfiguration (inferInstance) state).index <= state.commitIndex := by
  exact foldlSelectConfiguration_index_le
    state.commitIndex
    (configurationsInLog state.log)
    (implicitConfiguration (inferInstance))
    (by simp [implicitConfiguration])

/--
The current configuration has the greatest known configuration index at or
before the local commit frontier.
-/
lemma configuration_index_le_currentConfiguration
    (state : NodeState Node TxId)
    (configuration : Configuration Node)
    (known : configuration ∈ allConfigurations (inferInstance) state.log)
    (committed : configuration.index <= state.commitIndex)
    : configuration.index <= (currentConfiguration (inferInstance) state).index := by
  rw [allConfigurations] at known
  rcases List.mem_cons.mp known with implicit | physical
  · subst configuration
    simp [implicitConfiguration]
  · have afterImplicit :
        forall candidate,
          candidate ∈ configurationsInLog state.log ->
            (implicitConfiguration (inferInstance) (Node := Node)).index <
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
        (implicitConfiguration (inferInstance))
        afterImplicit
        (configurationsInLog_pairwise_index_lt
          (TxId := TxId) state.log)
        physical
        committed

/-- The current configuration is one of the active configurations. -/
lemma currentConfiguration_mem_activeConfigurations (state : NodeState Node TxId)
    : currentConfiguration (inferInstance) state
      ∈ activeConfigurationsOf (inferInstance) state := by
  simp [
    activeConfigurationsOf,
    currentConfiguration_mem_allConfigurations
  ]

end InitialConfig

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

variable [InitialConfig Node]

/-- The model commit frontier, phrased with the proof-side majority predicate. -/
lemma highestCommittableIndex_eq (config : InitialConfig Node)
    (state : NodeState Node TxId) (self : Node)
    : highestCommittableIndex config state self
      = (List.range (state.log.length + 1)).foldl
          (fun best index =>
            if index > state.commitIndex
                /\ isSignatureAt state.log index = true
                /\ termAt state.log index = state.currentTerm
                /\ hasMajorityAt config state self index then
              max best index
            else
              best)
          0 := by
  simp [highestCommittableIndex, hasMajorityAt, acknowledgingNodes]

/-- The computed commit frontier never exceeds the leader log length. -/
lemma highestCommittableIndexBounded (state : Model.State Node TxId) (leader : Node)
    : highestCommittableIndex (inferInstance) (nodeOf state leader) leader
      <= ((nodeOf state) leader).log.length := by
  rw [highestCommittableIndex_eq]
  let candidates := List.range (((nodeOf state) leader).log.length + 1)
  let choose :=
    fun best index =>
      if index > ((nodeOf state) leader).commitIndex /\
          isSignatureAt ((nodeOf state) leader).log index = true /\
          termAt ((nodeOf state) leader).log index =
            ((nodeOf state) leader).currentTerm /\
          hasMajorityAt (inferInstance) (nodeOf state leader) leader index then
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
    (advances
      : ((nodeOf state) leader).commitIndex
        < highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
    : isSignatureAt ((nodeOf state) leader).log
          (highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
        = true
      /\ termAt ((nodeOf state) leader).log
            (highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
          = ((nodeOf state) leader).currentTerm
      /\ hasMajorityAt (inferInstance) (nodeOf state leader) leader
          (highestCommittableIndex (inferInstance) (nodeOf state leader) leader) := by
  rw [highestCommittableIndex_eq] at advances ⊢
  let leaderState := (nodeOf state) leader
  let valid :=
    fun index =>
      index > leaderState.commitIndex /\
        isSignatureAt leaderState.log index = true /\
        termAt leaderState.log index = leaderState.currentTerm /\
        hasMajorityAt (inferInstance) (nodeOf state leader) leader index
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
    (advances
      : ((nodeOf state) leader).commitIndex
        < highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
    : termAt ((nodeOf state) leader).log
          (highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
        = ((nodeOf state) leader).currentTerm
      /\ hasMajorityAt (inferInstance) (nodeOf state leader) leader
          (highestCommittableIndex (inferInstance) (nodeOf state leader) leader) :=
  (highestCommittableIndexFacts state leader advances).2

/-- A newly selected positive commit frontier points to a signature. -/
lemma highestCommittableIndexIsSignature
    (state : Model.State Node TxId)
    (leader : Node)
    (advances
      : ((nodeOf state) leader).commitIndex
        < highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
    : isSignatureAt ((nodeOf state) leader).log
        (highestCommittableIndex (inferInstance) (nodeOf state leader) leader)
      = true :=
  (highestCommittableIndexFacts state leader advances).1

end BootstrapCommit

/-! ## Generic local-handler facts -/

variable [InitialConfig Node]

omit [DecidableEq TxId] [InitialConfig Node] in
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

omit [DecidableEq TxId] [InitialConfig Node] in
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

omit [DecidableEq TxId] [InitialConfig Node] in
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

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
lemma appendEntriesNackMetadata (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : (appendEntriesNack before request).success = false := by
  unfold appendEntriesNack
  split <;> rfl

omit [InitialConfig Node] in
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

omit [InitialConfig Node] in
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

omit [InitialConfig Node] in
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

omit [InitialConfig Node] in
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

omit [InitialConfig Node] in
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

omit [InitialConfig Node] in
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

/-- The state after a same-term candidate steps down for an AppendEntries request. -/
def appendEntriesSteppedDown (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : NodeState Node TxId :=
  if request.term = state.currentTerm
      /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
    { state with role := .follower, isNewFollower := true }
  else
    state

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
/-- Stepping down only changes the role and the new-follower flag. -/
lemma appendEntriesSteppedDown_eq (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : appendEntriesSteppedDown state request
      = {
        state with
          role := (appendEntriesSteppedDown state request).role
          isNewFollower := (appendEntriesSteppedDown state request).isNewFollower
      } := by
  unfold appendEntriesSteppedDown
  split <;> rfl

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
lemma appendEntriesSteppedDown_of_not
    {state : NodeState Node TxId} {request : AppendEntriesRequest Node TxId}
    (notStepped
      : ¬ (request.term = state.currentTerm
            ∧ (state.role = .candidate ∨ state.role = .preVoteCandidate)))
    : appendEntriesSteppedDown state request = state := by
  simp only [appendEntriesSteppedDown, notStepped, ite_false]

/--
The three outcomes of the AppendEntries handler for a request that is not from
a newer term: a NACK, a dropped request, or the accepting branch.
-/
lemma handleAppendEntriesRequest_cases
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : Option AppendEntriesResponse}
    (notNewer : request.term <= before.currentTerm)
    (handled
      : handleAppendEntriesRequest (inferInstance) self before request
        = (after, response))
    : ((request.term < before.currentTerm \/ Not (appendEntryMatchesLog before request))
        /\ after = appendEntriesSteppedDown before request
        /\ response = some (appendEntriesNack before request))
      \/ (request.term = before.currentTerm
          /\ appendEntryMatchesLog before request
          /\ (request.prevLogIndex < before.commitIndex
              \/ (hasTermConflict before request
                  /\ (appendEntriesSteppedDown before request).isNewFollower = false))
          /\ after = { appendEntriesSteppedDown before request with leaderKnown := true }
          /\ response = none)
      \/ Exists
          fun accepted =>
            acceptAppendEntriesRequest? (inferInstance) self
                (appendEntriesSteppedDown before request) request
              = some (after, accepted)
            /\ response = some accepted := by
  have shape := appendEntriesSteppedDown_eq before request
  generalize steppedEq : appendEntriesSteppedDown before request = stepped at shape ⊢
  have unfolded :
      handleAppendEntriesRequest (inferInstance) self before request =
        if request.term < stepped.currentTerm \/ Not (appendEntryMatchesLog stepped request) then
          (stepped, some (appendEntriesNack stepped request))
        else
          if request.prevLogIndex < stepped.commitIndex
              \/ (hasTermConflict stepped request /\ !stepped.isNewFollower) then
            ({ stepped with leaderKnown := true }, none)
          else
            let state :=
              if hasTermConflict stepped request then
                {
                  stepped with
                    leaderKnown := true
                    log := stepped.log.take request.prevLogIndex
                    isNewFollower := false
                }
              else
                { stepped with leaderKnown := true }
            let (next, response) := handleAppendEntiresFromLeader (inferInstance) self state request
            (next, some response) := by
    rw [← steppedEq]
    rfl
  have logEq : stepped.log = before.log := by rw [shape]
  have termEq : stepped.currentTerm = before.currentTerm := by rw [shape]
  have commitEq : stepped.commitIndex = before.commitIndex := by rw [shape]
  have nackEq : appendEntriesNack stepped request = appendEntriesNack before request := by
    simp only [appendEntriesNack, logEq, termEq]
  rw [unfolded] at handled
  split_ifs at handled with nack drop conflict
  · left
    simp only [Prod.mk.injEq] at handled
    obtain ⟨rfl, rfl⟩ := handled
    simp only [appendEntryMatchesLog, logEq, termEq] at nack
    exact ⟨nack, rfl, by rw [nackEq]⟩
  · right
    left
    simp only [Prod.mk.injEq] at handled
    obtain ⟨rfl, rfl⟩ := handled
    simp only [appendEntryMatchesLog, hasTermConflict, logEq, termEq, commitEq] at nack drop ⊢
    refine ⟨by omega, by tauto, ?_⟩
    simpa using drop
  all_goals
    right
    right
    dsimp only at handled
    simp only [Prod.mk.injEq] at handled
    obtain ⟨rfl, rfl⟩ := handled
    refine ⟨_, ?_, rfl⟩
    unfold acceptAppendEntriesRequest?
    dsimp only
    split_ifs with accept
    all_goals first
      | rfl
      | (exfalso
         apply accept
         simp only [appendEntryMatchesLog, hasTermConflict, logEq, termEq, commitEq] at nack drop ⊢
         exact ⟨by omega, by tauto, by omega, by tauto⟩)

/-- Facts about the accepting AppendEntries branch. -/
lemma acceptAppendEntriesRequest_eq
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted
      : acceptAppendEntriesRequest? (inferInstance) self before request
        = some (after, response))
    : request.term = before.currentTerm
      /\ appendEntryMatchesLog before request
      /\ before.commitIndex <= request.prevLogIndex
      /\ ((Not (hasTermConflict before request)
            /\ after.log
                = before.log
                  ++ request.entries.drop (before.log.length - request.prevLogIndex))
          \/ (hasTermConflict before request
              /\ before.isNewFollower = true
              /\ after.log = before.log.take request.prevLogIndex ++ request.entries))
      /\ after.commitIndex = committedFromLeader before request after.log
      /\ after.role = before.role
      /\ after.currentTerm = before.currentTerm
      /\ after.sentIndex = before.sentIndex
      /\ after.matchIndex = before.matchIndex
      /\ after.votedFor = before.votedFor
      /\ after.votesGranted = before.votesGranted
      /\ after.preVotesGranted = before.preVotesGranted
      /\ after.leaderKnown = true
      /\ response
          = {
            term := before.currentTerm
            success := true
            lastLogIndex := request.prevLogIndex + request.entries.length
          } := by
  unfold acceptAppendEntriesRequest? at accepted
  split_ifs at accepted with guard
  obtain ⟨term, matching, committed, notBlocked⟩ := guard
  have previousBound : request.prevLogIndex <= before.log.length := by
    rcases matching with zero | ⟨bound, _⟩ <;> omega
  refine ⟨term, matching, committed, ?_⟩
  dsimp only at accepted
  split_ifs at accepted with conflict
  all_goals
    simp only [handleAppendEntiresFromLeader, refreshRetirementState, Option.some.injEq,
      Prod.mk.injEq] at accepted
    obtain ⟨rfl, rfl⟩ := accepted
  · refine ⟨Or.inr ⟨conflict, ?_, ?_⟩, ?_⟩
    · by_contra fresh
      exact notBlocked ⟨conflict, by simpa using fresh⟩
    · simp [List.length_take, previousBound]
    · simp [committedFromLeader, List.length_take, previousBound]
  · exact ⟨Or.inl ⟨conflict, rfl⟩, by simp [committedFromLeader], by simp⟩

/-- State facts needed from the accepting AppendEntries request branch. -/
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
      \/ after.log = before.log.take request.prevLogIndex ++ request.entries
      \/ after.log
          = before.log ++ request.entries.drop (before.log.length - request.prevLogIndex)
  successfulShape
    : response.success = true
      -> (Not (hasTermConflict before request)
            /\ after.log
                = before.log
                  ++ request.entries.drop (before.log.length - request.prevLogIndex))
          \/ (hasTermConflict before request
              /\ after.log = before.log.take request.prevLogIndex ++ request.entries)
  successfulUnchangedEntryTerms
    : response.success = true -> after.log = before.log
      -> ((before.log.drop request.prevLogIndex).take request.entries.length).map
            Entry.term
          = request.entries.map Entry.term
  previousCommittedPrefix : before.committedLog <+: after.log
  commitIndexBounded
    : before.commitIndex <= before.log.length -> after.commitIndex <= after.log.length
  commitIndexMonotone : before.commitIndex <= after.commitIndex
  commitRequestEndBound
    : after.commitIndex
      <= max before.commitIndex (request.prevLogIndex + request.entries.length)
  commitUpperBound : after.commitIndex <= max before.commitIndex request.leaderCommit
  commitIndexSignature
    : (0 < before.commitIndex -> isSignatureAt before.log before.commitIndex = true)
      -> 0 < after.commitIndex -> isSignatureAt after.log after.commitIndex = true
  successfulIndexBound
    : response.success = true
      -> response.lastLogIndex <= request.prevLogIndex + request.entries.length
  successfulCurrentTerm : response.success = true -> request.term = before.currentTerm
  commitAdvancedSuccessful
    : before.commitIndex < after.commitIndex -> response.success = true
  successfulLogOk : response.success = true -> appendEntryMatchesLog before request
  successfulResponseTerm : response.success = true -> response.term = before.currentTerm
  successfulIndexExact
    : response.success = true
      -> response.lastLogIndex = request.prevLogIndex + request.entries.length
  failedResponse : response.success = false -> response = appendEntriesNack before request
  failedStateUnchanged : response.success = false -> after = before

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
/-- Matching terms over the whole request leave no term conflict. -/
lemma noConflictOfMappedTerms
    : forall (existing incoming : List (Entry Node TxId)),
        (existing.take incoming.length).map Entry.term = incoming.map Entry.term
        -> Not
            ((existing.zip incoming).any
                (fun (pair : Entry Node TxId × Entry Node TxId) =>
                  pair.1.term != pair.2.term)
              = true)
  | _, [], _ => by simp
  | [], _ :: _, terms => by simp at terms
  | head :: existing, first :: incoming, terms => by
      simp only [List.length_cons, List.take_succ_cons, List.map_cons, List.cons.injEq]
        at terms
      simp only [List.zip_cons_cons, List.any_cons, Bool.or_eq_true, bne_iff_ne, ne_eq,
        not_or, not_not]
      exact ⟨terms.1, noConflictOfMappedTerms existing incoming terms.2⟩

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
/-- Without a term conflict, the common prefix of a log and a request agrees on terms. -/
lemma overlapTermsOfNoConflict
    : forall (existing incoming : List (Entry Node TxId)),
        Not
          ((existing.zip incoming).any
              (fun (pair : Entry Node TxId × Entry Node TxId) =>
                pair.1.term != pair.2.term)
            = true)
        -> (existing.take incoming.length).map Entry.term
            = (incoming.take existing.length).map Entry.term
  | _, [], _ => by simp
  | [], _ :: _, _ => by simp
  | head :: existing, first :: incoming, noConflict => by
      simp only [List.zip_cons_cons, List.any_cons, Bool.or_eq_true, bne_iff_ne, ne_eq,
        not_or, not_not] at noConflict
      simp only [List.length_cons, List.take_succ_cons, List.map_cons, List.cons.injEq]
      exact ⟨noConflict.1, overlapTermsOfNoConflict existing incoming noConflict.2⟩

omit [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node] in
/-- Without a term conflict, the overlap of a log and a request agrees on terms. -/
lemma mappedTermsOfNoConflict
    : forall (existing incoming : List (Entry Node TxId)),
        incoming.length <= existing.length
        -> Not
            ((existing.zip incoming).any
                (fun (pair : Entry Node TxId × Entry Node TxId) =>
                  pair.1.term != pair.2.term)
              = true)
        -> (existing.take incoming.length).map Entry.term = incoming.map Entry.term
  | _, [], _, _ => by simp
  | [], _ :: _, bound, _ => by simp at bound
  | head :: existing, first :: incoming, bound, noConflict => by
      simp only [List.zip_cons_cons, List.any_cons, Bool.or_eq_true, bne_iff_ne, ne_eq,
        not_or, not_not] at noConflict
      simp only [List.length_cons, List.take_succ_cons, List.map_cons, List.cons.injEq]
      exact ⟨noConflict.1,
        mappedTermsOfNoConflict existing incoming (by simpa using bound) noConflict.2⟩

lemma acceptAppendEntriesRequestLocalPost
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted
      : acceptAppendEntriesRequest? (inferInstance) self before request
        = some (after, response))
    : AppendRequestLocalPost before after request response := by
  obtain ⟨term, matching, committed, shape, commitEq, role, currentTerm, sent, matchEq,
    voted, votes, -, -, rfl⟩ := acceptAppendEntriesRequest_eq accepted
  have previousBound : request.prevLogIndex <= before.log.length := by
    rcases matching with zero | ⟨bound, _⟩ <;> omega
  have retained : before.committedLog <+: after.log := by
    unfold NodeState.committedLog
    rcases shape with ⟨-, logEq⟩ | ⟨-, -, logEq⟩ <;> rw [logEq]
    · exact (List.take_prefix _ _).trans (List.prefix_append _ _)
    · rw [show before.log.take before.commitIndex =
          (before.log.take request.prevLogIndex).take before.commitIndex by
        rw [List.take_take, min_eq_left committed]]
      exact (List.take_prefix _ _).trans (List.prefix_append _ _)
  refine ⟨
    role,
    currentTerm,
    sent,
    matchEq,
    voted,
    votes,
    ?_,
    fun _ => ?_,
    fun _ => ?_,
    retained,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_,
    fun _ => le_rfl,
    fun _ => term,
    fun _ => rfl,
    fun _ => matching,
    fun _ => rfl,
    fun _ => rfl,
    fun failed => by simp at failed,
    fun failed => by simp at failed
  ⟩
  · rcases shape with ⟨-, logEq⟩ | ⟨-, -, logEq⟩
    · exact Or.inr (Or.inr logEq)
    · exact Or.inr (Or.inl logEq)
  · rcases shape with ⟨noConflict, logEq⟩ | ⟨conflict, -, logEq⟩
    · exact Or.inl ⟨noConflict, logEq⟩
    · exact Or.inr ⟨conflict, logEq⟩
  · intro unchanged
    rcases shape with ⟨noConflict, logEq⟩ | ⟨-, -, logEq⟩
    · rw [logEq] at unchanged
      have dropped := List.append_right_eq_self.mp unchanged
      rw [List.drop_eq_nil_iff] at dropped
      exact mappedTermsOfNoConflict _ _ (by simp; omega) noConflict
    · rw [← unchanged, logEq, List.drop_left' (by simp; omega), List.take_length]
  · intro bound
    rw [commitEq]
    apply committedFromLeader_bounded
    have := retained.length_le
    simp only [NodeState.committedLog, List.length_take] at this
    omega
  · rw [commitEq]
    exact le_max_left _ _
  · rw [commitEq]
    exact committedFromLeader_le_max_requestEnd before request after.log
  · rw [commitEq]
    exact committedFromLeader_le_max_leaderCommit before request after.log
  · intro oldSignature positive
    rw [commitEq] at positive ⊢
    apply committedFromLeader_isSignature _ _ _ _ positive
    intro oldPositive
    exact committedSignature_retained before after.log retained (oldSignature oldPositive)

lemma acceptAppendEntriesRequest_conditions
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (accepted
      : acceptAppendEntriesRequest? (inferInstance) self before request
        = some (after, response))
    : request.term = before.currentTerm
      ∧ appendEntryMatchesLog before request
      ∧ before.commitIndex ≤ request.prevLogIndex :=
  let facts := acceptAppendEntriesRequest_eq accepted
  ⟨facts.1, facts.2.1, facts.2.2.1⟩

/-- The NACK branch leaves the node unchanged. -/
lemma appendEntriesNackLocalPost (before : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : AppendRequestLocalPost before before request
        (appendEntriesNack before request) := by
  have failed := appendEntriesNackMetadata before request
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, Or.inl rfl, ?_, ?_, List.take_prefix _ _, id, le_rfl,
    le_max_left _ _, le_max_left _ _, id, ?_, ?_, ?_, ?_, ?_, ?_, fun _ => rfl, fun _ => rfl⟩
  all_goals intros; simp_all

/-- Every branch of the option-valued AppendEntries handler has the common local shape. -/
lemma handleAppendEntriesRequestLocalPost
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest? (inferInstance) self before request
        = some (after, response))
    : AppendRequestLocalPost before after request response := by
  unfold handleAppendEntriesRequest? at handled
  split_ifs at handled
  · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj handled)
    exact appendEntriesNackLocalPost before request
  · exact acceptAppendEntriesRequestLocalPost handled

/-- A successful response of the option-valued handler comes from the accepting branch. -/
lemma acceptedOfSuccess
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (handled
      : handleAppendEntriesRequest? (inferInstance) self before request
        = some (after, response))
    (success : response.success = true)
    : acceptAppendEntriesRequest? (inferInstance) self before request
      = some (after, response) := by
  unfold handleAppendEntriesRequest? at handled
  split_ifs at handled
  · obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj handled)
    simp [appendEntriesNackMetadata] at success
  · exact handled

/-- Every entry of a handled node's log was already there or came with the request. -/
lemma AppendRequestLocalPost.logMember
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (post : AppendRequestLocalPost before after request response)
    {entry : Entry Node TxId} (member : entry ∈ after.log)
    : entry ∈ before.log ∨ entry ∈ request.entries := by
  rcases post.logShape with shape | shape | shape <;> rw [shape] at member
  · exact Or.inl member
  · exact (List.mem_append.mp member).imp List.mem_of_mem_take id
  · exact (List.mem_append.mp member).imp id List.mem_of_mem_drop

/-- Node carriers of the old log's and the request's configurations cover the new log's. -/
lemma AppendRequestLocalPost.configurationCarried
    {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {response : AppendEntriesResponse}
    (post : AppendRequestLocalPost before after request response)
    {carrier : Finset Node}
    (old
      : forall configuration,
          configuration ∈ allConfigurations (inferInstance) before.log
          -> configuration.nodes ⊆ carrier)
    (learned
      : forall configuration,
          configuration ∈ allConfigurations (inferInstance) request.entries
          -> configuration.nodes ⊆ carrier)
    {configuration : Configuration Node}
    (member : configuration ∈ allConfigurations (inferInstance) after.log)
    : configuration.nodes ⊆ carrier := by
  rcases List.mem_cons.mp member with rfl | physical
  · exact old _ List.mem_cons_self
  · obtain ⟨entry, inLog, content⟩ := configurationsInLogFrom_entry physical
    rcases post.logMember inLog with inOld | inNew
    · obtain ⟨found, inOld, foundEq⟩ := configurationsInLogFrom_of_entry (start := 1) inOld content
      exact foundEq ▸ old found (List.mem_cons_of_mem _ inOld)
    · obtain ⟨found, inNew, foundEq⟩ := configurationsInLogFrom_of_entry (start := 1) inNew content
      exact foundEq ▸ learned found (List.mem_cons_of_mem _ inNew)

/--
The model handler of a node that does not step down either answers as the
option-valued handler does, or drops the request and records a known leader.
-/
lemma handleAppendEntriesRequest_option
    {self : Node} {before after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {response : Option AppendEntriesResponse}
    (notNewer : request.term <= before.currentTerm)
    (notStepped
      : ¬ (request.term = before.currentTerm
            ∧ (before.role = .candidate ∨ before.role = .preVoteCandidate)))
    (handled
      : handleAppendEntriesRequest (inferInstance) self before request
        = (after, response))
    : (Exists
        fun answer =>
          response = some answer
          /\ handleAppendEntriesRequest? (inferInstance) self before request
              = some (after, answer))
      \/ (response = none
          /\ handleAppendEntriesRequest? (inferInstance) self before request = none
          /\ after = { before with leaderKnown := true }) := by
  have stepped := appendEntriesSteppedDown_of_not notStepped
  rcases handleAppendEntriesRequest_cases notNewer handled with
    ⟨nack, rfl, rfl⟩ | ⟨term, matching, drop, rfl, rfl⟩ | ⟨accepted, acceptEq, rfl⟩
  · left
    refine ⟨_, rfl, ?_⟩
    simp only [handleAppendEntriesRequest?, stepped, nack, ite_true]
  · right
    refine ⟨rfl, ?_, by rw [stepped]⟩
    rw [stepped] at drop
    have notNack : Not (request.term < before.currentTerm \/ Not (appendEntryMatchesLog before request)) := by
      omega
    simp only [handleAppendEntriesRequest?, notNack, ite_false, acceptAppendEntriesRequest?]
    split_ifs with guard
    · exfalso
      obtain ⟨-, -, committed, notBlocked⟩ := guard
      rcases drop with early | ⟨conflict, fresh⟩
      · omega
      · exact notBlocked ⟨conflict, by simp [fresh]⟩
    · rfl
  · left
    refine ⟨_, rfl, ?_⟩
    rw [stepped] at acceptEq
    have conditions := acceptAppendEntriesRequest_conditions acceptEq
    have notNack : Not (request.term < before.currentTerm \/ Not (appendEntryMatchesLog before request)) := by
      omega
    simp only [handleAppendEntriesRequest?, notNack, ite_false]
    exact acceptEq

end CCFRaft.Proofs.Invariant
