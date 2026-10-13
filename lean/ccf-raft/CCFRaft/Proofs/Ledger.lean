-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Config
import Mathlib.Tactic

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-! Lemmas about node-level log functions, shared by every proof. -/

namespace CCFRaft.Proofs.Ledger

open CCFRaft.Proofs.Config

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM InitialConfig Configuration Entry EntryContent MembershipState NodeState
    PreVoteStatus Role becomeCandidateNodeState campaignEligible
    configurationHistory configurationMembers entryAt? findHighestPossibleMatch
    firstLogIndexAfter hasConfigurationMajority initialNodeState isSignatureAt
    lastCommittableIndex lastCommittableTerm maxCommittableIndex maxCommittableIndexUpTo
    maxCommittableTerm messageEntries refreshRetirementState retiredCommittedNodes
    retirementIndexInLog termAt
  )

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

omit [DecidableEq Node] [DecidableEq TxId] in
/-- A successful one-based lookup proves the index lies within the log. -/
lemma entryAtSomeIndexBound
    {log : List (Entry Node TxId)}
    {index : Nat}
    {entry : Entry Node TxId}
    (found : entryAt? log index = some entry)
    : index <= log.length := by
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
    (found : entryAt? log index = some entry)
    : entry ∈ log := by
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
    (found : entryAt? left index = some entry)
    : entryAt? right index = some entry := by
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

/-- A positive signature test identifies a concrete signature entry. -/
lemma isSignatureAtTrue
    {log : List (Entry Node TxId)}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : Exists
        fun entry =>
          entryAt? log index = some entry /\ entry.content = .signature := by
  cases found : entryAt? log index with
  | none =>
      simp [isSignatureAt, found] at signature
  | some entry =>
      refine ⟨entry, rfl, ?_⟩
      simpa [isSignatureAt, found] using signature

/-- The latest signature index lies within the log. -/
lemma maxCommittableIndexBounded (log : List (Entry Node TxId))
    : maxCommittableIndex log <= log.length := by
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
    (positive : 0 < maxCommittableIndex log)
    : isSignatureAt log (maxCommittableIndex log) = true := by
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
    (signature : isSignatureAt log index = true)
    : index <= maxCommittableIndex log := by
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
          exact (le_max_right best index).trans (foldAboveStart tail (max best index))
        · exact
            inductionHypothesis
              (choose best head) tailMember
  change index <= candidates.foldl choose 0
  exact foldContains candidates 0
    (by
      simp [candidates]
      omega)

/-- Extending a log preserves every earlier signature lookup. -/
lemma isSignatureAt_of_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true)
    : isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
lemma maxCommittableIndex_le_of_prefix
    {left right : List (Entry Node TxId)}
    (isPrefix : left <+: right)
    : maxCommittableIndex left <= maxCommittableIndex right := by
  by_cases zero : maxCommittableIndex left = 0
  · omega
  · have positive : 0 < maxCommittableIndex left :=
      Nat.pos_of_ne_zero zero
    exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_of_prefix isPrefix
          (maxCommittableIndexPositiveIsSignature positive))

/-- Taking a log prefix leaves lookups inside that prefix unchanged. -/
lemma isSignatureAt_take_of_le
    {log : List (Entry Node TxId)}
    {index count : Nat}
    (within : index <= count)
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take count) index = true := by
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
lemma maxCommittableIndexUpTo_le_frontier (log : List (Entry Node TxId)) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= frontier := by
  unfold maxCommittableIndexUpTo
  exact (maxCommittableIndexBounded (log.take frontier)).trans (by simp)

/-- The bounded committable frontier does not exceed the complete log. -/
lemma maxCommittableIndexUpTo_le_length (log : List (Entry Node TxId)) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  omega

/-- Restricting the search frontier cannot reveal a later signature. -/
lemma maxCommittableIndexUpTo_le (log : List (Entry Node TxId)) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= maxCommittableIndex log := by
  unfold maxCommittableIndexUpTo
  exact
    maxCommittableIndex_le_of_prefix
      (List.take_prefix frontier log)

/-- A positive bounded committable frontier points to a signature in the log. -/
lemma maxCommittableIndexUpToPositiveIsSignature
    {log : List (Entry Node TxId)}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier)
    : isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

lemma configurationHistory_filterMap (index : Nat) (log : List (Entry Node TxId))
    : (log.zipIdx index).filterMap
        (fun (entry, index) =>
          match entry.content with
          | .reconfiguration nodes => some ({ index, nodes } : Configuration Node)
          | _ => none)
      = configurationsInLogFrom index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry entries ih =>
      rcases entry with ⟨term, content⟩
      cases content <;> simp [configurationsInLogFrom, ih]

@[simp]
lemma configurationHistory_eq (config : InitialConfig Node) (log : List (Entry Node TxId))
    : configurationHistory config log = allConfigurations config log := by
  simp only [configurationHistory, allConfigurations, configurationsInLog,
    implicitConfiguration]
  congr 1
  exact configurationHistory_filterMap 1 log

lemma foldl_current_index (commitIndex : Nat) (configurations : List (Configuration Node))
    (current : Configuration Node)
    : (configurations.foldl
        (fun current configuration =>
          if configuration.index <= commitIndex then configuration else current)
        current).index
      = configurations.foldl
          (fun current configuration =>
            if configuration.index <= commitIndex then configuration.index else current)
          current.index := by
  induction configurations generalizing current with
  | nil => rfl
  | cons head tail ih =>
      simp only [List.foldl_cons]
      rw [ih]
      split <;> rfl

@[simp]
lemma activeConfigurations_eq (config : InitialConfig Node) (state : NodeState Node TxId)
    : Model.Local.activeConfigurations config state.log state.commitIndex
      = activeConfigurationsOf config state := by
  simp only [Model.Local.activeConfigurations, activeConfigurationsOf, currentConfiguration,
    currentConfigurationAt, configurationHistory_eq]
  simp [foldl_current_index, allConfigurations, implicitConfiguration]

@[simp]
lemma NodeState.activeConfigurations_eq (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : state.activeConfigurations config = activeConfigurationsOf config state :=
  CCFRaft.Proofs.Ledger.activeConfigurations_eq config state

@[simp]
lemma NodeState.activeMembers_eq (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : state.activeMembers config = activeNodeUnion config state := by
  simp [Model.Local.NodeState.activeMembers, activeNodeUnion, configurationMembers]

variable [InitialConfig Node]

@[simp]
lemma refreshRetirementState_log (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState (inferInstance) node state).log = state.log := by
  simp [refreshRetirementState]

@[simp]
lemma refreshRetirementState_commitIndex (node : Node) (state : NodeState Node TxId)
    : (refreshRetirementState (inferInstance) node state).commitIndex
      = state.commitIndex := by
  simp [refreshRetirementState]

end CCFRaft.Proofs.Ledger
