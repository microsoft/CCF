module

public import CCFRaft.Proofs.Config
public import Mathlib.Tactic

@[expose] public section

set_option linter.unusedSectionVars false

/-! Lemmas about node-level log functions, shared by every proof. -/

namespace CCFRaft.Proofs.Ledger

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node

@[simp]
lemma EntryContent.isSignature_eq_true {content : EntryContent}
    : content.isSignature = true <-> content = .signature := by
  cases content <;> simp [EntryContent.isSignature]

/-- A successful one-based lookup proves the index lies within the log. -/
lemma entryAtSomeIndexBound
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : index <= log.length := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    omega

/-- A successful one-based lookup is membership evidence. -/
lemma entryAt_mem
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, value⟩
    rw [← value]
    exact List.getElem_mem within

/-- A successful lookup is unchanged when the log is extended at the end. -/
lemma entryAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry}
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
    {log : List Entry}
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
lemma maxCommittableIndexBounded (log : List Entry)
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
    {log : List Entry}
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
    {log : List Entry}
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
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true)
    : isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
lemma maxCommittableIndex_le_of_prefix
    {left right : List Entry}
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
    {log : List Entry}
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
lemma maxCommittableIndexUpTo_le_frontier (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= frontier := by
  unfold maxCommittableIndexUpTo
  exact (maxCommittableIndexBounded (log.take frontier)).trans (by simp)

/-- The bounded committable frontier does not exceed the complete log. -/
lemma maxCommittableIndexUpTo_le_length (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  omega

/-- Restricting the search frontier cannot reveal a later signature. -/
lemma maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= maxCommittableIndex log := by
  unfold maxCommittableIndexUpTo
  exact
    maxCommittableIndex_le_of_prefix
      (List.take_prefix frontier log)

/-- A positive bounded committable frontier points to a signature in the log. -/
lemma maxCommittableIndexUpToPositiveIsSignature
    {log : List Entry}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier)
    : isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

lemma configurationHistory_filterMap (index : Nat) (log : List Entry)
    : (log.zipIdx index).filterMap
        (fun (entry, index) =>
          entry.content.metadata.configuration.map
            (fun nodes => ({ index, nodes } : Configuration)))
      = configurationsInLogFrom index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry entries ih =>
      rcases entry with ⟨term, content⟩
      cases h : content.metadata.configuration <;>
        simp [configurationsInLogFrom, h, ih]

@[simp]
lemma configurationHistory_eq (log : List Entry)
    : configurationHistory log = configurationsInLog log := by
  simp only [configurationHistory, configurationsInLog]
  exact configurationHistory_filterMap 1 log

lemma foldl_current_index (commitIndex : Nat) (configurations : List Configuration)
    (current : Configuration)
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
lemma activeConfigurations_eq (state : NodeState)
    : Model.Node.activeConfigurations state.log state.commitIndex
      = activeConfigurationsOf state := by
  rfl

@[simp]
lemma NodeState.activeConfigurations_eq (state : NodeState)
    : state.activeConfigurations = activeConfigurationsOf state :=
  CCFRaft.Proofs.Ledger.activeConfigurations_eq state

@[simp]
lemma NodeState.activeMembers_eq (state : NodeState)
    : state.activeMembers = activeNodeUnion state := by
  simp [Model.Node.NodeState.activeMembers, activeNodeUnion, configurationMembers]

/-- Recording a commit changes the commit index and retirement latch, and may
clear the role and primary knowledge. -/
lemma NodeState.recordCommit_eq (node : NodeID) (state : NodeState) (index : Nat)
    : exists retiredCommittedIndex role primaryKnown,
        state.recordCommit node index
          = { state with commitIndex := index, retiredCommittedIndex, role, primaryKnown }
        /\ (role = state.role \/ role = .none) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · exact ⟨_, _, _, rfl, Or.inr rfl⟩
  · exact ⟨_, _, _, rfl, Or.inl rfl⟩

/-- Recording a commit clears the role only once the node's retirement is committed. -/
lemma NodeState.recordCommit_role (node : NodeID) (state : NodeState) (index : Nat)
    : (state.recordCommit node index).role = state.role
      \/ ((state.recordCommit node index).role = .none
          /\ (state.recordCommit node index).isRetiredCommitted node) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · rename_i retired
    refine Or.inr ⟨rfl, ?_⟩
    have := retired.2
    simp only [NodeState.isRetiredCommitted, NodeState.retirement] at this ⊢
    exact this
  · exact Or.inl rfl

@[simp]
lemma NodeState.recordCommit_log (node : NodeID) (state : NodeState) (index : Nat)
    : (state.recordCommit node index).log = state.log := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

@[simp]
lemma NodeState.recordCommit_commitIndex (node : NodeID) (state : NodeState) (index : Nat)
    : (state.recordCommit node index).commitIndex = index := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

/-- Extending a log cannot move its bounded committable frontier backwards. -/
lemma maxCommittableIndexUpTo_mono {left right : List Entry}
    (isPrefix : left <+: right) (frontier : Nat)
    : maxCommittableIndexUpTo left frontier <= maxCommittableIndexUpTo right frontier :=
  maxCommittableIndex_le_of_prefix (isPrefix.take frontier)

/-- The follower append loop changes only the log, commit and retirement
fields, and may clear the role. -/
lemma fromLeader_loop (self : NodeID) (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        exists commitIndex retiredCommittedIndex role primaryKnown,
          entries.foldl
              (fun state entry =>
                let state := { state with log := state.log ++ [entry] }
                if entry.content.isSignature then
                  state.recordCommit self
                    (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
                else
                  state)
              state
            = {
              state with
                log := state.log ++ entries,
                commitIndex,
                retiredCommittedIndex,
                role,
                primaryKnown
            }
          /\ (role = state.role \/ role = .none)
          /\ state.commitIndex <= commitIndex
          /\ commitIndex
              <= max state.commitIndex
                  (maxCommittableIndexUpTo (state.log ++ entries) limit) := by
  induction entries with
  | nil =>
      intro state
      exact ⟨
        state.commitIndex,
        state.retiredCommittedIndex,
        state.role,
        state.primaryKnown,
        by simp,
        Or.inl rfl,
        le_rfl,
        le_max_left _ _
      ⟩
  | cons entry entries ih =>
      intro state
      simp only [List.foldl_cons]
      have mono :=
        maxCommittableIndexUpTo_mono (List.prefix_append (state.log ++ [entry]) entries) limit
      simp only [List.append_assoc, List.cons_append, List.nil_append] at mono
      by_cases signature : entry.content.isSignature
      · simp only [signature, ↓reduceIte]
        obtain ⟨retired₀, role₀, known₀, eq₀, roleCase₀⟩ :=
          NodeState.recordCommit_eq self { state with log := state.log ++ [entry] }
            (max state.commitIndex
              (maxCommittableIndexUpTo (state.log ++ [entry]) limit))
        rw [eq₀]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        refine ⟨commitIndex, retired, role, known, rfl, ?_, by omega, by omega⟩
        rcases roleCase with same | none
        · rw [same]
          exact roleCase₀
        · exact Or.inr none
      · simp only [signature, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        exact ⟨commitIndex, retired, role, known, rfl, roleCase, lower, by omega⟩

/--
Intermediate commits use prefixes of the final log, so the follower's final
commit index is the bounded committable frontier of the extended log.
-/
lemma handleAppendEntiresFromPrimary_eq (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let log :=
        state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      exists retiredCommittedIndex role primaryKnown,
        handleAppendEntiresFromPrimary self state request
          = (
            {
              state with
                log
                commitIndex :=
                  max state.commitIndex
                    (maxCommittableIndexUpTo log
                      (min request.primaryCommit
                        (request.prevLogIndex + request.entries.length)))
                retiredCommittedIndex
                role
                primaryKnown
            },
            {
              term := state.currentTerm
              success := true
              lastLogIndex := request.prevLogIndex + request.entries.length
            }
          )
        /\ (role = state.role \/ role = .none) := by
  intro log
  obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ :=
    fromLeader_loop self
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
      (request.entries.drop (state.log.length - request.prevLogIndex)) state
  unfold handleAppendEntiresFromPrimary
  dsimp only
  rw [eq]
  obtain ⟨retired', role', known', eq', roleCase'⟩ := NodeState.recordCommit_eq self _ _
  rw [eq']
  refine ⟨retired', role', known', ?_, ?_⟩
  · simp only [log]
    congr 2
    omega
  · rcases roleCase' with same | none
    · rw [same]
      exact roleCase
    · exact Or.inr none

/-- A rollback point lies after the request's previous index. -/
lemma firstTermConflictIndex_ge {state : NodeState} {request : AppendEntriesRequest}
    {index : Nat} (conflict : firstTermConflictIndex state request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold firstTermConflictIndex at conflict
  obtain ⟨pair, found, rfl⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨_, offset, lt, rfl, _⟩ := List.find?_eq_some_iff_getElem.mp found
  simp

end CCFRaft.Proofs.Ledger
