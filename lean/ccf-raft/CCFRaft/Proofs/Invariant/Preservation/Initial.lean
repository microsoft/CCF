-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Frames
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

attribute [local simp] Message.destination ConfigurationCoverageWitness.sharedPrefix

/-- Empty initial commits and network queues need no commit evidence. -/
lemma initialCommitEvidenceFacts
    (appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId))
    : Exists
        fun nodeEvidence : NodeCommitEvidence Node TxId =>
          Exists
            fun requestEvidence : RequestCommitEvidence Node TxId =>
              CommitEvidenceFacts
                (({
                      nodes := initialNodeState,
                      network := fun _ => [],
                      hasJoined := INITIAL_CONFIGURATION
                    }
                    : View Node TxId)
                  : View Node TxId)
                appendHistory nodeEvidence requestEvidence := by
  let nodeEvidence : NodeCommitEvidence Node TxId :=
    fun _ => none
  let requestEvidence : RequestCommitEvidence Node TxId :=
    fun _ => none
  refine ⟨nodeEvidence, requestEvidence, ?_⟩
  constructor
  · intro node positive
    simp [initialNodeState] at positive
  · intro destination request member
    simp [] at member

/-- The proof-only maps are empty in the deterministic initial state. -/
lemma initialSystemInductiveInvariant
    : SystemInductiveInvariant
        (({
              nodes := initialNodeState,
              network := fun _ => [],
              hasJoined := INITIAL_CONFIGURATION
            }
            : View Node TxId)
          : View Node TxId) := by
  let votes : VoteHistory (Node : Type) := fun _ _ => none
  let appendHistory : AppendEntriesRequest Node TxId -> List (Entry Node TxId) :=
    fun _ => []
  let responseHistory : AppendEntriesResponse Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteRequestHistory : RequestVoteRequest Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteCandidateHistory : RequestVoteResponse Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteVoterHistory : RequestVoteResponse Node -> List (Entry Node TxId) :=
    fun _ => []
  refine ⟨
    votes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  have initialLeaderMember :
      Membership.mem
        (INITIAL_CONFIGURATION (Node := Node))
        (INITIAL_LEADER (Node := Node)) :=
    initialLeader_mem_initialConfiguration (Node := Node)
  constructor
  · simp [CommitIndicesBounded, initialNodeState]
  · intro node participating
    by_cases member : node ∈ INITIAL_CONFIGURATION
    · simp [initialNodeState, member, BOOTSTRAP_TERM]
    · have notLeader : Not (node = INITIAL_LEADER) := by
        intro leader
        subst node
        exact member initialLeaderMember
      simp [
        initialNodeState, member, notLeader
      ] at participating
  · simp [
      EntriesDoNotExceedCurrentTerm,
      initialNodeState
    ]
  · intro node candidate
    by_cases leader : node = INITIAL_LEADER
    · simp [initialNodeState, leader] at candidate
    · by_cases member : node ∈ INITIAL_CONFIGURATION
      · simp [initialNodeState, leader, member] at candidate
      · simp [initialNodeState, leader, member] at candidate
  · intro leader role
    left
    by_cases leaderInitial : leader = INITIAL_LEADER
    · subst leader
      exact ⟨
        rfl,
        by
          simp [
            initialNodeState, initialLeaderMember
          ]
      ⟩
    · by_cases member : leader ∈ INITIAL_CONFIGURATION
      · simp [
          initialNodeState, leaderInitial, member
        ] at role
      · simp [
          initialNodeState, leaderInitial, member
        ] at role
  · intro leader role peer
    simp [initialNodeState]
  · constructor
    · intro voter
      rfl
    · intro voter
      simp only []
      simp [initialNodeState]
      rfl
    · intro voter term future
      rfl
    · intro candidate voter active member
      simp [initialNodeState] at member
  · constructor
    · simp []
    · simp []
    · simp []
    · simp []
    · simp []
  · let owners : TermOwners (Node : Type) :=
      fun term => if term = BOOTSTRAP_TERM then some INITIAL_LEADER else none
    let canonicalHistory : Nat -> List (Entry Node TxId) :=
      fun _ => []
    let elections : ElectionHistory Node TxId :=
      fun _ => none
    let activations : ActivationHistory Node TxId :=
      fun _ => none
    rcases initialCommitEvidenceFacts (Node := Node) appendHistory with
      ⟨nodeEvidence, requestEvidence, evidenceFacts⟩
    have noKnown :
        forall evidence supportedPrefix,
          KnownCommitEvidence
              ({ nodes := initialNodeState, network := fun _ => [], hasJoined := INITIAL_CONFIGURATION } : View Node TxId) appendHistory nodeEvidence requestEvidence
              evidence supportedPrefix ->
            False := by
      intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with ⟨node, positive, _, _⟩
        simp [initialNodeState] at positive
      · rcases requestKnown with
          ⟨destination, request, member, _⟩
        simp [] at member
    have prospectiveFacts :
        ProspectiveCommitEvidenceFacts
          ({ nodes := initialNodeState, network := fun _ => [], hasJoined := INITIAL_CONFIGURATION } : View Node TxId) appendHistory nodeEvidence requestEvidence elections := by
      constructor
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
    have activationHistoryFacts :
        ActivationHistoryFacts activations := by
      constructor <;> simp [activations]
    have activationEvidenceFacts :
        ActivationEvidenceFacts
          ({ nodes := initialNodeState, network := fun _ => [], hasJoined := INITIAL_CONFIGURATION } : View Node TxId) appendHistory responseHistory
            nodeEvidence requestEvidence
            elections activations := by
      constructor
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
      · intro left leftPrefix leftKnown
        exact False.elim (noKnown left leftPrefix leftKnown)
      · intro earlier earlierPrefix earlierKnown
        exact False.elim (noKnown earlier earlierPrefix earlierKnown)
      · intro left leftPrefix leftKnown
        exact False.elim (noKnown left leftPrefix leftKnown)
      · intro evidence supportedPrefix known
        exact False.elim (noKnown evidence supportedPrefix known)
    have activationCanonicalFacts :
        ActivationCanonicalFacts
          canonicalHistory owners activations := by
      constructor <;> simp [activations]
    have activationElectionFacts :
        ActivationElectionFacts votes elections activations := by
      constructor
      simp [activations]
    have activationVoteHistoryFacts :
        ActivationVoteHistory
          votes voteVoterHistory elections activations := by
      intro activationIndex activation
      simp [activations]
    have configurationActivationFacts :
        ConfigurationCoverageFacts ({ nodes := initialNodeState, network := fun _ => [], hasJoined := INITIAL_CONFIGURATION } : View Node TxId) activations := by
      intro node positive
      simp [
        initialNodeState,
        currentConfiguration, currentConfigurationAt,
        configurationsInLog, configurationsInLogFrom,
        implicitConfiguration
      ] at positive
    refine ⟨
      owners,
      canonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      activationVoteHistoryFacts,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_,
      activationCanonicalFacts,
      activationElectionFacts,
      configurationActivationFacts
    ⟩
    constructor
    · simp [owners]
    · intro leader role
      by_cases leaderInitial : leader = INITIAL_LEADER
      · subst leader
        simp [
          owners, initialNodeState, initialLeaderMember
        ]
      · simp [
          initialNodeState, leaderInitial
        ] at role
        split at role <;> contradiction
    · intro node index entry found
      simp [initialNodeState, entryAt?] at found
    · intro destination request member
      simp [] at member
    · intro leader role
      simp [
        canonicalHistory, initialNodeState
      ]
    · intro term index entry found
      simp [canonicalHistory, entryAt?] at found
    · intro term earlier later earlierEntry laterEntry order earlierFound
        laterFound
      simp [ canonicalHistory, entryAt?] at earlierFound
    · intro term owner owned
      simp [owners] at owned
      rcases owned with ⟨termEq, ownerEq⟩
      subst term
      subst owner
      simp [
        initialNodeState, initialLeaderMember
      ]
    · intro destination request member
      simp [] at member
    · intro destination request member
      simp [] at member
    · constructor
      · simp [elections]
      · intro term owner owned
        simp [owners] at owned
        exact Or.inl ⟨owned.1, owned.2.symm⟩
      all_goals simp [elections]
    · constructor
      · simp [elections]
      · simp [elections]
      · simp [elections]
      · simp [
          elections, activations,
          ActivationSupporterCurrentHistory
        ]
      · simp [elections]
      · intro left right leftRole
        by_cases leftEq : left = INITIAL_LEADER
        · subst left
          simp [initialNodeState] at leftRole
        · by_cases member : left ∈ INITIAL_CONFIGURATION
          · simp [initialNodeState, leftEq, member] at leftRole
          · simp [initialNodeState, leftEq, member] at leftRole
      · intro candidate role
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          simp [initialNodeState] at role
        · by_cases member : candidate ∈ INITIAL_CONFIGURATION
          · simp [
              initialNodeState, candidateEq, member
            ] at role
          · simp [
              initialNodeState, candidateEq, member
            ] at role
    · intro candidate voter active member
      simp [
        effectiveElectionVoters, queuedGrantedVote,
        initialNodeState
      ] at member
    · intro source index role current signature
      have impossible : False := by
        simp [
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro destination request member
      simp [] at member
    · intro index record recorded
      simp [activations] at recorded
    · constructor
      · exact activationHistoryFacts
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodeState] using signature
        simp [isSignatureAt, entryAt?] at impossible
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodeState] using signature
        simp [isSignatureAt, entryAt?] at impossible
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodeState] using signature
        simp [isSignatureAt, entryAt?] at impossible
      · intro left leftIndex role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) leftIndex = true := by
          simpa [initialNodeState] using signature
        simp [isSignatureAt, entryAt?] at impossible
      · intro _ _ destination request _ queued _
        simp [] at queued
      · intro node frontier within positive signature
        simp [
          initialNodeState,
          currentConfigurationAt, implicitConfiguration,
          configurationsInLog, configurationsInLogFrom
        ] at positive
      · intro destination request queued
        simp [] at queued
    · exact evidenceFacts
    · exact prospectiveFacts
    · exact activationEvidenceFacts
  · intro candidate voter active member
    simp [
      effectiveElectionVoters, queuedGrantedVote,
      initialNodeState
    ] at member
  · let ackHistory : ProcessedAckHistory Node TxId :=
      fun _ _ => none
    refine ⟨ackHistory, ?_⟩
    constructor
    · simp [ackHistory]
    · intro leader role peer positive
      simp [initialNodeState] at positive
  · constructor
    · intro node peer member
      simpa [
        initialNodeState, activeNodeUnion,
        activeConfigurations, currentConfiguration,
        currentConfigurationAt, allConfigurations,
        configurationsInLog, configurationsInLogFrom,
        implicitConfiguration
      ] using member
    · intro node configuration member peer inNodes
      simp [
        initialNodeState, allConfigurations,
        configurationsInLog, configurationsInLogFrom
      ] at member
      subst configuration
      simpa [implicitConfiguration] using inNodes
    · intro node peer member
      simp [initialNodeState] at member
    · intro destination request member
      simp [] at member
    · intro destination request member
      simp [] at member
    · intro destination request member
      simp [] at member
    · intro destination response member
      simp [] at member
    · constructor
      · intro node active
        by_cases same : node = INITIAL_LEADER
        · subst node
          exact initialLeaderMember
        · rcases active with candidate | leader
          · simp [initialNodeState, same] at candidate
            split at candidate <;> contradiction
          · simp [initialNodeState, same] at leader
            split at leader <;> contradiction
      · intro leader peer positive
        by_cases same : leader = INITIAL_LEADER <;>
          simp [initialNodeState, same] at positive
      · intro destination response member
        simp [] at member
      · intro node nonempty
        by_cases same : node = INITIAL_LEADER <;>
          simp [initialNodeState, same] at nonempty
  · exact fun _ => Iff.rfl
  · intro node
    by_cases member : node ∈ INITIAL_CONFIGURATION <;>
      simp [TermNumberValid, initialNodeState, member]
  · simp [NetworkTermsValid]

end CCFRaft.Proofs.Invariant
