-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Frames
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

/-- Empty initial commits and network queues need no commit evidence. -/
lemma initialCommitEvidenceFacts
    (state : Model.State Node TxId)
    (initialNodes : forall node, nodeOf state node = initialNodeState node)
    (networkEmpty : state.network = [])
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    : Exists
        fun nodeEvidence : NodeCommitEvidence Node TxId =>
          Exists
            fun requestEvidence : RequestCommitEvidence Node TxId =>
              CommitEvidenceFacts
                ((state
                    : Model.State Node TxId)
                  : Model.State Node TxId)
                appendHistory nodeEvidence requestEvidence := by
  let nodeEvidence : NodeCommitEvidence Node TxId :=
    fun _ => none
  let requestEvidence : RequestCommitEvidence Node TxId :=
    fun _ => none
  refine ⟨nodeEvidence, requestEvidence, ?_⟩
  constructor
  · intro node positive
    simp [initialNodes, networkEmpty, initialNodeState] at positive
  · intro destination request member
    simp [initialNodes, networkEmpty] at member

/-- The proof-only maps are empty in the deterministic initial state. -/
lemma initialSystemInductiveInvariant
    (state : Model.State Node TxId)
    (initialNodes : forall node, nodeOf state node = initialNodeState node)
    (networkEmpty : state.network = [])
    : SystemInductiveInvariant (joined := INITIAL_CONFIGURATION)
        ((state
            : Model.State Node TxId)
          : Model.State Node TxId) := by
  let votes : VoteHistory (Node : Type) := fun _ _ => none
  let appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId) :=
    fun _ => []
  let responseHistory : AppendResponseKey Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteCandidateHistory : VoteResponseKey Node -> List (Entry Node TxId) :=
    fun _ => []
  let voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId) :=
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
  · simp [initialNodes, networkEmpty, CommitIndicesBounded, initialNodeState]
  · intro node participating
    by_cases member : node ∈ INITIAL_CONFIGURATION
    · simp [initialNodes, networkEmpty, initialNodeState, member, BOOTSTRAP_TERM]
    · have notLeader : Not (node = INITIAL_LEADER) := by
        intro leader
        subst node
        exact member initialLeaderMember
      simp [initialNodes, networkEmpty, 
        initialNodeState, member, notLeader
      ] at participating
  · simp [initialNodes, networkEmpty, 
      EntriesDoNotExceedCurrentTerm,
      initialNodeState
    ]
  · intro node candidate
    by_cases leader : node = INITIAL_LEADER
    · simp [initialNodes, networkEmpty, initialNodeState, leader] at candidate
    · by_cases member : node ∈ INITIAL_CONFIGURATION
      · simp [initialNodes, networkEmpty, initialNodeState, leader, member] at candidate
      · simp [initialNodes, networkEmpty, initialNodeState, leader, member] at candidate
  · intro leader role
    left
    by_cases leaderInitial : leader = INITIAL_LEADER
    · subst leader
      exact ⟨
        rfl,
        by
          simp [initialNodes, networkEmpty, 
            initialNodeState, initialLeaderMember
          ]
      ⟩
    · by_cases member : leader ∈ INITIAL_CONFIGURATION
      · simp [initialNodes, networkEmpty, 
          initialNodeState, leaderInitial, member
        ] at role
      · simp [initialNodes, networkEmpty, 
          initialNodeState, leaderInitial, member
        ] at role
  · intro leader role peer
    simp [initialNodes, networkEmpty, initialNodeState]
  · constructor
    · intro voter
      rfl
    · intro voter
      simp only [initialNodes, networkEmpty]
      simp [initialNodes, networkEmpty, initialNodeState]
      rfl
    · intro voter term future
      rfl
    · intro candidate voter active member
      simp [initialNodes, networkEmpty, initialNodeState] at member
  · constructor
    · simp [initialNodes, networkEmpty]
    · simp [initialNodes, networkEmpty]
    · simp [initialNodes, networkEmpty]
    · simp [initialNodes, networkEmpty]
    · simp [initialNodes, networkEmpty]
  · let owners : TermOwners (Node : Type) :=
      fun term => if term = BOOTSTRAP_TERM then some INITIAL_LEADER else none
    let canonicalHistory : Nat -> List (Entry Node TxId) :=
      fun _ => []
    let elections : ElectionHistory Node TxId :=
      fun _ => none
    let activations : ActivationHistory Node TxId :=
      fun _ => none
    rcases initialCommitEvidenceFacts state initialNodes networkEmpty appendHistory with
      ⟨nodeEvidence, requestEvidence, evidenceFacts⟩
    have noKnown :
        forall evidence supportedPrefix,
          KnownCommitEvidence
              (state : Model.State Node TxId) appendHistory nodeEvidence requestEvidence
              evidence supportedPrefix ->
            False := by
      intro evidence supportedPrefix known
      rcases known with nodeKnown | requestKnown
      · rcases nodeKnown with ⟨node, positive, _, _⟩
        simp [initialNodes, networkEmpty, initialNodeState] at positive
      · rcases requestKnown with
          ⟨destination, request, member, _⟩
        simp [initialNodes, networkEmpty] at member
    have prospectiveFacts :
        ProspectiveCommitEvidenceFacts (joined := INITIAL_CONFIGURATION)
          (state : Model.State Node TxId) appendHistory nodeEvidence requestEvidence elections := by
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
      constructor <;> simp [initialNodes, networkEmpty, activations]
    have activationEvidenceFacts :
        ActivationEvidenceFacts (joined := INITIAL_CONFIGURATION)
          (state : Model.State Node TxId) appendHistory responseHistory
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
      constructor <;> simp [initialNodes, networkEmpty, activations]
    have activationElectionFacts :
        ActivationElectionFacts votes elections activations := by
      constructor
      simp [initialNodes, networkEmpty, activations]
    have activationVoteHistoryFacts :
        ActivationVoteHistory
          votes voteVoterHistory elections activations := by
      intro activationIndex activation
      simp [initialNodes, networkEmpty, activations]
    have configurationActivationFacts :
        ConfigurationCoverageFacts (state : Model.State Node TxId) activations := by
      intro node positive
      simp [initialNodes, networkEmpty, 
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
    · simp [initialNodes, networkEmpty, owners]
    · intro leader role
      by_cases leaderInitial : leader = INITIAL_LEADER
      · subst leader
        simp [initialNodes, networkEmpty, 
          owners, initialNodeState, initialLeaderMember
        ]
      · simp [initialNodes, networkEmpty, 
          initialNodeState, leaderInitial
        ] at role
        split at role <;> contradiction
    · intro node index entry found
      simp [initialNodes, networkEmpty, initialNodeState, entryAt?] at found
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro leader role
      simp [initialNodes, networkEmpty, 
        canonicalHistory, initialNodeState
      ]
    · intro term index entry found
      simp [initialNodes, networkEmpty, canonicalHistory, entryAt?] at found
    · intro term earlier later earlierEntry laterEntry order earlierFound
        laterFound
      simp [initialNodes, networkEmpty,  canonicalHistory, entryAt?] at earlierFound
    · intro term owner owned
      simp [initialNodes, networkEmpty, owners] at owned
      rcases owned with ⟨termEq, ownerEq⟩
      subst term
      subst owner
      simp [initialNodes, networkEmpty, 
        initialNodeState, initialLeaderMember
      ]
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · constructor
      · simp [initialNodes, networkEmpty, elections]
      · intro term owner owned
        simp [initialNodes, networkEmpty, owners] at owned
        exact Or.inl ⟨owned.1, owned.2.symm⟩
      all_goals simp [initialNodes, networkEmpty, elections]
    · constructor
      · simp [initialNodes, networkEmpty, elections]
      · simp [initialNodes, networkEmpty, elections]
      · simp [initialNodes, networkEmpty, elections]
      · simp [initialNodes, networkEmpty, 
          elections, activations,
          ActivationSupporterCurrentHistory
        ]
      · simp [initialNodes, networkEmpty, elections]
      · intro left right leftRole
        by_cases leftEq : left = INITIAL_LEADER
        · subst left
          simp [initialNodes, networkEmpty, initialNodeState] at leftRole
        · by_cases member : left ∈ INITIAL_CONFIGURATION
          · simp [initialNodes, networkEmpty, initialNodeState, leftEq, member] at leftRole
          · simp [initialNodes, networkEmpty, initialNodeState, leftEq, member] at leftRole
      · intro candidate role
        by_cases candidateEq : candidate = INITIAL_LEADER
        · subst candidate
          simp [initialNodes, networkEmpty, initialNodeState] at role
        · by_cases member : candidate ∈ INITIAL_CONFIGURATION
          · simp [initialNodes, networkEmpty, 
              initialNodeState, candidateEq, member
            ] at role
          · simp [initialNodes, networkEmpty, 
              initialNodeState, candidateEq, member
            ] at role
    · intro candidate voter active member
      simp [initialNodes, networkEmpty, 
        effectiveElectionVoters, queuedGrantedVote,
        initialNodeState
      ] at member
    · intro source index role current signature
      have impossible : False := by
        simp [initialNodes, networkEmpty, 
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [initialNodes, networkEmpty, 
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [initialNodes, networkEmpty, 
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro source index role current signature
      have impossible : False := by
        simp [initialNodes, networkEmpty, 
          initialNodeState, isSignatureAt, entryAt?
        ] at signature
      exact impossible.elim
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro index record recorded
      simp [initialNodes, networkEmpty, activations] at recorded
    · constructor
      · exact activationHistoryFacts
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodes, networkEmpty, initialNodeState] using signature
        simp [initialNodes, networkEmpty, isSignatureAt, entryAt?] at impossible
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodes, networkEmpty, initialNodeState] using signature
        simp [initialNodes, networkEmpty, isSignatureAt, entryAt?] at impossible
      · intro source index role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) index = true := by
          simpa [initialNodes, networkEmpty, initialNodeState] using signature
        simp [initialNodes, networkEmpty, isSignatureAt, entryAt?] at impossible
      · intro left leftIndex role current signature
        have impossible :
            isSignatureAt ([] : List (Entry Node TxId)) leftIndex = true := by
          simpa [initialNodes, networkEmpty, initialNodeState] using signature
        simp [initialNodes, networkEmpty, isSignatureAt, entryAt?] at impossible
      · intro _ _ destination request _ queued _
        simp [initialNodes, networkEmpty] at queued
      · intro node frontier within positive signature
        simp [initialNodes, networkEmpty, 
          initialNodeState,
          currentConfigurationAt, implicitConfiguration,
          configurationsInLog, configurationsInLogFrom
        ] at positive
      · intro destination request queued
        simp [initialNodes, networkEmpty] at queued
    · exact evidenceFacts
    · exact prospectiveFacts
    · exact activationEvidenceFacts
  · intro candidate voter active member
    simp [initialNodes, networkEmpty, 
      effectiveElectionVoters, queuedGrantedVote,
      initialNodeState
    ] at member
  · let ackHistory : ProcessedAckHistory Node TxId :=
      fun _ _ => none
    refine ⟨ackHistory, ?_⟩
    constructor
    · simp [initialNodes, networkEmpty, ackHistory]
    · intro leader role peer positive
      simp [initialNodes, networkEmpty, initialNodeState] at positive
  · constructor
    · intro node peer member
      simpa [initialNodes, networkEmpty, 
        initialNodeState, activeNodeUnion,
        activeConfigurations, currentConfiguration,
        currentConfigurationAt, allConfigurations,
        configurationsInLog, configurationsInLogFrom,
        implicitConfiguration
      ] using member
    · intro node configuration member peer inNodes
      simp [initialNodes, networkEmpty, 
        initialNodeState, allConfigurations,
        configurationsInLog, configurationsInLogFrom
      ] at member
      subst configuration
      simpa [initialNodes, networkEmpty, implicitConfiguration] using inNodes
    · intro node peer member
      simp [initialNodes, networkEmpty, initialNodeState] at member
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro destination request member
      simp [initialNodes, networkEmpty] at member
    · intro destination response member
      simp [initialNodes, networkEmpty] at member
    · constructor
      · intro node active
        by_cases same : node = INITIAL_LEADER
        · subst node
          exact initialLeaderMember
        · rcases active with candidate | leader
          · simp [initialNodes, networkEmpty, initialNodeState, same] at candidate
            split at candidate <;> contradiction
          · simp [initialNodes, networkEmpty, initialNodeState, same] at leader
            split at leader <;> contradiction
      · intro leader peer positive
        by_cases same : leader = INITIAL_LEADER <;>
          simp [initialNodes, networkEmpty, initialNodeState, same] at positive
      · intro destination response member
        simp [initialNodes, networkEmpty] at member
      · intro node nonempty
        by_cases same : node = INITIAL_LEADER <;>
          simp [initialNodes, networkEmpty, initialNodeState, same] at nonempty
  · exact fun _ => Iff.rfl
  · intro node
    by_cases member : node ∈ INITIAL_CONFIGURATION <;>
      simp [initialNodes, networkEmpty, TermNumberValid, initialNodeState, member]
  · simp [initialNodes, networkEmpty, NetworkTermsValid]

end CCFRaft.Proofs.Invariant
