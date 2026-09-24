-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Preservation.Authority
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
variable {joinedNodes : Finset Node}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

attribute [local simp] Shared.Envelope.target ConfigurationCoverageWitness.sharedPrefix

def leaderAppendJoined (joined : Finset Node)
    (state : Model.State Node TxId) (node : Node) (content : EntryContent Node TxId)
    : Finset Node :=
  joined ∪ match content with
    | .reconfiguration newConfiguration =>
        newConfiguration \ (latestConfiguration (nodeOf state node)).nodes
    | _ => ∅

/-- Append a current-term entry in the concrete node table. -/
def leaderAppendState
    (state : Model.State Node TxId)
    (node : Node)
    (content : EntryContent Node TxId)
    : Model.State Node TxId :=
  let entry : Entry Node TxId :=
    {
      term := ((nodeOf state) node).currentTerm
      content
    }
  let addedNodes :=
    match content with
    | .reconfiguration newConfiguration =>
        newConfiguration \ (latestConfiguration ((nodeOf state) node)).nodes
    | _ => ∅
  let nextNode :=
    refreshRetirementState node
      {
        (nodeOf state) node with
          log := ((nodeOf state) node).log ++ [entry]
          sentIndex :=
            fun peer =>
              if peer ∈ addedNodes then
                ((nodeOf state) node).log.length
              else
                ((nodeOf state) node).sentIndex peer
      }
  {
    state with
      nodes :=
        replaceNode state.nodes node nextNode
  }

@[simp]
lemma leaderAppendState_log_same
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) node).log
      = ((nodeOf state) node).log
        ++ [{
              term := ((nodeOf state) node).currentTerm
              content
            }] := by
  cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]

@[simp]
lemma leaderAppendState_nodes_of_ne
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    (different : Not (candidate = node))
    : (nodeOf (leaderAppendState state node content)) candidate = (nodeOf state) candidate := by
  cases content <;>
    simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, nodeOf_replaceNode, different]

@[simp]
lemma leaderAppendState_network
    (state : Model.State Node TxId)
    (node : Node)
    (content : EntryContent Node TxId)
    : (leaderAppendState state node content).network = state.network := by
  cases content <;> rfl

@[simp]
lemma leaderAppendState_role
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).role
      = ((nodeOf state) candidate).role := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]

@[simp]
lemma leaderAppendState_currentTerm
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).currentTerm
      = ((nodeOf state) candidate).currentTerm := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]

@[simp]
lemma leaderAppendState_commitIndex
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).commitIndex
      = ((nodeOf state) candidate).commitIndex := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]
lemma leaderAppendState_sentIndex_bounded
    (state : Model.State Node TxId)
    (node peer : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf state) node).sentIndex peer <= ((nodeOf state) node).log.length
      -> ((nodeOf (leaderAppendState state node content)) node).sentIndex peer
          <= ((nodeOf (leaderAppendState state node content)) node).log.length := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · intro bounded
    cases content with
    | reconfiguration nodes =>
        simp only [
          leaderAppendState, leaderAppendJoined, nodeOf_replaceNode, present, ite_true, List.length_append,
          List.length_singleton, refreshRetirementState_sentIndex,
          refreshRetirementState_log
        ]
        split <;> omega
    | transaction txId =>
        simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using Nat.le.step bounded
    | signature =>
        simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using Nat.le.step bounded
    | retiredCommitted nodes =>
        simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using Nat.le.step bounded
  · simp [leaderAppendState, present]

@[simp]
lemma leaderAppendState_matchIndex
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).matchIndex
      = ((nodeOf state) candidate).matchIndex := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]

@[simp]
lemma leaderAppendState_votedFor
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).votedFor
      = ((nodeOf state) candidate).votedFor := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]

@[simp]
lemma leaderAppendState_votesGranted
    (state : Model.State Node TxId)
    (node candidate : Node)
    (content : EntryContent Node TxId)
    : ((nodeOf (leaderAppendState state node content)) candidate).votesGranted
      = ((nodeOf state) candidate).votesGranted := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · by_cases same : candidate = node
    · subst candidate
      cases content <;> simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present]
    · rw [
        leaderAppendState_nodes_of_ne
          state node candidate content  same
      ]
  · simp [leaderAppendState, present]

/-- A leader append does not change any node's committed prefix. -/
lemma leaderAppendCommittedLogUnchanged
    (state : Model.State Node TxId)
    (node : Node)
    (content : EntryContent Node TxId)
    (bounded : CommitIndicesBounded state)
    : forall candidate,
        ((nodeOf (leaderAppendState state node content)) candidate).committedLog
        = ((nodeOf state) candidate).committedLog := by
  by_cases present : node ∈ state.nodes.map Prod.fst
  · intro candidate
    by_cases candidateEq : candidate = node
    · subst candidate
      simp only [
        leaderAppendState_log_same (present := present), leaderAppendState_commitIndex,
        NodeState.committedLog
      ]
      rw [List.take_append_of_le_length (bounded node)]
    · simp [
        leaderAppendState_nodes_of_ne state node candidate
          content  candidateEq
      ]
  · simp [leaderAppendState, present]

/-- Appending any current-term leader entry preserves the arbitrary-term facts. -/
lemma leaderAppendPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (content : EntryContent Node TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (_nodeAllocated : node ∈ joinedNodes)
    (leaderRole : ((nodeOf state) node).role = .leader)
    : SystemInductiveInvariant (joined := leaderAppendJoined joinedNodes state node content) (leaderAppendState state node content) := by
  classical
  rcases invariant with
    ⟨votes, appendHistory, responseHistory,
      voteRequestHistory, voteCandidateHistory, voteVoterHistory, facts⟩
  rcases facts.historicalSafety with
    ⟨owners, canonicalHistory, elections, activations,
      nodeEvidence, requestEvidence, ownership, electionFacts,
      configurationFacts, voteCanonicalFacts,
      ackerCurrentFacts, ackerVoteFacts, activationVoteHistory,
      ackerElectionFacts,
      ackerActivationFacts,
      electionQueuedFacts, activationProgress, activationQuorums,
      evidenceFacts, prospectiveFacts, activationEvidence,
      activationCanonical, activationElections, configurationActivations⟩
  rcases facts.processedAckHistory with ⟨ackHistory, ackFacts⟩
  have hasJoinedMono :
      joinedNodes ⊆
        (leaderAppendJoined joinedNodes state node content) := by
    intro peer joined
    simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, joined]
  have activationVoteHistoryAfter :
      ActivationVoteHistory
        votes voteVoterHistory elections activations := by
    apply
      activationVoteHistoryFrame
        votes votes voteVoterHistory voteVoterHistory
          elections activations activationVoteHistory
    · intro _ _ _ _ _ _ _ voted _ _
      exact voted
    · intro _ _ _ _ retained
      exact retained
  have monoLog := invariantFactsMonoLogFromCanonicalHistories facts
  have candidatesAboveBootstrap :=
    invariantFactsCandidatesAboveBootstrap facts
  have oldCandidateTermNot :
      CandidateTermNotInLogs (joined := joinedNodes) state :=
    termOwnershipCandidateTermNotInLogs
      candidatesAboveBootstrap facts.grantedVoteSnapshots
        ownership electionFacts configurationFacts
  let entry : Entry Node TxId :=
    { term := ((nodeOf state) node).currentTerm
      content }
  let newCanonicalHistory : Nat -> List (Entry Node TxId) :=
    Function.update canonicalHistory entry.term
      (((nodeOf state) node).log ++ [entry])
  have committedEq :=
    leaderAppendCommittedLogUnchanged
      state node content  facts.commitIndicesBounded
  have oldElectionSafety :
      ElectionSafety state :=
    invariantFactsElectionSafetyFromOwnership facts
  have roleEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).role =
          ((nodeOf state) candidate).role := by
    intro candidate
    exact leaderAppendState_role state node candidate content
  have currentTermEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).currentTerm =
          ((nodeOf state) candidate).currentTerm := by
    intro candidate
    exact
      leaderAppendState_currentTerm
        state node candidate content
  have commitIndexEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).commitIndex =
          ((nodeOf state) candidate).commitIndex := by
    intro candidate
    exact
      leaderAppendState_commitIndex
        state node candidate content
  have matchEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).matchIndex =
          ((nodeOf state) candidate).matchIndex := by
    intro candidate
    exact
      leaderAppendState_matchIndex
        state node candidate content
  have votedForEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).votedFor =
          ((nodeOf state) candidate).votedFor := by
    intro candidate
    exact
      leaderAppendState_votedFor
        state node candidate content
  have votesGrantedEq :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).votesGranted =
          ((nodeOf state) candidate).votesGranted := by
    intro candidate
    exact
      leaderAppendState_votesGranted
        state node candidate content
  have logEqNode :
      ((nodeOf (leaderAppendState state node content)) node).log =
        ((nodeOf state) node).log ++ [entry] := by
    simpa only [entry] using leaderAppendState_log_same state node (present := present) content
  have logEqOther :
      forall candidate,
        Not (candidate = node) ->
        ((nodeOf (leaderAppendState state node content))
          candidate).log =
          ((nodeOf state) candidate).log := by
    intro candidate candidateNe
    simp [leaderAppendState_nodes_of_ne
      state node candidate content  candidateNe]
  have logPrefix :
      forall candidate,
        ((nodeOf state) candidate).log <+:
          ((nodeOf (leaderAppendState state node content))
            candidate).log := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      rw [logEqNode]
      exact List.prefix_append _ _
    · rw [logEqOther candidate same]
  have currentConfigurationAtEq :
      forall frontier,
        frontier <= ((nodeOf state) node).log.length ->
          currentConfigurationAt
              ((nodeOf (leaderAppendState state node content)) node).log frontier =
            currentConfigurationAt ((nodeOf state) node).log frontier := by
    intro frontier within
    rw [logEqNode]
    cases content with
    | transaction txId =>
        exact currentConfigurationAt_append_nonreconfiguration
          ((nodeOf state) node).log
          {
            term := ((nodeOf state) node).currentTerm
            content := .transaction txId
          }
          frontier (by simp)
    | signature =>
        exact currentConfigurationAt_append_nonreconfiguration
          ((nodeOf state) node).log
          {
            term := ((nodeOf state) node).currentTerm
            content := .signature
          }
          frontier (by simp)
    | retiredCommitted retired =>
        exact currentConfigurationAt_append_nonreconfiguration
          ((nodeOf state) node).log
          {
            term := ((nodeOf state) node).currentTerm
            content := .retiredCommitted retired
          }
          frontier (by simp)
    | reconfiguration newConfiguration =>
        change
          currentConfigurationAt
              (((nodeOf state) node).log ++
                [{ term := ((nodeOf state) node).currentTerm
                   content := .reconfiguration newConfiguration }])
              frontier =
            currentConfigurationAt ((nodeOf state) node).log frontier
        have pending :
            ¬1 + ((nodeOf state) node).log.length <= frontier := by
          omega
        simp [
          currentConfigurationAt, configurationsInLog,
          configurationsInLogFrom_append, configurationsInLogFrom,
          pending
        ]
  have currentConfigurationEq :
    forall candidate,
      currentConfiguration
          ((nodeOf (leaderAppendState state node content))
            candidate) =
        currentConfiguration ((nodeOf state) candidate) := by
    intro candidate
    by_cases same : candidate = node
    · subst candidate
      simpa [currentConfiguration, commitIndexEq]
        using currentConfigurationAtEq
          ((nodeOf state) node).commitIndex
          (facts.commitIndicesBounded node)
    · rw [
      leaderAppendState_nodes_of_ne
        state node candidate content  same
    ]
  have activeConfigurationsForward :
      forall candidate configuration,
        configuration ∈ activeConfigurations ((nodeOf state) candidate) ->
          configuration ∈
            activeConfigurations
              ((nodeOf (leaderAppendState state node content))
                candidate) := by
    intro candidate configuration active
    have oldKnown :
        configuration ∈ allConfigurations ((nodeOf state) candidate).log :=
      (List.mem_filter.mp active).1
    have oldOrder :
        (currentConfiguration ((nodeOf state) candidate)).index <=
          configuration.index := by
      exact of_decide_eq_true (List.mem_filter.mp active).2
    apply List.mem_filter.mpr
    constructor
    · exact
        memOfPrefix
          (allConfigurations_mono_prefix (logPrefix candidate))
          oldKnown
    · apply decide_eq_true
      simpa [currentConfigurationEq] using oldOrder
  have effectiveElectionVotersEq :
        forall candidate,
          effectiveElectionVoters (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
                candidate =
            effectiveElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate
    ext voter
    simp only [
      effectiveElectionVoters, Finset.mem_filter]
    constructor
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨
          facts.joinedCarriers.grantedVotes candidate
            (by simpa [votesGrantedEq] using processed),
          Or.inl (by simpa [votesGrantedEq] using processed)
        ⟩
      · rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        refine ⟨
          by
            simpa [responseSource]
              using facts.joinedCarriers.voteResponseSources
                candidate response (by simpa using member),
          Or.inr ?_
        ⟩
        exact ⟨
          response,
          by simpa using member,
          granted,
          by simpa [currentTermEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
    · rintro ⟨joined, processed | queued⟩
      · exact ⟨hasJoinedMono joined, Or.inl (by simpa [votesGrantedEq] using processed)⟩
      · refine ⟨hasJoinedMono joined, Or.inr ?_⟩
        rcases queued with
          ⟨response, member, granted, responseTerm,
            responseSource, responseDestination⟩
        exact ⟨
          response,
          by simpa using member,
          granted,
          by simpa [currentTermEq] using responseTerm,
          responseSource,
          responseDestination
        ⟩
  have effectiveElectionMajorityBack :
        forall candidate,
          hasEffectiveElectionMajority (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
                candidate ->
            hasEffectiveElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate majority
    rw [hasEffectiveElectionMajority, List.all_eq_true] at majority
    rw [hasEffectiveElectionMajority, List.all_eq_true]
    intro configuration active
    have afterActive :=
      activeConfigurationsForward candidate configuration active
    simpa [effectiveElectionVotersEq] using majority configuration afterActive
  have monoAfterNode :
      MonoHistory
        ((nodeOf (leaderAppendState state node content)) node).log := by
    intro earlier later earlierEntry laterEntry order earlierFound laterFound
    rw [logEqNode] at earlierFound laterFound
    have laterClassified :=
      entryAtAppendSingleton laterFound
    rcases laterClassified with laterOld | laterNew
    · have earlierClassified :=
        entryAtAppendSingleton earlierFound
      rcases earlierClassified with earlierOld | earlierNew
      · exact
          monoLog node earlier later earlierEntry laterEntry
            order earlierOld.2 laterOld.2
      · omega
    · have earlierClassified :=
        entryAtAppendSingleton earlierFound
      rcases earlierClassified with earlierOld | earlierNew
      · have member := entryAt_mem earlierOld.2
        have bounded :=
          facts.entriesDoNotExceedCurrentTerm node earlierEntry member
        simpa [laterNew.2, entry] using bounded
      · omega
  have potentialElectionVotersSubset :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).role = .candidate ->
          forall voter,
            voter ∈
                potentialElectionVoters (joined := leaderAppendJoined joinedNodes state node content)
                  (leaderAppendState state node content)
                    candidate ->
              voter ∈
                  activeNodeUnion
                    ((nodeOf (leaderAppendState state node content))
                      candidate) ->
                voter ∈ potentialElectionVoters (joined := joinedNodes) state candidate := by
    intro candidate role voter member activeMember
    have candidateNe : Not (candidate = node) := by
      intro same
      subst candidate
      have oldRole :
          ((nodeOf state) node).role = .candidate := by
        simpa [roleEq] using role
      exact Role.noConfusion (oldRole.symm.trans leaderRole)
    simp only [
      potentialElectionVoters, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | eligible⟩
    · have oldEffective :
          voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
        rw [← effectiveElectionVotersEq candidate]
        exact effective
      exact ⟨(Finset.mem_filter.mp oldEffective).1, Or.inl oldEffective⟩
    · refine ⟨?_, Or.inr ?_⟩
      · exact
          facts.joinedCarriers.activeNodes candidate
            (by
              simpa [
                leaderAppendState_nodes_of_ne
                  state node candidate content  candidateNe
              ] using activeMember)
      unfold currentlyEligibleElectionVoter at eligible ⊢
      have requestEq :
          voteRequestKey
              (leaderAppendState state node content )
                candidate voter =
            voteRequestKey state candidate voter := by
        simp [
          voteRequestKey, Model.Local.makeRequestVoteRequest, leaderAppendState, leaderAppendJoined,
          nodeOf_replaceNode, candidateNe
        ]
      have termAccepted :
          (voteRequestKey state candidate voter).2.2.term =
            ((nodeOf state) voter).currentTerm := by
        simpa [requestEq, currentTermEq] using eligible.1
      have upToDateAfter :
          voteLogUpToDate ((nodeOf (leaderAppendState state node content)) voter) (voteRequestKey state candidate voter).2.2 := by
        simpa [requestEq] using eligible.2.1
      change
        voteLogUpToDate ((nodeOf (leaderAppendState state node content)) voter) (voteRequestKey state candidate voter).2.2
        at upToDateAfter
      refine ⟨termAccepted, ?_, by simpa [votedForEq] using eligible.2.2⟩
      by_cases voterEq : voter = node
      · subst voter
        exact
          voteLogUpToDateOfVoterPrefix
            (List.prefix_append ((nodeOf state) node).log [entry])
            (by simpa [logEqNode] using monoAfterNode)
            ((nodeOf state) node)
            ((nodeOf (leaderAppendState state node content)) node)
            (voteRequestKey state candidate node)
            rfl logEqNode upToDateAfter
      · simpa [logEqOther voter voterEq, voteLogUpToDate] using upToDateAfter
  have potentialElectionMajorityBack :
      forall candidate,
        ((nodeOf (leaderAppendState state node content))
          candidate).role = .candidate ->
          hasPotentialElectionMajority (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
                candidate ->
            hasPotentialElectionMajority (joined := joinedNodes) state candidate := by
    intro candidate role majority
    rw [hasPotentialElectionMajority, List.all_eq_true] at majority
    rw [hasPotentialElectionMajority, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    apply
      hasConfigurationMajority_mono_on_configuration
        (fun voter member inConfiguration =>
          potentialElectionVotersSubset candidate role voter member
            (configurationNodes_subset_activeNodeUnion
              ((nodeOf (leaderAppendState state node content))
                candidate)
              configuration
              (activeConfigurationsForward candidate configuration active)
              inConfiguration))
    exact
      of_decide_eq_true
        (majority configuration
          (activeConfigurationsForward candidate configuration active))
  have preserveCanonicalAgreement :
      forall (history : List (Entry Node TxId)) index value,
        entryAt? (canonicalHistory value.term) index = some value /\
          history.take index =
            (canonicalHistory value.term).take index ->
        entryAt? (newCanonicalHistory value.term) index = some value /\
          history.take index =
            (newCanonicalHistory value.term).take index := by
    intro history index value agreement
    by_cases sameTerm : value.term = entry.term
    · have oldCanonical :
          canonicalHistory value.term = ((nodeOf state) node).log := by
        rw [sameTerm]
        simpa [entry] using ownership.activeLeaderHistory node leaderRole
      have oldFound :
          entryAt? ((nodeOf state) node).log index = some value := by
        simpa [oldCanonical] using agreement.1
      have oldPrefixNew :
          ((nodeOf state) node).log <+:
            ((nodeOf state) node).log ++ [entry] :=
        List.prefix_append _ _
      have newFound :=
        entryAt_of_prefix oldPrefixNew oldFound
      have takesEqual :=
        takeEqOfPrefix oldPrefixNew
          (entryAtSomeIndexBound oldFound)
      constructor
      · simpa [
          newCanonicalHistory, Function.update, sameTerm
        ] using newFound
      · calc
          history.take index =
              (canonicalHistory value.term).take index :=
            agreement.2
          _ = ((nodeOf state) node).log.take index := by rw [oldCanonical]
          _ =
              (((nodeOf state) node).log ++ [entry]).take index :=
            takesEqual
          _ = (newCanonicalHistory value.term).take index := by
            simp [
              newCanonicalHistory, sameTerm
            ]
    · simpa [
        newCanonicalHistory, Function.update, sameTerm
      ] using agreement
  have effectiveAckersSubset :
      forall leader index,
        ((nodeOf state) leader).role = .leader ->
        forall peer,
          peer ∈
              effectiveAckers (joined := leaderAppendJoined joinedNodes state node content)
                (leaderAppendState state node content)
                responseHistory leader index ->
            peer ∈ joinedNodes ->
              peer ∈ effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader index leaderRole peer member oldJoined
    simp only [
      effectiveAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, self | matched | queued⟩
    · exact ⟨oldJoined, Or.inl self⟩
    · refine ⟨oldJoined, Or.inr (Or.inl ?_)⟩
      rw [matchEq] at matched
      exact matched
    · refine ⟨oldJoined, Or.inr (Or.inr ?_)⟩
      rcases queued with
        ⟨response, responseMember, success, responseTerm,
          responseSource, responseDestination, lastIndex, covered⟩
      have oldMember :
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = leader) := by
        simpa using responseMember
      have snapshot :=
        facts.networkHistory.appendResponse leader response oldMember
      have oldTerm :
          response.2.2.term = ((nodeOf state) leader).currentTerm := by
        rw [currentTermEq] at responseTerm
        exact responseTerm
      have oldTermAtDestination :
          response.2.2.term =
            ((nodeOf state) response.2.1).currentTerm := by
        simpa [responseDestination] using oldTerm
      have oldDestinationLeader :
          ((nodeOf state) response.2.1).role = .leader := by
        simpa [responseDestination] using leaderRole
      have oldCovered :=
        successfulResponseSnapshotCoveredOfLeader
          snapshot success oldTermAtDestination oldDestinationLeader
      rw [responseDestination] at oldCovered
      exact ⟨
        response,
        oldMember,
        success,
        oldTerm,
        responseSource,
        responseDestination,
        lastIndex,
        oldCovered
      ⟩
  have effectiveAckerJoinedBefore :
      forall leader index peer,
        ((nodeOf state) leader).role = .leader ->
        0 < index ->
        peer ∈
            effectiveAckers (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
              responseHistory leader index ->
          peer ∈ joinedNodes := by
    intro leader index peer role positive member
    simp only [
      effectiveAckers, Finset.mem_filter] at member
    rcases member with ⟨_, self | matched | queued⟩
    · subst peer
      exact facts.joinedCarriers.runtimeNodes.activeRoles leader (Or.inr role)
    · exact
        facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
          (positive.trans_le (by simpa [matchEq] using matched))
    · rcases queued with
        ⟨response, responseMember, _success, _responseTerm,
          responseSource, _responseDestination, _lastIndex, _covered⟩
      have sourceJoined :=
        facts.joinedCarriers.runtimeNodes.appendResponses
          leader response (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using responseMember)
      simpa [responseSource] using sourceJoined
  have effectiveAckersSubsetAtSignature :
      forall leader index,
        ((nodeOf state) leader).role = .leader ->
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              leader).log index = true ->
          effectiveAckers (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
              responseHistory leader index ⊆
            effectiveAckers (joined := joinedNodes) state responseHistory leader index := by
    intro leader index role signature peer member
    exact
      effectiveAckersSubset leader index role peer member
        (effectiveAckerJoinedBefore leader index peer role
          (isSignatureAtIndexPositive signature) member)
  have effectiveMajorityOld :
      forall leader index,
        ((nodeOf state) leader).role = .leader ->
        hasEffectiveMajorityAt (joined := leaderAppendJoined joinedNodes state node content)
            (leaderAppendState state node content)
            responseHistory leader index ->
          hasEffectiveMajorityAt (joined := joinedNodes) state responseHistory leader index := by
    intro leader index role majority
    rw [hasEffectiveMajorityAt, List.all_eq_true] at majority
    rw [hasEffectiveMajorityAt, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈
          activeConfigurations
            ((nodeOf (leaderAppendState state node content))
              leader) := by
      exact activeConfigurationsForward leader configuration active
    apply
      hasConfigurationMajority_mono_on_configuration
        (fun peer member inConfiguration =>
          effectiveAckersSubset leader index role peer member
            (facts.joinedCarriers.configurationNodes
              leader configuration
                (List.mem_filter.mp active).1
                inConfiguration))
    exact (of_decide_eq_true (majority configuration afterActive)) governs
  have beyondIndexSelf :
      forall index voter,
        ((nodeOf state) node).log.length < index ->
        voter ∈
            effectiveAckers (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
              responseHistory node index ->
          voter = node := by
    intro index voter beyond member
    have oldMember :=
      effectiveAckersSubset node index leaderRole voter member
        (effectiveAckerJoinedBefore node index voter leaderRole
          (by omega) member)
    exact
      effectiveAckersBeyondLeaderLog
        facts.leaderProgressBounded
        facts.networkHistory.appendResponse
        leaderRole beyond oldMember
  have signatureBackNode :
      forall index,
        index <= ((nodeOf state) node).log.length ->
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              node).log index =
          true ->
        isSignatureAt ((nodeOf state) node).log index = true := by
    intro index within signature
    rw [logEqNode] at signature
    rcases isSignatureAtTrue signature with
      ⟨foundEntry, found, foundSignature⟩
    rcases entryAtAppendSingleton found with old | appended
    · simp [isSignatureAt, old.2, foundSignature]
    · omega
  refine ⟨
    votes,
    appendHistory,
    responseHistory,
    voteRequestHistory,
    voteCandidateHistory,
    voteVoterHistory,
    ?_
  ⟩
  constructor
  · intro candidate
    rw [commitIndexEq]
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [logEqNode, List.length_append]
      simp only [List.length_singleton]
      have bounded := facts.commitIndicesBounded node
      omega
    · rw [logEqOther candidate candidateEq]
      exact facts.commitIndicesBounded candidate
  · intro candidate participating
    rw [currentTermEq]
    apply facts.currentTermsPositive candidate
    intro none
    apply participating
    simpa [roleEq] using none
  · intro candidate value member
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [logEqNode] at member
      simp at member
      rcases member with oldMember | newMember
      · rw [currentTermEq]
        exact facts.entriesDoNotExceedCurrentTerm node value oldMember
      · subst value
        simp [entry, currentTermEq]
    · have oldMember :
          value ∈ ((nodeOf state) candidate).log := by
        rw [logEqOther candidate candidateEq] at member
        exact member
      simpa [currentTermEq]
        using facts.entriesDoNotExceedCurrentTerm candidate value oldMember
  · intro candidate role
    rw [roleEq] at role
    have oldSelf := facts.candidatesSelfVote candidate role
    rw [votedForEq, votesGrantedEq]
    exact oldSelf
  · intro leader role
    rw [roleEq] at role
    have old := facts.leadersHaveElectionWitness leader role
    rw [currentTermEq]
    rcases old with bootstrap | majority
    · exact Or.inl bootstrap
    · rcases majority with ⟨configuration, known, majority⟩
      refine Or.inr ⟨configuration, ?_, ?_⟩
      · by_cases leaderEq : leader = node
        · subst leader
          rw [logEqNode]
          exact
            memOfPrefix
              (allConfigurations_mono_prefix
                (List.prefix_append _ _))
              known
        · simpa [logEqOther leader leaderEq] using known
      · simpa [votesGrantedEq] using majority
  · intro leader role peer
    rw [roleEq] at role
    have oldProgress := facts.leaderProgressBounded leader role peer
    by_cases leaderEq : leader = node
    · subst leader
      exact ⟨
        leaderAppendState_sentIndex_bounded
          state node peer content  oldProgress.1,
        by
          rw [matchEq, logEqNode, List.length_append]
          simp only [List.length_singleton]
          omega
      ⟩
    · simpa [
        leaderAppendState_nodes_of_ne
          state node leader content  leaderEq
      ] using oldProgress
  · constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [votedForEq]
      rw [currentTermEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      rw [currentTermEq] at future
      exact future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · rw [roleEq] at active
        exact active
      · rw [votesGrantedEq] at member
        exact member
  · constructor
    · intro destination message member
      exact facts.networkHistory.addressed destination message
        (by simpa using member)
    · intro destination request member
      have old :=
        facts.networkHistory.appendRequest destination request
          (by simpa using member)
      exact ⟨
        old.1,
        old.2.1,
        by
          unfold RequestCommitStillPresent at old ⊢
          exact old.2.2.trans (by simp [committedEq])
      ⟩
    · intro destination response member
      have oldMember :
          (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination) := by
        simpa using member
      have old :=
        facts.networkHistory.appendResponse destination response oldMember
      intro success
      rcases old success with ⟨bounded, termBound, stable⟩
      refine ⟨bounded, by simpa [currentTermEq] using termBound, ?_⟩
      intro sameTerm
      have oldTerm :
          response.2.2.term =
            ((nodeOf state) response.2.1).currentTerm := by
        rw [currentTermEq] at sameTerm
        exact sameTerm
      rcases stable oldTerm with active | follower | preVoteCandidate
      · left
        constructor
        · simpa [roleEq] using active.1
        · by_cases destinationEq : response.2.1 = node
          · rw [destinationEq] at active ⊢
            rw [logEqNode]
            exact active.2.trans (List.prefix_append _ _)
          · rw [logEqOther response.2.1 destinationEq]
            exact active.2
      · exact Or.inr (Or.inl (by simpa [roleEq] using follower))
      · exact
          Or.inr (Or.inr (by simpa [roleEq] using preVoteCandidate))
    · intro destination request member
      rcases
          facts.networkHistory.voteRequest destination request
            (by simpa using member) with
        ⟨lastIndex, lastTerm, maxIndex,
          aboveBootstrap, termBound, activePrefix⟩
      refine ⟨
        lastIndex,
        lastTerm,
        maxIndex,
        aboveBootstrap,
        by simpa [currentTermEq] using termBound,
        ?_
      ⟩
      intro sameTerm active
      have oldSameTerm :
          request.2.2.term =
            ((nodeOf state) request.1).currentTerm := by
        simpa [currentTermEq] using sameTerm
      have oldActive :
          ((nodeOf state) request.1).role = .candidate \/
            ((nodeOf state) request.1).role = .leader := by
        simpa [roleEq] using active
      have oldPrefix := activePrefix oldSameTerm oldActive
      by_cases sourceEq : request.1 = node
      · have oldPrefixNode :
            voteRequestHistory request <+: ((nodeOf state) node).log := by
          simpa [sourceEq] using oldPrefix
        rw [sourceEq, logEqNode]
        exact oldPrefixNode.trans (List.prefix_append _ _)
      · rw [logEqOther request.1 sourceEq]
        exact oldPrefix
    · intro destination response member granted
      rcases
          facts.networkHistory.voteResponse destination response
            (by simpa using member) granted with
        ⟨termBound, recorded, upToDate⟩
      exact ⟨
        by simpa [currentTermEq] using termBound,
        recorded,
        by simpa [voteLogUpToDate] using upToDate
      ⟩
  have evidenceAfter :
      CommitEvidenceFacts
        (leaderAppendState state node content )
        appendHistory nodeEvidence requestEvidence := by
    apply
      commitEvidenceFrame
      state (leaderAppendState state node content )
        appendHistory nodeEvidence requestEvidence evidenceFacts
        commitIndexEq committedEq
    · intro candidate
      exact Nat.le_of_eq (currentTermEq candidate).symm
    · intro destination request member
      simpa using member
  have prospectiveAfter :
      ProspectiveCommitEvidenceFacts (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        appendHistory nodeEvidence requestEvidence elections := by
    apply
      prospectiveCommitEvidenceFrame
        state (leaderAppendState state node content )
        appendHistory appendHistory
        nodeEvidence nodeEvidence requestEvidence requestEvidence
          elections prospectiveFacts
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (leaderAppendState state node content )
            appendHistory
            nodeEvidence requestEvidence
            commitIndexEq committedEq
            (fun destination request member => by
              simpa using member)
            known
    · intro member
      by_cases same : member = node
      · subst member
        rw [logEqNode]
        exact List.prefix_append _ _
      · rw [logEqOther member same]
    · intro evidence supportedPrefix destination request known queued sameTerm
      left
      exact ⟨by simpa using queued, rfl⟩
    · intro evidence supportedPrefix candidate member known role newer
        entriesBefore ackMember relaxed
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        have oldRole :
            ((nodeOf state) node).role = .candidate := by
          simpa [roleEq] using role
        exact Role.noConfusion (oldRole.symm.trans leaderRole)
      have oldKnown :=
        knownCommitEvidenceFrameBack
          state (leaderAppendState state node content )
            appendHistory nodeEvidence requestEvidence
            commitIndexEq committedEq
            (fun destination request member => by simpa using member)
            known
      have memberCovered :=
        prospectiveFacts.currentMember
          evidence supportedPrefix oldKnown member ackMember
      have valid := knownCommitEvidenceValid evidenceFacts oldKnown
      have frontierPositive : 0 < evidence.commitFrontier :=
        (knownCommitEvidenceSupportedLengthPositive evidenceFacts oldKnown).trans_le
          valid.2.2.1
      have memberLogNonempty : Not (((nodeOf state) member).log = []) := by
        intro empty
        have lengthBound := memberCovered.length_le
        rw [empty] at lengthBound
        simp [Nat.min_eq_left valid.1] at lengthBound
        omega
      have oldJoined :
          member ∈ joinedNodes :=
        facts.joinedCarriers.runtimeNodes.nonemptyLogs member memberLogNonempty
      left
      refine ⟨
        by simpa [roleEq] using role,
        by simpa [currentTermEq] using newer,
        ?_,
        ?_,
        ?_
      ⟩
      · intro entry entryMember
        have afterMember :
            entry ∈
              ((nodeOf (leaderAppendState state node content))
                candidate).log := by
          rw [logEqOther candidate candidateNe]
          exact entryMember
        have afterBound := entriesBefore entry afterMember
        simpa [currentTermEq] using afterBound
      · simp only [
          relaxedElectionVoters, Finset.mem_filter] at relaxed ⊢
        rcases relaxed with ⟨joined, effective | upToDate⟩
        · exact ⟨oldJoined, Or.inl (by simpa [effectiveElectionVotersEq] using effective)⟩
        · refine ⟨oldJoined, Or.inr ⟨by simpa [currentTermEq] using upToDate.1, ?_⟩⟩
          by_cases memberEq : member = node
          · subst member
            apply
              voteLogUpToDateOfVoterPrefix
                (List.prefix_append ((nodeOf state) node).log [entry])
                (by simpa [logEqNode] using monoAfterNode)
                ((nodeOf state) node)
                ((nodeOf (leaderAppendState state node content))
                  node)
                (voteRequestKey state candidate candidate)
                rfl logEqNode
            simpa [
              voteRequestKey, Model.Local.makeRequestVoteRequest, leaderAppendState, leaderAppendJoined,
              nodeOf_replaceNode, Function.update, candidateNe
            ] using upToDate.2
          · simpa [
              voteRequestKey, Model.Local.makeRequestVoteRequest, leaderAppendState, leaderAppendJoined,
              nodeOf_replaceNode, Function.update,
              candidateNe, memberEq,
              voteLogUpToDate
            ] using upToDate.2
      · rw [logEqOther candidate candidateNe]
  have configurationFactsAfter :
      ElectionConfigurationFacts (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        elections activations := by
    apply
      electionConfigurationFrame
        state (leaderAppendState state node content )
        elections activations activations configurationFacts
    · intro _ _ stored
      exact stored
    · apply
        activationSupporterCurrentHistoryFrame
          state (leaderAppendState state node content )
          elections elections activations
          configurationFacts.supporterCurrentHistory
      · intro candidate
        by_cases same : candidate = node
        · subst candidate
          rw [logEqNode]
          exact List.prefix_append _ _
        · rw [logEqOther candidate same]
      · intro candidate
        exact Nat.le_of_eq (currentTermEq candidate).symm
      · intro _ _ stored
        exact stored
    · intro candidate role majority
      have oldRole : ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using role
      exact ⟨
        oldRole,
        by simp [currentTermEq],
        effectiveElectionMajorityBack candidate majority
      ⟩
    · intro candidate configuration role active
      exact
        activeConfigurationsForward candidate configuration active
    · intro candidate role entry member
      have oldRole : ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using role
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        exact Role.noConfusion (oldRole.symm.trans leaderRole)
      simpa [currentTermEq]
        using configurationFacts.candidateEntriesBeforeTerm
          candidate oldRole entry
          (by simpa [logEqOther candidate candidateNe] using member)
  have activationEvidenceAfter :
      ActivationEvidenceFacts (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        appendHistory responseHistory nodeEvidence requestEvidence
          elections activations := by
    apply
      activationEvidenceFrame
        state (leaderAppendState state node content )
        appendHistory appendHistory responseHistory responseHistory
        nodeEvidence nodeEvidence
        requestEvidence requestEvidence elections elections activations
        activationEvidence
    · intro evidence supportedPrefix known
      exact
        knownCommitEvidenceFrameBack
          state (leaderAppendState state node content )
          appendHistory nodeEvidence requestEvidence
          commitIndexEq committedEq
          (fun destination request member => by simpa using member)
          known
    · intro candidate role majority
      have oldRole : ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using role
      exact ⟨oldRole, potentialElectionMajorityBack candidate role majority⟩
    · intro candidate role
      exact currentTermEq candidate
    · intro candidate role
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        have oldRole : ((nodeOf state) node).role = .candidate := by
          simpa [roleEq] using role
        exact Role.noConfusion (oldRole.symm.trans leaderRole)
      rw [logEqOther candidate candidateNe]
    · intro candidate configuration role active
      exact
        activeConfigurationsForward candidate configuration active
  have signatureIndexOld :
      Not (content = .signature) ->
      forall source index,
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              source).log index =
          true ->
        index <= ((nodeOf state) source).log.length /\
          ((nodeOf (leaderAppendState state node content))
              source).log.take index =
            ((nodeOf state) source).log.take index := by
    intro notSignature source index signature
    by_cases sourceEq : source = node
    · subst source
      rw [logEqNode] at signature
      rcases isSignatureAtTrue signature with
        ⟨foundEntry, found, foundSignature⟩
      rcases entryAtAppendSingleton found with old | appended
      · exact ⟨old.1, by rw [logEqNode, List.take_append_of_le_length old.1]⟩
      · have entrySignature : entry.content = .signature := by
          simpa [appended.2] using foundSignature
        exact False.elim (notSignature (by simpa [entry] using entrySignature))
    · rw [logEqOther source sourceEq] at signature ⊢
      rcases isSignatureAtTrue signature with ⟨foundEntry, found, _⟩
      exact ⟨entryAtSomeIndexBound found, rfl⟩
  have termAtIndexOld :
      forall source index,
        index <= ((nodeOf state) source).log.length ->
        termAt
            ((nodeOf (leaderAppendState state node content))
              source).log index =
          termAt ((nodeOf state) source).log index := by
    intro source index within
    by_cases sourceEq : source = node
    · subst source
      rw [logEqNode]
      exact termAtAppend_of_le_length within
    · rw [logEqOther source sourceEq]
  have potentialAckersSubset :
      forall source index,
        ((nodeOf state) source).role = .leader ->
        forall peer,
          peer ∈
              potentialAckers (joined := leaderAppendJoined joinedNodes state node content)
                (leaderAppendState state node content)
                appendHistory responseHistory source index ->
            peer ∈ joinedNodes ->
              peer ∈
                potentialAckers (joined := joinedNodes)
                  state appendHistory responseHistory source index := by
    intro source index sourceRole peer member oldJoined
    simp only [
      potentialAckers, Finset.mem_filter] at member ⊢
    rcases member with ⟨joined, effective | reserve⟩
    · exact ⟨
        oldJoined,
        Or.inl (effectiveAckersSubset source index sourceRole peer effective oldJoined)
      ⟩
    · refine ⟨oldJoined, Or.inr ?_⟩
      rcases reserve with
        ⟨request, queued, requestSource, requestDestination,
          requestTerm, producible, covered⟩
      have oldQueued :
          (appendRequestEnvelope request ∈ state.network /\ request.2.1 = peer) := by
        simpa using queued
      have requestDestinationEq := requestDestination
      have oldProducible :
          canProduceAppendAckEventuallyAt
            ((nodeOf state) peer) request index := by
        rcases producible with direct | future
        · by_cases peerEq : peer = node
          · have destinationEq : request.2.1 = node :=
              requestDestinationEq.trans peerEq
            have follower := canProduceAppendAckAt_role direct
            have afterLeader :
                ((nodeOf (leaderAppendState state node content)) node).role =
                    .leader := by
              simpa [roleEq] using leaderRole
            rw [peerEq, afterLeader] at follower
            contradiction
          · exact Or.inl (by
              simpa [
                leaderAppendState_nodes_of_ne
                  state node peer content  peerEq
              ] using direct)
        · exact Or.inr (by simpa [currentTermEq] using future)
      have oldCovered :
          appendHistory request <+: ((nodeOf state) source).log := by
        by_cases sourceEq : source = node
        · have oldRequestTerm :
              request.2.2.term =
                ((nodeOf state) request.1).currentTerm := by
            calc
              request.2.2.term
                  = ((nodeOf (leaderAppendState state node content)) source).currentTerm :=
                requestTerm
              _ = ((nodeOf state) source).currentTerm := currentTermEq source
              _ = ((nodeOf state) request.1).currentTerm := by
                rw [requestSource]
          have coveredAtRequestSource :=
            ownership.queuedActiveSourceHistory
              peer request oldQueued oldRequestTerm
              (by
                rw [requestSource]
                simpa [sourceEq] using leaderRole)
          simpa [requestSource] using coveredAtRequestSource
        · simpa [logEqOther source sourceEq] using covered
      exact ⟨
        request,
        oldQueued,
        requestSource,
        requestDestination,
        by simpa [currentTermEq] using requestTerm,
        oldProducible,
        oldCovered
      ⟩
  have potentialMajorityBack :
      forall source index,
        ((nodeOf state) source).role = .leader ->
        hasPotentialMajorityAt (joined := leaderAppendJoined joinedNodes state node content)
            (leaderAppendState state node content)
            appendHistory responseHistory source index ->
          hasPotentialMajorityAt (joined := joinedNodes)
            state appendHistory responseHistory source index := by
    intro source index role majority
    rw [hasPotentialMajorityAt, List.all_eq_true] at majority
    rw [hasPotentialMajorityAt, List.all_eq_true]
    intro configuration active
    apply decide_eq_true
    intro governs
    have afterActive :
        configuration ∈
          activeConfigurations
            ((nodeOf (leaderAppendState state node content))
              source) := by
      exact activeConfigurationsForward source configuration active
    apply
      hasConfigurationMajority_mono_on_configuration
        (fun peer member inConfiguration =>
          potentialAckersSubset source index role peer member
            (facts.joinedCarriers.configurationNodes
              source configuration
                (List.mem_filter.mp active).1
                inConfiguration))
    exact (of_decide_eq_true (majority configuration afterActive)) governs
  have supportedSignatureIndexOld :
      Not (content = .signature) ->
      forall source index,
        ((nodeOf (leaderAppendState state node content))
          source).role = .leader ->
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              source).log index = true ->
        hasPotentialMajorityAt (joined := leaderAppendJoined joinedNodes state node content)
            (leaderAppendState state node content)
            appendHistory responseHistory source index ->
          index <= ((nodeOf state) source).log.length /\
            ((nodeOf (leaderAppendState state node content))
                source).log.take index =
              ((nodeOf state) source).log.take index := by
    intro notSignature source index _role signature _potential
    exact signatureIndexOld notSignature source index signature
  have activationQuorumsOldCase :
      Not (content = .signature) ->
      ActivationQuorumFacts (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        appendHistory responseHistory elections activations := by
    intro notSignature
    constructor
    · exact activationQuorums.history
    · intro source index role current signature potential term record
        recorded newer
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      have indexOld :=
        supportedSignatureIndexOld
          notSignature source index role signature potential
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        have oldIndex := indexOld.1
        calc
          termAt ((nodeOf state) source).log index
              = termAt ((nodeOf (leaderAppendState state node content)) source).log index :=
            (termAtIndexOld source index oldIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) source).currentTerm :=
            current
          _ = ((nodeOf state) source).currentTerm := currentTermEq source
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix index ((nodeOf state) source).log)
          (by
            rw [← indexOld.2]
            exact isSignatureAt_take_of_le le_rfl signature)
      have oldPotential :=
        potentialMajorityBack source index oldRole potential
      have oldNewer :
          ((nodeOf state) source).currentTerm < term := by
        simpa [currentTermEq] using newer
      rcases
          activationQuorums.recordBridge
            source index oldRole oldCurrent oldSignature oldPotential
            term record recorded oldNewer with
        direct | shared
      · exact Or.inl
          (by simpa [indexOld.2] using direct)
      · right
        rcases shared with
          ⟨configuration, sourceActive, governs, ballotActive⟩
        exact ⟨
          configuration,
          activeConfigurationsForward source configuration sourceActive,
          governs,
          ballotActive
        ⟩
    · intro source index role current signature potential candidate
        candidateRole candidateMajority newer
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      have indexOld :=
        supportedSignatureIndexOld
          notSignature source index role signature potential
      have oldIndex := indexOld.1
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        calc
          termAt ((nodeOf state) source).log index
              = termAt ((nodeOf (leaderAppendState state node content)) source).log index :=
            (termAtIndexOld source index oldIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) source).currentTerm :=
            current
          _ = ((nodeOf state) source).currentTerm := currentTermEq source
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix index ((nodeOf state) source).log)
          (by
            rw [← indexOld.2]
            exact isSignatureAt_take_of_le le_rfl signature)
      have oldPotential :=
        potentialMajorityBack source index oldRole potential
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :=
        potentialElectionMajorityBack
          candidate candidateRole candidateMajority
      have oldNewer :
          ((nodeOf state) source).currentTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [currentTermEq] using newer
      rcases
          activationQuorums.candidateBridge
            source index oldRole oldCurrent oldSignature oldPotential
            candidate oldCandidateRole oldCandidateMajority oldNewer with
        direct | shared
      · have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact Role.noConfusion (leaderRole.symm.trans oldCandidateRole)
        exact Or.inl
          (by simpa [
            indexOld.2,
            logEqOther candidate candidateNe
          ] using direct)
      · right
        rcases shared with
          ⟨configuration, sourceActive, governs, candidateActive⟩
        exact ⟨
          configuration,
          activeConfigurationsForward source configuration sourceActive,
          governs,
          activeConfigurationsForward candidate configuration candidateActive
        ⟩
    · intro source index role current signature majority committed
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      have afterPotential :=
        effectiveMajorityImpliesPotential
          (leaderAppendState state node content )
          appendHistory responseHistory source index majority
      have indexOld :=
        supportedSignatureIndexOld
          notSignature source index role signature afterPotential
      have oldIndex := indexOld.1
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        calc
          termAt ((nodeOf state) source).log index
              = termAt ((nodeOf (leaderAppendState state node content)) source).log index :=
            (termAtIndexOld source index oldIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) source).currentTerm :=
            current
          _ = ((nodeOf state) source).currentTerm := currentTermEq source
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix index ((nodeOf state) source).log)
          (by
            rw [← indexOld.2]
            exact isSignatureAt_take_of_le le_rfl signature)
      have oldMajority :=
        effectiveMajorityOld source index oldRole majority
      rcases
          activationQuorums.committedBridge
            source index oldRole oldCurrent oldSignature oldMajority
            committed with
        direct | direct | shared
      · exact Or.inl
          (by simpa [
            indexOld.2, committedEq
          ] using direct)
      · exact Or.inr (Or.inl
          (by simpa [
            indexOld.2, committedEq
          ] using direct))
      · exact Or.inr (Or.inr
          (by
            rcases shared with
              ⟨configuration, sourceActive, governs, configurationEq⟩
            exact
              ⟨configuration,
                activeConfigurationsForward source configuration sourceActive,
                governs,
                by simpa [currentConfigurationEq] using configurationEq⟩))
    · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
        right rightIndex rightRole rightCurrent rightSignature rightMajority
      have oldLeftRole : ((nodeOf state) left).role = .leader := by
        simpa [roleEq] using leftRole
      have oldRightRole : ((nodeOf state) right).role = .leader := by
        simpa [roleEq] using rightRole
      have leftPotential :=
        effectiveMajorityImpliesPotential
          (leaderAppendState state node content )
          appendHistory responseHistory left leftIndex leftMajority
      have rightPotential :=
        effectiveMajorityImpliesPotential
          (leaderAppendState state node content )
          appendHistory responseHistory right rightIndex rightMajority
      have leftIndexOld :=
        supportedSignatureIndexOld
          notSignature left leftIndex leftRole leftSignature leftPotential
      have rightIndexOld :=
        supportedSignatureIndexOld
          notSignature right rightIndex rightRole rightSignature rightPotential
      have oldLeftIndex := leftIndexOld.1
      have oldRightIndex := rightIndexOld.1
      have oldLeftCurrent :
          termAt ((nodeOf state) left).log leftIndex =
            ((nodeOf state) left).currentTerm := by
        calc
          termAt ((nodeOf state) left).log leftIndex
              = termAt
                  ((nodeOf (leaderAppendState state node content)) left).log
                  leftIndex :=
            (termAtIndexOld left leftIndex oldLeftIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) left).currentTerm :=
            leftCurrent
          _ = ((nodeOf state) left).currentTerm := currentTermEq left
      have oldRightCurrent :
          termAt ((nodeOf state) right).log rightIndex =
            ((nodeOf state) right).currentTerm := by
        calc
          termAt ((nodeOf state) right).log rightIndex
              = termAt
                  ((nodeOf (leaderAppendState state node content)) right).log
                  rightIndex :=
            (termAtIndexOld right rightIndex oldRightIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) right).currentTerm :=
            rightCurrent
          _ = ((nodeOf state) right).currentTerm := currentTermEq right
      have oldLeftSignature :
          isSignatureAt ((nodeOf state) left).log leftIndex = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix leftIndex ((nodeOf state) left).log)
          (by
            rw [← leftIndexOld.2]
            exact isSignatureAt_take_of_le le_rfl leftSignature)
      have oldRightSignature :
          isSignatureAt ((nodeOf state) right).log rightIndex = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix rightIndex ((nodeOf state) right).log)
          (by
            rw [← rightIndexOld.2]
            exact isSignatureAt_take_of_le le_rfl rightSignature)
      have oldLeftMajority :=
        effectiveMajorityOld left leftIndex oldLeftRole leftMajority
      have oldRightMajority :=
        effectiveMajorityOld right rightIndex oldRightRole rightMajority
      rcases
          activationQuorums.potentialBridge
            left leftIndex oldLeftRole oldLeftCurrent oldLeftSignature
              oldLeftMajority
            right rightIndex oldRightRole oldRightCurrent oldRightSignature
              oldRightMajority with
        direct | direct | shared
      · exact Or.inl
          (by simpa [
            leftIndexOld.2, rightIndexOld.2
          ] using direct)
      · exact Or.inr (Or.inl
          (by simpa [
            leftIndexOld.2, rightIndexOld.2
          ] using direct))
      · exact Or.inr (Or.inr
          (by
            rcases shared with
              ⟨configuration, leftActive, leftGoverns,
                rightActive, rightGoverns⟩
            exact
              ⟨configuration,
                activeConfigurationsForward left configuration leftActive,
                leftGoverns,
                activeConfigurationsForward right configuration rightActive,
                rightGoverns⟩))
    · intro activationIndex activation destination request
        stored queued sameTerm
      exact
        activationQuorums.queuedComparable
          activationIndex activation destination request
          stored
          (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using queued)
          sameTerm
    · apply
        committedConfigurationCoverageTakeFrame
          activationQuorums.committedCoverage facts.commitIndicesBounded
          (fun candidate => by
            by_cases candidateEq : candidate = node
            · subst candidate
              have oldBound := facts.commitIndicesBounded node
              simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, nodeOf_replaceNode]
              omega
            · simpa [
                leaderAppendState_nodes_of_ne
                  state node candidate content  candidateEq
              ] using facts.commitIndicesBounded candidate)
          commitIndexEq
          (fun candidate => Nat.le_of_eq (currentTermEq candidate).symm)
      intro candidate frontier within
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [leaderAppendState_log_same (present := present)]
        exact List.take_append_of_le_length
          (within.trans (facts.commitIndicesBounded node))
      · rw [
          leaderAppendState_nodes_of_ne
            state node candidate content  candidateEq
        ]
    · apply
        queuedConfigurationCoverageFrame
          activationQuorums.queuedCoverage
          (afterAppendHistory := appendHistory)
      · intro destination request queued
        simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using queued
      · intro _
        rfl
  have activationProgressAfter :
      ActivationSupporterProgress
        (leaderAppendState state node content )
        activations := by
    apply
      activationSupporterProgressFrame
        state (leaderAppendState state node content )
          activations activationProgress
    intro candidate
    rw [currentTermEq]
  have ackerActivationAfter :
      AckerActivationHistory (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        responseHistory elections activations := by
    intro source index role current signature
        activationIndex activation configuration supporter
        activationStored governing activationSupporter effective later
    have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
    by_cases sourceEq : source = node
    · subst source
      by_cases within : index <= ((nodeOf state) node).log.length
      · have oldCurrent :
            termAt ((nodeOf state) node).log index =
              ((nodeOf state) node).currentTerm := by
          calc
            termAt ((nodeOf state) node).log index
                = termAt ((nodeOf (leaderAppendState state node content)) node).log index :=
              (termAtIndexOld node index within).symm
            _ = ((nodeOf (leaderAppendState state node content)) node).currentTerm :=
              current
            _ = ((nodeOf state) node).currentTerm :=
              currentTermEq node
        have oldSignature :
            isSignatureAt ((nodeOf state) node).log index = true :=
          signatureBackNode index within signature
        have oldEffective :
            supporter ∈
              effectiveAckers (joined := joinedNodes) state responseHistory node index :=
          effectiveAckersSubsetAtSignature
            node index leaderRole signature effective
        have oldLater :
            ((nodeOf state) node).currentTerm <
              activation.activationTerm := by
          simpa [currentTermEq] using later
        rcases
            ackerActivationFacts
              node index leaderRole oldCurrent oldSignature
              activationIndex activation configuration supporter
              activationStored governing activationSupporter
              oldEffective oldLater with
          retained | bad
        · exact Or.inl
            (by
              rw [logEqNode, List.take_append_of_le_length within]
              exact retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [currentTermEq] using above,
            bounded,
            recorded,
            by
              rw [logEqNode, List.take_append_of_le_length within]
              exact missing
          ⟩
      · have supporterEq : supporter = node :=
          beyondIndexSelf index supporter (Nat.lt_of_not_ge within) effective
        subst supporter
        have progress :=
          activationProgress
            activationIndex activation activationStored node
              activationSupporter
        have currentTerm :
            ((nodeOf (leaderAppendState state node content)) node).currentTerm =
              ((nodeOf state) node).currentTerm :=
          currentTermEq node
        rw [currentTerm] at later
        omega
    · have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        simpa [logEqOther source sourceEq, currentTermEq] using current
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        simpa [logEqOther source sourceEq] using signature
      have oldEffective :
          supporter ∈
            effectiveAckers (joined := joinedNodes) state responseHistory source index :=
        effectiveAckersSubsetAtSignature
          source index oldRole signature effective
      have oldLater :
          ((nodeOf state) source).currentTerm <
            activation.activationTerm := by
        simpa [currentTermEq] using later
      rcases
          ackerActivationFacts
            source index oldRole oldCurrent oldSignature
            activationIndex activation configuration supporter
            activationStored governing activationSupporter
            oldEffective oldLater with
        retained | bad
      · exact Or.inl
          (by simpa [logEqOther source sourceEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [currentTermEq] using above,
          bounded,
          recorded,
          by simpa [logEqOther source sourceEq] using missing
        ⟩
  have activationCanonicalAfter :
      ActivationCanonicalFacts
        newCanonicalHistory owners activations := by
    apply
      activationCanonicalFrame
        canonicalHistory newCanonicalHistory owners owners activations
          activationQuorums.history activationCanonical
    · intros
      rfl
    · intro history canonical index value found
      exact
        preserveCanonicalAgreement history index value
          (canonical index value found)
  have configurationActivationsAfter :
      ConfigurationCoverageFacts
        (leaderAppendState state node content )
        activations := by
    apply
      configurationCoverageFrame
        configurationActivations currentConfigurationEq
        (fun candidate => by rw [currentTermEq])
        (fun candidate => by rw [commitIndexEq])
    · intro candidate frontier within
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [logEqNode, List.take_append_of_le_length]
        exact within.trans (facts.commitIndicesBounded node)
      · rw [logEqOther candidate candidateEq]
    · intro candidate witness role
      have candidateNe : Not (candidate = node) := by
        intro same
        subst candidate
        have oldRole :
            ((nodeOf state) node).role = .candidate := by
          simpa [roleEq] using role
        exact Role.noConfusion (oldRole.symm.trans leaderRole)
      simpa [currentTermEq]
        using witness.candidateTermStrict (by simpa [roleEq] using role)
  have termsPositiveAfter :
      CurrentTermsPositive
        (leaderAppendState state node content ) := by
    intro candidate participating
    rw [currentTermEq]
    apply facts.currentTermsPositive candidate
    intro none
    apply participating
    simpa [roleEq] using none
  have entriesBoundedAfter :
      EntriesDoNotExceedCurrentTerm
        (leaderAppendState state node content ) := by
    intro candidate value member
    by_cases candidateEq : candidate = node
    · subst candidate
      rw [logEqNode] at member
      simp at member
      rcases member with oldMember | newMember
      · rw [currentTermEq]
        exact facts.entriesDoNotExceedCurrentTerm node value oldMember
      · subst value
        simp [entry, currentTermEq]
    · have oldMember :
          value ∈ ((nodeOf state) candidate).log := by
        rw [logEqOther candidate candidateEq] at member
        exact member
      simpa [currentTermEq]
        using facts.entriesDoNotExceedCurrentTerm candidate value oldMember
  have voteFactsAfter :
      VoteHistoryFacts
        (leaderAppendState state node content ) votes := by
    constructor
    · exact facts.voteHistory.bootstrapEmpty
    · intro voter
      rw [votedForEq, currentTermEq]
      exact facts.voteHistory.current voter
    · intro voter term future
      apply facts.voteHistory.future voter term
      rw [currentTermEq] at future
      exact future
    · intro candidate voter active member
      rw [currentTermEq]
      apply facts.voteHistory.counted candidate voter
      · rw [roleEq] at active
        exact active
      · rw [votesGrantedEq] at member
        exact member
  have ownershipAfter :
      TermOwnershipFacts
        (leaderAppendState state node content )
        votes appendHistory newCanonicalHistory owners := by
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [currentTermEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro candidate index value found
      by_cases candidateEq : candidate = node
      · subst candidate
        have classified :=
          entryAtAppendSingleton
            (by simpa [logEqNode] using found)
        rcases classified with old | new
        · have preserved :=
            preserveCanonicalAgreement
              ((nodeOf state) node).log index value
                (ownership.logEntryAgreement node index value old.2)
          have takesEqual :=
            takeEqOfPrefix
              (List.prefix_append ((nodeOf state) node).log [entry]) old.1
          exact ⟨
            preserved.1,
            by
              rw [logEqNode]
              exact takesEqual.symm.trans preserved.2
          ⟩
        · rcases new with ⟨indexEq, valueEq⟩
          subst index
          subst value
          constructor
          · simpa [
              newCanonicalHistory, Function.update, entry,
              logEqNode
            ] using found
          · simp [
              newCanonicalHistory, entry,
              logEqNode
            ]
      · have oldFound :
            entryAt? ((nodeOf state) candidate).log index = some value := by
          rw [logEqOther candidate candidateEq] at found
          exact found
        rcases
            preserveCanonicalAgreement
              ((nodeOf state) candidate).log index value
                (ownership.logEntryAgreement
                  candidate index value oldFound) with
          ⟨canonicalFound, agreed⟩
        exact ⟨
          canonicalFound,
          by
            rw [logEqOther candidate candidateEq]
            exact agreed
        ⟩
    · intro destination request member index value found
      exact
        preserveCanonicalAgreement
          (appendHistory request) index value
            (ownership.queuedHistoryEntryAgreement
              destination request
                (by simpa using member)
                index value found)
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        rw [currentTermEq node, logEqNode]
        simp [newCanonicalHistory, entry]
      · have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
        have termNe :
            Not (
              ((nodeOf state) leader).currentTerm = entry.term) := by
          intro sameTerm
          have sameLeaderTerm :
              ((nodeOf state) node).currentTerm =
                ((nodeOf state) leader).currentTerm := by
            simpa [entry] using sameTerm.symm
          exact leaderEq
            (oldElectionSafety
              node leader leaderRole oldRole sameLeaderTerm).symm
        have oldHistory :=
          ownership.activeLeaderHistory leader oldRole
        simpa [currentTermEq, logEqOther leader leaderEq, newCanonicalHistory,
          Function.update, termNe]
          using oldHistory
    · intro term index value found
      by_cases termEq : term = entry.term
      · subst term
        have classified :=
          entryAtAppendSingleton
            (by simpa [
              newCanonicalHistory, Function.update
            ] using found)
        rcases classified with old | new
        · exact
            termOwnershipLogEntryOwner ownership
              (entryAtSomeMember old.2)
        · rcases new with ⟨_, valueEq⟩
          subst value
          exact ⟨node, ownership.activeLeader node leaderRole⟩
      · exact
          ownership.canonicalEntryOwner term index value
            (by simpa [
              newCanonicalHistory, Function.update, termEq
            ] using found)
    · intro term
      by_cases termEq : term = entry.term
      · subst term
        intro earlier later earlierEntry laterEntry order
            earlierFound laterFound
        have earlierInExtended :
            entryAt? (((nodeOf state) node).log ++ [entry]) earlier =
              some earlierEntry := by
          simpa [newCanonicalHistory, Function.update] using earlierFound
        have laterInExtended :
            entryAt? (((nodeOf state) node).log ++ [entry]) later =
              some laterEntry := by
          simpa [newCanonicalHistory, Function.update] using laterFound
        rcases entryAtAppendSingleton laterInExtended with old | new
        · have earlierWithin :
              earlier <= ((nodeOf state) node).log.length := by
            omega
          have earlierOld :
              entryAt? ((nodeOf state) node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            monoLog
              node earlier later earlierEntry laterEntry
                order earlierOld old.2
        · rcases new with ⟨laterEq, laterEntryEq⟩
          subst later
          subst laterEntry
          have earlierWithin :
              earlier <= ((nodeOf state) node).log.length := by omega
          have earlierOld :
              entryAt? ((nodeOf state) node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            facts.entriesDoNotExceedCurrentTerm
              node earlierEntry (entryAtSomeMember earlierOld)
      · simpa [
          newCanonicalHistory, Function.update, termEq
        ] using ownership.canonicalMonoLog term
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      constructor
      · simpa [currentTermEq] using bound
      · intro same
        have oldSame :
            term = ((nodeOf state) owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa using member)
    · intro destination request member sameTerm sourceRole
      have oldMember :
          (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
        simpa using member
      have oldSameTerm :
          request.2.2.term =
            ((nodeOf state) request.1).currentTerm := by
        simpa [currentTermEq] using sameTerm
      have oldLeaderRole :
          ((nodeOf state) request.1).role = .leader := by
        simpa [roleEq] using sourceRole
      have oldPrefix :=
        ownership.queuedActiveSourceHistory
          destination request oldMember oldSameTerm oldLeaderRole
      by_cases sourceEq : request.1 = node
      · rw [sourceEq] at oldPrefix ⊢
        rw [logEqNode]
        exact oldPrefix.trans (List.prefix_append _ _)
      · rw [logEqOther request.1 sourceEq]
        exact oldPrefix
  have electionFactsAfter :
      ElectionHistoryFacts
        (leaderAppendState state node content )
        votes newCanonicalHistory owners elections := by
    apply
      electionHistoryFrame
        state (leaderAppendState state node content )
          votes votes canonicalHistory newCanonicalHistory
          owners elections electionFacts
    · intros
      rfl
    · intro term
      by_cases termEq : term = entry.term
      · subst term
        rw [ownership.activeLeaderHistory node leaderRole]
        simp [newCanonicalHistory, entry]
      · simp [
          newCanonicalHistory, termEq
        ]
    · intro history canonical index value found
      exact
        preserveCanonicalAgreement history index value
          (canonical index value found)
  have voteCanonicalAfter :
      GrantedVoteCanonicalSnapshots (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        newCanonicalHistory voteCandidateHistory voteVoterHistory := by
    apply
      grantedVoteCanonicalFrame
        state (leaderAppendState state node content )
          canonicalHistory newCanonicalHistory
          voteCandidateHistory voteVoterHistory voteCanonicalFacts
          (fun candidate _ => currentTermEq candidate)
    · intro candidate active
      simpa [roleEq] using active
    · intro candidate voter _ member
      rw [effectiveElectionVotersEq] at member
      exact member
    · intro history canonical index value found
      exact
        preserveCanonicalAgreement history index value
          (canonical index value found)
  have snapshotsAfter :
      GrantedVoteSnapshots (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        votes voteCandidateHistory voteVoterHistory := by
    intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    rcases
        facts.grantedVoteSnapshots candidate voter active oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · rcases snapshot with ⟨candidatePrefix, voterTerm, upToDate⟩
      refine ⟨recorded, Or.inr ⟨?_, voterTerm, upToDate⟩⟩
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [logEqNode]
        exact candidatePrefix.trans (List.prefix_append _ _)
      · simpa [logEqOther candidate candidateEq] using candidatePrefix
  have committedSignatureAfter :
      CommittedFrontierIsSignature
        (leaderAppendState state node content ) := by
    intro candidate positive
    have oldPositive :
        0 < ((nodeOf state) candidate).commitIndex := by
      simpa [commitIndexEq] using positive
    have oldSignature :=
      invariantFactsCommittedFrontierIsSignatureFromCommitEvidence
        facts candidate oldPositive
    simpa [commitIndexEq] using isSignatureAt_of_prefix (logPrefix candidate) oldSignature
  have ackerElectionAfter :
      AckerElectionHistory (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        responseHistory elections := by
    intro source index role current signature term record voter
        recorded member effective newer
    have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
    by_cases sourceEq : source = node
    · subst source
      by_cases oldIndex : index <= ((nodeOf state) node).log.length
      · have oldCurrent :
            termAt ((nodeOf state) node).log index =
              ((nodeOf state) node).currentTerm := by
          rw [logEqNode] at current
          simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using current
        rcases
            ackerElectionFacts node index oldRole oldCurrent
              (signatureBackNode index oldIndex signature)
              term record voter recorded member
              (effectiveAckersSubsetAtSignature
                node index oldRole signature effective)
              (by simpa [currentTermEq] using newer) with
          retained | bad
        · exact Or.inl (by
            rw [logEqNode]
            simpa [
              List.take_append_of_le_length oldIndex
            ] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [currentTermEq] using above,
            below,
            badRecorded,
            by
              rw [logEqNode]
              simpa [
                List.take_append_of_le_length oldIndex
              ] using missing
          ⟩
      · have voterEq : voter = node :=
          beyondIndexSelf index voter (by omega) effective
        subst voter
        have voterTerm :=
          electionHistoryVoterTerm
            facts.voteHistory electionFacts recorded member
        rw [currentTermEq] at newer
        omega
    · have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        simpa [logEqOther source sourceEq, currentTermEq] using current
      rcases
          ackerElectionFacts source index oldRole oldCurrent
            (by simpa [logEqOther source sourceEq] using signature)
            term record voter recorded member
            (effectiveAckersSubsetAtSignature
              source index oldRole signature effective)
            (by simpa [currentTermEq] using newer) with
        retained | bad
      · exact Or.inl
          (by simpa [logEqOther source sourceEq] using retained)
      · right
        rcases bad with
          ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
        exact ⟨
          badTerm,
          badRecord,
          by simpa [currentTermEq] using above,
          below,
          badRecorded,
          by simpa [logEqOther source sourceEq] using missing
        ⟩
  have recordBridgeAfter :
      forall source index,
        ((nodeOf (leaderAppendState state node content))
          source).role = .leader ->
        termAt
            ((nodeOf (leaderAppendState state node content))
              source).log index =
          ((nodeOf (leaderAppendState state node content))
            source).currentTerm ->
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              source).log index = true ->
        hasPotentialMajorityAt (joined := leaderAppendJoined joinedNodes state node content)
            (leaderAppendState state node content)
            appendHistory responseHistory source index ->
          forall term record,
            elections term = some record ->
            ((nodeOf (leaderAppendState state node content))
                source).currentTerm < term ->
              ((nodeOf (leaderAppendState state node content))
                  source).log.take index <+:
                record.promotionLog := by
    intro source index role current signature potential
        term record recorded later
    exact
      potentialPrefixInElectionRecordsFromActivationHistory
        termsPositiveAfter entriesBoundedAfter voteFactsAfter
        ownershipAfter electionFactsAfter configurationFactsAfter
        activationQuorums.history activationProgressAfter
        ackerActivationAfter ackerElectionAfter activationCanonicalAfter
        activationElections configurationActivationsAfter
        evidenceAfter prospectiveAfter
        role current signature potential term record recorded later
  have candidateBridgeAfter :
      forall source index,
        ((nodeOf (leaderAppendState state node content))
          source).role = .leader ->
        termAt
            ((nodeOf (leaderAppendState state node content))
              source).log index =
          ((nodeOf (leaderAppendState state node content))
            source).currentTerm ->
        isSignatureAt
            ((nodeOf (leaderAppendState state node content))
              source).log index = true ->
        hasPotentialMajorityAt (joined := leaderAppendJoined joinedNodes state node content)
            (leaderAppendState state node content)
            appendHistory responseHistory source index ->
          forall candidate,
            ((nodeOf (leaderAppendState state node content))
                candidate).role = .candidate ->
            hasPotentialElectionMajority (joined := leaderAppendJoined joinedNodes state node content)
              (leaderAppendState state node content)
              candidate ->
            ((nodeOf (leaderAppendState state node content))
                source).currentTerm <
              ((nodeOf (leaderAppendState state node content))
                candidate).currentTerm ->
              ((nodeOf (leaderAppendState state node content))
                    source).log.take index <+:
                  ((nodeOf (leaderAppendState state node content))
                    candidate).log \/
                Exists fun configuration =>
                  configuration ∈
                      activeConfigurations
                        ((nodeOf (leaderAppendState state node content)) source) /\
                    configuration.index <= index /\
                    configuration ∈
                      activeConfigurations
                        ((nodeOf (leaderAppendState state node content))
                            candidate) := by
    intro source index sourceRole current signature potential
        candidate candidateRole candidateMajority newer
    by_cases oldIndex : index <= ((nodeOf state) source).log.length
    · have oldSourceRole : ((nodeOf state) source).role = .leader := by
        simpa [roleEq] using sourceRole
      have oldCurrent :
          termAt ((nodeOf state) source).log index =
            ((nodeOf state) source).currentTerm := by
        calc
          termAt ((nodeOf state) source).log index
              = termAt ((nodeOf (leaderAppendState state node content)) source).log index :=
            (termAtIndexOld source index oldIndex).symm
          _ = ((nodeOf (leaderAppendState state node content)) source).currentTerm :=
            current
          _ = ((nodeOf state) source).currentTerm := currentTermEq source
      have oldSignature :
          isSignatureAt ((nodeOf state) source).log index = true := by
        exact isSignatureAt_of_prefix
          (List.take_prefix index ((nodeOf state) source).log)
          (by
            have takeEq :
                ((nodeOf (leaderAppendState state node content)) source).log.take
                    index =
                  ((nodeOf state) source).log.take index := by
              by_cases sourceEq : source = node
              · subst source
                rw [logEqNode, List.take_append_of_le_length oldIndex]
              · rw [logEqOther source sourceEq]
            rw [← takeEq]
            exact isSignatureAt_take_of_le le_rfl signature)
      have oldPotential :=
        potentialMajorityBack source index oldSourceRole potential
      have oldCandidateRole :
          ((nodeOf state) candidate).role = .candidate := by
        simpa [roleEq] using candidateRole
      have oldCandidateMajority :=
        potentialElectionMajorityBack
          candidate candidateRole candidateMajority
      have oldNewer :
          ((nodeOf state) source).currentTerm <
            ((nodeOf state) candidate).currentTerm := by
        simpa [currentTermEq] using newer
      rcases
          activationQuorums.candidateBridge
            source index oldSourceRole oldCurrent oldSignature oldPotential
            candidate oldCandidateRole oldCandidateMajority oldNewer with
        direct | shared
      · have candidateNe : Not (candidate = node) := by
          intro same
          subst candidate
          exact Role.noConfusion (leaderRole.symm.trans oldCandidateRole)
        have sourceTakeEq :
            ((nodeOf (leaderAppendState state node content)) source).log.take index =
              ((nodeOf state) source).log.take index := by
          by_cases sourceEq : source = node
          · subst source
            rw [logEqNode, List.take_append_of_le_length oldIndex]
          · rw [logEqOther source sourceEq]
        exact Or.inl
          (by simpa [
            sourceTakeEq, logEqOther candidate candidateNe
          ] using direct)
      · right
        rcases shared with
          ⟨configuration, sourceActive, governs, candidateActive⟩
        exact ⟨
          configuration,
          activeConfigurationsForward source configuration sourceActive,
          governs,
          activeConfigurationsForward candidate configuration candidateActive
        ⟩
    · have sourceEq : source = node := by
        by_contra different
        rw [logEqOther source different] at signature
        rcases isSignatureAtTrue signature with ⟨foundEntry, found, _⟩
        exact oldIndex (entryAtSomeIndexBound found)
      subst source
      left
      apply
        activationPrefixInEffectiveCandidateByAuthorityChain
          termsPositiveAfter committedSignatureAfter entriesBoundedAfter
          voteFactsAfter snapshotsAfter voteCanonicalAfter ownershipAfter
          electionFactsAfter configurationFactsAfter
          activationQuorums.history
          configurationFactsAfter.supporterCurrentHistory
          activationVoteHistoryAfter activationProgressAfter
          ackerActivationAfter ackerElectionAfter activationCanonicalAfter
          activationElections configurationActivationsAfter
          evidenceAfter prospectiveAfter
          sourceRole current signature potential
          candidateRole candidateMajority newer
      intro configuration sourceActive governs candidateActive
      rcases
          potentialElectionMajorityIntersectionEffective
            snapshotsAfter potential sourceActive governs
            (Or.inl candidateRole) candidateMajority candidateActive newer with
        ⟨voter, effective, electionMember⟩
      have voterEq : voter = node :=
        beyondIndexSelf index voter (Nat.lt_of_not_ge oldIndex) effective
      subst voter
      have termBound :=
        potentialElectionVoterTermBound
          snapshotsAfter (Or.inl candidateRole) electionMember
      omega
  have activationQuorumsAfter :
      ActivationQuorumFacts (joined := leaderAppendJoined joinedNodes state node content)
        (leaderAppendState state node content)
        appendHistory responseHistory elections activations := by
    by_cases notSignature : Not (content = .signature)
    · exact activationQuorumsOldCase notSignature
    · constructor
      · exact activationQuorums.history
      · intro source index role current signature potential
          term record recorded newer
        exact Or.inl
          (recordBridgeAfter
            source index role current signature potential
            term record recorded newer)
      · exact candidateBridgeAfter
      · intro source index role current signature majority committed
        by_cases zero :
            ((nodeOf (leaderAppendState state node content))
              committed).commitIndex = 0
        · have oldZero :
              ((nodeOf state) committed).commitIndex = 0 := by
            simpa [commitIndexEq] using zero
          exact Or.inr (Or.inl (by simp [NodeState.committedLog, oldZero]))
        · have positive :
              0 <
                ((nodeOf (leaderAppendState state node content))
                  committed).commitIndex :=
            Nat.pos_of_ne_zero zero
          rcases evidenceAfter.nodePositive committed positive with
            ⟨committedEvidence, stored, valid, _lengthEq, _termBound⟩
          have known :
              KnownCommitEvidence
                (leaderAppendState state node content )
                appendHistory nodeEvidence requestEvidence
                committedEvidence
                ((nodeOf (leaderAppendState state node content))
                    committed).committedLog :=
            Or.inl ⟨committed, positive, stored, rfl⟩
          by_cases termOrder :
              committedEvidence.commitTerm <=
                ((nodeOf (leaderAppendState state node content))
                    source).currentTerm
          · rcases
                configurationMajorityNonempty valid.2.2.2.2.2.1 with
              ⟨member, _authorityMember, ackMember⟩
            have committedInSource :
                ((nodeOf (leaderAppendState state node content))
                    committed).committedLog <+:
                  ((nodeOf (leaderAppendState state node content)) source).log :=
              (validEvidenceSupportedPrefixFrontier valid).trans
                (knownCommitEvidenceActiveLeaderContainsFrontier
                  ownershipAfter electionFactsAfter evidenceAfter
                  prospectiveAfter known role termOrder ackMember)
            rcases
                prefixesComparable
                  (List.take_prefix index
                    ((nodeOf (leaderAppendState state node content)) source).log)
                  committedInSource with
              direct | direct
            · exact Or.inl direct
            · exact Or.inr (Or.inl direct)
          · have sourceBefore :
                ((nodeOf (leaderAppendState state node content))
                    source).currentTerm <
                  committedEvidence.commitTerm := by
              omega
            have canonicalEq :=
              knownEvidenceFrontierCanonical
                ownershipAfter evidenceAfter prospectiveAfter known
            have frontierPositive :
                0 < committedEvidence.commitFrontier := by
              have supportedPositive :=
                knownCommitEvidenceSupportedLengthPositive
                  evidenceAfter known
              exact supportedPositive.trans_le valid.2.2.1
            rcases
                entryAtSomeOfPositiveBound frontierPositive valid.1 with
              ⟨frontierEntry, historyFound⟩
            have frontierEntryTerm :
                frontierEntry.term = committedEvidence.commitTerm := by
              simpa [termAt, historyFound] using valid.2.1
            have historyTakeFound :
                entryAt?
                    (committedEvidence.history.take
                      committedEvidence.commitFrontier)
                    committedEvidence.commitFrontier =
                  some frontierEntry := by
              rw [entryAtTake_of_le le_rfl]
              exact historyFound
            have canonicalTakeFound :
                entryAt?
                    ((newCanonicalHistory
                      committedEvidence.commitTerm).take
                        committedEvidence.commitFrontier)
                    committedEvidence.commitFrontier =
                  some frontierEntry := by
              rw [← canonicalEq]
              exact historyTakeFound
            have canonicalFound :
                entryAt?
                    (newCanonicalHistory committedEvidence.commitTerm)
                    committedEvidence.commitFrontier =
                  some frontierEntry := by
              rw [← entryAtTake_of_le
                (log := newCanonicalHistory committedEvidence.commitTerm)
                le_rfl]
              exact canonicalTakeFound
            rcases
                ownershipAfter.canonicalEntryOwner
                  committedEvidence.commitTerm
                  committedEvidence.commitFrontier
                  frontierEntry canonicalFound with
              ⟨owner, owned⟩
            rw [frontierEntryTerm] at owned
            rcases
                electionFactsAfter.ownerRecorded
                  committedEvidence.commitTerm owner owned with
              bootstrap | elected
            · have sourcePositive :=
                termsPositiveAfter source (by rw [role]; decide)
              rw [bootstrap.1] at sourceBefore
              omega
            · rcases elected with
                ⟨record, recordStored, _recordLeader⟩
              have sourceInCanonical :
                  ((nodeOf (leaderAppendState state node content)) source).log.take
                      index <+:
                    newCanonicalHistory committedEvidence.commitTerm :=
                (recordBridgeAfter
                  source index role current signature
                  (effectiveMajorityImpliesPotential
                    (leaderAppendState state node content )
                    appendHistory responseHistory source index majority)
                  committedEvidence.commitTerm record recordStored
                  sourceBefore).trans
                  (electionFactsAfter.promotionCanonical
                    committedEvidence.commitTerm record recordStored)
              have committedInCanonical :
                  ((nodeOf (leaderAppendState state node content))
                      committed).committedLog <+:
                    newCanonicalHistory committedEvidence.commitTerm :=
                (validEvidenceSupportedPrefixFrontier valid).trans
                  (by
                    rw [canonicalEq]
                    exact List.take_prefix _ _)
              rcases
                  prefixesComparable
                    sourceInCanonical committedInCanonical with
                direct | direct
              · exact Or.inl direct
              · exact Or.inr (Or.inl direct)
      · intro left leftIndex leftRole leftCurrent leftSignature leftMajority
          right rightIndex rightRole rightCurrent rightSignature rightMajority
        rcases Nat.lt_trichotomy
            ((nodeOf (leaderAppendState state node content))
              left).currentTerm
            ((nodeOf (leaderAppendState state node content))
              right).currentTerm with
          leftBefore | sameTerm | rightBefore
        · have rightOwned := ownershipAfter.activeLeader right rightRole
          rcases
              electionFactsAfter.ownerRecorded
                ((nodeOf (leaderAppendState state node content)) right).currentTerm
                right rightOwned with
            bootstrap | elected
          · have leftPositive :=
              termsPositiveAfter left (by rw [leftRole]; decide)
            rw [bootstrap.1] at leftBefore
            omega
          · rcases elected with
              ⟨record, recordStored, _recordLeader⟩
            have leftInRight :
                ((nodeOf (leaderAppendState state node content)) left).log.take
                    leftIndex <+:
                  ((nodeOf (leaderAppendState state node content)) right).log :=
              (recordBridgeAfter
                left leftIndex leftRole leftCurrent leftSignature
                (effectiveMajorityImpliesPotential
                  (leaderAppendState state node content )
                  appendHistory responseHistory
                  left leftIndex leftMajority)
                ((nodeOf (leaderAppendState state node content)) right).currentTerm
                record recordStored leftBefore).trans
                ((electionFactsAfter.promotionCanonical
                  ((nodeOf (leaderAppendState state node content))
                      right).currentTerm
                  record recordStored).trans
                  (by rw [
                    ownershipAfter.activeLeaderHistory right rightRole
                  ]))
            rcases
                prefixesComparable
                  leftInRight
                  (List.take_prefix rightIndex
                    ((nodeOf (leaderAppendState state node content)) right).log) with
              direct | direct
            · exact Or.inl direct
            · exact Or.inr (Or.inl direct)
        · have leftOwned := ownershipAfter.activeLeader left leftRole
          have rightOwned := ownershipAfter.activeLeader right rightRole
          rw [sameTerm] at leftOwned
          have sameNode : left = right :=
            Option.some.inj (leftOwned.symm.trans rightOwned)
          subst right
          rcases
              prefixesComparable
                (List.take_prefix leftIndex
                  ((nodeOf (leaderAppendState state node content)) left).log)
                (List.take_prefix rightIndex
                  ((nodeOf (leaderAppendState state node content)) left).log) with
            direct | direct
          · exact Or.inl direct
          · exact Or.inr (Or.inl direct)
        · have leftOwned := ownershipAfter.activeLeader left leftRole
          rcases
              electionFactsAfter.ownerRecorded
                ((nodeOf (leaderAppendState state node content)) left).currentTerm
                left leftOwned with
            bootstrap | elected
          · have rightPositive :=
              termsPositiveAfter right (by rw [rightRole]; decide)
            rw [bootstrap.1] at rightBefore
            omega
          · rcases elected with
              ⟨record, recordStored, _recordLeader⟩
            have rightInLeft :
                ((nodeOf (leaderAppendState state node content)) right).log.take
                    rightIndex <+:
                  ((nodeOf (leaderAppendState state node content)) left).log :=
              (recordBridgeAfter
                right rightIndex rightRole rightCurrent rightSignature
                (effectiveMajorityImpliesPotential
                  (leaderAppendState state node content )
                  appendHistory responseHistory
                  right rightIndex rightMajority)
                ((nodeOf (leaderAppendState state node content)) left).currentTerm
                record recordStored rightBefore).trans
                ((electionFactsAfter.promotionCanonical
                  ((nodeOf (leaderAppendState state node content))
                      left).currentTerm
                  record recordStored).trans
                  (by rw [
                    ownershipAfter.activeLeaderHistory left leftRole
                  ]))
            rcases
                prefixesComparable
                  rightInLeft
                  (List.take_prefix leftIndex
                    ((nodeOf (leaderAppendState state node content)) left).log) with
              direct | direct
            · exact Or.inr (Or.inl direct)
            · exact Or.inl direct
      · intro activationIndex activation destination request
          stored queued sameTerm
        exact
          activationQuorums.queuedComparable
            activationIndex activation destination request
            stored (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using queued) sameTerm
      · apply
          committedConfigurationCoverageTakeFrame
            activationQuorums.committedCoverage facts.commitIndicesBounded
            (fun candidate => by
              by_cases candidateEq : candidate = node
              · subst candidate
                have oldBound := facts.commitIndicesBounded node
                simp [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, nodeOf_replaceNode]
                omega
              · simpa [
                  leaderAppendState_nodes_of_ne
                    state node candidate content  candidateEq
                ] using facts.commitIndicesBounded candidate)
            commitIndexEq
            (fun candidate => Nat.le_of_eq (currentTermEq candidate).symm)
        intro candidate frontier within
        by_cases candidateEq : candidate = node
        · subst candidate
          rw [leaderAppendState_log_same (present := present)]
          exact List.take_append_of_le_length
            (within.trans (facts.commitIndicesBounded node))
        · rw [
            leaderAppendState_nodes_of_ne
              state node candidate content  candidateEq
          ]
      · apply
          queuedConfigurationCoverageFrame
            activationQuorums.queuedCoverage
            (afterAppendHistory := appendHistory)
        · intro destination request queued
          simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using queued
        · intro _
          rfl
  · refine ⟨
      owners,
      newCanonicalHistory,
      elections,
      activations,
      nodeEvidence,
      requestEvidence,
      ?_,
      ?_,
      configurationFactsAfter,
      ?_,
      ?_,
      ?_,
      activationVoteHistoryAfter,
      ?_,
      ackerActivationAfter,
      ?_,
      activationProgressAfter,
      activationQuorumsAfter,
      evidenceAfter,
      prospectiveAfter,
      activationEvidenceAfter,
      activationCanonicalAfter,
      activationElections,
      configurationActivationsAfter
    ⟩
    constructor
    · exact ownership.bootstrap
    · intro leader role
      rw [currentTermEq]
      exact ownership.activeLeader leader
        (by simpa [roleEq] using role)
    · intro candidate index value found
      by_cases candidateEq : candidate = node
      · subst candidate
        have classified :=
          entryAtAppendSingleton
            (by simpa [logEqNode] using found)
        rcases classified with old | new
        · have preserved :=
            preserveCanonicalAgreement
              ((nodeOf state) node).log index value
                (ownership.logEntryAgreement node index value old.2)
          have takesEqual :=
            takeEqOfPrefix
              (List.prefix_append ((nodeOf state) node).log [entry]) old.1
          exact ⟨
            preserved.1,
            by
              rw [logEqNode]
              exact takesEqual.symm.trans preserved.2
          ⟩
        · rcases new with ⟨indexEq, valueEq⟩
          subst index
          subst value
          constructor
          · simpa [
              newCanonicalHistory, Function.update, entry,
              logEqNode
            ] using found
          · simp [
              newCanonicalHistory, entry,
              logEqNode
            ]
      · have oldFound :
            entryAt? ((nodeOf state) candidate).log index = some value := by
          rw [logEqOther candidate candidateEq] at found
          exact found
        rcases
            preserveCanonicalAgreement
              ((nodeOf state) candidate).log index value
                (ownership.logEntryAgreement
                  candidate index value oldFound) with
          ⟨canonicalFound, agreed⟩
        exact ⟨
          canonicalFound,
          by
            rw [logEqOther candidate candidateEq]
            exact agreed
        ⟩
    · intro destination request member index value found
      exact
        preserveCanonicalAgreement
          (appendHistory request) index value
            (ownership.queuedHistoryEntryAgreement
              destination request
                (by simpa using member)
                index value found)
    · intro leader role
      by_cases leaderEq : leader = node
      · subst leader
        rw [currentTermEq node, logEqNode]
        simp [newCanonicalHistory, entry]
      · have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
        have termNe :
            Not (
              ((nodeOf state) leader).currentTerm = entry.term) := by
          intro sameTerm
          have sameLeaderTerm :
              ((nodeOf state) node).currentTerm =
                ((nodeOf state) leader).currentTerm := by
            simpa [entry] using sameTerm.symm
          exact leaderEq
            (oldElectionSafety
              node leader leaderRole oldRole sameLeaderTerm).symm
        have oldHistory :=
          ownership.activeLeaderHistory leader oldRole
        simpa [currentTermEq, logEqOther leader leaderEq, newCanonicalHistory,
          Function.update, termNe]
          using oldHistory
    · intro term index value found
      by_cases termEq : term = entry.term
      · subst term
        have classified :=
          entryAtAppendSingleton
            (by simpa [
              newCanonicalHistory, Function.update
            ] using found)
        rcases classified with old | new
        · exact
            termOwnershipLogEntryOwner ownership
              (entryAtSomeMember old.2)
        · rcases new with ⟨_, valueEq⟩
          subst value
          exact ⟨node, ownership.activeLeader node leaderRole⟩
      · exact
          ownership.canonicalEntryOwner term index value
            (by simpa [
              newCanonicalHistory, Function.update, termEq
            ] using found)
    · intro term
      by_cases termEq : term = entry.term
      · subst term
        intro earlier later earlierEntry laterEntry order
            earlierFound laterFound
        have earlierInExtended :
            entryAt? (((nodeOf state) node).log ++ [entry]) earlier =
              some earlierEntry := by
          simpa [newCanonicalHistory, Function.update] using earlierFound
        have laterInExtended :
            entryAt? (((nodeOf state) node).log ++ [entry]) later =
              some laterEntry := by
          simpa [newCanonicalHistory, Function.update] using laterFound
        rcases entryAtAppendSingleton laterInExtended with old | new
        · have earlierWithin :
              earlier <= ((nodeOf state) node).log.length := by
            omega
          have earlierOld :
              entryAt? ((nodeOf state) node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            monoLog
              node earlier later earlierEntry laterEntry
                order earlierOld old.2
        · rcases new with ⟨laterEq, laterEntryEq⟩
          subst later
          subst laterEntry
          have earlierWithin :
              earlier <= ((nodeOf state) node).log.length := by omega
          have earlierOld :
              entryAt? ((nodeOf state) node).log earlier =
                some earlierEntry := by
            rw [← entryAtAppend_of_le_length earlierWithin]
            exact earlierInExtended
          exact
            facts.entriesDoNotExceedCurrentTerm
              node earlierEntry (entryAtSomeMember earlierOld)
      · simpa [
          newCanonicalHistory, Function.update, termEq
        ] using ownership.canonicalMonoLog term
    · intro term owner owned
      rcases ownership.ownerProgress term owner owned with
        ⟨bound, oldLeader⟩
      constructor
      · simpa [currentTermEq] using bound
      · intro same
        have oldSame :
            term = ((nodeOf state) owner).currentTerm := by
          simpa [currentTermEq] using same
        simpa [roleEq] using oldLeader oldSame
    · intro destination request member
      exact
        ownership.queuedAppendMetadata destination request
          (by simpa using member)
    · intro destination request member sameTerm leaderRole
      have oldMember :
          (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination) := by
        simpa using member
      have oldSameTerm :
          request.2.2.term =
            ((nodeOf state) request.1).currentTerm := by
        simpa [currentTermEq] using sameTerm
      have oldLeaderRole :
          ((nodeOf state) request.1).role = .leader := by
        simpa [roleEq] using leaderRole
      have oldPrefix :=
        ownership.queuedActiveSourceHistory
          destination request oldMember oldSameTerm oldLeaderRole
      by_cases sourceEq : request.1 = node
      · rw [sourceEq] at oldPrefix ⊢
        rw [logEqNode]
        exact oldPrefix.trans (List.prefix_append _ _)
      · rw [logEqOther request.1 sourceEq]
        exact oldPrefix
    · apply
        electionHistoryFrame
          state (leaderAppendState state node content )
            votes votes canonicalHistory newCanonicalHistory
            owners elections electionFacts
      · intros
        rfl
      · intro term
        by_cases termEq : term = entry.term
        · subst term
          rw [ownership.activeLeaderHistory node leaderRole]
          simp [newCanonicalHistory, entry]
        · simp [
            newCanonicalHistory, termEq
          ]
      · intro history canonical index value found
        exact
          preserveCanonicalAgreement history index value
            (canonical index value found)
    · apply
        grantedVoteCanonicalFrame
          state (leaderAppendState state node content )
            canonicalHistory newCanonicalHistory
            voteCandidateHistory voteVoterHistory voteCanonicalFacts
            (fun candidate _ => currentTermEq candidate)
      · intro candidate active
        simpa [roleEq] using active
      · intro candidate voter _ member
        rw [effectiveElectionVotersEq] at member
        exact member
      · intro history canonical index value found
        exact
          preserveCanonicalAgreement history index value
            (canonical index value found)
    · intro source index role current signature voter effective
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= ((nodeOf state) node).log.length
        · have oldCurrent :
              termAt ((nodeOf state) node).log index =
                ((nodeOf state) node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using current
          rcases
              ackerCurrentFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature) voter
                (effectiveAckersSubsetAtSignature
                  node index oldRole signature effective) with
            retained | bad
          · left
            rw [logEqNode]
            have sourceTake :
                (((nodeOf state) node).log ++ [entry]).take index =
                  ((nodeOf state) node).log.take index := by
              rw [List.take_append_of_le_length oldIndex]
            rw [sourceTake]
            by_cases voterEq : voter = node
            · subst voter
              simpa [logEqNode] using retained.trans (List.prefix_append _ _)
            · simpa [logEqOther voter voterEq] using retained
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
            exact ⟨
              badTerm,
              badRecord,
              by simpa [currentTermEq] using above,
              by simpa [currentTermEq] using bounded,
              recorded,
              by
                rw [logEqNode]
                simpa [
                  List.take_append_of_le_length oldIndex
                ] using missing
            ⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          exact Or.inl (List.take_prefix index _)
      · have oldCurrent :
            termAt ((nodeOf state) source).log index =
              ((nodeOf state) source).currentTerm := by
          simpa [logEqOther source sourceEq, currentTermEq] using current
        rcases
            ackerCurrentFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature) voter
              (effectiveAckersSubsetAtSignature
                source index oldRole signature effective) with
          retained | bad
        · left
          rw [logEqOther source sourceEq]
          by_cases voterEq : voter = node
          · subst voter
            rw [logEqNode]
            exact retained.trans (List.prefix_append _ _)
          · simpa [logEqOther voter voterEq] using retained
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [currentTermEq] using above,
            by simpa [currentTermEq] using bounded,
            recorded,
            by simpa [logEqOther source sourceEq] using missing
          ⟩
    · intro source index role current signature
        voter voteTerm candidate effective voted different newer
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= ((nodeOf state) node).log.length
        · have oldCurrent :
              termAt ((nodeOf state) node).log index =
                ((nodeOf state) node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using current
          rcases
              ackerVoteFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature)
                voter voteTerm candidate
                (effectiveAckersSubsetAtSignature
                  node index oldRole signature effective)
                voted different (by simpa [currentTermEq] using newer) with
            retained | bad
          · exact Or.inl (by
              rw [logEqNode]
              simpa [
                List.take_append_of_le_length oldIndex
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
            exact ⟨
              badTerm,
              badRecord,
              by simpa [currentTermEq] using above,
              bounded,
              recorded,
              by
                rw [logEqNode]
                simpa [
                  List.take_append_of_le_length oldIndex
                ] using missing
            ⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          have future :
              votes node voteTerm = none :=
            facts.voteHistory.future node voteTerm
              (by simpa [currentTermEq] using newer)
          rw [future] at voted
          contradiction
      · have oldCurrent :
            termAt ((nodeOf state) source).log index =
              ((nodeOf state) source).currentTerm := by
          simpa [logEqOther source sourceEq, currentTermEq] using current
        rcases
            ackerVoteFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature)
              voter voteTerm candidate
              (effectiveAckersSubsetAtSignature
                source index oldRole signature effective)
              voted different (by simpa [currentTermEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logEqOther source sourceEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, bounded, recorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [currentTermEq] using above,
            bounded,
            recorded,
            by simpa [logEqOther source sourceEq] using missing
          ⟩
    · intro source index role current signature term record voter
        recorded member effective newer
      have oldRole : ((nodeOf state) source).role = .leader := by simpa [roleEq] using role
      by_cases sourceEq : source = node
      · subst source
        by_cases oldIndex : index <= ((nodeOf state) node).log.length
        · have oldCurrent :
              termAt ((nodeOf state) node).log index =
                ((nodeOf state) node).currentTerm := by
            rw [logEqNode] at current
            simpa [termAtAppend_of_le_length oldIndex, currentTermEq] using current
          rcases
              ackerElectionFacts node index oldRole oldCurrent
                (signatureBackNode index oldIndex signature)
                term record voter recorded member
                (effectiveAckersSubsetAtSignature
                  node index oldRole signature effective)
                (by simpa [currentTermEq] using newer) with
            retained | bad
          · exact Or.inl (by
              rw [logEqNode]
              simpa [
                List.take_append_of_le_length oldIndex
              ] using retained)
          · right
            rcases bad with
              ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
            exact ⟨
              badTerm,
              badRecord,
              by simpa [currentTermEq] using above,
              below,
              badRecorded,
              by
                rw [logEqNode]
                simpa [
                  List.take_append_of_le_length oldIndex
                ] using missing
            ⟩
        · have voterEq : voter = node :=
            beyondIndexSelf index voter (by omega) effective
          subst voter
          have voterTerm :=
            electionHistoryVoterTerm
              facts.voteHistory electionFacts recorded member
          rw [currentTermEq] at newer
          omega
      · have oldCurrent :
            termAt ((nodeOf state) source).log index =
              ((nodeOf state) source).currentTerm := by
          simpa [logEqOther source sourceEq, currentTermEq] using current
        rcases
            ackerElectionFacts source index oldRole oldCurrent
              (by simpa [logEqOther source sourceEq] using signature)
              term record voter recorded member
              (effectiveAckersSubsetAtSignature
                source index oldRole signature effective)
              (by simpa [currentTermEq] using newer) with
          retained | bad
        · exact Or.inl
            (by simpa [logEqOther source sourceEq] using retained)
        · right
          rcases bad with
            ⟨badTerm, badRecord, above, below, badRecorded, missing⟩
          exact ⟨
            badTerm,
            badRecord,
            by simpa [currentTermEq] using above,
            below,
            badRecorded,
            by simpa [logEqOther source sourceEq] using missing
          ⟩
    · intro destination request queued record recorded
      exact
        electionQueuedFacts destination request
          (by simpa using queued)
          record recorded
  · intro candidate voter active member
    rw [currentTermEq candidate, currentTermEq voter]
    rw [roleEq] at active
    have oldMember :
        voter ∈ effectiveElectionVoters (joined := joinedNodes) state candidate := by
      rw [effectiveElectionVotersEq] at member
      exact member
    rcases
        facts.grantedVoteSnapshots candidate voter active oldMember with
      ⟨recorded, self | snapshot⟩
    · exact ⟨recorded, Or.inl self⟩
    · rcases snapshot with ⟨candidatePrefix, voterTerm, upToDate⟩
      refine ⟨recorded, Or.inr ⟨?_, voterTerm, upToDate⟩⟩
      by_cases candidateEq : candidate = node
      · subst candidate
        rw [logEqNode]
        exact candidatePrefix.trans (List.prefix_append _ _)
      · simpa [logEqOther candidate candidateEq] using candidatePrefix
  · refine ⟨ackHistory, ?_⟩
    constructor
    · intro leader role peer zero
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      apply ackFacts.zero leader oldRole peer
      simpa [matchEq] using zero
    · intro leader role peer positive
      have oldRole : ((nodeOf state) leader).role = .leader := by simpa [roleEq] using role
      have oldPositive :
          0 < ((nodeOf state) leader).matchIndex peer := by
        simpa [matchEq] using positive
      rcases ackFacts.positive leader oldRole peer oldPositive with
        ⟨snapshot, stored, snapshotTerm, snapshotIndex,
          historyBound, agreed⟩
      refine ⟨
        snapshot,
        stored,
        by simpa [currentTermEq] using snapshotTerm,
        by simpa [matchEq] using snapshotIndex,
        historyBound,
        ?_
      ⟩
      by_cases leaderEq : leader = node
      · subst leader
        have matchBound :=
          (facts.leaderProgressBounded node leaderRole peer).2
        have indexBound :
            snapshot.index <= ((nodeOf state) node).log.length := by
          rw [snapshotIndex]
          exact matchBound
        rw [logEqNode]
        rw [List.take_append_of_le_length indexBound]
        exact agreed
      · simpa [logEqOther leader leaderEq] using agreed
  · have configurationNodesAfter :
        forall candidate configuration,
          configuration ∈
              allConfigurations
                ((nodeOf (leaderAppendState state node content)) candidate).log ->
            configuration.nodes ⊆
              (leaderAppendJoined joinedNodes state node content) := by
      intro candidate configuration member peer inNodes
      by_cases same : candidate = node
      · subst candidate
        have appendedMember :
            configuration ∈
              allConfigurations (((nodeOf state) node).log ++ [entry]) := by
          simpa [logEqNode] using member
        apply
          allConfigurations_append_nodes_carried
            ((nodeOf state) node).log [entry]
            (leaderAppendJoined joinedNodes state node content)
            (fun oldConfiguration oldMember oldPeer oldPeerMember =>
              hasJoinedMono
                (facts.joinedCarriers.configurationNodes
                  node oldConfiguration oldMember oldPeerMember))
            ?_ configuration appendedMember inNodes
        intro newConfiguration newMember newPeer newPeerMember
        cases content with
        | transaction txId =>
            simp [
              entry, allConfigurations, configurationsInLog,
              configurationsInLogFrom
            ] at newMember
            subst newConfiguration
            exact hasJoinedMono
              (facts.joinedCarriers.configurationNodes
                node implicitConfiguration
                (by simp [allConfigurations])
                newPeerMember)
        | signature =>
            simp [
              entry, allConfigurations, configurationsInLog,
              configurationsInLogFrom
            ] at newMember
            subst newConfiguration
            exact hasJoinedMono
              (facts.joinedCarriers.configurationNodes
                node implicitConfiguration
                (by simp [allConfigurations])
                newPeerMember)
        | retiredCommitted retired =>
            simp [
              entry, allConfigurations, configurationsInLog,
              configurationsInLogFrom
            ] at newMember
            subst newConfiguration
            exact hasJoinedMono
              (facts.joinedCarriers.configurationNodes
                node implicitConfiguration
                (by simp [allConfigurations])
                newPeerMember)
        | reconfiguration newNodes =>
            simp [
              entry, allConfigurations, configurationsInLog,
              configurationsInLogFrom
            ] at newMember
            rcases newMember with sameImplicit | sameNew
            · subst newConfiguration
              exact
                hasJoinedMono
                  (facts.joinedCarriers.configurationNodes
                    node implicitConfiguration
                      (by simp [allConfigurations])
                      newPeerMember)
            · subst newConfiguration
              simp only at newPeerMember
              by_cases retained :
                  newPeer ∈ (latestConfiguration ((nodeOf state) node)).nodes
              · apply hasJoinedMono
                exact
                  facts.joinedCarriers.configurationNodes
                    node (latestConfiguration ((nodeOf state) node))
                      (latestConfiguration_mem_allConfigurations
                        ((nodeOf state) node))
                      retained
              · simp [
                  leaderAppendState, leaderAppendJoined, Finset.mem_union,
                  Finset.mem_sdiff, newPeerMember, retained
                ]
      · apply hasJoinedMono
        exact
          facts.joinedCarriers.configurationNodes
            candidate configuration
              (by simpa [logEqOther candidate same] using member)
              inNodes
    constructor
    · intro candidate
      exact
        activeNodeUnion_subset_of_allConfigurations_carrier
          ((nodeOf (leaderAppendState state node content))
            candidate)
          (leaderAppendJoined joinedNodes state node content)
          (configurationNodesAfter candidate)
    · exact configurationNodesAfter
    · intro candidate peer member
      exact
        hasJoinedMono
          (facts.joinedCarriers.grantedVotes candidate
            (by simpa [votesGrantedEq] using member))
    · intro destination request member
      exact
        hasJoinedMono
          (facts.joinedCarriers.voteRequestDestinations
            destination request (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using member))
    · intro destination request member
      exact
        hasJoinedMono
          (facts.joinedCarriers.appendRequestDestinations
            destination request (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using member))
    · intro destination request member configuration configured peer inNodes
      exact
        hasJoinedMono
          (facts.joinedCarriers.appendRequestConfigurations
            destination request
              (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using member)
              configuration configured inNodes)
    · intro destination response member
      exact
        hasJoinedMono
          (facts.joinedCarriers.voteResponseSources
            destination response (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using member))
    · constructor
      · intro candidate active
        exact
          hasJoinedMono
            (facts.joinedCarriers.runtimeNodes.activeRoles candidate
              (by simpa [roleEq] using active))
      · intro leader peer positive
        exact
          hasJoinedMono
            (facts.joinedCarriers.runtimeNodes.positiveMatches leader peer
              (by simpa [matchEq] using positive))
      · intro destination response member
        exact
          hasJoinedMono
            (facts.joinedCarriers.runtimeNodes.appendResponses
              destination response (by simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present] using member))
      · intro candidate nonempty
        by_cases same : candidate = node
        · subst candidate
          exact
            hasJoinedMono
              (facts.joinedCarriers.runtimeNodes.activeRoles
                node (Or.inr leaderRole))
        · exact
            hasJoinedMono
              (facts.joinedCarriers.runtimeNodes.nonemptyLogs candidate
                (by
                  intro empty
                  apply nonempty
                  simpa [logEqOther candidate same] using empty))
  · exact fun _ => Iff.rfl
  · intro candidate
    simpa only [currentTermEq] using facts.currentTermsValid candidate
  · exact facts.networkTermsValid

/-- Appending a retired-committed record preserves the arbitrary-term invariant. -/
lemma appendRetiredCommittedPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ Not (((nodeOf state) node).membershipState = .retiredCommitted)
          /\ (((nodeOf state node).retirementCompleted \ allRetiredCommittedNodes (nodeOf state node).log)).Nonempty
          /\ Not
              ((refreshRetirementState node
                  {
                    ((nodeOf state) node) with
                      log :=
                        ((nodeOf state) node).log
                        ++ [({
                              term := ((nodeOf state) node).currentTerm,
                              content :=
                                .retiredCommitted
                                  (((nodeOf state node).retirementCompleted \ allRetiredCommittedNodes (nodeOf state node).log))
                            })]
                  }).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant (joined := joinedNodes) (appendRetiredCommittedEffect state node) := by
  simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, concrete_effects, concrete_effects]
    using leaderAppendPreservesSystemInductiveInvariant (present := present)
      state node
      (.retiredCommitted (((nodeOf state node).retirementCompleted \ allRetiredCommittedNodes (nodeOf state node).log)))
      invariant enabled.1 enabled.2.1

/-- A client transaction append preserves the arbitrary-term invariant. -/
lemma clientRequestPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (txId : TxId)
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ Not (((nodeOf state) node).membershipState = .retiredCommitted)
          /\ Not
              ((refreshRetirementState node
                  {
                    ((nodeOf state) node) with
                      log :=
                        ((nodeOf state) node).log
                        ++ [({
                              term := ((nodeOf state) node).currentTerm,
                              content := .transaction txId
                            })]
                  }).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant (joined := joinedNodes) (clientRequestEffect state node txId) := by
  simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, concrete_effects, concrete_effects]
    using leaderAppendPreservesSystemInductiveInvariant (present := present)
      state node (.transaction txId)
      invariant enabled.1 enabled.2.1

/-- Appending a current-term signature preserves the arbitrary-term invariant. -/
lemma signCommittableMessagesPreservesSystemInductiveInvariant
    (state : Model.State Node TxId)
    (node : Node)
    {present : node ∈ state.nodes.map Prod.fst}
    (invariant : SystemInductiveInvariant (joined := joinedNodes) state)
    (enabled
      : (node ∈ joinedNodes
          /\ ((nodeOf state) node).role = .leader
          /\ Not (((nodeOf state) node).membershipState = .retiredCommitted)
          /\ Not (((nodeOf state) node).log = [])
          /\ Not
              ((refreshRetirementState node
                  {
                    ((nodeOf state) node) with
                      log :=
                        ((nodeOf state) node).log
                        ++ [({
                              term := ((nodeOf state) node).currentTerm,
                              content := .signature
                            })]
                  }).membershipState
                = .retiredCommitted)))
    : SystemInductiveInvariant (joined := joinedNodes) (signCommittableMessagesEffect state node) := by
  simpa [leaderAppendState, leaderAppendJoined, leaderAppendJoined, present, concrete_effects, concrete_effects]
    using leaderAppendPreservesSystemInductiveInvariant (present := present)
      state node .signature invariant enabled.1 enabled.2.1

end CCFRaft.Proofs.Invariant
