-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.HandlerProofs
import CCFRaft.Proofs.Abstract.Invariant

set_option autoImplicit false

namespace CCFRaft.Proofs.Abstract.CommittedLog

open CCFRaft.Proofs.Abstract CCFRaft.Proofs.Abstract.Model CCFRaft.Proofs.Abstract.Safety
  CCFRaft.Proofs.Abstract.ModelProofs CCFRaft.Proofs.Abstract.HandlerProofs
  CCFRaft.Proofs.Abstract.Invariant
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

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

omit [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node] in
/-- Retaining the committed entries and advancing the frontier retains the prefix. -/
lemma committedLog_prefix
    {before after : NodeState Node TxId}
    (retained : before.committedLog <+: after.log)
    (monotone : before.commitIndex <= after.commitIndex)
    : before.committedLog <+: after.committedLog := by
  apply List.prefix_take_iff.mpr
  exact ⟨retained, (List.length_take_le _ _).trans monotone⟩

/-- Every processed message retains the destination's committed prefix. -/
lemma receive_committedLog_prefix
    {state after : State Node TxId}
    {source destination : Node}
    (handled : handleReceive? state source destination = some after)
    : forall node,
        (state.nodes node).committedLog <+: (after.nodes node).committedLog := by
  unfold handleReceive? at handled
  split at handled
  · contradiction
  · rename_i message remaining taken
    split at handled
    · contradiction
    · cases message with
      | appendEntriesRequest request =>
          simp only at handled
          split at handled
          · rename_i nextNode returned
            unfold returnToFollowerState? at returned
            split at returned
            · cases Option.some.inj returned
              cases Option.some.inj handled
              intro node
              by_cases same : node = destination <;>
                simp [same, NodeState.committedLog]
            · contradiction
          · split at handled
            · contradiction
            · rename_i nextNode response accepted
              have post := handleAppendEntriesRequestLocalPost accepted
              cases Option.some.inj handled
              intro node
              by_cases same : node = destination
              · subst node
                simpa [NodeState.committedLog]
                  using committedLog_prefix post.previousCommittedPrefix
                    post.commitIndexMonotone
              · simp [same]
      | appendEntriesResponse response =>
          simp only at handled
          split at handled
          · split at handled
            · contradiction
            · rename_i nextNode accepted
              unfold handleAppendEntriesResponse? at accepted
              split_ifs at accepted <;> simp only [Option.some.injEq] at accepted
              all_goals
                first
                | contradiction
                | subst nextNode
                  cases Option.some.inj handled
                  intro node
                  by_cases same : node = destination <;>
                    simp [same, NodeState.committedLog]
          · cases Option.some.inj handled
            intro node
            exact prefixRefl _
      | requestVoteRequest request =>
          simp only at handled
          split at handled
          · contradiction
          · rename_i nextNode response accepted
            unfold handleRequestVoteRequest? at accepted
            split at accepted
            · dsimp only at accepted
              split_ifs at accepted <;>
                simp only [Option.some.injEq, Prod.mk.injEq] at accepted
              all_goals
                rcases accepted with ⟨rfl, rfl⟩
                cases Option.some.inj handled
                intro node
                by_cases same : node = destination <;>
                  simp [same, NodeState.committedLog]
            · contradiction
      | requestVoteResponse response =>
          simp only at handled
          split at handled
          · split at handled
            · contradiction
            · rename_i nextNode accepted
              have post := handleRequestVoteResponsePreserves accepted
              cases Option.some.inj handled
              intro node
              by_cases same : node = destination <;>
                simp [same, NodeState.committedLog, post.logUnchanged,
                  post.commitIndexUnchanged]
          · cases Option.some.inj handled
            intro node
            exact prefixRefl _
      | requestPreVote request =>
          simp only at handled
          split at handled
          · contradiction
          · rename_i nextNode response accepted
            have unchanged := handleRequestPreVoteStateUnchanged accepted
            subst nextNode
            cases Option.some.inj handled
            intro node
            by_cases same : node = destination <;> simp [same]
      | requestPreVoteResponse response =>
          simp only at handled
          split at handled
          · split at handled
            · contradiction
            · rename_i nextNode accepted
              have post := handleRequestPreVoteResponsePreserves accepted
              cases Option.some.inj handled
              intro node
              by_cases same : node = destination <;>
                simp [same, NodeState.committedLog, post.logUnchanged,
                  post.commitIndexUnchanged]
          · cases Option.some.inj handled
            intro node
            exact prefixRefl _
      | proposeVoteRequest request =>
          simp only at handled
          split at handled
          · contradiction
          · rename_i nextNode accepted
            rcases handleProposeVoteRequestCases accepted with unchanged | ⟨_, _, unchanged⟩
            all_goals
              subst nextNode
              cases Option.some.inj handled
              intro node
              by_cases same : node = destination <;>
                simp [same, NodeState.committedLog, becomeCandidateNodeState]

omit [DecidableEq TxId] [Bootstrap Node] in
private lemma demoteRetiredCommitted_committedLog
    (state : State Node TxId) (retired node : Node)
    : ((demoteRetiredCommitted state retired).nodes node).committedLog
      = (state.nodes node).committedLog := by
  dsimp only [demoteRetiredCommitted]
  split <;> by_cases same : node = retired <;>
    simp [same, NodeState.committedLog]

private lemma advanceCommitState_committedLog_prefix
    (state : State Node TxId) (leader node : Node)
    (advances : (state.nodes leader).commitIndex <= highestCommittableIndex state leader)
    : (state.nodes node).committedLog
      <+: ((advanceCommitState state leader).nodes node).committedLog := by
  by_cases same : node = leader
  · subst node
    apply committedLog_prefix
    · simpa [advanceCommitState, NodeState.committedLog]
        using List.take_prefix (state.nodes leader).commitIndex (state.nodes leader).log
    · simpa [advanceCommitState] using advances
  · simp [advanceCommitState, same]

/-- Each enabled action retains every node's committed entries, including truncations. -/
lemma next_committedLog_prefix
    (state : State Node TxId) (action : Action Node TxId)
    (bounded : CommitIndicesBounded state)
    (signature : CommittedFrontierIsSignature state)
    (enabled : Enabled state action)
    : forall node,
        (state.nodes node).committedLog
        <+: ((next state action).nodes node).committedLog := by
  intro node
  cases action with
  | initializeConfiguration leader =>
      have zero := enabled.2.2.2.2.2.1
      by_cases same : node = leader <;>
        simp [next, same, NodeState.committedLog, zero]
  | clientRequest leader txId =>
      by_cases same : node = leader <;>
        simp [next, same, NodeState.committedLog,
          List.take_append_of_le_length (bounded leader)]
  | changeConfiguration leader configuration =>
      by_cases same : node = leader
      · subst node
        simp [next, NodeState.committedLog,
          List.take_append_of_le_length (bounded leader)]
      · by_cases allocated : state.nodes.allocated node
        · simp only [next, updateNode_of_ne _ _ _ _ same]
          simp [NodeStore.get, NodeStore.node?_allocate_of_allocated _ _ _ allocated]
        · have missing : state.nodes.node? node = none := by
            simpa [NodeStore.allocated] using allocated
          simp [NodeState.committedLog, NodeStore.get, missing, freshNodeState]
  | appendRetiredCommitted leader =>
      by_cases same : node = leader <;>
        simp [next, same, NodeState.committedLog,
          List.take_append_of_le_length (bounded leader)]
  | signCommittableMessages leader =>
      by_cases same : node = leader <;>
        simp [next, same, NodeState.committedLog,
          List.take_append_of_le_length (bounded leader)]
  | appendEntries source destination batchEnd =>
      by_cases same : node = source <;>
        simp [next, same, NodeState.committedLog]
  | receive source destination =>
      cases received : handleReceive? state source destination with
      | none => simp [next, received]
      | some after =>
          simpa [next, received] using receive_committedLog_prefix received node
  | drop source destination occurrence =>
      cases removed
            : takeOccurrenceFrom source occurrence (state.network destination) with
      | none => simp [next, removed]
      | some result => simp [next, removed]
  | advanceCommitIndex leader =>
      simpa only [next, definition, demoteRetiredCommitted_committedLog]
        using advanceCommitState_committedLog_prefix state leader node
          (Nat.le_of_lt enabled.2.2.1)
  | timeout candidate =>
      by_cases same : node = candidate <;>
        simp [next, same, NodeState.committedLog, becomeCandidateNodeState]
  | becomePreVoteCandidate candidate =>
      by_cases same : node = candidate <;>
        simp [next, same, NodeState.committedLog]
  | becomeCandidate candidate =>
      by_cases same : node = candidate <;>
        simp [next, same, NodeState.committedLog, becomeCandidateNodeState]
  | requestVote source destination => exact prefixRefl _
  | requestPreVote source destination => exact prefixRefl _
  | checkQuorum leader =>
      by_cases same : node = leader <;>
        simp [next, stepDownState, same, NodeState.committedLog]
  | updateTerm source destination =>
      cases found : newerMessage? state source destination with
      | none => simp [next, found]
      | some message =>
          by_cases same : node = destination <;>
            simp [next, found, same, NodeState.committedLog]
  | becomeLeader leader =>
      have frontier :
          (state.nodes leader).commitIndex <= maxCommittableIndex (state.nodes leader).log := by
        by_cases zero : (state.nodes leader).commitIndex = 0
        · simp [zero]
        · exact signatureIndex_le_maxCommittableIndex
            (signature leader (Nat.pos_of_ne_zero zero))
      by_cases same : node = leader <;>
        simp [next, same, NodeState.committedLog,
          List.take_take, Nat.min_eq_left frontier]
  | proposeVote source destination => exact prefixRefl _
  | advanceCommitIndexAndProposeVote source destination =>
      simpa only [next, definition, demoteRetiredCommitted_committedLog]
        using advanceCommitState_committedLog_prefix state source node
          (Nat.le_of_lt enabled.2.2.2.1)

end CCFRaft.Proofs.Abstract.CommittedLog
