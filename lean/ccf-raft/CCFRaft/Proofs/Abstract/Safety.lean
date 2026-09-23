-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.Model

set_option autoImplicit false

namespace CCFRaft.Proofs.Abstract.Safety

open CCFRaft.Proofs.Abstract.Model
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
variable [DecidableEq Node] [DecidableEq TxId]

/-- Every positive node commit frontier points to a signature entry. -/
def CommittedFrontierIsSignature (state : State Node TxId) : Prop :=
  forall node,
    0 < (state.nodes node).commitIndex
    -> isSignatureAt (state.nodes node).log (state.nodes node).commitIndex = true

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety (state : State Node TxId) : Prop :=
  forall left right,
    (state.nodes left).role = .leader
    -> (state.nodes right).role = .leader
    -> (state.nodes left).currentTerm = (state.nodes right).currentTerm
    -> left = right

/-- Any two node-local committed logs are prefix-comparable. -/
def CommittedLogsPrefix (state : State Node TxId) : Prop :=
  forall left right,
    (state.nodes left).committedLog <+: (state.nodes right).committedLog
    \/ (state.nodes right).committedLog <+: (state.nodes left).committedLog

/--
Every enabled next step extends each node's committed log. Holding in every
reachable state gives TLA+'s `CommittedLogAppendOnlyProp`; stuttering is reflexive.
-/
def CommittedLogAppendOnly [Bootstrap Node] (state : State Node TxId) : Prop :=
  forall action,
    Enabled state action
    -> forall node,
        (state.nodes node).committedLog <+: ((next state action).nodes node).committedLog

/-- Public safety includes agreement across nodes and committed history across time. -/
structure ConsensusSafety [Bootstrap Node] (state : State Node TxId) : Prop where
  committedLogsPrefix : CommittedLogsPrefix state
  committedLogAppendOnly : CommittedLogAppendOnly state
  committedFrontierIsSignature : CommittedFrontierIsSignature state
  electionSafety : ElectionSafety state

end CCFRaft.Proofs.Abstract.Safety
