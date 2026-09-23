-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Abstract.Safety
import Mathlib

set_option autoImplicit false

namespace CCFRaft.Proofs.Abstract.Support

open CCFRaft.Proofs.Abstract CCFRaft.Proofs.Abstract.Model
open CCFRaft.Model.Local (BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm messageEntries refreshRetirementState retiredCommittedIndexFrom retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom retirementCommittableIndexInLog retirementCompletedNodes retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt updateIndex)

/-- Projection used only to compare handler results independently of retirement metadata. -/
def protocolNodeState {Node TxId : Type} (node : NodeState Node TxId) :
    NodeState Node TxId :=
  { node with
    membershipState := .active
    retirementIndex := none
    retirementCommittableIndex := none
    retiredCommittedIndex := none }

lemma reachableInvariant
    (system : ExecutableTransitionSystem)
    {Invariant : system.State -> Prop}
    (initial : Invariant system.initial)
    (preserved : forall state action,
      Invariant state -> system.Enabled state action ->
        Invariant (system.next state action))
    {state : system.State}
    (reachable : system.Reachable state) :
    Invariant state := by
  induction reachable with
  | initial => exact initial
  | step reachable enabled invariant =>
      exact preserved _ _ invariant enabled

end CCFRaft.Proofs.Abstract.Support
