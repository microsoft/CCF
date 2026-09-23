-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Invariant.NodeFacts
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
variable [DecidableEq Node] [DecidableEq TxId]

/-- Every positive node commit frontier points to a signature entry. -/
def CommittedFrontierIsSignature (state : View Node TxId) : Prop :=
  forall node,
    0 < (state.nodes node).commitIndex
    -> isSignatureAt (state.nodes node).log (state.nodes node).commitIndex = true

variable [Bootstrap Node]

/--
Every request directly ACKable after exact UpdateTerm preparation is included
in the stable future-aware reserve.
-/
lemma preparedAppendAckIsReserved
    {node : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId}
    {index : Nat}
    (newer : node.currentTerm < request.term)
    (_prepared
      : canProduceAppendAckAt (prepareNodeForUpdateTerm node request.term) request index)
    : index <= request.prevLogIndex + request.entries.length
      -> canProduceAppendAckEventuallyAt node request index :=
  fun covered => Or.inr ⟨newer, covered⟩

lemma CommitEvidence.Valid.supportedSignature
    {evidence : CommitEvidence Node TxId}
    {supportedPrefix : List (Entry Node TxId)}
    (valid : evidence.Valid supportedPrefix)
    : 0 < evidence.supportedLength
      -> isSignatureAt evidence.history evidence.supportedLength = true :=
  valid.2.2.2.2.2.2.2

end CCFRaft.Proofs.Invariant
