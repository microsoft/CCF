module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Invariant.Ops
public import CCFRaft.Proofs.Ledger

@[expose] public section

set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

register_simp_attr concrete_effects

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node (
  BOOTSTRAP_TERM InitialConfig Configuration Entry EntryContent MembershipState NodeState
    PreVoteStatus Role campaignEligible
    configurationHistory configurationMembers entryAt? findHighestPossibleMatch
    firstLogIndexAfter hasConfigurationMajority initialNodeState isSignatureAt
    lastCommittableIndex lastCommittableTerm maxCommittableIndex maxCommittableIndexUpTo
    maxCommittableTerm messageEntries retiredCommittedNodes
    retirementIndexInLog termAt
  )
open CCFRaft.Proofs.Ledger

/-- Every valid bootstrap configuration contains its selected leader. -/
lemma initialLeader_mem_initialConfiguration
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : InitialConfig Node]
    : Membership.mem
        (INITIAL_CONFIGURATION (Node := Node))
        (INITIAL_LEADER (Node := Node)) :=
  bootstrap.leader_mem

variable {Node TxId : Type}
variable [DecidableEq Node]

variable [InitialConfig Node] [DecidableEq TxId] [LinearOrder Node] [Inhabited TxId]

omit [InitialConfig Node] in
/-- Erasing a selected occurrence preserves membership of every remaining message. -/
lemma selectedSound
    {source : Node} {queue remaining : List (Model.Envelope Node TxId)}
    {selected : Model.Envelope Node TxId}
    (taken : Selected source queue selected remaining)
    : selected.source = source
      /\ selected ∈ queue
      /\ (forall message, message ∈ remaining -> message ∈ queue) := by
  obtain ⟨sourceEq, member, rfl⟩ := taken
  refine ⟨sourceEq, member, ?_⟩
  intro message present
  have remaining : message ∈ queue.erase selected := by
    simpa only [removeOne_eq_list_erase] using present
  exact List.mem_of_mem_erase remaining

end CCFRaft.Proofs.Invariant
