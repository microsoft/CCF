-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Invariant.HandlerFacts

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option maxHeartbeats 700000

namespace CCFRaft.Proofs.Invariant

open Model.Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- Immediate ACK eligibility depends on protocol fields, not retirement metadata. -/
theorem canProduceAppendAckAt_iff (node : NodeState Node TxId)
    (request : AppendRequestKey Node TxId) (index : Nat)
    : canProduceAppendAckAt node request index
      ↔ request.2.2.term = node.currentTerm
        ∧ node.role = .follower
        ∧ logOk node request.2.2
        ∧ node.commitIndex ≤ request.2.2.prevLogIndex
        ∧ index ≤ request.2.2.prevLogIndex + request.2.2.entries.length
        ∧ (alreadyDone node request.2.2
            ∨ noConflictExtension node request.2.2
            ∨ (hasTermConflict node request.2.2
                ∧ node.isNewFollower = true
                ∧ (alreadyDone
                      {
                        node with
                          log := node.log.take request.2.2.prevLogIndex
                          isNewFollower := false
                      }
                      request.2.2
                    ∨ noConflictExtension
                        {
                          node with
                            log := node.log.take request.2.2.prevLogIndex
                            isNewFollower := false
                        }
                        request.2.2))) := by
  unfold canProduceAppendAckAt acceptAppendEntriesRequest?
  split_ifs with accepted
  · simp only [accepted, true_and]
    unfold appendEntriesAlreadyDone? noConflictAppendEntriesRequest? conflictAppendEntriesRequest?
    split_ifs <;> simp_all [successResponse, noConflictExtension, List.length_take,
      Nat.min_eq_left, List.take_take]
    all_goals split_ifs <;> simp_all [successResponse, noConflictExtension,
      List.length_take, Nat.min_eq_left, List.take_take]
  · simp_all

theorem canProduceAppendAckAt_frame
    {before after : NodeState Node TxId}
    (role : after.role = before.role) (term : after.currentTerm = before.currentTerm)
    (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
    (follower : after.isNewFollower = before.isNewFollower)
    (request : AppendRequestKey Node TxId) (index : Nat)
    : canProduceAppendAckAt after request index
      ↔ canProduceAppendAckAt before request index := by
  simp only [canProduceAppendAckAt_iff, logOk, alreadyDone, noConflictExtension,
    hasTermConflict, overlapLength, role, term, log, commit, follower]

end CCFRaft.Proofs.Invariant
