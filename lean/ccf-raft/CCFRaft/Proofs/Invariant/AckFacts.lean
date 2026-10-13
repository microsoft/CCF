-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Facts
import CCFRaft.Proofs.Invariant.HandlerFacts

set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option maxHeartbeats 700000

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open Model.Local

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]

/-- Immediate ACK eligibility depends on protocol fields, not retirement metadata. -/
theorem canProduceAppendAckAt_iff (node : NodeState Node TxId)
    (request : AppendRequestKey Node TxId) (index : Nat)
    : canProduceAppendAckAt node request index
      ↔ request.2.2.term = node.currentTerm
        ∧ logOk node request.2.2
        ∧ node.commitIndex ≤ request.2.2.prevLogIndex
        ∧ ¬(hasTermConflict node request.2.2 ∧ node.isNewFollower = false)
        ∧ index ≤ request.2.2.prevLogIndex + request.2.2.entries.length
        ∧ (node.role = .follower ∨ node.role = .none) := by
  constructor
  · rintro ⟨next, response, accepted, -, covered, passive⟩
    obtain ⟨term, matching, committed, shape, -, -, -, -, -, -, -, -, -, rfl⟩ :=
      acceptAppendEntriesRequest_eq accepted
    refine ⟨term, matching, committed, ?_, covered, passive⟩
    rintro ⟨conflict, fresh⟩
    rcases shape with ⟨noConflict, -⟩ | ⟨-, fresh', -⟩
    · exact noConflict conflict
    · simp [fresh] at fresh'
  · rintro ⟨term, matching, committed, notBlocked, covered, passive⟩
    have enabled :
        request.2.2.term = node.currentTerm
          ∧ logOk node request.2.2
          ∧ node.commitIndex ≤ request.2.2.prevLogIndex
          ∧ ¬(hasTermConflict node request.2.2 ∧ (!node.isNewFollower) = true) :=
      ⟨term, matching, committed, by simpa using notBlocked⟩
    have isSome : (acceptAppendEntriesRequest? (inferInstance) request.2.1 node
        request.2.2).isSome := by
      unfold acceptAppendEntriesRequest?
      split_ifs
      rfl
    obtain ⟨⟨next, response⟩, accepted⟩ := Option.isSome_iff_exists.mp isSome
    obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, rfl⟩ := acceptAppendEntriesRequest_eq accepted
    exact ⟨next, _, accepted, rfl, covered, passive⟩

theorem canProduceAppendAckAt_frame
    {before after : NodeState Node TxId}
    (role : after.role = before.role)
    (term : after.currentTerm = before.currentTerm)
    (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
    (follower : after.isNewFollower = before.isNewFollower)
    (request : AppendRequestKey Node TxId) (index : Nat)
    : canProduceAppendAckAt after request index
      ↔ canProduceAppendAckAt before request index := by
  simp only [canProduceAppendAckAt_iff, logOk, hasTermConflict, role, term, log, commit,
    follower]

end CCFRaft.Proofs.Invariant
