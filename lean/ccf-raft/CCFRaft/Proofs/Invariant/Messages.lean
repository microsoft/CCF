-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.State

set_option autoImplicit false

namespace CCFRaft.Proofs.Invariant

open Model.Local

/-- History keys retain both endpoints and the unchanged local payload. -/
abbrev AppendRequestKey (Node TxId : Type) :=
  Node × Node × AppendEntriesRequest Node TxId

abbrev AppendResponseKey (Node : Type) := Node × Node × AppendEntriesResponse

abbrev VoteRequestKey (Node : Type) := Node × Node × RequestVoteRequest

abbrev VoteResponseKey (Node : Type) := Node × Node × RequestVoteResponse

variable {Node TxId : Type}

abbrev appendRequestEnvelope (key : AppendRequestKey Node TxId)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .appendEntriesRequest key.2.2⟩

abbrev appendResponseEnvelope (key : AppendResponseKey Node) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .appendEntriesResponse key.2.2⟩

abbrev voteRequestEnvelope (key : VoteRequestKey Node) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestVoteRequest key.2.2⟩

abbrev voteResponseEnvelope (key : VoteResponseKey Node) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestVoteResponse key.2.2⟩

abbrev preVoteRequestEnvelope (key : VoteRequestKey Node) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestPreVote key.2.2⟩

abbrev preVoteResponseEnvelope (key : VoteResponseKey Node) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestPreVoteResponse key.2.2⟩

abbrev proposeVoteEnvelope (key : Node × Node × Nat) : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .proposeVoteRequest key.2.2⟩

@[simp]
theorem appendRequestEnvelope.injEq {left right : AppendRequestKey Node TxId}
    : appendRequestEnvelope left = appendRequestEnvelope right ↔ left = right := by
  rcases left with ⟨_, _, _⟩
  rcases right with ⟨_, _, _⟩
  simp [appendRequestEnvelope]

@[simp]
theorem appendResponseEnvelope.injEq {left right : AppendResponseKey Node}
    : (appendResponseEnvelope left : Model.Envelope Node TxId)
        = appendResponseEnvelope right
      ↔ left = right := by
  rcases left with ⟨_, _, _⟩
  rcases right with ⟨_, _, _⟩
  simp [appendResponseEnvelope]

@[simp]
theorem voteRequestEnvelope.injEq {left right : VoteRequestKey Node}
    : (voteRequestEnvelope left : Model.Envelope Node TxId) = voteRequestEnvelope right
      ↔ left = right := by
  rcases left with ⟨_, _, _⟩
  rcases right with ⟨_, _, _⟩
  simp [voteRequestEnvelope]

@[simp]
theorem voteResponseEnvelope.injEq {left right : VoteResponseKey Node}
    : (voteResponseEnvelope left : Model.Envelope Node TxId) = voteResponseEnvelope right
      ↔ left = right := by
  rcases left with ⟨_, _, _⟩
  rcases right with ⟨_, _, _⟩
  simp [voteResponseEnvelope]

/-- These messages carry no log, vote, or acknowledgement evidence. -/
def IsSafetyInert : Message Node TxId -> Prop
  | .requestPreVote _ | .requestPreVoteResponse _ | .proposeVoteRequest _ => True
  | _ => False

variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

def voteRequestKey (state : Model.State Node TxId) (source target : Node)
    : VoteRequestKey Node :=
  ⟨source, target, makeRequestVoteRequest (nodeOf state source)⟩

def appendRequestKey (state : Model.State Node TxId) (source target : Node)
    (batchEnd : Nat)
    : AppendRequestKey Node TxId :=
  ⟨source, target, makeAppendEntriesRequest (nodeOf state source) target batchEnd⟩

end CCFRaft.Proofs.Invariant
