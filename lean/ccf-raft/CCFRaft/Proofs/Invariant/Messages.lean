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

abbrev appendResponseEnvelope (key : AppendResponseKey Node)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .appendEntriesResponse key.2.2⟩

abbrev voteRequestEnvelope (key : VoteRequestKey Node)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestVoteRequest key.2.2⟩

abbrev voteResponseEnvelope (key : VoteResponseKey Node)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestVoteResponse key.2.2⟩

abbrev preVoteRequestEnvelope (key : VoteRequestKey Node)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestPreVote key.2.2⟩

abbrev preVoteResponseEnvelope (key : VoteResponseKey Node)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .requestPreVoteResponse key.2.2⟩

abbrev proposeVoteEnvelope (key : Node × Node × Nat)
    : Model.Envelope Node TxId :=
  ⟨key.1, key.2.1, .proposeVoteRequest key.2.2⟩

/-- These messages carry no log, vote, or acknowledgement evidence. -/
def IsSafetyInert : Message Node TxId -> Prop
  | .requestPreVote _ | .requestPreVoteResponse _ | .proposeVoteRequest _ => True
  | _ => False

variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

def voteRequestKey (state : Model.State Node TxId) (source target : Node)
    : VoteRequestKey Node :=
  ⟨source, target, makeRequestVoteRequest (nodeOf state source)⟩

def appendRequestKey (state : Model.State Node TxId) (source target : Node)
    (batchEnd : Nat) : AppendRequestKey Node TxId :=
  ⟨source, target, makeAppendEntriesRequest (nodeOf state source) target batchEnd⟩

end CCFRaft.Proofs.Invariant
