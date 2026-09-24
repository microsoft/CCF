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

variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

def voteRequestKey (state : Model.State Node TxId) (source target : Node)
    : VoteRequestKey Node :=
  ⟨source, target, makeRequestVoteRequest (nodeOf state source)⟩

end CCFRaft.Proofs.Invariant
