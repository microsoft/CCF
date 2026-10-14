-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.NodeState

/-!
# Messages between nodes

An empty AppendEntries batch is a heartbeat. Pre-votes do not advance the term.
-/

namespace CCFRaft.Model.Local

structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
deriving DecidableEq

structure AppendEntriesResponse where
  term : Nat
  success : Bool
  lastLogIndex : Nat
deriving DecidableEq, Repr

structure RequestVoteRequest where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
deriving DecidableEq, Repr

structure RequestVoteResponse where
  term : Nat
  voteGranted : Bool
deriving DecidableEq, Repr

inductive Message (Node TxId : Type) where
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  | appendEntriesResponse (response : AppendEntriesResponse)
  | requestVoteRequest (request : RequestVoteRequest)
  | requestVoteResponse (response : RequestVoteResponse)
  | requestPreVote (request : RequestVoteRequest)
  | requestPreVoteResponse (response : RequestVoteResponse)
  /-- A leader's same-term request that a replica start an election. -/
  | proposeVoteRequest (term : Nat)
deriving DecidableEq

abbrev Notification := Empty

variable {Node TxId : Type}

def Message.term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest term => term

end CCFRaft.Model.Local
