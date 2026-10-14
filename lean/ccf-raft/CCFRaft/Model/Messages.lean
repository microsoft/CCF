-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Node
import CCFRaft.Shared.Capabilities

/-!
# Messages between nodes

AppendEntries replicates log entries (an empty batch is a heartbeat);
RequestVote runs elections, with pre-vote variants that do not advance the
term. `proposeVoteRequest` asks a node to start an election. Every message
carries the sender's term, read by `Message.term`.

`NodeEffect` is what a step may do: send messages through `Caps`, or fail.
-/

namespace CCFRaft.Model.Local

open Shared (Capabilities Effect)

/-- A replication request, as captured when the leader sends it. -/
structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
deriving DecidableEq

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse where
  term : Nat
  success : Bool
  lastLogIndex : Nat
deriving DecidableEq, Repr

/-- A candidate's last committable position, sent in a vote or pre-vote request. -/
structure RequestVoteRequest where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
deriving DecidableEq, Repr

/-- A voter's reply to a vote or pre-vote request. -/
structure RequestVoteResponse where
  term : Nat
  voteGranted : Bool
deriving DecidableEq, Repr

/-- Messages exchanged by replication and elections. The envelope carries the
source and destination. -/
inductive Message (Node TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse)
  /-- A candidate-to-voter RequestVote request. -/
  | requestVoteRequest (request : RequestVoteRequest)
  /-- A voter-to-candidate RequestVote response. -/
  | requestVoteResponse (response : RequestVoteResponse)
  /-- A pre-vote candidate-to-voter RequestPreVote request. -/
  | requestPreVote (request : RequestVoteRequest)
  /-- A voter-to-pre-vote-candidate RequestPreVote response. -/
  | requestPreVoteResponse (response : RequestVoteResponse)
  /-- A leader's same-term request that a replica start an election. -/
  | proposeVoteRequest (term : Nat)
deriving DecidableEq

/-- CCF Raft nodes emit no notifications. -/
abbrev Notification := Empty

variable {Node TxId : Type}

/-- The term a message carries. -/
def Message.term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest term => term

/-- The capabilities (send/notify callbacks) lent to one node step. -/
abbrev Caps (Node TxId : Type) := Capabilities Node (Message Node TxId) Notification

/-- The effect monad of one node step: it can send messages or fail when disabled. -/
abbrev NodeEffect (Node TxId : Type) := Effect Node (Message Node TxId) Notification

end CCFRaft.Model.Local
