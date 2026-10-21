module

public import CCFRaft.Model.NodeState

@[expose] public section

/-!
# Messages between nodes

An empty AppendEntries batch is a heartbeat. Starting a pre-vote round does not
increment the term, but receiving a newer-term pre-vote can advance it.
-/

namespace CCFRaft.Model.Node

structure AppendEntriesRequest where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List Entry
  primaryCommit : Nat
deriving DecidableEq

structure AppendEntriesResponse where
  /-- Current election term, except a log-mismatch NACK carries the hinted log term. -/
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

inductive Message where
  | appendEntriesRequest (request : AppendEntriesRequest)
  | appendEntriesResponse (response : AppendEntriesResponse)
  | requestVoteRequest (request : RequestVoteRequest)
  | requestVoteResponse (response : RequestVoteResponse)
  | requestPreVoteRequest (request : RequestVoteRequest)
  | requestPreVoteResponse (response : RequestVoteResponse)
  /-- A primary's same-term request that a replica start an election. -/
  | proposeRequestVoteRequest (term : Nat)
deriving DecidableEq

abbrev Notification := Empty

def Message.term : Message -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVoteRequest request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeRequestVoteRequest term => term

end CCFRaft.Model.Node
