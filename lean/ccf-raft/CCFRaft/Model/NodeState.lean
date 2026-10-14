-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Lattice.Fold

/-!
# Node state and log

Log positions are one-based; index zero is the empty prefix.
Signatures make their prefixes committable. Behaviour is in `Node.lean`.
-/

namespace CCFRaft.Model.Local

/-- Transaction effects take effect in list order. -/
inductive TransactionEffect (Node : Type) where
  | reconfiguration (nodes : Finset Node)
  | retiredCommitted (nodes : Finset Node)
deriving DecidableEq

inductive EntryContent (Node TxId : Type) where
  | transaction (txId : TxId) (effects : List (TransactionEffect Node))
  | signature
deriving DecidableEq

def EntryContent.effects {Node TxId : Type}
    : EntryContent Node TxId -> List (TransactionEffect Node)
  | .transaction _ effects => effects
  | .signature => []

structure Entry (Node TxId : Type) where
  term : Nat
  content : EntryContent Node TxId
deriving DecidableEq

inductive Role where
  /-- No leadership role, including fresh and newly retired nodes. -/
  | none
  | follower
  | preVoteCandidate
  | candidate
  | leader
deriving DecidableEq, Repr

inductive MembershipState where
  | active
  | retirementOrdered
  | retirementSigned
  | retirementCompleted
  | retiredCommitted
deriving DecidableEq, Repr

variable {Node TxId : Type}

structure NodeState (Node TxId : Type) where
  /-- Leadership role, independent of membership and retirement status. -/
  role : Role
  currentTerm : Nat
  log : List (Entry Node TxId)
  commitIndex : Nat
  /-- Leader's send frontier for each peer; a rejection can move it backwards. -/
  sentIndex : Node -> Nat
  /-- Leader's highest acknowledged log position for each peer. -/
  matchIndex : Node -> Nat
  /-- Whether AppendEntries may roll back a conflicting uncommitted suffix. -/
  isNewFollower : Bool
  votedFor : Option Node
  /-- A known leader prevents granting regular votes in this term. -/
  leaderKnown : Bool := false
  votesGranted : Finset Node
  preVotesGranted : Finset Node := {}
  membershipState : MembershipState := .active
  /-- First configuration log position that removes this node, if any. -/
  retirementIndex : Option Nat := none
  /-- First signature position after removal, making retirement committable. -/
  retirementCommittableIndex : Option Nat := none
  /--
  Commit frontier when a record confirming this node's completed retirement
  first became committed; not necessarily the position of that record.
  -/
  retiredCommittedIndex : Option Nat := none
  /--
  One-shot permission for an outgoing retiring leader to nominate after commit
  clears its role. Captures the term and eligible peers before configuration
  pruning; any other local event expires the permission.
  -/
  pendingRetirementNomination : Option (Nat × Finset Node) := none

namespace NodeState

def committedLog (state : NodeState Node TxId) : List (Entry Node TxId) :=
  state.log.take state.commitIndex

end NodeState

variable [DecidableEq Node] [DecidableEq TxId]

def entryAt? (log : List (Entry Node TxId)) (index : Nat) : Option (Entry Node TxId) :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List (Entry Node TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

def isSignatureAt (log : List (Entry Node TxId)) (index : Nat) : Bool :=
  match entryAt? log index with
  | some entry => decide (entry.content = .signature)
  | none => false

/-- The one-based index of the latest signature, or zero if the log has none. -/
def maxCommittableIndex (log : List (Entry Node TxId)) : Nat :=
  (List.range (log.length + 1)).foldl
    (fun best index =>
      if isSignatureAt log index then max best index else best)
    0

def maxCommittableTerm (log : List (Entry Node TxId)) : Nat :=
  termAt log (maxCommittableIndex log)

def maxCommittableIndexUpTo (log : List (Entry Node TxId)) (frontier : Nat) : Nat :=
  maxCommittableIndex (log.take frontier)

/-- Entries in (previousIndex, batchEnd]. -/
def messageEntries (log : List (Entry Node TxId)) (previousIndex batchEnd : Nat)
    : List (Entry Node TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

/-- The highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch (log : List (Entry Node TxId)) (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

def firstLogIndexAfter (log : List (Entry Node TxId)) (afterIndex : Nat)
    (predicate : EntryContent Node TxId -> Bool)
    : Option Nat :=
  ((log.zipIdx 1).find?
    fun (entry, index) => decide (afterIndex < index) && predicate entry.content).map
    Prod.snd

/--
The log position a node reports when it campaigns: its commit index or its
latest signature, whichever is higher.
-/
def lastCommittableIndex (state : NodeState Node TxId) : Nat :=
  max state.commitIndex (maxCommittableIndex state.log)

def lastCommittableTerm (state : NodeState Node TxId) : Nat :=
  termAt state.log (lastCommittableIndex state)

end CCFRaft.Model.Local
