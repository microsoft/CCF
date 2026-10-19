module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Mathlib.Data.Finset.Card
public import Mathlib.Data.Finset.Lattice.Fold

@[expose] public section

/-!
# Node state and log

Log positions are one-based; index zero is the empty prefix.
Signatures make their prefixes committable. Behaviour is in `Node.lean`.
-/

namespace CCFRaft.Model.Node

/-- A node's identifier. -/
abbrev NodeID := Nat

/-- A request identifier recorded in a transaction entry. -/
abbrev ReqID := Nat

/-- The consensus-relevant changes recorded by one transaction. -/
structure TransactionMetadata where
  configuration : Option (Finset NodeID) := none
  /-- Nodes whose retirement this transaction confirms, whether committed or not. -/
  retirementConfirmations : Finset NodeID := ∅
deriving DecidableEq

inductive EntryContent where
  | transaction (reqId : ReqID) (metadata : TransactionMetadata)
  | signature
deriving DecidableEq

def EntryContent.metadata : EntryContent -> TransactionMetadata
  | .transaction _ metadata => metadata
  | .signature => {}

def EntryContent.isSignature : EntryContent -> Bool
  | .transaction _ _ => false
  | .signature => true

structure Entry where
  term : Nat
  content : EntryContent
deriving DecidableEq

inductive Role where
  /-- No protocol role, including fresh and newly retired nodes. -/
  | none
  | follower
  | preVoteCandidate
  | candidate
  | primary
deriving DecidableEq, Repr

structure NodeState where
  /-- Election role, independent of membership and retirement status. -/
  role : Role
  currentTerm : Nat
  log : List Entry
  commitIndex : Nat
  /-- Primary's send frontier for each peer; a rejection can move it backwards. -/
  sentIndex : NodeID -> Nat
  /-- Primary's highest acknowledged log position for each peer. -/
  matchIndex : NodeID -> Nat
  /-- Whether AppendEntries may roll back a conflicting uncommitted suffix. -/
  isNewFollower : Bool
  votedFor : Option NodeID
  /-- A known primary prevents granting regular votes in this term. -/
  primaryKnown : Bool := false
  votesGranted : Finset NodeID
  preVotesGranted : Finset NodeID := {}
  /--
  One-based log index of the transaction confirming this node's retirement,
  populated only once that confirmation commits.
  -/
  retiredCommittedIndex : Option Nat := none

namespace NodeState

def committedLog (state : NodeState) : List Entry :=
  state.log.take state.commitIndex

end NodeState

def entryAt? (log : List Entry) (index : Nat) : Option Entry :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List Entry) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

def isSignatureAt (log : List Entry) (index : Nat) : Bool :=
  match entryAt? log index with
  | some entry => entry.content.isSignature
  | none => false

/-- The one-based index of the latest signature, or zero if the log has none. -/
def maxCommittableIndex (log : List Entry) : Nat :=
  (List.range (log.length + 1)).foldl
    (fun best index =>
      if isSignatureAt log index then max best index else best)
    0

def maxCommittableTerm (log : List Entry) : Nat :=
  termAt log (maxCommittableIndex log)

def maxCommittableIndexUpTo (log : List Entry) (frontier : Nat) : Nat :=
  maxCommittableIndex (log.take frontier)

/-- Entries in (previousIndex, batchEnd]. -/
def messageEntries (log : List Entry) (previousIndex batchEnd : Nat) : List Entry :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

def firstLogIndexAfter (log : List Entry) (afterIndex : Nat)
    (predicate : EntryContent -> Bool)
    : Option Nat :=
  ((log.zipIdx 1).find?
    fun (entry, index) => decide (afterIndex < index) && predicate entry.content).map
    Prod.snd

/--
The log position a node reports when it campaigns: its commit index or its
latest signature, whichever is higher.
-/
def lastCommittableIndex (state : NodeState) : Nat :=
  max state.commitIndex (maxCommittableIndex state.log)

def lastCommittableTerm (state : NodeState) : Nat :=
  termAt state.log (lastCommittableIndex state)

end CCFRaft.Model.Node
