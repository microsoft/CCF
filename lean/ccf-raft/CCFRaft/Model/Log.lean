-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Lattice.Fold

/-!
# Log entries and log queries

The entries a node's log holds and pure queries over a log. Log positions are
one-based; index zero is the empty prefix. Signatures make the prefix they
cover committable.
-/

namespace CCFRaft.Model.Local

/-- The payload kinds stored in the log. -/
inductive EntryContent (Node TxId : Type) where
  /-- An ordinary client transaction with its external identifier. -/
  | transaction (txId : TxId)
  /-- A signature over the preceding log prefix. -/
  | signature
  /-- A new configuration, identified by its one-based log index. -/
  | reconfiguration (nodes : Finset Node)
  /-- Nodes whose completed retirement is now durably recorded. -/
  | retiredCommitted (nodes : Finset Node)
deriving DecidableEq

/-- One entry in a node's log. -/
structure Entry (Node TxId : Type) where
  term : Nat
  content : EntryContent Node TxId
deriving DecidableEq

variable {Node TxId : Type}

variable [DecidableEq Node] [DecidableEq TxId]

/-- Read a one-based log index, returning `none` for index zero or past the end. -/
def entryAt? (log : List (Entry Node TxId)) (index : Nat) : Option (Entry Node TxId) :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List (Entry Node TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

/-- Check whether a one-based log position contains a signature. -/
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

/-- The term of the latest signature, or zero if the log has none. -/
def maxCommittableTerm (log : List (Entry Node TxId)) : Nat :=
  termAt log (maxCommittableIndex log)

/-- The one-based index of the latest signature at or before a log position. -/
def maxCommittableIndexUpTo (log : List (Entry Node TxId)) (frontier : Nat) : Nat :=
  maxCommittableIndex (log.take frontier)

/-- The log entries after `previousIndex` up to `batchEnd`. -/
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

/-- The first matching entry's one-based index, strictly after `afterIndex`. -/
def firstLogIndexAfter (log : List (Entry Node TxId)) (afterIndex : Nat)
    (predicate : EntryContent Node TxId -> Bool)
    : Option Nat :=
  ((log.zipIdx 1).find?
    fun (entry, index) => decide (afterIndex < index) && predicate entry.content).map
    Prod.snd

end CCFRaft.Model.Local
