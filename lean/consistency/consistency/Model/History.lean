module

public import consistency.Model.Types

@[expose] public section

namespace consistency.Model

/-- Safe one-based lookup, rejecting the sentinel instead of saturating subtraction. -/
def at? {α : Type} (xs : List α) (index : Nat) : Option α :=
  if index = 0 then none else xs[index - 1]?

/-- IDs start at zero and are shared by read-only and read-write requests. -/
def nextRequestId (history : List Event) : TxContent :=
  history.foldl
    (fun next event =>
      match event with
      | .request _ tx => tx + 1
      | _ => next)
    0

/-- Explicitly received status knowledge, not an internal consensus frontier. -/
def statusIDs (history : List Event) (status : Status) : List TxID :=
  history.filterMap
    fun event =>
      match event with
      | .status txid value => if value = status then some txid else none
      | _ => none

/-- Highest sequence number explicitly reported committed, or zero. -/
def commitSeqno (history : List Event) : Nat :=
  (statusIDs history .committed).foldl (fun seqno txid => max seqno txid.seqno) 0

/-- Application state is the sequence of writes, excluding other ledger entries. -/
def writes (branch : List Entry) : List TxContent :=
  branch.filterMap Entry.tx

/-- A response after this request has already been delivered. -/
def responded (history : List Event) (requestIndex : Nat) (kind : TxType) (tx : TxContent)
    : Bool :=
  (history.drop requestIndex).any
    fun event =>
      match event with
      | .response value request _ _ => value = kind && request = tx
      | _ => false

/-- The branch exists and is eligible for processing requests; view 1 is reserved. -/
def activeBranch (state : State) (branch : Nat) : Bool :=
  2 ≤ branch && branch ≤ state.branches.length

end consistency.Model
