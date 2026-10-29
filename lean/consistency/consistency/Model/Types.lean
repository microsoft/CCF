module

public import CCF.TransitionSystem

@[expose] public section

namespace consistency.Model

/-- The dummy application's writes and request identifiers are natural numbers.
A read-write transaction appends its number to a list and reads the resulting list;
a read-only transaction just reads that list. -/
abbrev TxContent := Nat

/-- Ledger positions use one-based views and sequence numbers; zero is a sentinel. -/
structure TxID where
  view : Nat
  seqno : Nat
deriving DecidableEq, Repr

/-- Only final status observations are modeled.
Unknown and pending statuses are omitted to reduce the state space. -/
inductive Status where
  | committed
  | invalid
deriving DecidableEq, Repr

/-- Both transaction kinds are forwarded to a primary, including former primaries. -/
inductive TxType where
  | rw
  | ro
deriving DecidableEq, Repr

/-- Client observations, in global real-time order.
Unlike traditional client histories, a response can arrive before commitment.
Status requests themselves are omitted; only their received final statuses are recorded. -/
inductive Event where
  | request (kind : TxType) (tx : TxContent)
  | response (kind : TxType) (tx : TxContent) (observed : List TxContent) (txid : TxID)
  | status (txid : TxID) (status : Status)
deriving DecidableEq, Repr

/-- Other transactions occupy ledger positions without affecting the application. -/
structure Entry where
  view : Nat
  tx : Option TxContent
deriving DecidableEq, Repr

/-- Each branch is the append-only ledger of the leader of its one-based view.
A concrete node's ledger is represented by one of these branches or a prefix of one.
The history is shared by all nodes and has no timestamps: its order records the
order in which clients observe events, according to a global clock. -/
structure State where
  history : List Event := []
  branches : List (List Entry) := []
deriving DecidableEq, Repr

/-- Nondeterministic choices are explicit inputs; all indices are one-based. -/
inductive Action where
  | request (kind : TxType)
  | execute (requestIndex branch : Nat)
  | respond (requestIndex branch seqno : Nat)
  | read (requestIndex branch : Nat)
  | commit (responseIndex : Nat)
  | invalidate (responseIndex : Nat)
  | appendOther (branch : Nat)
  | elect (branch prefixLength : Nat)
deriving DecidableEq, Repr

end consistency.Model
