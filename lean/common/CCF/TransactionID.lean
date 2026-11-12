module

@[expose] public section

namespace CCF

/-- A ledger position, ordered first by view and then by sequence number. -/
structure TransactionID where
  /-- The transaction's consensus view. -/
  view : Nat
  /-- The transaction's sequence number. -/
  seqno : Nat
deriving Repr, BEq, ReflBEq, LawfulBEq, Hashable, Inhabited, DecidableEq

/-- Strict lexicographic order on view, then sequence number. -/
abbrev TransactionID.lt (left right : TransactionID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno < right.seqno)

/-- Non-strict lexicographic order on view, then sequence number. -/
abbrev TransactionID.le (left right : TransactionID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end CCF
