module

public import consistency.Properties.History

@[expose] public section

/-!
Executable predicates for the consistency model's client-visible histories.
These helpers describe client-visible histories independently of proofs.
-/

namespace consistency.Properties

open Model

/-- Responses of the specified kind follow an associated request. -/
def receivedIsFirstSent (history : List Event) (kind : TxType) : Prop :=
  ∀ response ∈ responsesOf history kind,
    ∃ request ∈ requests history,
      request.1 < response.1 ∧ request.2 = (kind, response.2.tx)

/-- Read-write responses follow an associated request. -/
def allRwReceivedIsFirstSent (history : List Event) : Prop :=
  receivedIsFirstSent history .rw

/-- Read-only responses follow an associated request. -/
def allRoReceivedIsFirstSent (history : List Event) : Prop :=
  receivedIsFirstSent history .ro

/-- Responses of either kind follow an associated request. -/
def allReceivedIsFirstSent (history : List Event) : Prop :=
  allRwReceivedIsFirstSent history ∧ allRoReceivedIsFirstSent history

/-- A transaction ID identifies at most one write. -/
def uniqueTxs (history : List Event) : Prop :=
  ∀ left ∈ responsesOf history .rw,
  ∀ right ∈ responsesOf history .rw, left.2.txid = right.2.txid → left.2.tx = right.2.tx

/-- Equal transaction IDs give equal observations, including read-only responses. -/
def sameObservations (history : List Event) : Prop :=
  ∀ left ∈ responses history,
  ∀ right ∈ responses history,
    left.2.txid = right.2.txid → left.2.observed = right.2.observed

/-- Request IDs are distinct across both transaction kinds. -/
def uniqueTxRequests (history : List Event) : Prop :=
  ∀ left ∈ requests history,
  ∀ right ∈ requests history, left.1 ≠ right.1 → left.2.2 ≠ right.2.2

/-- Each request receives a unique transaction ID. -/
def uniqueTxIds (history : List Event) : Prop :=
  ∀ left ∈ responses history,
  ∀ right ∈ responses history, left.2.tx = right.2.tx → left.2.txid = right.2.txid

/-- Single-node write sequence numbers are unique. -/
def uniqueSeqNums (history : List Event) : Prop :=
  ∀ left ∈ responsesOf history .rw,
  ∀ right ∈ responsesOf history .rw,
    left.2.txid.seqno = right.2.txid.seqno → left.2.tx = right.2.tx

/-- Committed write sequence numbers are unique. -/
def uniqueSeqNumsCommitted (history : List Event) : Prop :=
  ∀ left ∈ committedResponses history .rw,
  ∀ right ∈ committedResponses history .rw,
    left.2.txid.seqno = right.2.txid.seqno → left.2.tx = right.2.tx

/-- Final statuses are disjoint. -/
def committedOrInvalid (history : List Event) : Prop :=
  ∀ txid ∈ statusIDs history .committed, txid ∉ statusIDs history .invalid

/-- Reported statuses in a committed prefix agree. -/
def onceCommittedPrevCommitted (history : List Event) : Prop :=
  ∀ left ∈ statuses history,
  ∀ right ∈ statuses history,
    left.2 = .committed
    → left.1.view = right.1.view
    → right.1.seqno ≤ left.1.seqno
    → right.2 = .committed

/-- Older-view conflicting suffixes are invalid. -/
def onceCommittedNextInvalid (history : List Event) : Prop :=
  ∀ left ∈ statuses history,
  ∀ right ∈ statuses history,
    left.2 = .committed
    → left.1.seqno ≤ right.1.seqno
    → right.1.view < left.1.view
    → right.2 = .invalid

/-- Reported statuses in an invalid suffix agree. -/
def onceInvalidNextInvalid (history : List Event) : Prop :=
  ∀ left ∈ statuses history,
  ∀ right ∈ statuses history,
    left.2 = .invalid
    → left.1.view = right.1.view
    → left.1.seqno ≤ right.1.seqno
    → right.2 = .invalid

/-- All three status-propagation claims hold. -/
def committedOrInvalidStrong (history : List Event) : Prop :=
  onceCommittedPrevCommitted history
  ∧ onceCommittedNextInvalid history
  ∧ onceInvalidNextInvalid history

/-- Observations contain only earlier requested writes. -/
def onlyObserveSentRequests (history : List Event) : Prop :=
  ∀ response ∈ responses history,
  ∀ tx ∈ response.2.observed,
    ∃ request ∈ requests history, request.1 < response.1 ∧ request.2 = (.rw, tx)

/-- Observations contain no duplicate writes. -/
def atMostOnceObserved (history : List Event) : Prop :=
  ∀ response ∈ responses history, response.2.observed.Nodup

/-- Real time uses the initial response, not the later committed-status event. -/
def allCommittedObservedBy (history : List Event) (kind : TxType) : Prop :=
  ∀ earlier ∈ committedResponses history .rw,
  ∀ request ∈ committedRequests history kind,
  ∀ later ∈ committedResponses history kind,
    later.2.tx = request.2.2 → earlier.1 < request.1 → earlier.2.tx ∈ later.2.observed

/-- Committed writes observe real-time predecessor writes. -/
def allCommittedObserved (history : List Event) : Prop :=
  allCommittedObservedBy history .rw

/-- Single-node committed reads observe predecessor writes; not a multi-node guarantee. -/
def allCommittedObservedRo (history : List Event) : Prop :=
  allCommittedObservedBy history .ro

/-- Write responses exclude writes whose transaction IDs have an invalid status. -/
def invalidNotObserved (history : List Event) : Prop :=
  ∀ invalid ∈ responsesOf history .rw,
  ∀ observer ∈ responsesOf history .rw,
    invalid.1 ≠ observer.1
    → invalid.2.txid ∈ statusIDs history .invalid
    → invalid.2.tx ∉ observer.2.observed

/-- Committed write responses exclude writes whose transaction IDs have an invalid status. -/
def invalidNotObservedByCommitted (history : List Event) : Prop :=
  ∀ invalid ∈ responsesOf history .rw,
  ∀ observer ∈ committedResponses history .rw,
    invalid.1 ≠ observer.1
    → invalid.2.txid ∈ statusIDs history .invalid
    → invalid.2.tx ∉ observer.2.observed

/-- Prefix comparability of application observations. -/
def comparable (left right : List TxContent) : Prop :=
  left <+: right ∨ right <+: left

/-- Write observations are prefix-comparable; not a multi-node speculative-write guarantee. -/
def rwSerializable (history : List Event) : Prop :=
  ∀ left ∈ responsesOf history .rw,
  ∀ right ∈ responsesOf history .rw, comparable left.2.observed right.2.observed

/-- Committed write observations are prefix-comparable. -/
def committedRwSerializable (history : List Event) : Prop :=
  ∀ left ∈ committedResponses history .rw,
  ∀ right ∈ committedResponses history .rw, comparable left.2.observed right.2.observed

/-- Committed writes are serializable, observe real-time predecessors, and have no duplicates. -/
def committedRwLinearizable (history : List Event) : Prop :=
  committedRwSerializable history
  ∧ allCommittedObserved history
  ∧ atMostOnceObserved history

/-- TxID order respects request-to-response intervals. -/
def committedRwOrderedRealTime (history : List Event) : Prop :=
  ∀ earlier ∈ committedResponses history .rw,
  ∀ request ∈ committedRequests history .rw,
  ∀ later ∈ committedResponses history .rw,
    later.2.tx = request.2.2
    → earlier.1 < request.1
    → txIDStrictlyLessThan earlier.2.txid later.2.txid

/-- Adjacent sorted committed responses strictly extend.
Intervening writes need not have explicitly received a committed status.
Empty and singleton response sets satisfy this adjacent-pair condition vacuously. -/
def committedRwOrderedSerializable (history : List Event) : Prop :=
  let ordered := committedRwResponses history
  ∀ pair ∈ ordered.zip ordered.tail,
    pair.1.observed <+: pair.2.observed
    ∧ pair.1.observed.length < pair.2.observed.length
    ∧ pair.2.observed.getLast? = some pair.2.tx

/-- The primary CCF consistency claim: ordered serializability respecting real time. -/
def committedRwOrderedSpecLinearizable (history : List Event) : Prop :=
  committedRwOrderedSerializable history ∧ committedRwOrderedRealTime history

/-- Intended common invariants, not established theorems. -/
def commonGuarantees (history : List Event) : Prop :=
  allReceivedIsFirstSent history
  ∧ uniqueTxs history
  ∧ sameObservations history
  ∧ uniqueTxRequests history
  ∧ uniqueTxIds history
  ∧ uniqueSeqNumsCommitted history
  ∧ committedOrInvalid history
  ∧ committedOrInvalidStrong history
  ∧ onlyObserveSentRequests history
  ∧ atMostOnceObserved history
  ∧ allCommittedObserved history
  ∧ invalidNotObservedByCommitted history
  ∧ committedRwLinearizable history
  ∧ committedRwOrderedSpecLinearizable history

/-- Variant-specific intended guarantees; non-guarantees remain separately named predicates. -/
def variantGuarantees (config : Config) (history : List Event) : Prop :=
  commonGuarantees history
  ∧ (config.multiNode = false
      → uniqueSeqNums history
        ∧ rwSerializable history
        ∧ invalidNotObserved history
        ∧ allCommittedObservedRo history)

-- Finite history predicates remain transparent to executable decidability inference.
attribute [reducible] receivedIsFirstSent allRwReceivedIsFirstSent
  allRoReceivedIsFirstSent allReceivedIsFirstSent uniqueTxs sameObservations
  uniqueTxRequests uniqueTxIds uniqueSeqNums uniqueSeqNumsCommitted committedOrInvalid
  onceCommittedPrevCommitted onceCommittedNextInvalid onceInvalidNextInvalid
  committedOrInvalidStrong onlyObserveSentRequests atMostOnceObserved
  allCommittedObservedBy allCommittedObserved allCommittedObservedRo invalidNotObserved
  invalidNotObservedByCommitted comparable rwSerializable committedRwSerializable
  committedRwLinearizable committedRwOrderedRealTime committedRwOrderedSerializable
  committedRwOrderedSpecLinearizable commonGuarantees variantGuarantees

end consistency.Properties
