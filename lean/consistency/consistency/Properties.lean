module

public import consistency.Properties.History
public import CCF.Execution

import consistency.Proofs.Responses
import consistency.Proofs.Statuses
import consistency.Proofs.Ordered
import consistency.Proofs.InvalidObservations
import consistency.Proofs.Witnesses

@[expose] public section

/-!
Safety theorem statements for the consistency model.
The primary consistency guarantee is expressed by `committed_rw_ordered_serializable`
and `committed_rw_ordered_real_time` together: committed writes serialize in
transaction-ID order, respecting request-to-initial-response real-time intervals
rather than waiting for committed-status notifications.
-/

namespace consistency.Properties

open Model

abbrev GlobalTrace := CCF.Execution.Trace State

/-- Adjacent TxID-ordered committed responses strictly extend.
The later observation ends with its own write; intervening ledger writes need not
have responses with explicitly received committed statuses. -/
theorem committed_rw_ordered_serializable
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ pair ∈
            (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail,
            let (earlier, later) := pair
            earlier.observed <+: later.observed
            /\ earlier.observed.length < later.observed.length
            /\ later.observed.getLast? = some later.tx := by
  exact Proofs.Ordered.committed_rw_ordered_serializable

/-- The sorted committed responses contain an adjacent pair. -/
lemma committed_rw_ordered_serializable_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (left, right)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail := by
  exact Proofs.Witnesses.committed_rw_ordered_serializable_witness

/-- TxID order respects request-to-response intervals. -/
theorem committed_rw_ordered_real_time
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ earlier ∈ committedResponses state.history .rw,
            let (earlierIndex, earlier) := earlier
            ∀ request ∈ committedRequests state.history .rw,
              let (requestIndex, _, requestTx) := request
              ∀ later ∈ committedResponses state.history .rw,
                let (_, later) := later
                later.tx = requestTx
                -> earlierIndex < requestIndex
                -> txIDStrictlyLessThan earlier.txid later.txid := by
  exact Proofs.RealTime.committed_rw_ordered_real_time

/-- Committed writes and a matching request satisfy the real-time antecedents. -/
lemma committed_rw_ordered_real_time_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        let (earlierIndex, earlier) := earlier
        let (laterIndex, later) := later
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (earlierIndex, earlier) ∈ committedResponses state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ committedRequests state.history .rw
        ∧ (laterIndex, later) ∈ committedResponses state.history .rw
        ∧ later.tx = requestTx
        ∧ earlierIndex < requestIndex := by
  exact Proofs.Witnesses.real_time_witness

/-- Responses of either kind follow matching requests.
Matching uses request IDs; distinct reads may return the same transaction ID. -/
theorem all_received_is_first_sent
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> forall (kind : TxType),
            ∀ response ∈ responsesOf state.history kind,
              let (responseIndex, response) := response
              ∃ request ∈ requests state.history,
                let (requestIndex, requestKind, requestTx) := request
                requestIndex < responseIndex
                /\ (requestKind, requestTx) = (kind, response.tx) := by
  exact Proofs.History.all_received_is_first_sent

/-- Both response kinds occur in the same execution. -/
lemma all_received_is_first_sent_witness
    : ∃ (trace : GlobalTrace) (state : State) (write read : Nat × Response),
        let (writeIndex, write) := write
        let (readIndex, read) := read
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (writeIndex, write) ∈ responsesOf state.history .rw
        ∧ (readIndex, read) ∈ responsesOf state.history .ro := by
  exact Proofs.Witnesses.all_received_witness

/-- A transaction ID identifies at most one write.
This uniqueness does not apply to reads, which can observe the same ledger position. -/
theorem unique_txs
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ responsesOf state.history .rw,
            let (_, left) := left
            ∀ right ∈ responsesOf state.history .rw,
              let (_, right) := right
              left.txid = right.txid -> left.tx = right.tx := by
  exact Proofs.LedgerIdentity.unique_txs

/-- Write responses with matching transaction IDs occur in a valid execution. -/
lemma unique_txs_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ responsesOf state.history .rw
        ∧ (rightIndex, right) ∈ responsesOf state.history .rw
        ∧ left.txid = right.txid := by
  exact Proofs.Witnesses.unique_txs_witness

/-- Equal transaction IDs give equal observations. -/
theorem same_observations
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            let (_, left) := left
            ∀ right ∈ responses state.history,
              let (_, right) := right
              left.txid = right.txid -> left.observed = right.observed := by
  exact Proofs.LedgerIdentity.same_observations

/-- Responses with matching transaction IDs occur in a valid execution. -/
lemma same_observations_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ responses state.history
        ∧ (rightIndex, right) ∈ responses state.history
        ∧ left.txid = right.txid := by
  exact Proofs.Witnesses.same_observations_witness

/-- Requests have distinct IDs across both transaction kinds. -/
theorem unique_tx_requests
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ requests state.history,
            let (leftIndex, _, leftTx) := left
            ∀ right ∈ requests state.history,
              let (rightIndex, _, rightTx) := right
              leftIndex ≠ rightIndex -> leftTx ≠ rightTx := by
  exact Proofs.History.unique_tx_requests

/-- Requests at distinct history positions occur in a valid execution. -/
lemma unique_tx_requests_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × (TxType × TxContent)),
        let (leftIndex, leftKind, leftTx) := left
        let (rightIndex, rightKind, rightTx) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, leftKind, leftTx) ∈ requests state.history
        ∧ (rightIndex, rightKind, rightTx) ∈ requests state.history
        ∧ leftIndex ≠ rightIndex := by
  exact Proofs.Witnesses.unique_tx_requests_witness

/-- Each request receives a unique transaction ID. -/
theorem unique_tx_ids
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            let (_, left) := left
            ∀ right ∈ responses state.history,
              let (_, right) := right
              left.tx = right.tx -> left.txid = right.txid := by
  exact Proofs.Responses.unique_tx_ids

/-- Responses with matching request IDs occur in a valid execution. -/
lemma unique_tx_ids_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ responses state.history
        ∧ (rightIndex, right) ∈ responses state.history
        ∧ left.tx = right.tx := by
  exact Proofs.Witnesses.unique_tx_ids_witness

/-- Committed write sequence numbers are unique.
This is weaker than uniqueness for all writes and excludes disaster recovery,
which is outside this model. -/
theorem unique_seq_nums_committed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ committedResponses state.history .rw,
            let (_, left) := left
            ∀ right ∈ committedResponses state.history .rw,
              let (_, right) := right
              left.txid.seqno = right.txid.seqno -> left.tx = right.tx := by
  exact Proofs.Commitment.unique_seq_nums_committed

/-- Committed write responses with matching sequence numbers occur in a valid execution. -/
lemma unique_seq_nums_committed_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw
        ∧ left.txid.seqno = right.txid.seqno := by
  exact Proofs.Witnesses.unique_seq_nums_committed_witness

/-- Committed and invalid statuses are disjoint. -/
theorem committed_or_invalid
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  exact Proofs.Statuses.committed_or_invalid

/-- A committed status occurs in a valid execution. -/
lemma committed_or_invalid_witness
    : ∃ (trace : GlobalTrace) (state : State) (committed : TxID),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ committed ∈ statusIDs state.history .committed := by
  exact Proofs.Witnesses.committed_or_invalid_witness

/-- Reported statuses in a committed prefix agree. -/
theorem once_committed_prev_committed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            let (leftTxID, leftStatus) := left
            ∀ right ∈ statuses state.history,
              let (rightTxID, rightStatus) := right
              leftStatus = .committed
              -> leftTxID.view = rightTxID.view
              -> rightTxID.seqno ≤ leftTxID.seqno
              -> rightStatus = .committed := by
  exact Proofs.Statuses.once_committed_prev_committed

/-- Reported statuses satisfy the same-view committed-prefix antecedents. -/
lemma once_committed_prev_committed_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : TxID × Status),
        let (leftTxID, leftStatus) := left
        let (rightTxID, rightStatus) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftTxID, leftStatus) ∈ statuses state.history
        ∧ (rightTxID, rightStatus) ∈ statuses state.history
        ∧ leftStatus = .committed
        ∧ leftTxID.view = rightTxID.view
        ∧ rightTxID.seqno ≤ leftTxID.seqno := by
  exact Proofs.Witnesses.once_committed_prev_committed_witness

/-- Older-view conflicting suffixes are invalid. -/
theorem once_committed_next_invalid
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            let (leftTxID, leftStatus) := left
            ∀ right ∈ statuses state.history,
              let (rightTxID, rightStatus) := right
              leftStatus = .committed
              -> leftTxID.seqno ≤ rightTxID.seqno
              -> rightTxID.view < leftTxID.view
              -> rightStatus = .invalid := by
  exact Proofs.Statuses.once_committed_next_invalid

/-- Reported statuses satisfy the older-view conflicting-suffix antecedents. -/
lemma once_committed_next_invalid_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : TxID × Status),
        let (leftTxID, leftStatus) := left
        let (rightTxID, rightStatus) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftTxID, leftStatus) ∈ statuses state.history
        ∧ (rightTxID, rightStatus) ∈ statuses state.history
        ∧ leftStatus = .committed
        ∧ leftTxID.seqno ≤ rightTxID.seqno
        ∧ rightTxID.view < leftTxID.view := by
  exact Proofs.Witnesses.once_committed_next_invalid_witness

/-- Reported statuses in an invalid suffix agree. -/
theorem once_invalid_next_invalid
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            let (leftTxID, leftStatus) := left
            ∀ right ∈ statuses state.history,
              let (rightTxID, rightStatus) := right
              leftStatus = .invalid
              -> leftTxID.view = rightTxID.view
              -> leftTxID.seqno ≤ rightTxID.seqno
              -> rightStatus = .invalid := by
  exact Proofs.Statuses.once_invalid_next_invalid

/-- Reported statuses satisfy the same-view invalid-suffix antecedents. -/
lemma once_invalid_next_invalid_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : TxID × Status),
        let (leftTxID, leftStatus) := left
        let (rightTxID, rightStatus) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftTxID, leftStatus) ∈ statuses state.history
        ∧ (rightTxID, rightStatus) ∈ statuses state.history
        ∧ leftStatus = .invalid
        ∧ leftTxID.view = rightTxID.view
        ∧ leftTxID.seqno ≤ rightTxID.seqno := by
  exact Proofs.Witnesses.once_invalid_next_invalid_witness

/-- Observations contain only earlier requested writes. -/
theorem only_observe_sent_requests
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ response ∈ responses state.history,
            let (responseIndex, response) := response
            ∀ tx ∈ response.observed,
              ∃ request ∈ requests state.history,
                let (requestIndex, requestKind, requestTx) := request
                requestIndex < responseIndex /\ (requestKind, requestTx) = (.rw, tx) := by
  exact Proofs.Observations.only_observe_sent_requests

/-- An observed write populates the observation-membership antecedent. -/
lemma only_observe_sent_requests_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (tx : TxContent),
        let (responseIndex, response) := response
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responses state.history
        ∧ tx ∈ response.observed := by
  exact Proofs.Witnesses.only_observe_sent_requests_witness

/-- Observations contain no duplicate writes. -/
theorem at_most_once_observed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ response ∈ responses state.history,
            let (_, response) := response
            response.observed.Nodup := by
  exact Proofs.Observations.at_most_once_observed

/-- A response populates the observation domain. -/
lemma at_most_once_observed_witness
    : ∃ (trace : GlobalTrace) (state : State) (response : Nat × Response),
        let (responseIndex, response) := response
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responses state.history := by
  exact Proofs.Witnesses.at_most_once_observed_witness

/-- Committed writes observe real-time predecessor writes.
Once a write is known committed, real-time ordering uses its original response,
not the later event at which the client learns it committed. -/
theorem all_committed_observed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ earlier ∈ committedResponses state.history .rw,
            let (earlierIndex, earlier) := earlier
            ∀ request ∈ committedRequests state.history .rw,
              let (requestIndex, _, requestTx) := request
              ∀ later ∈ committedResponses state.history .rw,
                let (_, later) := later
                later.tx = requestTx
                -> earlierIndex < requestIndex
                -> earlier.tx ∈ later.observed := by
  exact Proofs.RealTime.all_committed_observed

/-- Committed writes and a matching request satisfy the real-time antecedents. -/
lemma all_committed_observed_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        let (earlierIndex, earlier) := earlier
        let (laterIndex, later) := later
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (earlierIndex, earlier) ∈ committedResponses state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ committedRequests state.history .rw
        ∧ (laterIndex, later) ∈ committedResponses state.history .rw
        ∧ later.tx = requestTx
        ∧ earlierIndex < requestIndex := by
  exact Proofs.Witnesses.real_time_witness

/-- Committed writes exclude invalid writes. -/
theorem invalid_not_observed_by_committed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ invalid ∈ responsesOf state.history .rw,
            let (invalidIndex, invalid) := invalid
            ∀ observer ∈ committedResponses state.history .rw,
              let (observerIndex, observer) := observer
              invalidIndex ≠ observerIndex
              -> invalid.txid ∈ statusIDs state.history .invalid
              -> invalid.tx ∉ observer.observed := by
  exact Proofs.InvalidObservations.invalid_not_observed_by_committed

/-- An invalid write and a different committed response populate the exclusion antecedents. -/
lemma invalid_not_observed_by_committed_witness
    : ∃ (trace : GlobalTrace) (state : State) (invalid observer : Nat × Response),
        let (invalidIndex, invalid) := invalid
        let (observerIndex, observer) := observer
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (invalidIndex, invalid) ∈ responsesOf state.history .rw
        ∧ (observerIndex, observer) ∈ committedResponses state.history .rw
        ∧ invalidIndex ≠ observerIndex
        ∧ invalid.txid ∈ statusIDs state.history .invalid := by
  exact Proofs.Witnesses.invalid_not_observed_by_committed_witness

/-- Committed write histories are serializable. -/
theorem committed_rw_serializable
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ left ∈ committedResponses state.history .rw,
            let (_, left) := left
            ∀ right ∈ committedResponses state.history .rw,
              let (_, right) := right
              left.observed <+: right.observed \/ right.observed <+: left.observed := by
  exact Proofs.Commitment.committed_rw_serializable

/-- Committed write responses populate the serialization domain. -/
lemma committed_rw_serializable_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw := by
  exact Proofs.Witnesses.write_pair_witness

end consistency.Properties
