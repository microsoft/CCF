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
All proofs link to checked implementations under `Proofs/`.
Adjacent witness lemmas exhibit populated reachable cases.
-/

namespace consistency.Properties

open Model

abbrev GlobalTrace := CCF.Execution.Trace State

/-- Read-write responses follow an associated request. -/
theorem all_rw_received_is_first_sent
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ response ∈ responsesOf state.history .rw,
            let (responseIndex, response) := response
            ∃ request ∈ requests state.history,
              let (requestIndex, requestKind, requestTx) := request
              requestIndex < responseIndex
              /\ (requestKind, requestTx) = (.rw, response.tx) := by
  exact Proofs.History.all_rw_received_is_first_sent

/-- A write request receives a response with a nonempty observation. -/
lemma all_rw_received_is_first_sent_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent)),
        let (responseIndex, response) := response
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responsesOf state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ requests state.history
        ∧ requestIndex < responseIndex
        ∧ (requestKind, requestTx) = (.rw, response.tx)
        ∧ response.observed ≠ [] := by
  exact Proofs.Witnesses.received_witness .rw

/-- Read-only responses follow an associated request.
Multiple read requests can receive the same transaction ID; matching is by request,
not by uniqueness of the returned ledger position. -/
theorem all_ro_received_is_first_sent
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ response ∈ responsesOf state.history .ro,
            let (responseIndex, response) := response
            ∃ request ∈ requests state.history,
              let (requestIndex, requestKind, requestTx) := request
              requestIndex < responseIndex
              /\ (requestKind, requestTx) = (.ro, response.tx) := by
  exact Proofs.History.all_ro_received_is_first_sent

/-- A read request receives a response with a nonempty observation. -/
lemma all_ro_received_is_first_sent_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent)),
        let (responseIndex, response) := response
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responsesOf state.history .ro
        ∧ (requestIndex, requestKind, requestTx) ∈ requests state.history
        ∧ requestIndex < responseIndex
        ∧ (requestKind, requestTx) = (.ro, response.tx)
        ∧ response.observed ≠ [] := by
  exact Proofs.Witnesses.received_witness .ro

/-- Responses of either kind follow requests. -/
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

/-- Both response kinds occur in the same execution with nonempty observations. -/
lemma all_received_is_first_sent_witness
    : ∃ (trace : GlobalTrace) (state : State) (write read : Nat × Response),
        let (writeIndex, write) := write
        let (readIndex, read) := read
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (writeIndex, write) ∈ responsesOf state.history .rw
        ∧ (readIndex, read) ∈ responsesOf state.history .ro
        ∧ write.observed ≠ []
        ∧ read.observed ≠ [] := by
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

/-- Two distinct committed writes populate the uniqueness domain.
Matching-ID comparisons include each actual response compared with itself. -/
lemma unique_txs_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw
        ∧ leftIndex < rightIndex
        ∧ left.tx ≠ right.tx
        ∧ left.txid.seqno < right.txid.seqno
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

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

/-- Distinct read requests receive the same transaction ID and nonempty observation. -/
lemma same_observations_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ responsesOf state.history .ro
        ∧ (rightIndex, right) ∈ responsesOf state.history .ro
        ∧ leftIndex ≠ rightIndex
        ∧ left.tx ≠ right.tx
        ∧ left.txid = right.txid
        ∧ left.observed = right.observed
        ∧ left.observed ≠ [] := by
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

/-- A read request and a write request have distinct positions and request IDs. -/
lemma unique_tx_requests_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × (TxType × TxContent)),
        let (leftIndex, leftKind, leftTx) := left
        let (rightIndex, rightKind, rightTx) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, leftKind, leftTx) ∈ requests state.history
        ∧ (rightIndex, rightKind, rightTx) ∈ requests state.history
        ∧ leftIndex ≠ rightIndex
        ∧ leftKind ≠ rightKind
        ∧ leftTx ≠ rightTx := by
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

/-- Two real requests receive distinct write IDs; matching-request cases are reflexive. -/
lemma unique_tx_ids_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw
        ∧ leftIndex < rightIndex
        ∧ left.tx ≠ right.tx
        ∧ left.txid.seqno < right.txid.seqno
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

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

/-- Two committed writes occupy different positions; matching-position cases are reflexive. -/
lemma unique_seq_nums_committed_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw
        ∧ leftIndex < rightIndex
        ∧ left.tx ≠ right.tx
        ∧ left.txid.seqno < right.txid.seqno
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed and invalid statuses are disjoint. -/
theorem committed_or_invalid
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  exact Proofs.Statuses.committed_or_invalid

/-- An execution reports both a committed write and a different invalid write. -/
lemma committed_or_invalid_witness
    : ∃ (trace : GlobalTrace) (state : State) (committed invalid : TxID),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ committed ∈ statusIDs state.history .committed
        ∧ invalid ∈ statusIDs state.history .invalid
        ∧ committed ≠ invalid
        ∧ committed ∉ statusIDs state.history .invalid := by
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

/-- Distinct positions in the same committed prefix have reported committed statuses. -/
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
        ∧ rightTxID.seqno < leftTxID.seqno
        ∧ rightStatus = .committed := by
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

/-- A newer-view commitment coexists with an invalid older-view suffix. -/
lemma once_committed_next_invalid_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : TxID × Status),
        let (leftTxID, leftStatus) := left
        let (rightTxID, rightStatus) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftTxID, leftStatus) ∈ statuses state.history
        ∧ (rightTxID, rightStatus) ∈ statuses state.history
        ∧ leftStatus = .committed
        ∧ leftTxID.seqno < rightTxID.seqno
        ∧ rightTxID.view < leftTxID.view
        ∧ rightStatus = .invalid := by
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

/-- Distinct positions in the same invalid suffix have reported invalid statuses. -/
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
        ∧ leftTxID.seqno < rightTxID.seqno
        ∧ rightStatus = .invalid := by
  exact Proofs.Witnesses.once_invalid_next_invalid_witness

/-- All three status-propagation claims. -/
theorem committed_or_invalid_strong
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> (∀ left ∈ statuses state.history,
              let (leftTxID, leftStatus) := left
              ∀ right ∈ statuses state.history,
                let (rightTxID, rightStatus) := right
                leftStatus = .committed
                -> leftTxID.view = rightTxID.view
                -> rightTxID.seqno ≤ leftTxID.seqno
                -> rightStatus = .committed)
            /\ (∀ left ∈ statuses state.history,
                  let (leftTxID, leftStatus) := left
                  ∀ right ∈ statuses state.history,
                    let (rightTxID, rightStatus) := right
                    leftStatus = .committed
                    -> leftTxID.seqno ≤ rightTxID.seqno
                    -> rightTxID.view < leftTxID.view
                    -> rightStatus = .invalid)
            /\ (∀ left ∈ statuses state.history,
                  let (leftTxID, leftStatus) := left
                  ∀ right ∈ statuses state.history,
                    let (rightTxID, rightStatus) := right
                    leftStatus = .invalid
                    -> leftTxID.view = rightTxID.view
                    -> leftTxID.seqno ≤ rightTxID.seqno
                    -> rightStatus = .invalid) := by
  exact Proofs.Statuses.committed_or_invalid_strong

/-- One execution activates all three propagation clauses at distinct positions. -/
lemma committed_or_invalid_strong_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlyCommit lateCommit earlyInvalid lateInvalid : TxID),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ earlyCommit ∈ statusIDs state.history .committed
        ∧ lateCommit ∈ statusIDs state.history .committed
        ∧ earlyInvalid ∈ statusIDs state.history .invalid
        ∧ lateInvalid ∈ statusIDs state.history .invalid
        ∧ earlyCommit.view = lateCommit.view
        ∧ earlyCommit.seqno < lateCommit.seqno
        ∧ earlyInvalid.view = lateInvalid.view
        ∧ earlyInvalid.seqno < lateInvalid.seqno
        ∧ earlyCommit.seqno < lateInvalid.seqno
        ∧ lateInvalid.view < earlyCommit.view := by
  exact Proofs.Witnesses.committed_or_invalid_strong_witness

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

/-- A real read observes a write requested earlier in the execution. -/
lemma only_observe_sent_requests_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent))
        (tx : TxContent),
        let (responseIndex, response) := response
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responses state.history
        ∧ response.kind = .ro
        ∧ tx ∈ response.observed
        ∧ (requestIndex, requestKind, requestTx) ∈ requests state.history
        ∧ requestIndex < responseIndex
        ∧ (requestKind, requestTx) = (.rw, tx) := by
  exact Proofs.Witnesses.only_observe_sent_requests_witness

/-- Observations contain no duplicate writes. -/
theorem at_most_once_observed
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> ∀ response ∈ responses state.history,
            let (_, response) := response
            response.observed.Nodup := by
  exact Proofs.Observations.at_most_once_observed

/-- An observation contains at least two writes without duplicates. -/
lemma at_most_once_observed_witness
    : ∃ (trace : GlobalTrace) (state : State) (response : Nat × Response),
        let (responseIndex, response) := response
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (responseIndex, response) ∈ responses state.history
        ∧ 2 ≤ response.observed.length
        ∧ response.observed.Nodup := by
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

/-- A later committed write observes a write that responded before its request. -/
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
        ∧ earlierIndex < requestIndex
        ∧ earlier.tx ∈ later.observed
        ∧ earlier.observed ≠ [] := by
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

/-- An invalid write coexists with a nonempty committed observation that excludes it. -/
lemma invalid_not_observed_by_committed_witness
    : ∃ (trace : GlobalTrace) (state : State) (invalid observer : Nat × Response),
        let (invalidIndex, invalid) := invalid
        let (observerIndex, observer) := observer
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (invalidIndex, invalid) ∈ responsesOf state.history .rw
        ∧ (observerIndex, observer) ∈ committedResponses state.history .rw
        ∧ invalidIndex ≠ observerIndex
        ∧ invalid.txid ∈ statusIDs state.history .invalid
        ∧ observer.observed ≠ []
        ∧ invalid.tx ∉ observer.observed := by
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

/-- Two committed write observations are nonempty and strictly prefix-ordered. -/
lemma committed_rw_serializable_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Nat × Response),
        let (leftIndex, left) := left
        let (rightIndex, right) := right
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (leftIndex, left) ∈ committedResponses state.history .rw
        ∧ (rightIndex, right) ∈ committedResponses state.history .rw
        ∧ leftIndex < rightIndex
        ∧ left.tx ≠ right.tx
        ∧ left.txid.seqno < right.txid.seqno
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed writes are serializable, observe real-time predecessors, and have no duplicates.
For this single-object application, linearizability is equivalent to strict serializability. -/
theorem committed_rw_linearizable
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> (∀ left ∈ committedResponses state.history .rw,
              let (_, left) := left
              ∀ right ∈ committedResponses state.history .rw,
                let (_, right) := right
                left.observed <+: right.observed \/ right.observed <+: left.observed)
            /\ (∀ earlier ∈ committedResponses state.history .rw,
                  let (earlierIndex, earlier) := earlier
                  ∀ request ∈ committedRequests state.history .rw,
                    let (requestIndex, _, requestTx) := request
                    ∀ later ∈ committedResponses state.history .rw,
                      let (_, later) := later
                      later.tx = requestTx
                      -> earlierIndex < requestIndex
                      -> earlier.tx ∈ later.observed)
            /\ (∀ response ∈ responses state.history,
                  let (_, response) := response
                  response.observed.Nodup) := by
  exact Proofs.RealTime.committed_rw_linearizable

/-- Distinct committed writes exercise both serialization and real-time ordering. -/
lemma committed_rw_linearizable_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        let (earlierIndex, earlier) := earlier
        let (laterIndex, later) := later
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (earlierIndex, earlier) ∈ committedResponses state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ committedRequests state.history .rw
        ∧ (laterIndex, later) ∈ committedResponses state.history .rw
        ∧ later.tx = requestTx
        ∧ earlierIndex < requestIndex
        ∧ state.history[commitIndex]? = some (.status earlier.txid .committed)
        ∧ requestIndex < commitIndex
        ∧ (earlier, later)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.observed ≠ []
        ∧ earlier.observed <+: later.observed
        ∧ earlier.observed.length < later.observed.length
        ∧ earlier.tx ∈ later.observed
        ∧ txIDStrictlyLessThan earlier.txid later.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

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

/-- Distinct committed writes have a genuine request-to-response real-time order. -/
lemma committed_rw_ordered_real_time_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        let (earlierIndex, earlier) := earlier
        let (laterIndex, later) := later
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (earlierIndex, earlier) ∈ committedResponses state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ committedRequests state.history .rw
        ∧ (laterIndex, later) ∈ committedResponses state.history .rw
        ∧ later.tx = requestTx
        ∧ earlierIndex < requestIndex
        ∧ state.history[commitIndex]? = some (.status earlier.txid .committed)
        ∧ requestIndex < commitIndex
        ∧ (earlier, later)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.observed ≠ []
        ∧ earlier.observed <+: later.observed
        ∧ earlier.observed.length < later.observed.length
        ∧ earlier.tx ∈ later.observed
        ∧ txIDStrictlyLessThan earlier.txid later.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

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

/-- The sorted committed responses contain an actual adjacent pair with strict growth. -/
lemma committed_rw_ordered_serializable_witness
    : ∃ (trace : GlobalTrace) (state : State) (left right : Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (left, right)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length
        ∧ right.observed.getLast? = some right.tx := by
  exact Proofs.Witnesses.committed_rw_ordered_serializable_witness

/-- CCF's primary consistency claim.
Once a write commits, its execution must be linearizable in transaction-ID order.
The speculative real-time interval runs from the client's request to its initial
response, not to the later committed-status notification. This shorter interval
imposes a stricter ordering than waiting for the client to learn commitment.
The two conjuncts require serializability in transaction-ID order and agreement
between that order and the real-time order of client observations. -/
theorem committed_rw_ordered_spec_linearizable
    : forall (trace : GlobalTrace) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        -> (∀ pair ∈
              (committedRwResponses state.history).zip
                (committedRwResponses state.history).tail,
              let (earlier, later) := pair
              earlier.observed <+: later.observed
              /\ earlier.observed.length < later.observed.length
              /\ later.observed.getLast? = some later.tx)
            /\ (∀ earlier ∈ committedResponses state.history .rw,
                  let (earlierIndex, earlier) := earlier
                  ∀ request ∈ committedRequests state.history .rw,
                    let (requestIndex, _, requestTx) := request
                    ∀ later ∈ committedResponses state.history .rw,
                      let (_, later) := later
                      later.tx = requestTx
                      -> earlierIndex < requestIndex
                      -> txIDStrictlyLessThan earlier.txid later.txid) := by
  exact Proofs.Ordered.committed_rw_ordered_spec_linearizable

/-- One execution supplies both a real-time pair and adjacent ordered committed responses. -/
lemma committed_rw_ordered_spec_linearizable_witness
    : ∃ (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        let (earlierIndex, earlier) := earlier
        let (laterIndex, later) := later
        let (requestIndex, requestKind, requestTx) := request
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (earlierIndex, earlier) ∈ committedResponses state.history .rw
        ∧ (requestIndex, requestKind, requestTx) ∈ committedRequests state.history .rw
        ∧ (laterIndex, later) ∈ committedResponses state.history .rw
        ∧ later.tx = requestTx
        ∧ earlierIndex < requestIndex
        ∧ state.history[commitIndex]? = some (.status earlier.txid .committed)
        ∧ requestIndex < commitIndex
        ∧ (earlier, later)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.observed ≠ []
        ∧ earlier.observed <+: later.observed
        ∧ earlier.observed.length < later.observed.length
        ∧ earlier.tx ∈ later.observed
        ∧ txIDStrictlyLessThan earlier.txid later.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

end consistency.Properties
