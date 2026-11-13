module

public import consistency.Properties.History
public import CCF.Execution
public import CCF.Witnessed

import consistency.Proofs.Claims
import consistency.Proofs.Deadlock
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

abbrev GlobalTrace := CCF.Execution.Trace transitionSystem

/-- Every reachable state has an enabled action. -/
theorem deadlock_free : transitionSystem.DeadlockFree := by
  exact Proofs.deadlock_free

/-- Witness: the initial state is reachable. -/
theorem deadlock_free_witness : exists state, transitionSystem.Reachable state := by
  exact Proofs.deadlock_free_witness

/-- Adjacent TxID-ordered committed responses strictly extend.
The later observation ends with its own write; intervening ledger writes need not
have responses with explicitly received committed statuses.
Witness: the sorted committed responses contain an adjacent pair. -/
theorem committed_rw_ordered_serializable
    : witnessed% forall (trace : GlobalTrace) (state : State) (earlier later : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (earlier, later)
                          ∈ (committedRwResponses state.history).zip
                              (committedRwResponses state.history).tail
                    post :=
                      earlier.observed <+: later.observed
                      /\ earlier.observed.length < later.observed.length
                      /\ later.observed.getLast? = some later.tx
                  } := by
  exact Proofs.Claims.committed_rw_ordered_serializable

/-- TxID order respects request-to-response intervals.
Witness: committed writes and a matching request satisfy the real-time antecedents. -/
theorem committed_rw_ordered_real_time
    : witnessed% forall (trace : GlobalTrace) (state : State) (earlierIndex : Nat)
                        (earlier : Response) (requestIndex : Nat) (requestKind : TxType)
                        (requestTx : TxContent) (laterIndex : Nat) (later : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (earlierIndex, earlier) ∈ committedResponses state.history .rw
                      /\ (requestIndex, requestKind, requestTx)
                          ∈ committedRequests state.history .rw
                      /\ (laterIndex, later) ∈ committedResponses state.history .rw
                      /\ later.tx = requestTx
                      /\ earlierIndex < requestIndex
                    post := txIDStrictlyLessThan earlier.txid later.txid
                  } := by
  exact Proofs.Claims.committed_rw_ordered_real_time

/-- Responses of either kind follow matching requests.
Matching uses request IDs; distinct reads may return the same transaction ID. -/
theorem all_received_is_first_sent
    : forall (trace : GlobalTrace) (state : State),
        (state ∈ trace)
        -> forall (kind : TxType),
            ∀ response ∈ responsesOf state.history kind,
              let (responseIndex, response) := response
              ∃ request ∈ requests state.history,
                let (requestIndex, requestKind, requestTx) := request
                requestIndex < responseIndex
                /\ (requestKind, requestTx) = (kind, response.tx) := by
  exact Proofs.History.all_received_is_first_sent

/-- Both response kinds occur in the same execution. -/
theorem all_received_is_first_sent_witness
    : ∃ (trace : GlobalTrace) (state : State) (write read : Nat × Response),
        let (writeIndex, write) := write
        let (readIndex, read) := read
        state ∈ trace
        ∧ (writeIndex, write) ∈ responsesOf state.history .rw
        ∧ (readIndex, read) ∈ responsesOf state.history .ro := by
  exact Proofs.Witnesses.all_received_witness

/-- A transaction ID identifies at most one write.
This uniqueness does not apply to reads, which can observe the same ledger position.
Witness: write responses with matching transaction IDs occur in a valid execution. -/
theorem unique_txs
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (left : Response) (rightIndex : Nat) (right : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, left) ∈ responsesOf state.history .rw
                      /\ (rightIndex, right) ∈ responsesOf state.history .rw
                      /\ left.txid = right.txid
                    post := left.tx = right.tx
                  } := by
  exact Proofs.Claims.unique_txs

/-- Equal transaction IDs give equal observations.
Witness: responses with matching transaction IDs occur in a valid execution. -/
theorem same_observations
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (left : Response) (rightIndex : Nat) (right : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, left) ∈ responses state.history
                      /\ (rightIndex, right) ∈ responses state.history
                      /\ left.txid = right.txid
                    post := left.observed = right.observed
                  } := by
  exact Proofs.Claims.same_observations

/-- Requests have distinct IDs across both transaction kinds.
Witness: requests at distinct history positions occur in a valid execution. -/
theorem unique_tx_requests
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (leftKind : TxType) (leftTx : TxContent) (rightIndex : Nat)
                        (rightKind : TxType) (rightTx : TxContent),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, leftKind, leftTx) ∈ requests state.history
                      /\ (rightIndex, rightKind, rightTx) ∈ requests state.history
                      /\ leftIndex ≠ rightIndex
                    post := leftTx ≠ rightTx
                  } := by
  exact Proofs.Claims.unique_tx_requests

/-- Each request receives a unique transaction ID.
Witness: responses with matching request IDs occur in a valid execution. -/
theorem unique_tx_ids
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (left : Response) (rightIndex : Nat) (right : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, left) ∈ responses state.history
                      /\ (rightIndex, right) ∈ responses state.history
                      /\ left.tx = right.tx
                    post := left.txid = right.txid
                  } := by
  exact Proofs.Claims.unique_tx_ids

/-- Committed write sequence numbers are unique.
This is weaker than uniqueness for all writes and excludes disaster recovery,
which is outside this model.
Witness: committed write responses with matching sequence numbers occur in a valid
execution. -/
theorem unique_seq_nums_committed
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (left : Response) (rightIndex : Nat) (right : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, left) ∈ committedResponses state.history .rw
                      /\ (rightIndex, right) ∈ committedResponses state.history .rw
                      /\ left.txid.seqno = right.txid.seqno
                    post := left.tx = right.tx
                  } := by
  exact Proofs.Claims.unique_seq_nums_committed

/-- Committed and invalid statuses are disjoint.
Witness: a committed status occurs in a valid execution. -/
theorem committed_or_invalid
    : witnessed% forall (trace : GlobalTrace) (state : State) (txid : TxID),
                  {
                    pre := state ∈ trace /\ txid ∈ statusIDs state.history .committed
                    post := txid ∉ statusIDs state.history .invalid
                  } := by
  exact Proofs.Claims.committed_or_invalid

/-- Reported statuses in a committed prefix agree.
Witness: reported statuses satisfy the same-view committed-prefix antecedents. -/
theorem once_committed_prev_committed
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftTxID : TxID)
                        (leftStatus : Status) (rightTxID : TxID) (rightStatus : Status),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftTxID, leftStatus) ∈ statuses state.history
                      /\ (rightTxID, rightStatus) ∈ statuses state.history
                      /\ leftStatus = .committed
                      /\ leftTxID.view = rightTxID.view
                      /\ rightTxID.seqno ≤ leftTxID.seqno
                    post := rightStatus = .committed
                  } := by
  exact Proofs.Claims.once_committed_prev_committed

/-- Older-view conflicting suffixes are invalid.
Witness: reported statuses satisfy the older-view conflicting-suffix antecedents. -/
theorem once_committed_next_invalid
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftTxID : TxID)
                        (leftStatus : Status) (rightTxID : TxID) (rightStatus : Status),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftTxID, leftStatus) ∈ statuses state.history
                      /\ (rightTxID, rightStatus) ∈ statuses state.history
                      /\ leftStatus = .committed
                      /\ leftTxID.seqno ≤ rightTxID.seqno
                      /\ rightTxID.view < leftTxID.view
                    post := rightStatus = .invalid
                  } := by
  exact Proofs.Claims.once_committed_next_invalid

/-- Reported statuses in an invalid suffix agree.
Witness: reported statuses satisfy the same-view invalid-suffix antecedents. -/
theorem once_invalid_next_invalid
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftTxID : TxID)
                        (leftStatus : Status) (rightTxID : TxID) (rightStatus : Status),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftTxID, leftStatus) ∈ statuses state.history
                      /\ (rightTxID, rightStatus) ∈ statuses state.history
                      /\ leftStatus = .invalid
                      /\ leftTxID.view = rightTxID.view
                      /\ leftTxID.seqno ≤ rightTxID.seqno
                    post := rightStatus = .invalid
                  } := by
  exact Proofs.Claims.once_invalid_next_invalid

/-- Observations contain only earlier requested writes.
Witness: an observed write populates the observation-membership antecedent. -/
theorem only_observe_sent_requests
    : witnessed% forall (trace : GlobalTrace) (state : State) (responseIndex : Nat)
                        (response : Response) (tx : TxContent),
                  {
                    pre :=
                      state ∈ trace
                      /\ (responseIndex, response) ∈ responses state.history
                      /\ tx ∈ response.observed
                    post :=
                      ∃ request ∈ requests state.history,
                        let (requestIndex, requestKind, requestTx) := request
                        requestIndex < responseIndex
                        /\ (requestKind, requestTx) = (.rw, tx)
                  } := by
  exact Proofs.Claims.only_observe_sent_requests

/-- Observations contain no duplicate writes.
Witness: a response populates the observation domain. -/
theorem at_most_once_observed
    : witnessed% forall (trace : GlobalTrace) (state : State) (responseIndex : Nat)
                        (response : Response),
                  {
                    pre :=
                      state ∈ trace /\ (responseIndex, response) ∈ responses state.history
                    post := response.observed.Nodup
                  } := by
  exact Proofs.Claims.at_most_once_observed

/-- Committed writes observe real-time predecessor writes.
Once a write is known committed, real-time ordering uses its original response,
not the later event at which the client learns it committed.
Witness: committed writes and a matching request satisfy the real-time antecedents. -/
theorem all_committed_observed
    : witnessed% forall (trace : GlobalTrace) (state : State) (earlierIndex : Nat)
                        (earlier : Response) (requestIndex : Nat) (requestKind : TxType)
                        (requestTx : TxContent) (laterIndex : Nat) (later : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (earlierIndex, earlier) ∈ committedResponses state.history .rw
                      /\ (requestIndex, requestKind, requestTx)
                          ∈ committedRequests state.history .rw
                      /\ (laterIndex, later) ∈ committedResponses state.history .rw
                      /\ later.tx = requestTx
                      /\ earlierIndex < requestIndex
                    post := earlier.tx ∈ later.observed
                  } := by
  exact Proofs.Claims.all_committed_observed

/-- Committed writes exclude invalid writes.
Witness: an invalid write and a different committed response populate the exclusion
antecedents. -/
theorem invalid_not_observed_by_committed
    : witnessed% forall (trace : GlobalTrace) (state : State) (invalidIndex : Nat)
                        (invalid : Response) (observerIndex : Nat) (observer : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (invalidIndex, invalid) ∈ responsesOf state.history .rw
                      /\ (observerIndex, observer) ∈ committedResponses state.history .rw
                      /\ invalidIndex ≠ observerIndex
                      /\ invalid.txid ∈ statusIDs state.history .invalid
                    post := invalid.tx ∉ observer.observed
                  } := by
  exact Proofs.Claims.invalid_not_observed_by_committed

/-- Committed write histories are serializable.
Witness: committed write responses populate the serialization domain. -/
theorem committed_rw_serializable
    : witnessed% forall (trace : GlobalTrace) (state : State) (leftIndex : Nat)
                        (left : Response) (rightIndex : Nat) (right : Response),
                  {
                    pre :=
                      state ∈ trace
                      /\ (leftIndex, left) ∈ committedResponses state.history .rw
                      /\ (rightIndex, right) ∈ committedResponses state.history .rw
                    post :=
                      left.observed <+: right.observed \/ right.observed <+: left.observed
                  } := by
  exact Proofs.Claims.committed_rw_serializable

end consistency.Properties
