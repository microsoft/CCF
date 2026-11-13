module

public import consistency.Properties.History
public import CCF.Execution
public import CCF.Witnessed

import consistency.Proofs.Deadlock
import consistency.Proofs.Invalidation
import consistency.Proofs.Ordering
import consistency.Proofs.Witnesses

@[expose] public section

/-!
The witnessed claims of `consistency/Properties.lean`, each assembled from its safety theorem
and its witness.
`Properties.lean` restates each claim and refers to its proof here.
-/

namespace consistency.Proofs.Claims

open Model
open Properties

/-- A finite or infinite execution of the model, as in `Properties.lean`. -/
abbrev GlobalTrace := CCF.Execution.Trace transitionSystem

/-- The claim `committed_rw_ordered_serializable` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state earlier later ⟨member, adjacent⟩ =>
      Proofs.Ordered.committed_rw_ordered_serializable trace state member (earlier, later)
        adjacent,
    Proofs.Witnesses.committed_rw_ordered_serializable_witness
  ⟩

/-- The claim `committed_rw_ordered_real_time` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state earlierIndex earlier requestIndex requestKind requestTx laterIndex
        later ⟨member, earlierIn, requestIn, laterIn, matching, before⟩ =>
      Proofs.RealTime.committed_rw_ordered_real_time trace state member
        (earlierIndex, earlier) earlierIn (requestIndex, requestKind, requestTx) requestIn
        (laterIndex, later) laterIn matching before,
    let ⟨
      trace,
      state,
      ⟨earlierIndex, earlier⟩,
      ⟨laterIndex, later⟩,
      ⟨requestIndex, requestKind, requestTx⟩,
      holds
    ⟩ :=
      Proofs.Witnesses.real_time_witness
    ⟨
      trace,
      state,
      earlierIndex,
      earlier,
      requestIndex,
      requestKind,
      requestTx,
      laterIndex,
      later,
      holds
    ⟩
  ⟩

/-- The claim `unique_txs` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex left rightIndex right ⟨member, leftIn, rightIn, same⟩ =>
      Proofs.LedgerIdentity.unique_txs trace state member (leftIndex, left) leftIn
        (rightIndex, right) rightIn same,
    let ⟨trace, state, ⟨leftIndex, left⟩, ⟨rightIndex, right⟩, holds⟩ :=
      Proofs.Witnesses.unique_txs_witness
    ⟨trace, state, leftIndex, left, rightIndex, right, holds⟩
  ⟩

/-- The claim `same_observations` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex left rightIndex right ⟨member, leftIn, rightIn, same⟩ =>
      Proofs.LedgerIdentity.same_observations trace state member (leftIndex, left) leftIn
        (rightIndex, right) rightIn same,
    let ⟨trace, state, ⟨leftIndex, left⟩, ⟨rightIndex, right⟩, holds⟩ :=
      Proofs.Witnesses.same_observations_witness
    ⟨trace, state, leftIndex, left, rightIndex, right, holds⟩
  ⟩

/-- The claim `unique_tx_requests` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex leftKind leftTx rightIndex rightKind rightTx
        ⟨member, leftIn, rightIn, distinct⟩ =>
      Proofs.History.unique_tx_requests trace state member (leftIndex, leftKind, leftTx)
        leftIn (rightIndex, rightKind, rightTx) rightIn distinct,
    let ⟨
      trace,
      state,
      ⟨leftIndex, leftKind, leftTx⟩,
      ⟨rightIndex, rightKind, rightTx⟩,
      holds
    ⟩ :=
      Proofs.Witnesses.unique_tx_requests_witness
    ⟨trace, state, leftIndex, leftKind, leftTx, rightIndex, rightKind, rightTx, holds⟩
  ⟩

/-- The claim `unique_tx_ids` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex left rightIndex right ⟨member, leftIn, rightIn, same⟩ =>
      Proofs.Responses.unique_tx_ids trace state member (leftIndex, left) leftIn
        (rightIndex, right) rightIn same,
    let ⟨trace, state, ⟨leftIndex, left⟩, ⟨rightIndex, right⟩, holds⟩ :=
      Proofs.Witnesses.unique_tx_ids_witness
    ⟨trace, state, leftIndex, left, rightIndex, right, holds⟩
  ⟩

/-- The claim `unique_seq_nums_committed` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex left rightIndex right ⟨member, leftIn, rightIn, same⟩ =>
      Proofs.Commitment.unique_seq_nums_committed trace state member (leftIndex, left)
        leftIn (rightIndex, right) rightIn same,
    let ⟨trace, state, ⟨leftIndex, left⟩, ⟨rightIndex, right⟩, holds⟩ :=
      Proofs.Witnesses.unique_seq_nums_committed_witness
    ⟨trace, state, leftIndex, left, rightIndex, right, holds⟩
  ⟩

/-- The claim `committed_or_invalid` of `Properties.lean`. -/
theorem committed_or_invalid
    : witnessed% forall (trace : GlobalTrace) (state : State) (txid : TxID),
                  {
                    pre := state ∈ trace /\ txid ∈ statusIDs state.history .committed
                    post := txid ∉ statusIDs state.history .invalid
                  } :=
  ⟨
    fun trace state txid ⟨member, committed⟩ =>
      Proofs.Statuses.committed_or_invalid trace state member txid committed,
    Proofs.Witnesses.committed_or_invalid_witness
  ⟩

/-- The claim `once_committed_prev_committed` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftTxID leftStatus rightTxID rightStatus
        ⟨member, leftIn, rightIn, committed, sameView, earlier⟩ =>
      Proofs.Statuses.once_committed_prev_committed trace state member
        (leftTxID, leftStatus) leftIn (rightTxID, rightStatus) rightIn committed sameView
        earlier,
    let ⟨trace, state, ⟨leftTxID, leftStatus⟩, ⟨rightTxID, rightStatus⟩, holds⟩ :=
      Proofs.Witnesses.once_committed_prev_committed_witness
    ⟨trace, state, leftTxID, leftStatus, rightTxID, rightStatus, holds⟩
  ⟩

/-- The claim `once_committed_next_invalid` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftTxID leftStatus rightTxID rightStatus
        ⟨member, leftIn, rightIn, committed, later, older⟩ =>
      Proofs.Statuses.once_committed_next_invalid trace state member
        (leftTxID, leftStatus) leftIn (rightTxID, rightStatus) rightIn committed later
        older,
    let ⟨trace, state, ⟨leftTxID, leftStatus⟩, ⟨rightTxID, rightStatus⟩, holds⟩ :=
      Proofs.Witnesses.once_committed_next_invalid_witness
    ⟨trace, state, leftTxID, leftStatus, rightTxID, rightStatus, holds⟩
  ⟩

/-- The claim `once_invalid_next_invalid` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftTxID leftStatus rightTxID rightStatus
        ⟨member, leftIn, rightIn, invalid, sameView, later⟩ =>
      Proofs.Statuses.once_invalid_next_invalid trace state member (leftTxID, leftStatus)
        leftIn (rightTxID, rightStatus) rightIn invalid sameView later,
    let ⟨trace, state, ⟨leftTxID, leftStatus⟩, ⟨rightTxID, rightStatus⟩, holds⟩ :=
      Proofs.Witnesses.once_invalid_next_invalid_witness
    ⟨trace, state, leftTxID, leftStatus, rightTxID, rightStatus, holds⟩
  ⟩

/-- The claim `only_observe_sent_requests` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state responseIndex response tx ⟨member, responseIn, observed⟩ =>
      Proofs.Observations.only_observe_sent_requests trace state member
        (responseIndex, response) responseIn tx observed,
    let ⟨trace, state, ⟨responseIndex, response⟩, tx, holds⟩ :=
      Proofs.Witnesses.only_observe_sent_requests_witness
    ⟨trace, state, responseIndex, response, tx, holds⟩
  ⟩

/-- The claim `at_most_once_observed` of `Properties.lean`. -/
theorem at_most_once_observed
    : witnessed% forall (trace : GlobalTrace) (state : State) (responseIndex : Nat)
                        (response : Response),
                  {
                    pre :=
                      state ∈ trace /\ (responseIndex, response) ∈ responses state.history
                    post := response.observed.Nodup
                  } :=
  ⟨
    fun trace state responseIndex response ⟨member, responseIn⟩ =>
      Proofs.Observations.at_most_once_observed trace state member
        (responseIndex, response) responseIn,
    let ⟨trace, state, ⟨responseIndex, response⟩, holds⟩ :=
      Proofs.Witnesses.at_most_once_observed_witness
    ⟨trace, state, responseIndex, response, holds⟩
  ⟩

/-- The claim `all_committed_observed` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state earlierIndex earlier requestIndex requestKind requestTx laterIndex
        later ⟨member, earlierIn, requestIn, laterIn, matching, before⟩ =>
      Proofs.RealTime.all_committed_observed trace state member (earlierIndex, earlier)
        earlierIn (requestIndex, requestKind, requestTx) requestIn (laterIndex, later)
        laterIn matching before,
    let ⟨
      trace,
      state,
      ⟨earlierIndex, earlier⟩,
      ⟨laterIndex, later⟩,
      ⟨requestIndex, requestKind, requestTx⟩,
      holds
    ⟩ :=
      Proofs.Witnesses.real_time_witness
    ⟨
      trace,
      state,
      earlierIndex,
      earlier,
      requestIndex,
      requestKind,
      requestTx,
      laterIndex,
      later,
      holds
    ⟩
  ⟩

/-- The claim `invalid_not_observed_by_committed` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state invalidIndex invalid observerIndex observer
        ⟨member, invalidIn, observerIn, distinct, reported⟩ =>
      Proofs.InvalidObservations.invalid_not_observed_by_committed trace state member
        (invalidIndex, invalid) invalidIn (observerIndex, observer) observerIn distinct
        reported,
    let ⟨trace, state, ⟨invalidIndex, invalid⟩, ⟨observerIndex, observer⟩, holds⟩ :=
      Proofs.Witnesses.invalid_not_observed_by_committed_witness
    ⟨trace, state, invalidIndex, invalid, observerIndex, observer, holds⟩
  ⟩

/-- The claim `committed_rw_serializable` of `Properties.lean`. -/
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
                  } :=
  ⟨
    fun trace state leftIndex left rightIndex right ⟨member, leftIn, rightIn⟩ =>
      Proofs.Commitment.committed_rw_serializable trace state member (leftIndex, left)
        leftIn (rightIndex, right) rightIn,
    let ⟨trace, state, ⟨leftIndex, left⟩, ⟨rightIndex, right⟩, holds⟩ :=
      Proofs.Witnesses.write_pair_witness
    ⟨trace, state, leftIndex, left, rightIndex, right, holds⟩
  ⟩

end consistency.Proofs.Claims
