module

public import consistency.Properties.History
public import CCF.Execution

import consistency.Proofs.Responses
import consistency.Proofs.Reads
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
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responsesOf state.history .rw,
            ∃ request ∈ requests state.history,
              request.1 < response.1 /\ request.2 = (.rw, response.2.tx) := by
  exact Proofs.History.all_rw_received_is_first_sent

/-- A write request receives a response with a nonempty observation. -/
lemma all_rw_received_is_first_sent_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent)),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ response ∈ responsesOf state.history .rw
        ∧ request ∈ requests state.history
        ∧ request.1 < response.1
        ∧ request.2 = (.rw, response.2.tx)
        ∧ response.2.observed ≠ [] := by
  exact Proofs.Witnesses.received_witness .rw

/-- Read-only responses follow an associated request.
Multiple read requests can receive the same transaction ID; matching is by request,
not by uniqueness of the returned ledger position. -/
theorem all_ro_received_is_first_sent
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responsesOf state.history .ro,
            ∃ request ∈ requests state.history,
              request.1 < response.1 /\ request.2 = (.ro, response.2.tx) := by
  exact Proofs.History.all_ro_received_is_first_sent

/-- A read request receives a response with a nonempty observation. -/
lemma all_ro_received_is_first_sent_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent)),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ response ∈ responsesOf state.history .ro
        ∧ request ∈ requests state.history
        ∧ request.1 < response.1
        ∧ request.2 = (.ro, response.2.tx)
        ∧ response.2.observed ≠ [] := by
  exact Proofs.Witnesses.received_witness .ro

/-- Responses of either kind follow requests. -/
theorem all_received_is_first_sent
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> forall (kind : TxType),
            ∀ response ∈ responsesOf state.history kind,
              ∃ request ∈ requests state.history,
                request.1 < response.1 /\ request.2 = (kind, response.2.tx) := by
  exact Proofs.History.all_received_is_first_sent

/-- Both response kinds occur in the same execution with nonempty observations. -/
lemma all_received_is_first_sent_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (write read : Nat × Response),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ write ∈ responsesOf state.history .rw
        ∧ read ∈ responsesOf state.history .ro
        ∧ write.2.observed ≠ []
        ∧ read.2.observed ≠ [] := by
  exact Proofs.Witnesses.all_received_witness

/-- A transaction ID identifies at most one write.
This uniqueness does not apply to reads, which can observe the same ledger position. -/
theorem unique_txs
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responsesOf state.history .rw,
            ∀ right ∈ responsesOf state.history .rw,
              left.2.txid = right.2.txid -> left.2.tx = right.2.tx := by
  exact Proofs.LedgerIdentity.unique_txs

/-- Two distinct committed writes populate the uniqueness domain.
Matching-ID comparisons include each actual response compared with itself. -/
lemma unique_txs_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Equal transaction IDs give equal observations. -/
theorem same_observations
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.txid = right.2.txid -> left.2.observed = right.2.observed := by
  exact Proofs.LedgerIdentity.same_observations

/-- Distinct read requests receive the same transaction ID and nonempty observation. -/
lemma same_observations_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ responsesOf state.history .ro
        ∧ right ∈ responsesOf state.history .ro
        ∧ left.1 ≠ right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid = right.2.txid
        ∧ left.2.observed = right.2.observed
        ∧ left.2.observed ≠ [] := by
  exact Proofs.Witnesses.same_observations_witness

/-- Requests have distinct IDs across both transaction kinds. -/
theorem unique_tx_requests
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ requests state.history,
            ∀ right ∈ requests state.history,
              left.1 ≠ right.1 -> left.2.2 ≠ right.2.2 := by
  exact Proofs.History.unique_tx_requests

/-- A read request and a write request have distinct positions and request IDs. -/
lemma unique_tx_requests_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × (TxType × TxContent)),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ requests state.history
        ∧ right ∈ requests state.history
        ∧ left.1 ≠ right.1
        ∧ left.2.1 ≠ right.2.1
        ∧ left.2.2 ≠ right.2.2 := by
  exact Proofs.Witnesses.unique_tx_requests_witness

/-- Each request receives a unique transaction ID. -/
theorem unique_tx_ids
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.tx = right.2.tx -> left.2.txid = right.2.txid := by
  exact Proofs.Responses.unique_tx_ids

/-- Two real requests receive distinct write IDs; matching-request cases are reflexive. -/
lemma unique_tx_ids_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Single-node write sequence numbers are unique. -/
theorem unique_seq_nums
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        -> ∀ left ∈ responsesOf state.history .rw,
            ∀ right ∈ responsesOf state.history .rw,
              left.2.txid.seqno = right.2.txid.seqno -> left.2.tx = right.2.tx := by
  exact Proofs.SingleNode.unique_seq_nums

/-- Two single-node writes occupy different positions; matching-position cases are reflexive. -/
lemma unique_seq_nums_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed write sequence numbers are unique.
This is weaker than uniqueness for all writes and excludes disaster recovery,
which is outside this model. -/
theorem unique_seq_nums_committed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ committedResponses state.history .rw,
            ∀ right ∈ committedResponses state.history .rw,
              left.2.txid.seqno = right.2.txid.seqno -> left.2.tx = right.2.tx := by
  exact Proofs.Commitment.unique_seq_nums_committed

/-- Two committed writes occupy different positions; matching-position cases are reflexive. -/
lemma unique_seq_nums_committed_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed and invalid statuses are disjoint. -/
theorem committed_or_invalid
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  exact Proofs.Statuses.committed_or_invalid

/-- An execution reports both a committed write and a different invalid write. -/
lemma committed_or_invalid_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (committed invalid : TxID),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ committed ∈ statusIDs state.history .committed
        ∧ invalid ∈ statusIDs state.history .invalid
        ∧ committed ≠ invalid
        ∧ committed ∉ statusIDs state.history .invalid := by
  exact Proofs.Witnesses.committed_or_invalid_witness

/-- Reported statuses in a committed prefix agree. -/
theorem once_committed_prev_committed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            ∀ right ∈ statuses state.history,
              left.2 = .committed
              -> left.1.view = right.1.view
              -> right.1.seqno ≤ left.1.seqno
              -> right.2 = .committed := by
  exact Proofs.Statuses.once_committed_prev_committed

/-- Distinct positions in the same committed prefix have reported committed statuses. -/
lemma once_committed_prev_committed_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : TxID × Status),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.view = right.1.view
        ∧ right.1.seqno < left.1.seqno
        ∧ right.2 = .committed := by
  exact Proofs.Witnesses.once_committed_prev_committed_witness

/-- Older-view conflicting suffixes are invalid. -/
theorem once_committed_next_invalid
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            ∀ right ∈ statuses state.history,
              left.2 = .committed
              -> left.1.seqno ≤ right.1.seqno
              -> right.1.view < left.1.view
              -> right.2 = .invalid := by
  exact Proofs.Statuses.once_committed_next_invalid

/-- A newer-view commitment coexists with an invalid older-view suffix. -/
lemma once_committed_next_invalid_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : TxID × Status),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.seqno < right.1.seqno
        ∧ right.1.view < left.1.view
        ∧ right.2 = .invalid := by
  exact Proofs.Witnesses.once_committed_next_invalid_witness

/-- Reported statuses in an invalid suffix agree. -/
theorem once_invalid_next_invalid
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ statuses state.history,
            ∀ right ∈ statuses state.history,
              left.2 = .invalid
              -> left.1.view = right.1.view
              -> left.1.seqno ≤ right.1.seqno
              -> right.2 = .invalid := by
  exact Proofs.Statuses.once_invalid_next_invalid

/-- Distinct positions in the same invalid suffix have reported invalid statuses. -/
lemma once_invalid_next_invalid_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : TxID × Status),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .invalid
        ∧ left.1.view = right.1.view
        ∧ left.1.seqno < right.1.seqno
        ∧ right.2 = .invalid := by
  exact Proofs.Witnesses.once_invalid_next_invalid_witness

/-- All three status-propagation claims. -/
theorem committed_or_invalid_strong
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> (∀ left ∈ statuses state.history,
            ∀ right ∈ statuses state.history,
              left.2 = .committed
              -> left.1.view = right.1.view
              -> right.1.seqno ≤ left.1.seqno
              -> right.2 = .committed)
            /\ (∀ left ∈ statuses state.history,
                ∀ right ∈ statuses state.history,
                  left.2 = .committed
                  -> left.1.seqno ≤ right.1.seqno
                  -> right.1.view < left.1.view
                  -> right.2 = .invalid)
            /\ (∀ left ∈ statuses state.history,
                ∀ right ∈ statuses state.history,
                  left.2 = .invalid
                  -> left.1.view = right.1.view
                  -> left.1.seqno ≤ right.1.seqno
                  -> right.2 = .invalid) := by
  exact Proofs.Statuses.committed_or_invalid_strong

/-- One execution activates all three propagation clauses at distinct positions. -/
lemma committed_or_invalid_strong_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlyCommit lateCommit earlyInvalid lateInvalid : TxID),
        trace.Valid (transitionSystem config)
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
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responses state.history,
            ∀ tx ∈ response.2.observed,
              ∃ request ∈ requests state.history,
                request.1 < response.1 /\ request.2 = (.rw, tx) := by
  exact Proofs.Observations.only_observe_sent_requests

/-- A real read observes a write requested earlier in the execution. -/
lemma only_observe_sent_requests_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent))
        (tx : TxContent),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ response ∈ responses state.history
        ∧ response.2.kind = .ro
        ∧ tx ∈ response.2.observed
        ∧ request ∈ requests state.history
        ∧ request.1 < response.1
        ∧ request.2 = (.rw, tx) := by
  exact Proofs.Witnesses.only_observe_sent_requests_witness

/-- Observations contain no duplicate writes. -/
theorem at_most_once_observed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responses state.history, response.2.observed.Nodup := by
  exact Proofs.Observations.at_most_once_observed

/-- An observation contains at least two writes without duplicates. -/
lemma at_most_once_observed_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (response : Nat × Response),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ response ∈ responses state.history
        ∧ 2 ≤ response.2.observed.length
        ∧ response.2.observed.Nodup := by
  exact Proofs.Witnesses.at_most_once_observed_witness

/-- Committed writes observe real-time predecessor writes.
Once a write is known committed, real-time ordering uses its original response,
not the later event at which the client learns it committed. -/
theorem all_committed_observed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ earlier ∈ committedResponses state.history .rw,
            ∀ request ∈ committedRequests state.history .rw,
            ∀ later ∈ committedResponses state.history .rw,
              later.2.tx = request.2.2
              -> earlier.1 < request.1
              -> earlier.2.tx ∈ later.2.observed := by
  exact Proofs.RealTime.all_committed_observed

/-- A later committed write observes a write that responded before its request. -/
lemma all_committed_observed_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ earlier.2.observed ≠ [] := by
  exact Proofs.Witnesses.real_time_witness .rw

/-- Single-node committed reads observe predecessor writes. -/
theorem all_committed_observed_ro
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        -> ∀ earlier ∈ committedResponses state.history .rw,
            ∀ request ∈ committedRequests state.history .ro,
            ∀ later ∈ committedResponses state.history .ro,
              later.2.tx = request.2.2
              -> earlier.1 < request.1
              -> earlier.2.tx ∈ later.2.observed := by
  exact Proofs.Reads.all_committed_observed_ro

/-- A committed single-node read observes a write that responded before its request. -/
lemma all_committed_observed_ro_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .ro
        ∧ later ∈ committedResponses state.history .ro
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ earlier.2.observed ≠ [] := by
  exact Proofs.Witnesses.real_time_witness .ro

/-- Single-node writes exclude invalid writes.
This is vacuous for a single node, where views never change and writes cannot
be invalidated; speculative multi-node writes need not satisfy it. -/
theorem invalid_not_observed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        -> ∀ invalid ∈ responsesOf state.history .rw,
            ∀ observer ∈ responsesOf state.history .rw,
              invalid.1 ≠ observer.1
              -> invalid.2.txid ∈ statusIDs state.history .invalid
              -> invalid.2.tx ∉ observer.2.observed := by
  exact Proofs.Structural.invalid_not_observed

/-- No invalid-status antecedent can occur in a valid single-node execution. -/
lemma invalid_not_observed_vacuous
    : ∀ (config : Config) (trace : GlobalTrace) (state : State),
        (config.multiNode = false ∧ trace.Valid (transitionSystem config) ∧ state ∈ trace)
        → statusIDs state.history .invalid = [] := by
  exact Proofs.Witnesses.invalid_not_observed_vacuous

/-- Committed writes exclude invalid writes. -/
theorem invalid_not_observed_by_committed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ invalid ∈ responsesOf state.history .rw,
            ∀ observer ∈ committedResponses state.history .rw,
              invalid.1 ≠ observer.1
              -> invalid.2.txid ∈ statusIDs state.history .invalid
              -> invalid.2.tx ∉ observer.2.observed := by
  exact Proofs.InvalidObservations.invalid_not_observed_by_committed

/-- An invalid write coexists with a nonempty committed observation that excludes it. -/
lemma invalid_not_observed_by_committed_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (invalid observer : Nat × Response),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ invalid ∈ responsesOf state.history .rw
        ∧ observer ∈ committedResponses state.history .rw
        ∧ invalid.1 ≠ observer.1
        ∧ invalid.2.txid ∈ statusIDs state.history .invalid
        ∧ observer.2.observed ≠ []
        ∧ invalid.2.tx ∉ observer.2.observed := by
  exact Proofs.Witnesses.invalid_not_observed_by_committed_witness

/-- Single-node speculative write histories are serializable.
Serializability ignores event order, transaction IDs, and commitment: observations
must admit a common execution order. If one response observes A before B, every
response containing both must agree; each write also observes itself. -/
theorem rw_serializable
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (config.multiNode = false
          /\ trace.Valid (transitionSystem config)
          /\ state ∈ trace)
        -> ∀ left ∈ responsesOf state.history .rw,
            ∀ right ∈ responsesOf state.history .rw,
              left.2.observed <+: right.2.observed
              \/ right.2.observed <+: left.2.observed := by
  exact Proofs.SingleNode.rw_serializable

/-- Two single-node write observations are nonempty and strictly prefix-ordered. -/
lemma rw_serializable_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed write histories are serializable. -/
theorem committed_rw_serializable
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ committedResponses state.history .rw,
            ∀ right ∈ committedResponses state.history .rw,
              left.2.observed <+: right.2.observed
              \/ right.2.observed <+: left.2.observed := by
  exact Proofs.Commitment.committed_rw_serializable

/-- Two committed write observations are nonempty and strictly prefix-ordered. -/
lemma committed_rw_serializable_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (left right : Nat × Response),
        config.multiNode = false
        ∧ trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  exact Proofs.Witnesses.write_pair_witness

/-- Committed writes are serializable, observe real-time predecessors, and have no duplicates.
For this single-object application, linearizability is equivalent to strict serializability. -/
theorem committed_rw_linearizable
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> (∀ left ∈ committedResponses state.history .rw,
            ∀ right ∈ committedResponses state.history .rw,
              left.2.observed <+: right.2.observed
              \/ right.2.observed <+: left.2.observed)
            /\ (∀ earlier ∈ committedResponses state.history .rw,
                ∀ request ∈ committedRequests state.history .rw,
                ∀ later ∈ committedResponses state.history .rw,
                  later.2.tx = request.2.2
                  -> earlier.1 < request.1
                  -> earlier.2.tx ∈ later.2.observed)
            /\ (∀ response ∈ responses state.history, response.2.observed.Nodup) := by
  exact Proofs.RealTime.committed_rw_linearizable

/-- Distinct committed writes exercise both serialization and real-time ordering. -/
lemma committed_rw_linearizable_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ state.history[commitIndex]? = some (.status earlier.2.txid .committed)
        ∧ request.1 < commitIndex
        ∧ (earlier.2, later.2)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.2.observed ≠ []
        ∧ earlier.2.observed <+: later.2.observed
        ∧ earlier.2.observed.length < later.2.observed.length
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

/-- TxID order respects request-to-response intervals. -/
theorem committed_rw_ordered_real_time
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ earlier ∈ committedResponses state.history .rw,
            ∀ request ∈ committedRequests state.history .rw,
            ∀ later ∈ committedResponses state.history .rw,
              later.2.tx = request.2.2
              -> earlier.1 < request.1
              -> txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  exact Proofs.RealTime.committed_rw_ordered_real_time

/-- Distinct committed writes have a genuine request-to-response real-time order. -/
lemma committed_rw_ordered_real_time_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ state.history[commitIndex]? = some (.status earlier.2.txid .committed)
        ∧ request.1 < commitIndex
        ∧ (earlier.2, later.2)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.2.observed ≠ []
        ∧ earlier.2.observed <+: later.2.observed
        ∧ earlier.2.observed.length < later.2.observed.length
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

/-- Adjacent TxID-ordered committed responses strictly extend.
The later observation ends with its own write; intervening ledger writes need not
have responses with explicitly received committed statuses. -/
theorem committed_rw_ordered_serializable
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ pair ∈
            (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail,
            pair.1.observed <+: pair.2.observed
            /\ pair.1.observed.length < pair.2.observed.length
            /\ pair.2.observed.getLast? = some pair.2.tx := by
  exact Proofs.Ordered.committed_rw_ordered_serializable

/-- The sorted committed responses contain an actual adjacent pair with strict growth. -/
lemma committed_rw_ordered_serializable_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State) (left right : Response),
        trace.Valid (transitionSystem config)
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
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> (∀ pair ∈
              (committedRwResponses state.history).zip
                (committedRwResponses state.history).tail,
              pair.1.observed <+: pair.2.observed
              /\ pair.1.observed.length < pair.2.observed.length
              /\ pair.2.observed.getLast? = some pair.2.tx)
            /\ (∀ earlier ∈ committedResponses state.history .rw,
                ∀ request ∈ committedRequests state.history .rw,
                ∀ later ∈ committedResponses state.history .rw,
                  later.2.tx = request.2.2
                  -> earlier.1 < request.1
                  -> txIDStrictlyLessThan earlier.2.txid later.2.txid) := by
  exact Proofs.Ordered.committed_rw_ordered_spec_linearizable

/-- One execution supplies both a real-time pair and adjacent ordered committed responses. -/
lemma committed_rw_ordered_spec_linearizable_witness
    : ∃ (config : Config) (trace : GlobalTrace) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        trace.Valid (transitionSystem config)
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ state.history[commitIndex]? = some (.status earlier.2.txid .committed)
        ∧ request.1 < commitIndex
        ∧ (earlier.2, later.2)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ earlier.2.observed ≠ []
        ∧ earlier.2.observed <+: later.2.observed
        ∧ earlier.2.observed.length < later.2.observed.length
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  exact Proofs.Witnesses.ordered_pair_witness

end consistency.Properties
