module

public import consistency.Properties.Predicates
public import CCF.Execution

import consistency.Proofs.Responses
import consistency.Proofs.Reads
import consistency.Proofs.Statuses
import consistency.Proofs.Ordered
import consistency.Proofs.InvalidObservations

@[expose] public section

/-!
Safety theorem statements for the consistency model.
All proofs link to checked implementations under `Proofs/`.
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

/-- Responses of either kind follow requests. -/
theorem all_received_is_first_sent
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> forall (kind : TxType),
            ∀ response ∈ responsesOf state.history kind,
              ∃ request ∈ requests state.history,
                request.1 < response.1 /\ request.2 = (kind, response.2.tx) := by
  exact Proofs.History.all_received_is_first_sent

/-- A transaction ID identifies at most one write.
This uniqueness does not apply to reads, which can observe the same ledger position. -/
theorem unique_txs
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responsesOf state.history .rw,
            ∀ right ∈ responsesOf state.history .rw,
              left.2.txid = right.2.txid -> left.2.tx = right.2.tx := by
  exact Proofs.LedgerIdentity.unique_txs

/-- Equal transaction IDs give equal observations. -/
theorem same_observations
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.txid = right.2.txid -> left.2.observed = right.2.observed := by
  exact Proofs.LedgerIdentity.same_observations

/-- Requests have distinct IDs across both transaction kinds. -/
theorem unique_tx_requests
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ requests state.history,
            ∀ right ∈ requests state.history,
              left.1 ≠ right.1 -> left.2.2 ≠ right.2.2 := by
  exact Proofs.History.unique_tx_requests

/-- Each request receives a unique transaction ID. -/
theorem unique_tx_ids
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ responses state.history,
            ∀ right ∈ responses state.history,
              left.2.tx = right.2.tx -> left.2.txid = right.2.txid := by
  exact Proofs.Responses.unique_tx_ids

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

/-- Committed and invalid statuses are disjoint. -/
theorem committed_or_invalid
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ txid ∈ statusIDs state.history .committed,
            txid ∉ statusIDs state.history .invalid := by
  exact Proofs.Statuses.committed_or_invalid

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

/-- Observations contain only earlier requested writes. -/
theorem only_observe_sent_requests
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responses state.history,
            ∀ tx ∈ response.2.observed,
              ∃ request ∈ requests state.history,
                request.1 < response.1 /\ request.2 = (.rw, tx) := by
  exact Proofs.Observations.only_observe_sent_requests

/-- Observations contain no duplicate writes. -/
theorem at_most_once_observed
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ response ∈ responses state.history, response.2.observed.Nodup := by
  exact Proofs.Observations.at_most_once_observed

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

/-- Committed write histories are serializable. -/
theorem committed_rw_serializable
    : forall (config : Config) (trace : GlobalTrace) (state : State),
        (trace.Valid (transitionSystem config) /\ state ∈ trace)
        -> ∀ left ∈ committedResponses state.history .rw,
            ∀ right ∈ committedResponses state.history .rw,
              left.2.observed <+: right.2.observed
              \/ right.2.observed <+: left.2.observed := by
  exact Proofs.Commitment.committed_rw_serializable

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

/-- History only grows along executions of the actual model. -/
theorem history_monotonic
    : forall (config : Config) (trace : GlobalTrace),
        trace.Valid (transitionSystem config)
        -> forall (index : Nat) (before after : State),
            (trace.get? index = some before /\ trace.get? (index + 1) = some after)
            -> before.history <+: after.history := by
  exact Proofs.Structural.history_monotonic

/-- Elections add branches without shortening existing ones. -/
theorem ledgers_monotonic
    : forall (config : Config) (trace : GlobalTrace),
        trace.Valid (transitionSystem config)
        -> forall (index : Nat) (before after : State),
            (trace.get? index = some before /\ trace.get? (index + 1) = some after)
            -> forall (branch : Nat) (ledger : List Entry),
                at? before.branches branch = some ledger
                -> exists extended,
                    at? after.branches branch = some extended /\ ledger <+: extended := by
  exact Proofs.Structural.ledgers_monotonic

end consistency.Properties
