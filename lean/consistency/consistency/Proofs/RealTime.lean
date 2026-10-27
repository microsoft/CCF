module

public import consistency.Proofs.ViewOrder

@[expose] public section

namespace consistency.Proofs.RealTime

open Model Properties Observations LedgerIdentity Commitment

theorem write_in_prefix {ledger : List Entry} {seqno count : Nat} {entry : Entry}
    {tx : TxContent} (found : at? ledger seqno = some entry) (value : entry.tx = some tx)
    (bound : seqno ≤ count)
    : tx ∈ writes (ledger.take count) :=
  List.mem_filterMap.mpr ⟨entry, mem_of_at? (at_take_of_le found bound), value⟩

theorem committed_sequence_order {state : State}
    (reachable : transitionSystem.Reachable state)
    {earlier later : Nat × Response}
    (first : earlier ∈ committedResponses state.history .rw)
    (second : later ∈ committedResponses state.history .rw)
    {request : Nat × (TxType × TxContent)} (sent : request ∈ requests state.history)
    (matchesRequest : later.2.tx = request.2.2) (beforeRequest : earlier.1 < request.1)
    : earlier.2.txid.seqno < later.2.txid.seqno := by
  by_contra notLater
  obtain ⟨leftLedger, leftFound, leftObs, _⟩ := committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, _, rightEntry, rightAt, rightTx⟩ :=
    committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  have observed : later.2.tx ∈ earlier.2.observed := by
    rw [leftObs]
    exact write_in_prefix rightAt rightTx (by omega)
  have firstLookup := ((History.mem_responsesOf_iff _ _ _).mp
    (List.mem_filter.mp first).1).2
  obtain ⟨index, prior, lookup⟩ :=
    ((safe_reachable reachable).2 _ _ _ _ _ firstLookup).2 later.2.tx observed
  have requestLookup := (History.mem_requests_iff _ _ _ _).mp sent
  have sameIndex := (History.requests_reachable reachable).2
    _ _ _ _ _ _ lookup requestLookup matchesRequest
  omega

theorem all_committed_observed
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ earlier ∈ committedResponses state.history .rw,
          ∀ request ∈ committedRequests state.history .rw,
          ∀ later ∈ committedResponses state.history .rw,
            later.2.tx = request.2.2
            → earlier.1 < request.1
            → earlier.2.tx ∈ later.2.observed := by
  intro trace state ⟨valid, member⟩ earlier first request sent later second same before
  have reachable := valid.reachable member
  have bound := committed_sequence_order reachable first second
    (List.mem_filter.mp sent).1 same before
  obtain ⟨leftLedger, leftFound, _, leftEntry, leftAt, leftTx⟩ :=
    committed_snapshot reachable first
  obtain ⟨rightLedger, rightFound, rightObs, _⟩ := committed_snapshot reachable second
  rw [leftFound] at rightFound
  cases rightFound
  rw [rightObs]
  exact write_in_prefix leftAt leftTx (Nat.le_of_lt bound)

theorem committed_rw_ordered_real_time
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ earlier ∈ committedResponses state.history .rw,
          ∀ request ∈ committedRequests state.history .rw,
          ∀ later ∈ committedResponses state.history .rw,
            later.2.tx = request.2.2
            → earlier.1 < request.1
            → txIDStrictlyLessThan earlier.2.txid later.2.txid := by
  intro trace state ⟨valid, member⟩ earlier first request sent later second same before
  have reachable := valid.reachable member
  have seqno := committed_sequence_order reachable first second
    (List.mem_filter.mp sent).1 same before
  have earlierKnown : earlier.2.txid ∈ statusIDs state.history .committed := by
    simpa using (List.mem_filter.mp first).2
  have laterKnown : later.2.txid ∈ statusIDs state.history .committed := by
    simpa using (List.mem_filter.mp second).2
  have views := ViewOrder.committed_views reachable earlierKnown laterKnown (Nat.le_of_lt seqno)
  rcases Nat.lt_or_eq_of_le views with strict | equal
  · exact Or.inl strict
  · exact Or.inr ⟨equal, seqno⟩

theorem committed_rw_linearizable
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → (∀ left ∈ committedResponses state.history .rw,
            ∀ right ∈ committedResponses state.history .rw,
              left.2.observed <+: right.2.observed ∨ right.2.observed <+: left.2.observed)
          ∧ (∀ earlier ∈ committedResponses state.history .rw,
              ∀ request ∈ committedRequests state.history .rw,
              ∀ later ∈ committedResponses state.history .rw,
                later.2.tx = request.2.2
                → earlier.1 < request.1
                → earlier.2.tx ∈ later.2.observed)
          ∧ (∀ response ∈ responses state.history, response.2.observed.Nodup) := by
  intro trace state valid
  exact ⟨Commitment.committed_rw_serializable trace state valid,
    all_committed_observed trace state valid,
    Observations.at_most_once_observed trace state valid⟩

end consistency.Proofs.RealTime
