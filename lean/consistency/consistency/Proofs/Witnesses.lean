module

public import consistency.Properties.History
public import CCF.Execution

@[expose] public section

namespace consistency.Proofs.Witnesses

open Model Properties

private def replay (state : State) : List Action → Option State
  | [] => some state
  | action :: actions =>
      (step state action).bind fun next => replay next actions

private theorem replay_reachable (actions : List Action)
    {before after : State} (reachable : transitionSystem.Reachable before)
    (executed : replay before actions = some after)
    : transitionSystem.Reachable after := by
  induction actions generalizing before with
  | nil =>
      simp only [replay, Option.some.injEq] at executed
      subst before
      exact reachable
  | cons action actions ih =>
      obtain ⟨next, transition, rest⟩ := Option.bind_eq_some_iff.mp executed
      exact ih (.step reachable transition) rest

private def writesAndReads : State :=
  {
    history :=
      [
        .request .rw 0,
        .response .rw 0 [0] ⟨2, 1⟩,
        .request .rw 1,
        .response .rw 1 [0, 1] ⟨2, 2⟩,
        .status ⟨2, 1⟩ .committed,
        .status ⟨2, 2⟩ .committed,
        .request .ro 2,
        .response .ro 2 [0, 1] ⟨2, 2⟩,
        .request .ro 3,
        .response .ro 3 [0, 1] ⟨2, 2⟩
      ]
    branches := [[], [⟨2, some 0⟩, ⟨2, some 1⟩]]
  }

private theorem writes_and_reads_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem, writesAndReads ∈ trace := by
  apply (CCF.Execution.reachable_iff_trace
    (system := transitionSystem) (state := writesAndReads)).mp
  exact replay_reachable
    [
      .request .rw,
      .execute 1 2,
      .respond 1 2 1,
      .request .rw,
      .execute 3 2,
      .respond 3 2 2,
      .commit 2,
      .commit 4,
      .request .ro,
      .read 7 2,
      .request .ro,
      .read 9 2
    ]
    (.initial rfl) (by decide)

private def replacedWrites : State :=
  {
    history :=
      [
        .request .rw 0,
        .response .rw 0 [0] ⟨2, 1⟩,
        .request .rw 1,
        .response .rw 1 [0, 1] ⟨2, 2⟩,
        .status ⟨2, 1⟩ .invalid,
        .status ⟨2, 2⟩ .invalid,
        .request .rw 2,
        .response .rw 2 [2] ⟨3, 1⟩,
        .status ⟨3, 1⟩ .committed,
        .request .rw 3,
        .response .rw 3 [2, 3] ⟨3, 2⟩,
        .status ⟨3, 2⟩ .committed,
        .request .ro 4,
        .response .ro 4 [2, 3] ⟨3, 2⟩,
        .request .ro 5,
        .response .ro 5 [0, 1] ⟨2, 2⟩
      ]
    branches := [[], [⟨2, some 0⟩, ⟨2, some 1⟩], [⟨3, some 2⟩, ⟨3, some 3⟩]]
  }

private theorem replaced_writes_trace
    : ∃ trace : CCF.Execution.Trace transitionSystem, replacedWrites ∈ trace := by
  apply (CCF.Execution.reachable_iff_trace
    (system := transitionSystem) (state := replacedWrites)).mp
  exact replay_reachable
    [
      .request .rw,
      .execute 1 2,
      .respond 1 2 1,
      .request .rw,
      .execute 3 2,
      .respond 3 2 2,
      .invalidate 2,
      .invalidate 4,
      .elect 2 0,
      .request .rw,
      .execute 7 3,
      .respond 7 3 1,
      .commit 8,
      .request .rw,
      .execute 10 3,
      .respond 10 3 2,
      .commit 11,
      .request .ro,
      .read 13 3,
      .request .ro,
      .read 15 2
    ]
    (.initial rfl) (by decide)

private def writeA : Nat × Response := ⟨1, ⟨.rw, 0, [0], ⟨2, 1⟩⟩⟩
private def writeB : Nat × Response := ⟨3, ⟨.rw, 1, [0, 1], ⟨2, 2⟩⟩⟩
private def readA : Nat × Response := ⟨7, ⟨.ro, 2, [0, 1], ⟨2, 2⟩⟩⟩
private def readB : Nat × Response := ⟨9, ⟨.ro, 3, [0, 1], ⟨2, 2⟩⟩⟩

private theorem writes_and_reads_ordered
    : committedRwResponses writesAndReads.history = [writeA.2, writeB.2] := by
  change [writeA.2, writeB.2].mergeSort _ = _
  rw [List.mergeSort_pair]
  rfl

theorem all_received_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (write read : Nat × Response),
        state ∈ trace
        ∧ write ∈ responsesOf state.history .rw
        ∧ read ∈ responsesOf state.history .ro := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, readA, member, by decide⟩

theorem unique_txs_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responsesOf state.history .rw
        ∧ right ∈ responsesOf state.history .rw
        ∧ left.2.txid = right.2.txid := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeA, member, by decide⟩

theorem same_observations_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responses state.history
        ∧ right ∈ responses state.history
        ∧ left.2.txid = right.2.txid := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, readB, member, by decide⟩

theorem unique_tx_requests_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × (TxType × TxContent)),
        state ∈ trace
        ∧ left ∈ requests state.history
        ∧ right ∈ requests state.history
        ∧ left.1 ≠ right.1 := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, ⟨0, .rw, 0⟩, ⟨6, .ro, 2⟩, member, by decide⟩

theorem unique_tx_ids_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ responses state.history
        ∧ right ∈ responses state.history
        ∧ left.2.tx = right.2.tx := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeA, member, by decide⟩

theorem unique_seq_nums_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.2.txid.seqno = right.2.txid.seqno := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeA, member, by decide⟩

theorem committed_or_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State) (committed : TxID),
        state ∈ trace ∧ committed ∈ statusIDs state.history .committed := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, replacedWrites, ⟨3, 1⟩, member, by decide⟩

theorem once_committed_prev_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.view = right.1.view
        ∧ right.1.seqno ≤ left.1.seqno := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    ⟨⟨3, 2⟩, .committed⟩,
    ⟨⟨3, 1⟩, .committed⟩,
    member,
    by decide
  ⟩

theorem once_committed_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.seqno ≤ right.1.seqno
        ∧ right.1.view < left.1.view := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    ⟨⟨3, 1⟩, .committed⟩,
    ⟨⟨2, 2⟩, .invalid⟩,
    member,
    by decide
  ⟩

theorem once_invalid_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : TxID × Status),
        state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .invalid
        ∧ left.1.view = right.1.view
        ∧ left.1.seqno ≤ right.1.seqno := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, replacedWrites, ⟨⟨2, 1⟩, .invalid⟩, ⟨⟨2, 2⟩, .invalid⟩, member, by decide⟩

theorem only_observe_sent_requests_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (response : Nat × Response) (tx : TxContent),
        state ∈ trace
        ∧ response ∈ responses state.history
        ∧ tx ∈ response.2.observed := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, 0, member, by decide⟩

theorem at_most_once_observed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (response : Nat × Response),
        state ∈ trace ∧ response ∈ responses state.history := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, member, by decide⟩

theorem real_time_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1 := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeB, ⟨2, .rw, 1⟩, member, by decide⟩

theorem invalid_not_observed_by_committed_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (invalid observer : Nat × Response),
        state ∈ trace
        ∧ invalid ∈ responsesOf state.history .rw
        ∧ observer ∈ committedResponses state.history .rw
        ∧ invalid.1 ≠ observer.1
        ∧ invalid.2.txid ∈ statusIDs state.history .invalid := by
  obtain ⟨trace, member⟩ := replaced_writes_trace
  exact ⟨trace, replacedWrites, writeA, ⟨7, ⟨.rw, 2, [2], ⟨3, 1⟩⟩⟩, member, by decide⟩

theorem write_pair_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Nat × Response),
        state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeB, member, by decide⟩

theorem committed_rw_ordered_serializable_witness
    : ∃ (trace : CCF.Execution.Trace transitionSystem) (state : State)
        (left right : Response),
        state ∈ trace
        ∧ (left, right)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail := by
  obtain ⟨trace, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    writesAndReads,
    writeA.2,
    writeB.2,
    member,
    by rw [writes_and_reads_ordered]; decide
  ⟩

end consistency.Proofs.Witnesses
