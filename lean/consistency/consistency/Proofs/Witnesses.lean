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
    : ∃ trace : CCF.Execution.Trace State,
        trace.Valid (transitionSystem) ∧ writesAndReads ∈ trace := by
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
    : ∃ trace : CCF.Execution.Trace State,
        trace.Valid (transitionSystem) ∧ replacedWrites ∈ trace := by
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

theorem received_witness (kind : TxType)
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent)),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ response ∈ responsesOf state.history kind
        ∧ request ∈ requests state.history
        ∧ request.1 < response.1
        ∧ request.2 = (kind, response.2.tx)
        ∧ response.2.observed ≠ [] := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  cases kind with
  | rw =>
      exact ⟨trace, writesAndReads, writeA, ⟨0, .rw, 0⟩, valid, member, by decide⟩
  | ro =>
      exact ⟨trace, writesAndReads, readA, ⟨6, .ro, 2⟩, valid, member, by decide⟩

theorem all_received_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (write read : Nat × Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ write ∈ responsesOf state.history .rw
        ∧ read ∈ responsesOf state.history .ro
        ∧ write.2.observed ≠ []
        ∧ read.2.observed ≠ [] := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, readA, valid, member, by decide⟩

theorem write_pair_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : Nat × Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ committedResponses state.history .rw
        ∧ right ∈ committedResponses state.history .rw
        ∧ left.1 < right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid.seqno < right.2.txid.seqno
        ∧ left.2.observed ≠ []
        ∧ left.2.observed <+: right.2.observed
        ∧ left.2.observed.length < right.2.observed.length := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeB, valid, member, by decide⟩

theorem same_observations_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : Nat × Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ responsesOf state.history .ro
        ∧ right ∈ responsesOf state.history .ro
        ∧ left.1 ≠ right.1
        ∧ left.2.tx ≠ right.2.tx
        ∧ left.2.txid = right.2.txid
        ∧ left.2.observed = right.2.observed
        ∧ left.2.observed ≠ [] := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, readB, valid, member, by decide⟩

theorem unique_tx_requests_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (left right : Nat × (TxType × TxContent)),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ requests state.history
        ∧ right ∈ requests state.history
        ∧ left.1 ≠ right.1
        ∧ left.2.1 ≠ right.2.1
        ∧ left.2.2 ≠ right.2.2 := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, ⟨0, .rw, 0⟩, ⟨6, .ro, 2⟩, valid, member, by decide⟩

theorem committed_or_invalid_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (committed invalid : TxID),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ committed ∈ statusIDs state.history .committed
        ∧ invalid ∈ statusIDs state.history .invalid
        ∧ committed ≠ invalid
        ∧ committed ∉ statusIDs state.history .invalid := by
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨trace, replacedWrites, ⟨3, 1⟩, ⟨2, 1⟩, valid, member, by decide⟩

theorem once_committed_prev_committed_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : TxID × Status),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.view = right.1.view
        ∧ right.1.seqno < left.1.seqno
        ∧ right.2 = .committed := by
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    ⟨⟨3, 2⟩, .committed⟩,
    ⟨⟨3, 1⟩, .committed⟩,
    valid,
    member,
    by decide
  ⟩

theorem once_committed_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : TxID × Status),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .committed
        ∧ left.1.seqno < right.1.seqno
        ∧ right.1.view < left.1.view
        ∧ right.2 = .invalid := by
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    ⟨⟨3, 1⟩, .committed⟩,
    ⟨⟨2, 2⟩, .invalid⟩,
    valid,
    member,
    by decide
  ⟩

theorem once_invalid_next_invalid_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : TxID × Status),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ left ∈ statuses state.history
        ∧ right ∈ statuses state.history
        ∧ left.2 = .invalid
        ∧ left.1.view = right.1.view
        ∧ left.1.seqno < right.1.seqno
        ∧ right.2 = .invalid := by
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    ⟨⟨2, 1⟩, .invalid⟩,
    ⟨⟨2, 2⟩, .invalid⟩,
    valid,
    member,
    by decide
  ⟩

theorem committed_or_invalid_strong_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
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
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨trace, replacedWrites, ⟨3, 1⟩, ⟨3, 2⟩, ⟨2, 1⟩, ⟨2, 2⟩, valid, member, by decide⟩

theorem only_observe_sent_requests_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (response : Nat × Response) (request : Nat × (TxType × TxContent))
        (tx : TxContent),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ response ∈ responses state.history
        ∧ response.2.kind = .ro
        ∧ tx ∈ response.2.observed
        ∧ request ∈ requests state.history
        ∧ request.1 < response.1
        ∧ request.2 = (.rw, tx) := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, ⟨0, .rw, 0⟩, 0, valid, member, by decide⟩

theorem at_most_once_observed_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (response : Nat × Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ response ∈ responses state.history
        ∧ 2 ≤ response.2.observed.length
        ∧ response.2.observed.Nodup := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, readA, valid, member, by decide⟩

theorem real_time_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent)),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ earlier ∈ committedResponses state.history .rw
        ∧ request ∈ committedRequests state.history .rw
        ∧ later ∈ committedResponses state.history .rw
        ∧ later.2.tx = request.2.2
        ∧ earlier.1 < request.1
        ∧ earlier.2.tx ∈ later.2.observed
        ∧ earlier.2.observed ≠ [] := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨trace, writesAndReads, writeA, writeB, ⟨2, .rw, 1⟩, valid, member, by decide⟩

theorem invalid_not_observed_by_committed_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (invalid observer : Nat × Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ invalid ∈ responsesOf state.history .rw
        ∧ observer ∈ committedResponses state.history .rw
        ∧ invalid.1 ≠ observer.1
        ∧ invalid.2.txid ∈ statusIDs state.history .invalid
        ∧ observer.2.observed ≠ []
        ∧ invalid.2.tx ∉ observer.2.observed := by
  obtain ⟨trace, valid, member⟩ := replaced_writes_trace
  exact ⟨
    trace,
    replacedWrites,
    writeA,
    ⟨7, ⟨.rw, 2, [2], ⟨3, 1⟩⟩⟩,
    valid,
    member,
    by decide
  ⟩

theorem ordered_pair_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State)
        (earlier later : Nat × Response) (request : Nat × (TxType × TxContent))
        (commitIndex : Nat),
        trace.Valid transitionSystem
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
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    writesAndReads,
    writeA,
    writeB,
    ⟨2, .rw, 1⟩,
    4,
    valid,
    member,
    by rw [writes_and_reads_ordered]; decide
  ⟩

theorem committed_rw_ordered_serializable_witness
    : ∃ (trace : CCF.Execution.Trace State) (state : State) (left right : Response),
        trace.Valid transitionSystem
        ∧ state ∈ trace
        ∧ (left, right)
          ∈ (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail
        ∧ left.observed ≠ []
        ∧ left.observed <+: right.observed
        ∧ left.observed.length < right.observed.length
        ∧ right.observed.getLast? = some right.tx := by
  obtain ⟨trace, valid, member⟩ := writes_and_reads_trace
  exact ⟨
    trace,
    writesAndReads,
    writeA.2,
    writeB.2,
    valid,
    member,
    by rw [writes_and_reads_ordered]; decide
  ⟩

end consistency.Proofs.Witnesses
