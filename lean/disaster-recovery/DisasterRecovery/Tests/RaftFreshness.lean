/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Properties

/-! Regression cases for Raft freshness and strict-majority thresholds. -/

namespace DisasterRecovery.Tests.RaftFreshness

open Model.Local
open Properties

private def low : TxID := { view := 1, seqno := 5 }
private def high : TxID := { view := 1, seqno := 10 }

private def config (ledgers : List (Location × TxID)) : Model.Config :=
  {
    protocol :=
      { instanceId := "raft-freshness-tests", expectedLocations := ledgers.map Prod.fst }
    recovered := ledgers
  }

example : LogUpToDate high high := by decide
example : LogUpToDate high low := by decide
example : ¬ LogUpToDate low high := by decide

-- The freshness check orders terms before indices; it does not compare prefixes.
example : LogUpToDate { view := 2, seqno := 5 } high := by decide
example : ¬ LogUpToDate { view := 1, seqno := 100 } { view := 2, seqno := 5 } := by decide

example : UpToDateWithQuorum (config [("A", high)]) high := by
  unfold UpToDateWithQuorum
  decide

example : UpToDateWithQuorum (config [("A", low), ("B", low), ("C", high)]) low := by
  unfold UpToDateWithQuorum
  decide

example : ¬ UpToDateWithQuorum (config [("A", high), ("B", high), ("C", low)]) low := by
  unfold UpToDateWithQuorum
  decide

private def evenConfig := config [("A", low), ("B", low), ("C", high), ("D", high)]

example : evenConfig.Valid := by
  unfold Model.Config.Valid
  decide

-- Two of four is not an election majority, even when the candidate is one of them.
example : ¬ UpToDateWithQuorum evenConfig low := by
  unfold UpToDateWithQuorum
  decide

example : UpToDateWithQuorum evenConfig high := by
  unfold UpToDateWithQuorum
  decide

example
    : UpToDateWithQuorum
        (config [("A", low), ("B", low), ("C", low), ("D", high)]) low := by
  unfold UpToDateWithQuorum
  decide

-- The old majority-supported-bound condition admitted the same two-of-four candidate.
example (txid : TxID)
    (majority
      : voteQuorum evenConfig.protocol
        <= (evenConfig.recovered.filter
              fun (_, head) => decide (LogUpToDate head txid)).length)
    : LogUpToDate low txid := by
  by_cases atLow : LogUpToDate low txid
  · exact atLow
  · simp only [voteQuorum, evenConfig, config, List.map_cons, List.map_nil, List.length_cons,
    List.length_nil, Nat.zero_add, Nat.reduceAdd, Nat.reduceDiv, Bool.decide_or, Bool.decide_and,
    Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, atLow, not_false_eq_true,
    List.filter_cons_of_neg] at majority
    exact absurd (Nat.le_trans majority (List.length_filter_le _ _)) (by decide)

end DisasterRecovery.Tests.RaftFreshness
