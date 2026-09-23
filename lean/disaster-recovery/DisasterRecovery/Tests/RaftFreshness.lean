import DisasterRecovery.Properties

namespace DisasterRecovery.Tests.RaftFreshness

open Model.Local
open Properties

private def low : TxID := { view := 1, seqno := 5 }
private def high : TxID := { view := 1, seqno := 10 }

private def config (ledgers : List (Location × TxID)) : Model.Config := {
  protocol := { instanceId := "raft-freshness-tests", expectedLocations := ledgers.map Prod.fst }
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

example : UpToDateWithQuorum
    (config [("A", low), ("B", low), ("C", low), ("D", high)]) low := by
  unfold UpToDateWithQuorum
  decide

-- The old majority-supported-bound condition admitted the same two-of-four candidate.
example (txid : TxID)
    (majority : voteQuorum evenConfig.protocol <=
      (evenConfig.recovered.filter fun (_, head) => decide (LogUpToDate head txid)).length) :
    LogUpToDate low txid := by
  by_cases atLow : LogUpToDate low txid
  · exact atLow
  · simp [evenConfig, config, voteQuorum, atLow] at majority
    exact absurd (Nat.le_trans majority (List.length_filter_le _ _)) (by decide)

end DisasterRecovery.Tests.RaftFreshness
