module

public import DisasterRecovery.Model

@[expose] public section

namespace DisasterRecovery.Properties

open Model.Local in
/-- Raft's vote freshness check on last signed TxIDs, not a log-prefix relation. -/
abbrev LogUpToDate (candidate voter : TxID) : Prop :=
  voter.view < candidate.view
  \/ (voter.view = candidate.view /\ voter.seqno <= candidate.seqno)

open Model.Local in
/-- The candidate passes Raft's log freshness check against a strict majority.
Valid model configs give one recovered ledger per configured node. -/
def UpToDateWithQuorum (config : Model.Config) (candidate : TxID) : Prop :=
  voteQuorum config.protocol
  <= (config.recovered.filter
        fun (_, voter) => decide (LogUpToDate candidate voter)).length

end DisasterRecovery.Properties
