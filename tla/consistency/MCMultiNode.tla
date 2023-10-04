---- MODULE MCMultiNode ----
\* Bounded version of MultiNode

EXTENDS MultiNode, MCSingleNode

\* Upper bound on the number of possible view changes
CONSTANT ViewLimit

MCTruncateLedgerAction ==
    \* check ViewLimit will not be exceed before truncating the ledger
    /\ Len(ledgerBranches) < ViewLimit
    /\ TruncateLedgerAction

MCStatusInvalidResponseAction ==
     /\ Len(history) < HistoryLimit
     /\ StatusInvalidResponseAction

MCNextMultiNodeAction ==
    \/ MCNextSingleNodeAction
    \/ MCTruncateLedgerAction
    \/ MCStatusInvalidResponseAction


MCSpecMultiNode == Init /\ [][MCNextMultiNodeAction]_vars


====