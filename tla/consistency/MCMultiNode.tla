---- MODULE MCMultiNode ----

EXTENDS MultiNode, MCSingleNode

\* Upper bound on the view
CONSTANT ViewLimit

MCTruncateLedgerAction == 
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