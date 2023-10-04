---- MODULE MCSingleNode ----

EXTENDS SingleNode

CONSTANT HistoryLimit

MCRwTxRequestAction ==
    /\ Len(history) < HistoryLimit
    /\ RwTxRequestAction

MCRwTxExecuteAction ==
    RwTxExecuteAction

MCRwTxResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ RwTxResponseAction

MCStatusCommittedResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ StatusCommittedResponseAction

MCNextSingleNodeAction ==
    \/ MCRwTxRequestAction
    \/ MCRwTxExecuteAction
    \/ MCRwTxResponseAction
    \/ MCStatusCommittedResponseAction

MCSpecSingleNode == Init /\ [][MCNextSingleNodeAction]_vars

====