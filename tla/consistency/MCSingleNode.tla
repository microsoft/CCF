---- MODULE MCSingleNode ----
\* Bounded version of SingleNode for model checking

EXTENDS SingleNode

\* Capping the number of events in the history
CONSTANT HistoryLimit

MCRwTxRequestAction ==
    /\ Len(history) < HistoryLimit
    /\ RwTxRequestAction

MCRwTxResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ RwTxResponseAction

MCStatusCommittedResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ StatusCommittedResponseAction

MCNextSingleNodeAction ==
    \/ MCRwTxRequestAction
    \/ RwTxExecuteAction
    \/ MCRwTxResponseAction
    \/ MCStatusCommittedResponseAction

MCSpecSingleNode == Init /\ [][MCNextSingleNodeAction]_vars

====