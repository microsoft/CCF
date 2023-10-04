---- MODULE MCSingleNodeReads ----

EXTENDS SingleNodeReads, MCSingleNode

MCRoTxRequestAction ==
    /\ Len(history) < HistoryLimit
    /\ RoTxRequestAction

MCRoTxResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ RoTxResponseAction

MCNextSingleNodeReadsAction ==
    \/ MCNextSingleNodeAction
    \/ MCRoTxRequestAction
    \/ MCRoTxResponseAction

MCSpecSingleNodeReads == Init /\ [][MCNextSingleNodeReadsAction]_vars

====