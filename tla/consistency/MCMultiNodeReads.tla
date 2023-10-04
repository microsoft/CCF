---- MODULE MCMultiNodeReads ----

EXTENDS MCSingleNodeReads, MCMultiNode

MCNextMultiNodeReadsAction ==
    \/ MCNextMultiNodeAction
    \/ MCRoTxRequestAction
    \/ MCRoTxResponseAction

MCSpecMultiNodeReads == Init /\ [][MCNextMultiNodeReadsAction]_vars

====