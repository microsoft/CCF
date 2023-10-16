---- MODULE MCMultiNodeReads ----
\* Bounded version of MultiNodeReads

EXTENDS MCSingleNodeReads, MCMultiNode

MCNextMultiNodeReadsAction ==
    \/ MCNextMultiNodeAction
    \/ MCRoTxRequestAction
    \/ MCRoTxResponseAction

MCSpecMultiNodeReads == Init /\ [][MCNextMultiNodeReadsAction]_vars

====