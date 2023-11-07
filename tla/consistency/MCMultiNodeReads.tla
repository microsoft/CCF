---- MODULE MCMultiNodeReads ----
\* Bounded version of MultiNodeReads

EXTENDS MCSingleNodeReads, MCMultiNodegit s

MCNextMultiNodeReadsAction ==
    \/ MCNextMultiNodeAction
    \/ MCRoTxRequestAction
    \/ MCRoTxResponseAction

MCSpecMultiNodeReads == Init /\ [][MCNextMultiNodeReadsAction]_vars

====