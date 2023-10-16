---- MODULE MultiNodeReads ----
\* This specification extends MultiNode to add read-only transactions

EXTENDS SingleNodeReads, MultiNode

NextMultiNodeReadsAction ==
    \/ NextMultiNodeAction
    \/ RoTxRequestAction
    \/ RoTxResponseAction

SpecMultiNodeReads == Init /\ [][NextMultiNodeReadsAction]_vars

====