---- MODULE SingleNodeReads ----
\* Expanding SingleNode to add read-only transactions

EXTENDS SingleNode

\* Submit new read-only transaction
RoTxRequestAction ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> RoTxRequest, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgerViews

\* Response to a read-only transaction request
\* Assumes read-only transactions are always forwarded
\* TODO: Separate execution and response
RoTxResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        \* Check request has been received but not yet responded to
        /\ history[i].type = RoTxRequest
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RoTxResponse
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in DOMAIN ledgerViews:
            /\ Len(ledgerViews[view]) > 0
            /\ history' = Append(
                history,[
                    type |-> RoTxResponse, 
                    tx |-> history[i].tx, 
                    observed |-> [seqnum \in DOMAIN ledgerViews[view] |-> ledgerViews[view][seqnum].tx],
                    tx_id |-> <<ledgerViews[view][Len(ledgerViews[view])].view, Len(ledgerViews[view])>>] )
    /\ UNCHANGED ledgerViews

NextSingleNodeReadsAction ==
    \/ NextSingleNodeAction
    \/ RoTxRequestAction
    \/ RoTxResponseAction

SpecSingleNodeReads == Init /\ [][NextSingleNodeReadsAction]_vars

====