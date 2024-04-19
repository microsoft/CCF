---- MODULE SingleNodeReads ----
\* Expanding SingleNode to add read-only transactions

EXTENDS SingleNode

\* Submit new read-only transaction
RoTxRequestAction ==
    /\ history' = Append(
        history, 
        [type |-> RoTxRequest, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgerBranches

\* Response to a read-only transaction request
\* Assumes read-only transactions are always forwarded
\* TODO: Separate execution and response
RoTxResponseAction ==
    /\ \E i \in DOMAIN history :
        \* Check request has been received but not yet responded to
        /\ history[i].type = RoTxRequest
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RoTxResponse
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in FirstBranch..Len(ledgerBranches):
            /\ ledgerBranches[view] # <<>>
            /\ history' = Append(
                history,[
                    type |-> RoTxResponse, 
                    tx |-> history[i].tx, 
                    observed |-> LedgerBranchTxOnly(ledgerBranches[view]),
                    tx_id |-> <<ledgerBranches[view][Max(DOMAIN ledgerBranches[view])].view, Max(DOMAIN ledgerBranches[view])>>] )
    /\ UNCHANGED ledgerBranches

NextSingleNodeReadsAction ==
    \/ NextSingleNodeAction
    \/ RoTxRequestAction
    \/ RoTxResponseAction

SpecSingleNodeReads == Init /\ [][NextSingleNodeReadsAction]_vars

====