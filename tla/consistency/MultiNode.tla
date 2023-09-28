---- MODULE MultiNode ----
\* This specification extends SingleNodeConsistency to model a multi-node CCF service

EXTENDS SingleNode, TLC

\* Upper bound on the view
CONSTANT ViewLimit

\* The set of views where the corresponding terms have all committed log entries
ViewWithAllCommitted ==
    {view \in DOMAIN ledgers: 
        /\ Len(ledgers[view]) >= CommitSeqNum
        /\  \/ CommitSeqNum = 0
            \/ <<ledgers[view][CommitSeqNum].view, CommitSeqNum>> \in CommittedTxIDs }    

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
TruncateLedgerAction ==
    /\ Len(ledgers) < ViewLimit
    /\ \E view \in ViewWithAllCommitted:
        /\ \E i \in (CommitSeqNum + 1)..Len(ledgers[view]) :
            /\ ledgers' = Append(ledgers, SubSeq(ledgers[view], 1, i))
            /\ UNCHANGED history

\* TODO: check CCF source code for rules regarding when a transaction is considered invalid
StatusInvalidResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxResponse
        /\ CommitSeqNum >= history[i].tx_id[2]
        /\ Len(ledgers[Len(ledgers)]) >= history[i].tx_id[2]
        /\ ledgers[Len(ledgers)][history[i].tx_id[2]].view # history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> InvalidStatus]
            )
    /\ UNCHANGED ledgers

NextMultiNodeAction ==
    \/ NextSingleNodeAction
    \/ TruncateLedgerAction
    \/ StatusInvalidResponseAction


SpecMultiNode == Init /\ [][NextMultiNodeAction]_vars

NextMultiNodeWithReadsAction ==
    \/ NextMultiNodeAction
    \/ RoTxRequestAction
    \/ RoTxResponseAction

SpecMultiNodeWithReads == Init /\ [][NextMultiNodeWithReadsAction]_vars

====