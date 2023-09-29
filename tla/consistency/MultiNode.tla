---- MODULE MultiNode ----
\* This specification extends SingleNode to model a multi-node CCF service

EXTENDS SingleNode

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

\* Sends status invalid message
StatusInvalidResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxResponse
        \* either commit has passed seqnum but committed another transaction
        /\ \/ /\ CommitSeqNum >= history[i].tx_id[2]
              /\ Len(ledgers[Len(ledgers)]) >= history[i].tx_id[2]
              /\ ledgers[Len(ledgers)][history[i].tx_id[2]].view # history[i].tx_id[1]
        \* or commit hasn't reached seqnum but never will as current seqnum is higher
            \/ /\ CommitSeqNum > 0
               /\ CommitSeqNum < history[i].tx_id[2]
               /\ ledgers[Len(ledgers)][CommitSeqNum].view > history[i].tx_id[1]
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

====