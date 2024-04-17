---- MODULE MultiNode ----
\* This specification extends SingleNode to model a multi-node CCF service

EXTENDS SingleNode

\* The set of views where the corresponding terms have all committed log entries
ViewWithAllCommitted ==
    {view \in DOMAIN ledgerBranches: 
        /\ Len(ledgerBranches[view]) >= CommitSeqNum
        /\  \/ CommitSeqNum = 0
            \/ <<ledgerBranches[view][CommitSeqNum].view, CommitSeqNum>> \in CommittedTxIDs }    

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
TruncateLedgerAction ==
    /\ \E view \in ViewWithAllCommitted:
        /\ \E i \in (CommitSeqNum + 1)..Len(ledgerBranches[view]) :
            /\ ledgerBranches' = Append(ledgerBranches, SubSeq(ledgerBranches[view], 1, i))
            /\ UNCHANGED history

\* Sends status invalid message
StatusInvalidResponseAction ==
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxResponse
        \* either commit has passed seqnum but committed another transaction
        /\ \/ /\ CommitSeqNum >= history[i].tx_id[2]
              /\ Len(ledgerBranches[Len(ledgerBranches)]) >= history[i].tx_id[2]
              /\ ledgerBranches[Len(ledgerBranches)][history[i].tx_id[2]].view # history[i].tx_id[1]
        \* or commit hasn't reached seqnum but never will as current seqnum is higher
            \/ /\ CommitSeqNum > 0
               /\ CommitSeqNum < history[i].tx_id[2]
               /\ ledgerBranches[Len(ledgerBranches)][CommitSeqNum].view > history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> InvalidStatus]
            )
    /\ UNCHANGED ledgerBranches

NextMultiNodeAction ==
    \/ NextSingleNodeAction
    \/ TruncateLedgerAction
    \/ StatusInvalidResponseAction


SpecMultiNode == Init /\ [][NextMultiNodeAction]_vars
====