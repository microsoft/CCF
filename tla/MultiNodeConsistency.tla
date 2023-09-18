---- MODULE MultiNodeConsistency ----

EXTENDS SingeNodeConsistency

\* Upper bound on the view
CONSTANT ViewLimit

StatusInvalidResponse ==
    /\ Len(history) < HistoryLimit
    /\ commit_seqnum # 0
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxReceived
        \* Check the tx_id is committed
        /\ history[i].tx_id[2] <= commit_seqnum
        /\ ledgers[Len(ledgers)][history[i].tx_id[2]].view # history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> InvalidStatus]
            )
    /\ UNCHANGED <<ledgers, commit_seqnum>>

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
\* TODO: model the fact that uncommitted entries from previous terms might be kept
TruncateLedger ==
    /\ Len(ledgers) < ViewLimit
    /\ \E i \in (commit_seqnum + 1)..Len(ledgers[Len(ledgers)]) :
        /\ ledgers' = Append(ledgers, SubSeq(ledgers[Len(ledgers)], 1, i))
        /\ UNCHANGED <<commit_seqnum, history>>

NextMultiNode ==
    \/ NextSingleNode
    \/ TruncateLedger
    \/ StatusInvalidResponse


SpecMultiNode == Init /\ [][NextMultiNode]_vars

====