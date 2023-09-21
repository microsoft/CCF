---- MODULE MultiNodeConsistency ----
\* This specification extends SingleNodeConsistency to model a multi-node CCF service

EXTENDS FiniteSetsExt, SingleNodeConsistency

\* Upper bound on the view
CONSTANT ViewLimit

CommittedEventIndexes == 
    {i \in DOMAIN history: 
        /\ history[i].type = TxStatusReceived
        /\ history[i].status = CommittedStatus
        }

CommitSeqNum == 
    IF CommittedEventIndexes = {} 
    THEN 0
    ELSE Max({history[i].tx_id[2]: i \in CommittedEventIndexes})

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
\* TODO: model the fact that uncommitted entries from previous terms might be kept
TruncateLedger ==
    /\ Len(ledgers) < ViewLimit
    /\ \E i \in (CommitSeqNum + 1)..Len(ledgers[Len(ledgers)]) :
        /\ ledgers' = Append(ledgers, SubSeq(ledgers[Len(ledgers)], 1, i))
        /\ UNCHANGED history

StatusInvalidResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxReceived
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

NextMultiNode ==
    \/ NextSingleNode
    \/ TruncateLedger
    \/ StatusInvalidResponse


SpecMultiNode == Init /\ [][NextMultiNode]_vars

NextMultiNodeWithReads ==
    \/ NextMultiNode
    \/ RoTxRequest
    \/ RoTxResponse

SpecMultiNodeWithReads == Init /\ [][NextMultiNodeWithReads]_vars

Init1 ==
    /\ ledgers = << 
        <<[view |-> 1, tx |-> 0]>>,
        <<[view |-> 1, tx |-> 0], [view |-> 2, tx |-> 1]>> >>
    /\ history = <<[type |-> RwTxRequested, tx |-> 0], [type |-> RwTxRequested, tx |-> 1], [type |-> RwTxReceived, tx_id |-> <<1, 1>>, tx |-> 0, observed |-> <<0>>], [type |-> RwTxReceived, tx_id |-> <<2, 2>>, tx |-> 1, observed |-> <<0, 1>>], [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<1, 1>>], [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<2, 2>>]>>

SpecMultiNodeWithReads1 == Init1 /\ [][NextMultiNodeWithReads]_vars
====