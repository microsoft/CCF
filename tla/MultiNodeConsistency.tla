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

\* Transaction IDs which received committed status messages
CommittedTxIDs ==
    {history[i].tx_id: i \in CommittedEventIndexes}

\* Highest commit sequence number
CommitSeqNum == 
    IF CommittedTxIDs = {} 
    THEN 0
    ELSE Max({i[2]: i \in CommittedTxIDs})

\* The set of views where the corresponding terms have all committed log entries
ViewWithAllCommitted ==
    {view \in DOMAIN ledgers: 
        /\ Len(ledgers[view]) >= CommitSeqNum
        /\  \/ CommitSeqNum = 0
            \/ <<ledgers[view][CommitSeqNum].view, CommitSeqNum>> \in CommittedTxIDs }    

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
TruncateLedger ==
    /\ Len(ledgers) < ViewLimit
    /\ \E view \in ViewWithAllCommitted:
        /\ \E i \in (CommitSeqNum + 1)..Len(ledgers[view]) :
            /\ ledgers' = Append(ledgers, SubSeq(ledgers[view], 1, i))
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

\* In this abstract version of CCF's consensus layer, each ledger is append-only
LedgersMonoProp ==
    [][\A view \in DOMAIN ledgers: IsPrefix(ledgers[view], ledgers[view]')]_ledgers

\* Alternative initial state with transactions already committed
InitAlt ==
    /\ ledgers = << 
        <<[view |-> 1, tx |-> 0]>>,
        <<[view |-> 1, tx |-> 0], [view |-> 2, tx |-> 1]>> 
        >>
    /\ history = <<
        [type |-> RwTxRequested, tx |-> 0], 
        [type |-> RwTxRequested, tx |-> 1], 
        [type |-> RwTxReceived, tx_id |-> <<1, 1>>, tx |-> 0, observed |-> <<0>>], 
        [type |-> RwTxReceived, tx_id |-> <<2, 2>>, tx |-> 1, observed |-> <<0, 1>>], 
        [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<1, 1>>], 
        [type |-> TxStatusReceived, status |-> CommittedStatus, tx_id |-> <<2, 2>>]
        >>

SpecMultiNodeWithReadsAltInit == InitAlt /\ [][NextMultiNodeWithReads]_vars

====