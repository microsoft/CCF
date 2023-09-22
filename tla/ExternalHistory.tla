---- MODULE ExternalHistory ----
\* Defines the notion of a externally observable client history and associated properties

EXTENDS Naturals, Sequences, SequencesExt

\* Event types
\* TODO: Add more types of read-only transactions
CONSTANTS RwTxRequested, RwTxReceived, RoTxRequested, RoTxReceived, TxStatusReceived
EventTypes == {
    RwTxRequested, 
    RwTxReceived,
    RoTxRequested, 
    RoTxReceived, 
    TxStatusReceived
    }

\* Transaction statuses
\* This model does not include the unknown and pending status to reduce state space
CONSTANTS CommittedStatus, InvalidStatus
TxStatuses == {
    CommittedStatus,
    InvalidStatus
    }

\* History of events visible to clients
VARIABLES history

\* Views start at 1, 0 is used a null value
Views == Nat

\* Sequence numbers start at 1, 0 is used a null value
SeqNums == Nat

\* TxIDs start at (1,1)
TxIDs == Views \X SeqNums

\* This models uses a dummy applications where read-write transactions 
\* append an integer to a list and then read the list
Txs == Nat

HistoryTypeOK ==
    \A i \in DOMAIN history:
        \/  /\ history[i].type \in {RwTxRequested, RoTxRequested}
            /\ history[i].tx \in Txs
        \/  /\ history[i].type \in {RwTxReceived, RoTxReceived}
            /\ history[i].tx \in Txs
            /\ history[i].observed \in Seq(Txs)
            /\ history[i].tx_id \in TxIDs
        \/  /\ history[i].type = TxStatusReceived
            /\ history[i].tx_id \in TxIDs
            /\ history[i].status \in TxStatuses

\* History is append-only
HistoryMonoProp ==
    [][IsPrefix(history, history')]_history

AllRwReceivedIsFirstSentInv ==
    \A i \in DOMAIN history :
        history[i].type = RwTxReceived
        => \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = RwTxRequested
            /\ history[j].tx = history[i].tx

AllRoReceivedIsFirstSentInv ==
    \A i \in DOMAIN history :
        history[i].type = RoTxReceived
        => \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = RoTxRequested
            /\ history[j].tx = history[i].tx

\* All responses must have an associated request earlier in the history
AllReceivedIsFirstSentInv ==
    /\ AllRwReceivedIsFirstSentInv 
    /\ AllRoReceivedIsFirstSentInv

\* Transaction IDs uniquely identify read-write transactions
UniqueTxsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = RwTxReceived} :
        history[i].tx_id = history[j].tx_id 
        => history[i].tx = history[j].tx

\* Each read-write transaction has a unique transaction ID
UniqueTxIdsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = RwTxReceived} :
        history[i].tx = history[j].tx
        => history[i].tx_id = history[j].tx_id  

\* Sequence numbers uniquely identify all transactions
\* This does not hold unless there is only a single CCF node
UniqueSeqNumsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = RwTxReceived} :
        history[i].tx_id[2] = history[j].tx_id[2] 
        => history[i].tx = history[j].tx  

\* Committed transactions have unique sequence numbers
\* This is a weaker version of UniqueSeqNumsInv
\* This always holds (except during DR)
UniqueSeqNumsCommittedInv ==
    \A i,j,k,l \in DOMAIN history:
        \* Event k is the committed status received for the transaction in event i
        /\ history[i].type = RwTxReceived
        /\ history[k].type = TxStatusReceived
        /\ history[k].status = CommittedStatus
        /\ history[i].tx_id = history[k].tx_id
        \* Event l is the committed status received for the transaction in event j
        /\ history[j].type = RwTxReceived
        /\ history[l].type = TxStatusReceived
        /\ history[l].status = CommittedStatus
        /\ history[j].tx_id = history[l].tx_id
        \* Same sequences numbers imples same transaction
        /\ history[i].tx_id[2] = history[j].tx_id[2] 
        => history[i].tx = history[j].tx  


\* A transaction status cannot be both committed and invalid
CommittedOrInvalidInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = TxStatusReceived}:
        /\ history[i].tx_id = history[j].tx_id
        => history[i].status = history[j].status

\* If a transaction is committed then so are all others from the same term with smaller seqnums
\* These transaction cannot be invalid
OnceCommittedPrevCommittedInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = TxStatusReceived}:
        /\ history[i].status = CommittedStatus
        /\ history[i].tx_id[1] = history[j].tx_id[1]
        /\ history[j].tx_id[2] <= history[i].tx_id[2]
        => history[j].status = CommittedStatus

\* If a transaction is invalid then so are all others from the same term with greater seqnums
OnceInvalidNextInvalidInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = TxStatusReceived}:
        /\ history[i].status = InvalidStatus
        /\ history[i].tx_id[1] = history[j].tx_id[1]
        /\ history[j].tx_id[2] >= history[i].tx_id[2]
        => history[j].status = InvalidStatus

\* The following is strengthened variant of CommittedOrInvalidInv
CommittedOrInvalidStrongInv ==
    /\ OnceCommittedPrevCommittedInv
    /\ OnceInvalidNextInvalidInv

\* Responses never observe requests that have not been sent
OnlyObserveSentRequestsInv ==
    \A i \in {x \in DOMAIN history : history[x].type = RwTxReceived} :
        ToSet(history[i].observed) \subseteq 
        {history[j].tx : j \in {k \in DOMAIN history : 
            /\ k < i 
            /\ history[k].type = RwTxRequested}}

\* All responses never observe the same request more than once
AtMostOnceObservedInv ==
    \A i \in DOMAIN history :
        history[i].type = RwTxReceived
        => \A seqnum_x, seqnum_y \in DOMAIN history[i].observed:
            seqnum_x # seqnum_y 
            => history[i].observed[seqnum_x] # history[i].observed[seqnum_y]

\* All committed read-write txs observe all previously committed txs (wrt to real-time)
\* Note that this requires committed txs to be observed from their response, 
\* not just from when the client learns they were committed
AllCommittedObservedInv ==
    \A i, j, k, l, m \in DOMAIN history :
        /\ history[i].type = RwTxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = CommittedStatus
        /\ history[j].tx_id = history[i].tx_id
        /\ k > i \* note k > i not just k > j
        /\ history[k].type = RwTxRequested
        /\ history[l].type = RwTxReceived
        /\ history[k].tx = history[l].tx
        /\ history[m].type = TxStatusReceived
        /\ history[m].status = CommittedStatus
        /\ history[l].tx_id = history[m].tx_id
        => Contains(history[l].observed, history[i].tx)

\* All committed read-only txs observe all previously committed txs (wrt to real-time)
\* Note that this requires committed txs to be observed from their response, 
\* not just from when the client learns they were committed
AllCommittedObservedRoInv ==
    \A i, j, k, l, m \in DOMAIN history :
        /\ history[i].type = RwTxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = CommittedStatus
        /\ history[j].tx_id = history[i].tx_id
        /\ k > i 
        /\ history[k].type = RoTxRequested
        /\ history[l].type = RoTxReceived
        /\ history[k].tx = history[l].tx
        /\ history[m].type = TxStatusReceived
        /\ history[m].status = CommittedStatus
        /\ history[l].tx_id = history[m].tx_id
        => Contains(history[l].observed, history[i].tx)

\* Invalid requests are not observed by any other requests
\* This is vacuously true for single node CCF services and does not hold for multi node services
InvalidNotObservedInv ==
    \A i, j, k \in DOMAIN history:
        /\ history[i].type = RwTxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = InvalidStatus
        /\ history[k].type = RwTxReceived
        /\ i # k
        => history[i].tx \notin ToSet(history[k].observed)

\* A weaker variant of InvalidNotObservedInv which states that invalid requests are 
\* not observed by committed requests
InvalidNotObservedByCommittedInv ==
    \A i, j, k, l \in DOMAIN history:
        /\ history[i].type = RwTxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = InvalidStatus
        /\ history[k].type = RwTxReceived
        /\ history[l].type = TxStatusReceived
        /\ history[l].type = CommittedStatus
        /\ history[k].tx_id = history[l]
        /\ i # k
        => history[i].tx \notin ToSet(history[k].observed)

\* A history is serializable then there exists a execution sequence which is consistent 
\* with client observations. This property completely ignores the order of events.
\* If any request observes A before B then every request must observe A before B
\* In this model, every request execution observes itself
\* This invariant ignores transaction IDs and whether transactions are committed
\* This invariant only holds for a single node CCF service
AllSerializableInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = RwTxReceived
        /\ history[j].type = RwTxReceived
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)

\* A weaker version of AllSerializableInv which only considers committed requests
\* If any committed request observes A before B then every committed request must observe A before B
CommittedSerializableInv ==
    \A i,j,k,l \in DOMAIN history:
        \* Event k is the committed status received for the transaction in event i
        /\ history[i].type = RwTxReceived
        /\ history[k].type = TxStatusReceived
        /\ history[k].status = CommittedStatus
        /\ history[i].tx_id = history[k].tx_id
        \* Event l is the committed status received for the transaction in event j
        /\ history[j].type = RwTxReceived
        /\ history[l].type = TxStatusReceived
        /\ history[l].status = CommittedStatus
        /\ history[j].tx_id = history[l].tx_id
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)

\* Linearizability, or equivalently, strict serializability for a single object system.
\* This is not checked in cfg files as underlying properties are checked seperately
CommittedLinearizableInv ==
    /\ CommittedSerializableInv
    /\ AllCommittedObservedInv
    /\ AtMostOnceObservedInv

\*Debugging invariant to check specific states are reachable

SomeCommittedTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = CommittedStatus)

SomeInvalidTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = InvalidStatus)

====