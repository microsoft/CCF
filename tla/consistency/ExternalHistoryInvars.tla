---- MODULE ExternalHistoryInvars ----

EXTENDS ExternalHistory

\* Read-write transaction responses always follow an associated request
AllRwReceivedIsFirstSentInv ==
    \A i \in DOMAIN history :
        history[i].type = RwTxResponse
        => \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = RwTxRequest
            /\ history[j].tx = history[i].tx

\* Read-only transaction responses always follow an associated request
\* Note that since multiple read requests can receive the same transaction ID this
\* invariant specifies only that at least one request was sent before the responses.
AllRoReceivedIsFirstSentInv ==
    \A i \in DOMAIN history :
        history[i].type = RoTxResponse
        => \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = RoTxRequest
            /\ history[j].tx = history[i].tx

\* All responses must have an associated request earlier in the history (except tx status)
AllReceivedIsFirstSentInv ==
    /\ AllRwReceivedIsFirstSentInv 
    /\ AllRoReceivedIsFirstSentInv

\* Transaction IDs uniquely identify read-write transactions
\* Note that it does not hold for read-only transactions
UniqueTxsInv ==
    \A i, j \in DOMAIN history:
        /\ history[i].type = RwTxResponse
        /\ history[j].type = RwTxResponse
        /\ history[i].tx_id = history[j].tx_id 
        => history[i].tx = history[j].tx

\* All transactions with the same ID observe the same transactions
SameObservationsInv ==
    \A i, j \in DOMAIN history:
        /\ history[i].type \in {RwTxResponse, RoTxResponse}
        /\ history[j].type \in {RwTxResponse, RoTxResponse}
        /\ history[i].tx_id = history[j].tx_id 
        => history[i].observed = history[j].observed

\* Transaction requested are unique
UniqueTxRequestsInv ==
    \A i, j \in DOMAIN history:
        /\ history[i].type \in {RwTxRequest, RoTxRequest}
        /\ history[j].type \in {RwTxRequest, RoTxRequest}
        /\ i # j
        => history[i].tx # history[j].tx


\* Each transaction has a unique transaction ID
UniqueTxIdsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type \in {RwTxResponse, RoTxResponse}} :
        history[i].tx = history[j].tx
        => history[i].tx_id = history[j].tx_id  

\* Sequence numbers uniquely identify read-write transactions
\* This invariant does not hold unless there is only a single CCF node
UniqueSeqNumsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = RwTxResponse} :
        history[i].tx_id[2] = history[j].tx_id[2] 
        => history[i].tx = history[j].tx  

\* Committed transactions have unique sequence numbers
\* This is a weaker version of UniqueSeqNumsInv
\* This always holds (except during DR)
UniqueSeqNumsCommittedInv ==
    \A i,j \in RwTxResponseCommittedEventIndexes:
        \* Same sequences numbers implies same transaction
        /\ history[i].tx_id[2] = history[j].tx_id[2] 
        => history[i].tx = history[j].tx  

\* A transaction status cannot be both committed and invalid
CommittedOrInvalidInv ==
    CommittedTxIDs \intersect InvalidTxIDs = {}

\* If a transaction is committed then so are all others from the same term with smaller seqnums
\* These transactions cannot be invalid
OnceCommittedPrevCommittedInv ==
    \A i, j \in TxStatusReceivedEventIndexes:
        /\ history[i].status = CommittedStatus
        /\ history[i].tx_id[1] = history[j].tx_id[1]
        /\ history[j].tx_id[2] <= history[i].tx_id[2]
        => history[j].status = CommittedStatus

\* If a transaction is invalid then so are all others from the same term with greater seqnums
OnceInvalidNextInvalidInv ==
    \A i, j \in TxStatusReceivedEventIndexes:
        /\ history[i].status = InvalidStatus
        /\ history[i].tx_id[1] = history[j].tx_id[1]
        /\ history[j].tx_id[2] >= history[i].tx_id[2]
        => history[j].status = InvalidStatus

\* The following is strengthened variant of CommittedOrInvalidInv
CommittedOrInvalidStrongInv ==
    /\ OnceCommittedPrevCommittedInv
    /\ OnceInvalidNextInvalidInv


\* Responses never observe transactions that have not been requested
OnlyObserveSentRequestsInv ==
    \A i \in {x \in DOMAIN history : history[x].type \in {RoTxResponse, RwTxResponse}} :
        ToSet(history[i].observed) \subseteq 
        {history[j].tx : j \in {k \in DOMAIN history : 
            /\ k < i 
            /\ history[k].type = RwTxRequest}}

\* All responses never observe the same request more than once
AtMostOnceObservedInv ==
    \A i \in DOMAIN history :
        history[i].type \in {RoTxResponse, RwTxResponse}
        => \A seqnum_x, seqnum_y \in DOMAIN history[i].observed:
            seqnum_x # seqnum_y 
            => history[i].observed[seqnum_x] # history[i].observed[seqnum_y]


\* All committed read-write txs observe all previously committed txs (wrt to real-time)
\* Note that this requires committed txs to be observed from their response, 
\* not just from when the client learns they were committed
AllCommittedObservedInv ==
    \A i \in RwTxResponseCommittedEventIndexes :
        \A j \in RwTxRequestCommittedEventIndexes :
            \A k \in RwTxResponseCommittedEventIndexes :
                /\ history[k].tx = history[j].tx
                /\ i < j
                => Contains(history[k].observed, history[i].tx)

\* All committed read-only txs observe all previously committed txs (wrt to real-time)
\* Note that this requires committed txs to be observed from their response, 
\* not just from when the client learns they were committed
\* This does not hold for CCF services with multiple nodes
AllCommittedObservedRoInv ==
    \A i \in RwTxResponseCommittedEventIndexes :
        \A j \in RoTxRequestCommittedEventIndexes :
            \A k \in RoTxResponseCommittedEventIndexes :
                /\ history[k].tx = history[j].tx
                /\ i < j
                => Contains(history[k].observed, history[i].tx)

\* Invalid requests are not observed by any other requests
\* This is vacuously true for single node CCF services and does not hold for multi node services
InvalidNotObservedInv ==
    \A i, j, k \in DOMAIN history:
        /\ history[i].type = RwTxResponse
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = InvalidStatus
        /\ history[k].type = RwTxResponse
        /\ i # k
        => history[i].tx \notin ToSet(history[k].observed)


\* A weaker variant of InvalidNotObservedInv which states that invalid requests are 
\* not observed by committed requests
InvalidNotObservedByCommittedInv ==
    \A i, k \in RwTxResponseEventIndexes:
        i # k =>
        \A j \in InvalidEventIndexes:
            \A l \in CommittedEventIndexes:
                history[k].tx_id = history[l]
                => history[i].tx \notin ToSet(history[k].observed)

\* A history is serializable if there exists an execution sequence which is consistent 
\* with client observations. This property completely ignores the order of events.
\* If any request observes A before B then every request must observe A before B
\* In this model, every request execution observes itself
\* This invariant ignores transaction IDs and whether transactions are committed
\* This invariant only holds for a single node CCF service
RwSerializableInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = RwTxResponse
        /\ history[j].type = RwTxResponse
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)

\* A weaker version of RwSerializableInv which only considers committed requests
\* If any committed request observes A before B then every committed request must observe A before B
CommittedRwSerializableInv ==
    \A i, j \in RwTxResponseEventIndexes:
        \A k, l \in CommittedEventIndexes:
            \* Event k is the committed status received for the transaction in event i
            /\ history[i].tx_id = history[k].tx_id
            \* Event l is the committed status received for the transaction in event j
            /\ history[j].tx_id = history[l].tx_id
            => \/ IsPrefix(history[i].observed, history[j].observed)
               \/ IsPrefix(history[j].observed, history[i].observed)

\* Linearizability for read-write transactions
\* Or equivalently, strict serializability as we are modeling a single object system
\* Refer to "Linearizability: A Correctness Condition for Concurrent Objects" 
CommittedRwLinearizableInv ==
    /\ CommittedRwSerializableInv
    /\ AllCommittedObservedInv
    /\ AtMostOnceObservedInv

CommittedRwOrderedRealTimeInv == 
    \A i \in RwTxResponseCommittedEventIndexes :
        \A j \in RwTxRequestCommittedEventIndexes :
                i < j => TxIDStrictlyLessThan(history[i].tx_id, history[j].tx_id)

CommittedRwOrderedSerializableInv ==
    \A i \in DOMAIN CommittedObservedSorted \ Len(CommittedObservedSorted):
        CommittedObservedSorted[i+1].observed = Append(CommittedObservedSorted[i], CommittedObservedSorted[i+1].tx)

\* TxID ordered speculative linearizability for committed read-write transactions is the primary consistency
\* guarantee provided by CCF. Note that this invariant is stronger than traditional linearizability.
\* TxID ordered speculative linearizability means that once a rw transaction is committed, it is linearizable
\* and that the ordering of execution is consistent with the order of transaction IDs.
\* In CCF, a client receives a response before it learns that the transaction is committed, the speculative 
\* part of speculative linearizability means that time window for real-time ordering from the client's request 
\* to its initial response, instead of to when the client learns the transaction is committed. This time window 
\* is smaller and thus the ordering is more strict. 
\* We check TxID ordered speculative linearizability in two stages:
\* 1) We check that the rw committed transactions are serializable using the TxID order
\* 2) We check that the TxID order is consistent with the real-time order of client observations
CommittedRwOrderedSpecLinearizableInv ==
    /\ CommittedRwOrderedSerializableInv
    /\ CommittedRwOrderedRealTimeInv

\*Debugging invariants to check that specific states are reachable

SomeCommittedTxDebugInv == 
    Cardinality(CommittedTxIDs) = 0

SomeInvalidTxDebugInv ==
    Cardinality(InvalidTxIDs) = 0

\* Two different transactions are committed
MultiCommittedTxDebugInv ==
    Cardinality(CommittedTxIDs) <= 1

\* Two different invalid transactions
MultiInvalidTxDebugInv ==
    Cardinality(InvalidTxIDs) <= 1
    
====