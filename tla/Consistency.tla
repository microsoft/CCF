---- MODULE Consistency ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* This specification has been inspired by https://github.com/tlaplus/azure-cosmos-tla
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html

EXTENDS Naturals, Sequences, SequencesExt

\* Upper bound of the number of events
\* Note that this abstract specification does not model CCF nodes
CONSTANTS HistoryLimit

\* Event types
\* TODO: Add read-only transactions
CONSTANTS TxRequested, TxReceived, TxStatusRequested, TxStatusReceived
EventTypes == {
    TxRequested, 
    TxReceived, 
    TxStatusRequested, 
    TxStatusReceived
    }

\* Transaction statuses
\* This model does not include the unknown and pending status
CONSTANTS CommittedStatus, InvalidStatus
TxStatuses == {
    CommittedStatus,
    InvalidStatus
    }

\* History of events visible to clients
VARIABLES history

\* Abstract ledger which contains only client transactions (no signatures)
\* TODO: switch to a tree which can represent forks
VARIABLES ledger 

\* Set of ledgers which might be held by previous leaders
VARIABLES previous_ledgers

\* High water mark for the commit sequence number across all CCF nodes and all time
\* This commit sequence number is therefore monontonically increasing
VARIABLES commit_seqnum

\* View of current leader
VARIABLE view

vars == << history, ledger, commit_seqnum, view, previous_ledgers >>

Views == Nat
SeqNums == Nat
TxIDs == Views \X SeqNums

\* This models uses a dummy applications where transactions 
\* append an integer to a list and then read the list
Txs == Nat

\* TODO: add previous_ledgers
TypeOK ==
    /\ \A i \in DOMAIN history:
        \/  /\ history[i].type = TxRequested
            /\ history[i].tx \in Txs
        \/  /\ history[i].type = TxReceived
            /\ history[i].tx \in Txs
            /\ history[i].observed \in Seq(Txs)
            /\ history[i].tx_id \in TxIDs
        \/  /\ history[i].type = TxStatusRequested
            /\ history[i].tx_id \in TxIDs
        \/  /\ history[i].type = TxStatusReceived
            /\ history[i].tx_id \in TxIDs
            /\ history[i].status \in TxStatuses
    /\ \A i \in DOMAIN ledger:
        /\ ledger[i].view \in Views
        /\ ledger[i].tx \in Txs
    /\ commit_seqnum \in SeqNums
    /\ view \in Views

Init ==
    /\ history = <<>>
    /\ ledger = <<>>
    /\ commit_seqnum = 0
    /\ view = 1
    /\ previous_ledgers = {}

IndexOfLastSent ==
    SelectLastInSeq(history, LAMBDA e : e.type = TxRequested)

NextRequestId ==
    IF IndexOfLastSent = 0 THEN 0 ELSE history[IndexOfLastSent].tx+1

\* TODO: Add a notion of session and then check for session consistency
\* TODO: Add read-only transactions
TxRequest ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> TxRequested, tx |-> NextRequestId]
        )
    /\ UNCHANGED <<ledger, commit_seqnum, view, previous_ledgers>>

TxExecute ==
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxRequested 
        /\ {seqnum \in DOMAIN ledger: 
                history[i].tx = ledger[seqnum].tx} = {}
        /\ \A l \in previous_ledgers: 
            {seqnum \in DOMAIN l: 
                history[i].tx = l[seqnum].tx} = {}
        /\ ledger' = Append(ledger, [view |-> view, tx |-> history[i].tx])
        /\ UNCHANGED <<commit_seqnum, view, history, previous_ledgers>>

\* Response to a transaction request if its been received and not yet responded to
\* This assumes that every transaction is handled by the current leader (singular)
\* TODO: remove this assumption
TxResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxRequested
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = TxReceived
            /\ history[j].tx = history[i].tx} = {}
        /\ \E seqnum \in DOMAIN ledger: 
            /\ history[i].tx = ledger[seqnum].tx
            /\ history' = Append(
                history,[
                    type |-> TxReceived, 
                    tx |-> history[i].tx, 
                    observed |-> [x \in 1..seqnum |-> ledger[x].tx],
                    tx_id |-> <<ledger[seqnum].view,seqnum>>]
                )
        /\ UNCHANGED <<commit_seqnum, view, ledger, previous_ledgers>>

\* Request transaction status if a transaction response has been received
\* Multiple status requests may be sent for the same transaction ID
\* TODO: Remove action to cut down state space
StatusRequest ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxReceived
        /\ history' =  Append(
            history,[
                type |-> TxStatusRequested, 
                tx_id |-> history[i].tx_id]
            )
    /\ UNCHANGED <<commit_seqnum, view, ledger, previous_ledgers>>


StatusCommittedResponse ==
    /\ Len(history) < HistoryLimit
    /\ commit_seqnum # 0
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxStatusRequested
        \* Check tx status request has not already been replied to
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = TxStatusReceived
            /\ history[j].tx_id = history[i].tx_id} = {}
        \* Check the tx_id is committed
        /\ history[i].tx_id[2] <= commit_seqnum
        /\ ledger[history[i].tx_id[2]].view = history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> CommittedStatus]
            )
    /\ UNCHANGED <<ledger, commit_seqnum, view, previous_ledgers>>


IncreaseCommitSeqnum ==
    /\ commit_seqnum' \in commit_seqnum..Len(ledger)
    /\ UNCHANGED <<ledger, history, view, previous_ledgers>>

\* A CCF service will a single node will never have a leader election
\* so the log will never be rolled back and thus tranasction IDs cannot be invalid
NextSingleNode ==
    \/ TxRequest
    \/ TxExecute
    \/ TxResponse
    \/ StatusRequest
    \/ StatusCommittedResponse
    \/ IncreaseCommitSeqnum

StatusInvalidResponse ==
    /\ Len(history) < HistoryLimit
    /\ commit_seqnum # 0
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxStatusRequested
        \* Check tx status request has not already been replied to
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = TxStatusReceived
            /\ history[j].tx_id = history[i].tx_id} = {}
        \* Check the tx_id is committed
        /\ history[i].tx_id[2] <= commit_seqnum
        /\ ledger[history[i].tx_id[2]].view # history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> InvalidStatus]
            )
    /\ UNCHANGED <<ledger, commit_seqnum, view, previous_ledgers>>

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
\* Note that the view is incremented by one to reduce state space but could increase arbitrarily
TruncateLedger ==
    \E i \in (commit_seqnum + 1)..Len(ledger) :
        /\ ledger' = SubSeq(ledger, 1, i - 1)
        /\ view' = view + 1 
        /\ previous_ledgers' = previous_ledgers \union {ledger}
        /\ UNCHANGED <<commit_seqnum, history>>

NextMultiNode ==
    \/ NextSingleNode
    \/ TruncateLedger
    \/ StatusInvalidResponse

CommittedStatusForCommittedOnlyInv ==
    \A i \in DOMAIN history:
        /\ history[i].type = TxStatusReceived
        /\ history[i].status = CommittedStatus
        => history[i].tx_id[2] <= commit_seqnum


\* All responses must have an associated request earlier in the history
AllReceivedIsFirstSentInv ==
    \A i \in {x \in DOMAIN history : history[x].type = TxReceived} :
        \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = TxRequested
            /\ history[j].tx = history[i].tx


\* All requests observe all previously committed requests (wrt to real-time)
\* Note that this is stronger than is needed for linearizability which only requires
\* that committed requests observe all previously committed requests
AllCommittedObservedInv ==
    \A i, j, k, l \in DOMAIN history :
        /\ history[i].type = TxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = CommittedStatus
        /\ history[j].tx_id = history[i].tx_id
        /\ k > j 
        /\ history[k].type = TxRequested
        /\ history[l].type = TxReceived
        /\ history[k].tx = history[l].tx
        => history[i].tx \in ToSet(history[l].observed)

\* Invalid requests are not observed by any other requests
\* This is vacuously true for single node CCF services and does not hold for multi node services
InvalidNotObservedInv ==
    \A i, j, k \in DOMAIN history:
        /\ history[i].type = TxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = InvalidStatus
        /\ history[k].type = TxReceived
        /\ i # k
        => history[i].tx \notin ToSet(history[k].observed)

\* A weaker variant of InvalidNotObservedInv which states that invalid requests are 
\* not observed by committed requests
InvalidNotObservedByCommittedInv ==
    \A i, j, k, l \in DOMAIN history:
        /\ history[i].type = TxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = InvalidStatus
        /\ history[k].type = TxReceived
        /\ history[l].type = TxStatusReceived
        /\ history[l].type = CommittedStatus
        /\ history[k].tx_id = history[l]
        /\ i # k
        => history[i].tx \notin ToSet(history[k].observed)

\* Responses never observe requests that have not been sent
OnlyObserveSentRequestsInv ==
    \A i \in {x \in DOMAIN history : history[x].type = TxReceived} :
        ToSet(history[i].observed) \subseteq 
        {history[j].tx : j \in {k \in DOMAIN history : 
            /\ k < i 
            /\ history[k].type = TxRequested}}

\* Transaction IDs should uniquely identify transactions
UniqueTxIdsInv ==
    \A i, j \in {x \in DOMAIN history : history[x].type = TxReceived} :
        history[i].tx_id = history[j].tx_id 
        => history[i].tx = history[j].tx   

\* A transaction ID cannot be both committed and invalid
CommittedOrInvalidInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = TxStatusReceived
        /\ history[j].type = TxStatusReceived
        /\ history[i].tx_id = history[j].tx_id
        => history[i].status = history[j].status

\* A history is serializable then there exists a execution sequence which is consistent 
\* with client observations. This property completely ignores the order of events.
\* If any request observes A before B then every request must observe A before B
\* In this model, every request execution observes itself
\* This invariant ignores transaction IDs and whether transactions are committed
\* This invariant only holds for a single node CCF service
AllSerializableInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = TxReceived
        /\ history[j].type = TxReceived
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)

\* A weaker version of AllSerializableInv which only considers committed requests
\* If any committed request observes A before B then every committed request must observe A before B
CommittedSerializableInv ==
    \A i,j,k,l \in DOMAIN history:
        \* Event k is the committed status received for the transaction in event i
        /\ history[i].type = TxReceived
        /\ history[k].type = TxStatusReceived
        /\ history[k].status = CommittedStatus
        /\ history[i].tx_id = history[k].tx_id
        \* Event l is the committed status received for the transaction in event j
        /\ history[j].type = TxReceived
        /\ history[l].type = TxStatusReceived
        /\ history[l].status = CommittedStatus
        /\ history[j].tx_id = history[l].tx_id
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)

CommittedlinearizableInv ==
    /\ CommittedSerializableInv
    /\ AllCommittedObservedInv

SpecSingleNode == Init /\ [][NextSingleNode]_vars

SpecMultiNode == Init /\ [][NextMultiNode]_vars

\* This debugging action allows committed transaction to be rolled back
DecreaseCommitSeqnumUnsafe ==
    /\ commit_seqnum' \in 0..commit_seqnum
    /\ UNCHANGED <<ledger, history>>

NextUnsafe == 
    \/ NextMultiNode
    \/ DecreaseCommitSeqnumUnsafe

SpecUnsafe == Init /\ [][NextUnsafe]_vars

SomeCommittedTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = CommittedStatus)

SomeInvalidTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = InvalidStatus)

====