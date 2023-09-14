---- MODULE Consistency ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* This specification has been inspired by https://github.com/tlaplus/azure-cosmos-tla
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html

EXTENDS Naturals, Sequences, SequencesExt

\* Upper bound of the number of events
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

\* High water mark for the commit sequence number across all CCF nodes and all time
\* This commit sequence number is therefore monontonically increasing
VARIABLES commit_seqnum

\* View of current leader
VARIABLE view

vars == << history, ledger, commit_seqnum, view >>

Views == Nat
SeqNums == Nat
TxIDs == Views \X SeqNums

\* This models uses a dummy applications where transactions read a list and append an integer
Txs == Nat

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
    /\ UNCHANGED <<ledger, commit_seqnum, view>>

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
        /\ ledger' = Append(ledger, [view |-> view, tx |-> history[i].tx])
        /\ history' = Append(
            history,[
                type |-> TxReceived, 
                tx |-> history[i].tx, 
                observed |-> [x \in DOMAIN ledger |-> ledger[x].tx],
                tx_id |-> <<view,Len(ledger)+1>>]
            )
        /\ UNCHANGED <<commit_seqnum, view>>

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
    /\ UNCHANGED <<commit_seqnum, view, ledger>>


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
    /\ UNCHANGED <<ledger, commit_seqnum, view>>

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
    /\ UNCHANGED <<ledger, commit_seqnum, view>>


IncreaseCommitSeqnum ==
    /\ commit_seqnum' \in commit_seqnum..Len(ledger)
    /\ UNCHANGED <<ledger, history, view>>

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
\* Note that the view is incremented by one to reduce state space but could increase arbitrarily
TruncateLedger ==
    \E i \in (commit_seqnum + 1)..Len(ledger) :
        /\ ledger' = SubSeq(ledger, 1, i - 1)
        /\ view' = view+1 
        /\ UNCHANGED <<commit_seqnum, history>>

Next ==
    \/ TxRequest
    \/ TxResponse
    \/ StatusRequest
    \/ StatusCommittedResponse
    \/ StatusInvalidResponse
    \/ IncreaseCommitSeqnum
    \/ TruncateLedger

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


\* All responses observe all previously successful requests
AllSuccessfulRequestObserveredInv ==
    \A i, j, k \in DOMAIN history :
        /\ history[i].type = TxReceived
        /\ history[j].type = TxStatusReceived
        /\ history[j].status = CommittedStatus
        /\ history[j].tx_id = history[i].tx_id
        /\ k > j 
        /\ history[k].type = TxReceived
        => history[i].tx \in ToSet(history[k].observed)

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

\* A Transaction ID cannot be both committed and invalid
CommittedOrInvalidInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = TxStatusReceived
        /\ history[j].type = TxStatusReceived
        /\ history[i].tx_id = history[j].tx_id
        => history[i].status = history[j].status

\* If any request observes A before B then every request must observe A before B
\* Note this invariant completely ignores the order of events and transaction IDs
SerializableInv ==
    \A i,j \in DOMAIN history:
        /\ history[i].type = TxReceived
        /\ history[j].type = TxReceived
        => \/ IsPrefix(history[i].observed, history[j].observed)
           \/ IsPrefix(history[j].observed, history[i].observed)


Spec == Init /\ [][Next]_vars

\* This debugging action allows committed transaction to be rolled back
DecreaseCommitSeqnumUnsafe ==
    /\ commit_seqnum' \in 0..commit_seqnum
    /\ UNCHANGED <<ledger, history>>

NextUnsafe == 
    \/ Next
    \/ DecreaseCommitSeqnumUnsafe

SpecUnsafe == Init /\ [][NextUnsafe]_vars

SomeCommittedTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = CommittedStatus)

SomeInvalidTxDebugInv ==
    \A i \in DOMAIN history: 
        ~(history[i].type = TxStatusReceived /\ history[i].status = InvalidStatus)

====