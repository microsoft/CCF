---- MODULE Consistency ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* This specification has been inspired by https://github.com/tlaplus/azure-cosmos-tla
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html

EXTENDS Naturals, Sequences, SequencesExt

\* Upper bound of the number of client events
\* Note that this abstract specification does not model CCF nodes
CONSTANT HistoryLimit

CONSTANT ViewLimit

\* Event types
\* TODO: Add read-only transactions
CONSTANTS TxRequested, TxReceived, TxStatusReceived
EventTypes == {
    TxRequested, 
    TxReceived, 
    TxStatusReceived
    }

\* Transaction statuses
\* This model does not include the unknown and pending status
CONSTANTS CommittedStatus, InvalidStatus
TxStatuses == {
    CommittedStatus,
    InvalidStatus
    }

\* Views start at 1, 0 is used a null value
Views == Nat

\* Sequence numbers start at 1, 0 is used a null value
SeqNums == Nat

\* TxIDs start at (1,1)
TxIDs == Views \X SeqNums

\* This models uses a dummy applications where transactions 
\* append an integer to a list and then read the list
Txs == Nat

\* History of events visible to clients
VARIABLES history

HistoryTypeOK ==
    \A i \in DOMAIN history:
        \/  /\ history[i].type = TxRequested
            /\ history[i].tx \in Txs
        \/  /\ history[i].type = TxReceived
            /\ history[i].tx \in Txs
            /\ history[i].observed \in Seq(Txs)
            /\ history[i].tx_id \in TxIDs
        \/  /\ history[i].type = TxStatusReceived
            /\ history[i].tx_id \in TxIDs
            /\ history[i].status \in TxStatuses

\* Abstract ledgers that contains only client transactions (no signatures)
\* Indexed by view, each ledger is the ledger associated with leader of that view 
\* In practice, the ledger of every CCF node is one of these or a prefix for one of these
\* TODO: switch to a tree which can represent forks more elegantly
VARIABLES ledgers

LedgerTypeOK ==     
    \A view \in DOMAIN ledgers:
        \A seqnum \in DOMAIN ledgers[view]:
            \* Each ledger entry is tuple containing a view and tx
            \* The ledger entry index is the sequence number
            /\ ledgers[view][seqnum].view \in Views
            /\ ledgers[view][seqnum].tx \in Txs

\* The true commit point
\* High water mark for the commit sequence number across all CCF nodes and all time
\* This commit sequence number is thus monontonically increasing
VARIABLES commit_seqnum


vars == <<history, ledgers, commit_seqnum>>

TypeOK ==
    /\ HistoryTypeOK
    /\ LedgerTypeOK
    /\ commit_seqnum \in SeqNums

Init ==
    /\ history = <<>>
    /\ ledgers = [ x \in {1} |-> <<>>]
    /\ commit_seqnum = 0

IndexOfLastRequested ==
    SelectLastInSeq(history, LAMBDA e : e.type = TxRequested)

NextRequestId ==
    IF IndexOfLastRequested = 0 THEN 0 ELSE history[IndexOfLastRequested].tx+1

\* Submit new transaction
\* TODO: Add a notion of session and then check for session consistency
TxRequest ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> TxRequested, tx |-> NextRequestId]
        )
    /\ UNCHANGED <<ledgers, commit_seqnum>>

\* Execute transaction
TxExecute ==
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxRequested
        \* Check transaction has not already been added a ledger
        /\ \A view \in DOMAIN ledgers: 
            {seqnum \in DOMAIN ledgers[view]: 
                history[i].tx = ledgers[view][seqnum].tx} = {}
        \* Note that a transaction can be added to any ledger, simulating the fact
        \* that it can be picked up by the current leader or any former leader
        /\ \E view \in DOMAIN ledgers:
                ledgers' = [ledgers EXCEPT ![view] = 
                    Append(@,[view |-> view, tx |-> history[i].tx])]
        /\ UNCHANGED <<commit_seqnum, history>>

\* Response to a transaction request
TxResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        \* Check request has been received and executed but not yet responded to
        /\ history[i].type = TxRequested
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = TxReceived
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in DOMAIN ledgers:
            /\ \E seqnum \in DOMAIN ledgers[view]: 
                /\ history[i].tx = ledgers[view][seqnum].tx
                /\ history' = Append(
                    history,[
                        type |-> TxReceived, 
                        tx |-> history[i].tx, 
                        observed |-> [x \in 1..seqnum |-> ledgers[view][x].tx],
                        tx_id |-> <<ledgers[view][seqnum].view, seqnum>>] )
    /\ UNCHANGED <<commit_seqnum, ledgers>>

StatusCommittedResponse ==
    /\ Len(history) < HistoryLimit
    /\ commit_seqnum # 0
    /\ \E i \in DOMAIN history :
        /\ history[i].type = TxReceived
        \* Check the tx_id is committed
        /\ history[i].tx_id[2] <= commit_seqnum
        /\ ledgers[Len(ledgers)][history[i].tx_id[2]].view = history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> CommittedStatus]
            )
    /\ UNCHANGED <<ledgers, commit_seqnum>>


IncreaseCommitSeqnum ==
    /\ commit_seqnum' \in commit_seqnum..Len(ledgers[Len(ledgers)])
    /\ UNCHANGED <<ledgers, history>>

\* A CCF service with a single node will never have a leader election
\* so the log will never be rolled back and thus tranasction IDs cannot be invalid
NextSingleNode ==
    \/ TxRequest
    \/ TxExecute
    \/ TxResponse
    \/ StatusCommittedResponse
    \/ IncreaseCommitSeqnum

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
    /\ UNCHANGED <<ledgers, history>>

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