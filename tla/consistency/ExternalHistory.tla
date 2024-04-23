---- MODULE ExternalHistory ----
\* Defines the notion of a externally observable client history and its associated properties.
\* The history differs for traditional client histories, as clients receive responses to 
\* transactions before they have been committed.

EXTENDS Naturals, Sequences, SequencesExt, FiniteSets, FiniteSetsExt

\* Event types recorded in the history
\* Note that transaction status requests are not modelled to reduce state space
\* Currently only read-write (Rw) transactions and read-only (Ro) transactions are modelled
\* Both transaction types are modelled as forward-always transactions
\* This could be extended to support more types of read-only transactions
CONSTANTS RwTxRequest, RwTxResponse, RoTxRequest, RoTxResponse, TxStatusReceived


\* Transaction statuses
\* This model does not include the unknown and pending status to reduce state space
CONSTANTS CommittedStatus, InvalidStatus
TxStatuses == {
    CommittedStatus,
    InvalidStatus
    }

\* Although views start at 1 in the consistency spec, this constant allows increasing the first branch
\* that can be appended to, to enable trace validation against the implementation, where view starts at 2
CONSTANT FirstBranch

\* Views start at 1, 0 is used a null value
Views == Nat

\* Sequence numbers start at 1, 0 is used a null value
SeqNums == Nat

\* TxIDs consist of a view and sequence number and thus start at (1,1)
TxIDs == Views \X SeqNums

\* This models uses a dummy application where read-write transactions 
\* append an integer to a list and then reads the list
\* Read-only transactions simply read the list
Txs == Nat

\* History of events visible to clients
VARIABLES history

HistoryTypeOK ==
    \A i \in DOMAIN history:
        \/  /\ history[i].type \in {RwTxRequest, RoTxRequest}
            /\ history[i].tx \in Txs
        \/  /\ history[i].type \in {RwTxResponse, RoTxResponse}
            /\ history[i].tx \in Txs
            /\ history[i].observed \in Seq(Txs)
            /\ history[i].tx_id \in TxIDs
        \/  /\ history[i].type = TxStatusReceived
            /\ history[i].tx_id \in TxIDs
            /\ history[i].status \in TxStatuses

\* History is append-only
\* Like HistoryTypeOK, this property should always hold
HistoryMonoProp ==
    [][IsPrefix(history, history')]_history

\* Indexes into history for events where a committed status is received
CommittedEventIndexes == 
    {i \in DOMAIN history: 
        /\ history[i].type = TxStatusReceived
        /\ history[i].status = CommittedStatus
        }

\* Transaction IDs which received committed status messages
CommittedTxIDs ==
    {history[i].tx_id: i \in CommittedEventIndexes}
        
InvalidEventIndexes == 
    {i \in DOMAIN history: 
        /\ history[i].type = TxStatusReceived
        /\ history[i].status = InvalidStatus
        }

\* Transaction IDs which received invalid status messages
InvalidTxIDs ==
    {history[i].tx_id: i \in InvalidEventIndexes}

\* Highest commit sequence number
CommitSeqNum == 
    Max({i[2]: i \in CommittedTxIDs} \cup {0})

RwTxResponseEventIndexes ==
    {x \in DOMAIN history : history[x].type = RwTxResponse}
        
RoTxResponseEventIndexes ==
    {x \in DOMAIN history : history[x].type = RoTxResponse}

TxResponseEventIndexes ==
    RwTxResponseEventIndexes \union RoTxResponseEventIndexes


\* Note these index are the events where the transaction was responded to
RwTxResponseCommittedEventIndexes ==
    {x \in DOMAIN history : 
        /\ history[x].type = RwTxResponse
        /\ history[x].tx_id \in CommittedTxIDs}

RwTxRequestCommittedEventIndexes ==
    {x \in DOMAIN history :
        /\ history[x].type = RwTxRequest
        /\ \E y \in RwTxResponseCommittedEventIndexes:
            history[y].tx = history[x].tx}

\* Note these index are the events where the transaction was responded to
RoTxResponseCommittedEventIndexes ==
    {x \in DOMAIN history : 
        /\ history[x].type = RoTxResponse
        /\ history[x].tx_id \in CommittedTxIDs}

RoTxRequestCommittedEventIndexes ==
    {x \in DOMAIN history :
        /\ history[x].type = RoTxRequest
        /\ \E y \in RoTxResponseCommittedEventIndexes:
            history[y].tx = history[x].tx}

TxStatusReceivedEventIndexes ==
    {x \in DOMAIN history : history[x].type = TxStatusReceived}

RoTxRequestedCommittedEventIndexes ==
    {x \in DOMAIN history : 
        /\ history[x].type = RoTxRequest
        /\ history[x].tx_id \in CommittedTxIDs}

====