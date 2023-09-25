---- MODULE SingleNode ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* This specification has been inspired by https://github.com/tlaplus/azure-cosmos-tla
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html
\* This spec considers a single node CCF service, so no view changes or rollbacks

EXTENDS ExternalHistory

\* Upper bound of the number of client events
\* Note that this abstract specification does not model CCF nodes
CONSTANT HistoryLimit

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

vars == <<history, ledgers >>

TypeOK ==
    /\ HistoryTypeOK
    /\ LedgerTypeOK

Init ==
    /\ history = <<>>
    /\ ledgers = [ x \in {1} |-> <<>>]

IndexOfLastRequested ==
    SelectLastInSeq(history, LAMBDA e : e.type \in {RwTxRequested, RoTxRequested})

NextRequestId ==
    IF IndexOfLastRequested = 0 THEN 0 ELSE history[IndexOfLastRequested].tx+1

\* Submit new read-write transaction
\* TODO: Add a notion of session and then check for session consistency
RwTxRequest ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> RwTxRequested, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgers

\* Execute transaction
RwTxExecute ==
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxRequested
        \* Check transaction has not already been added a ledger
        /\ \A view \in DOMAIN ledgers: 
            {seqnum \in DOMAIN ledgers[view]: 
                history[i].tx = ledgers[view][seqnum].tx} = {}
        \* Note that a transaction can be added to any ledger, simulating the fact
        \* that it can be picked up by the current leader or any former leader
        /\ \E view \in DOMAIN ledgers:
                ledgers' = [ledgers EXCEPT ![view] = 
                    Append(@,[view |-> view, tx |-> history[i].tx])]
        /\ UNCHANGED history

\* Response to a read-write transaction request
RwTxResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        \* Check request has been received and executed but not yet responded to
        /\ history[i].type = RwTxRequested
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RwTxReceived
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in DOMAIN ledgers:
            /\ \E seqnum \in DOMAIN ledgers[view]: 
                /\ history[i].tx = ledgers[view][seqnum].tx
                /\ history' = Append(
                    history,[
                        type |-> RwTxReceived, 
                        tx |-> history[i].tx, 
                        observed |-> [x \in 1..seqnum |-> ledgers[view][x].tx],
                        tx_id |-> <<ledgers[view][seqnum].view, seqnum>>] )
    /\ UNCHANGED ledgers

StatusCommittedResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxReceived
        /\ Len(ledgers[Len(ledgers)]) >= history[i].tx_id[2]
        /\ ledgers[Len(ledgers)][history[i].tx_id[2]].view = history[i].tx_id[1]
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> CommittedStatus]
            )
    /\ UNCHANGED ledgers

\* A CCF service with a single node will never have a leader election
\* so the log will never be rolled back and thus tranasction IDs cannot be invalid
NextSingleNode ==
    \/ RwTxRequest
    \/ RwTxExecute
    \/ RwTxResponse
    \/ StatusCommittedResponse


SpecSingleNode == Init /\ [][NextSingleNode]_vars

\* Submit new read-only transaction
RoTxRequest ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> RoTxRequested, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgers

\* Response to a read-only transaction request
\* Assumes read-only transactions are always forwarded
\* TODO: Seperate execution and response
RoTxResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        \* Check request has been received but not yet responded to
        /\ history[i].type = RoTxRequested
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RoTxReceived
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in DOMAIN ledgers:
            /\ Len(ledgers[view]) > 0
            /\ history' = Append(
                history,[
                    type |-> RoTxReceived, 
                    tx |-> history[i].tx, 
                    observed |-> [seqnum \in DOMAIN ledgers[view] |-> ledgers[view][seqnum].tx],
                    tx_id |-> <<ledgers[view][Len(ledgers[view])].view, Len(ledgers[view])>>] )
    /\ UNCHANGED ledgers

NextSingleNodeWithReads ==
    \/ NextSingleNode
    \/ RoTxRequest
    \/ RoTxResponse

SpecSingleNodeWithReads == Init /\ [][NextSingleNodeWithReads]_vars

====