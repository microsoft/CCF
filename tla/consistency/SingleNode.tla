---- MODULE SingleNode ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* This specification has been inspired by https://github.com/tlaplus/azure-cosmos-tla
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html
\* SingleNode considers a single node CCF service, so no view changes

EXTENDS ExternalHistory

\* Upper bound of the number of client events
\* Note that this abstract specification does not model CCF nodes so there's no
\* constant for the number of nodes
CONSTANT HistoryLimit

\* Abstract ledgers that contains only client transactions (no signatures)
\* Indexed by view, each ledger is the ledger associated with leader of that view 
\* In practice, the ledger of every CCF node is one of these or a prefix for one of these
\* This could be switched to a tree which can represent forks more elegantly
VARIABLES ledgers

LedgerTypeOK ==
    \A view \in DOMAIN ledgers:
        \A seqnum \in DOMAIN ledgers[view]:
            \* Each ledger entry is tuple containing a view and tx
            \* The ledger entry index is the sequence number
            /\ ledgers[view][seqnum].view \in Views
            /\ ledgers[view][seqnum].tx \in Txs

\* In this abstract version of CCF's consensus layer, each ledger is append-only
LedgersMonoProp ==
    [][\A view \in DOMAIN ledgers: IsPrefix(ledgers[view], ledgers[view]')]_ledgers

vars == << history, ledgers >>

TypeOK ==
    /\ HistoryTypeOK
    /\ LedgerTypeOK

Init ==
    /\ history = <<>>
    /\ ledgers = [ x \in {1} |-> <<>>]

IndexOfLastRequested ==
    SelectLastInSeq(history, LAMBDA e : e.type \in {RwTxRequest, RoTxRequest})

NextRequestId ==
    IF IndexOfLastRequested = 0 THEN 0 ELSE history[IndexOfLastRequested].tx+1

\* Submit new read-write transaction
\* This could be extended to add a notion of session and then check for session consistency
RwTxRequestAction ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> RwTxRequest, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgers

\* Execute a read-write transaction
RwTxExecuteAction ==
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxRequest
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

\* Response to a read-write transaction
RwTxResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        \* Check request has been received and executed but not yet responded to
        /\ history[i].type = RwTxRequest
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RwTxResponse
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in DOMAIN ledgers:
            /\ \E seqnum \in DOMAIN ledgers[view]: 
                /\ history[i].tx = ledgers[view][seqnum].tx
                /\ history' = Append(
                    history,[
                        type |-> RwTxResponse, 
                        tx |-> history[i].tx, 
                        observed |-> [x \in 1..seqnum |-> ledgers[view][x].tx],
                        tx_id |-> <<ledgers[view][seqnum].view, seqnum>>] )
    /\ UNCHANGED ledgers

\* Sending a committed status message
\* Note that a request could only be committed if its in the highest view's ledger
StatusCommittedResponseAction ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxResponse
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

\* A CCF service with a single node will never have a view change
\* so the log will never be rolled back and thus tranasction IDs cannot be invalid
NextSingleNodeAction ==
    \/ RwTxRequestAction
    \/ RwTxExecuteAction
    \/ RwTxResponseAction
    \/ StatusCommittedResponseAction


SpecSingleNode == Init /\ [][NextSingleNodeAction]_vars

====