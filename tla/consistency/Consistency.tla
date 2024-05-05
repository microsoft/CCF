---- MODULE Consistency ----

EXTENDS Naturals, Sequences

----------------------------------------------------------------------

\* tla-web doesn't have a builtin for the standard module's Sequences!SelectSeq.
\* This is why its definition is included under a new name here.  TLC will suffer
\* a slowdown because it's module override won't be active for MySelectSeq.
MySelectSeq(s, Test(_)) == 
  LET F[i \in 0..Len(s)] == 
        IF i = 0 THEN << >>
                 ELSE IF Test(s[i]) THEN Append(F[i-1], s[i])
                                    ELSE F[i-1]
  IN F[Len(s)]

----------------------------------------------------------------------

\* The following four operators are taken from the CommunityModule's SequencesExt,
\* because tla-web does not have a module system.
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

Last(s) == s[Len(s)]

SelectLastInSeq(seq, Test(_)) ==
  LET I == { i \in 1..Len(seq) : Test(seq[i]) }
  IN IF I # {} THEN Max(I) ELSE 0

IsPrefix(s, t) ==
  Len(s) <= Len(t) /\ SubSeq(s, 1, Len(s)) = SubSeq(t, 1, Len(s))

----------------------------------------------------------------------

RwTxRequest == "RwTxRequest"
RwTxResponse == "RwTxResponse"
RoTxRequest == "RoTxRequest"
RoTxResponse == "RoTxResponse"
TxStatusReceived == "TxStatusReceived"

CommittedStatus == "CommittedStatus"
InvalidStatus == "InvalidStatus"
TxStatuses == {
    CommittedStatus,
    InvalidStatus
    }

FirstBranch == 1

Views == Nat

\* Sequence numbers start at 1, 0 is used a null value
SeqNums == Nat

\* TxIDs consist of a view and sequence number and thus start at (1,1)
TxIDs == Views \X SeqNums

\* This models uses a dummy application where read-write transactions 
\* append an integer to a list and then reads the list
\* Read-only transactions simply read the list
Txs == Nat

----------------------------------------------------------------------

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

CommittedEventIndexes == 
    {i \in DOMAIN history: 
        /\ history[i].type = TxStatusReceived
        /\ history[i].status = CommittedStatus
        }

\* Transaction IDs which received committed status messages
CommittedTxIDs ==
    {history[i].tx_id: i \in CommittedEventIndexes}
CommitSeqNum == 
    Max({i[2]: i \in CommittedTxIDs} \cup {0})

\* Abstract ledgers that contains only client transactions (no signatures)
\* Indexed by view, each ledger is the ledger associated with leader of that view 
\* In practice, the ledger of every CCF node is one of these or a prefix for one of these
\* This could be switched to a tree which can represent forks more elegantly
VARIABLES ledgerBranches

LedgerTypeOK ==
    \A view \in DOMAIN ledgerBranches:
        \A seqnum \in DOMAIN ledgerBranches[view]:
            \* Each ledger entry is tuple containing a view and tx
            \* The ledger entry index is the sequence number
            /\ ledgerBranches[view][seqnum].view \in Views
            /\ "tx" \in DOMAIN ledgerBranches[view][seqnum] => ledgerBranches[view][seqnum].tx \in Txs

\* In this abstract version of CCF's consensus layer, each ledger is append-only
LedgersMonoProp ==
    [][\A view \in DOMAIN ledgerBranches: IsPrefix(ledgerBranches[view], ledgerBranches'[view])]_ledgerBranches

vars == << history, ledgerBranches >>

TypeOK ==
    /\ HistoryTypeOK
    /\ LedgerTypeOK

Init ==
    /\ history = <<>>
    /\ ledgerBranches = [ x \in 1..FirstBranch |-> <<>>]

IndexOfLastRequested ==
    SelectLastInSeq(history, LAMBDA e : e.type \in {RwTxRequest, RoTxRequest})

NextRequestId ==
    IF IndexOfLastRequested = 0 THEN 0 ELSE history[IndexOfLastRequested].tx+1

\* Submit new read-write transaction
\* This could be extended to add a notion of session and then check for session consistency
RwTxRequestAction ==
    /\ history' = Append(
        history, 
        [type |-> RwTxRequest, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgerBranches

\* Execute a read-write transaction
RwTxExecuteAction(i) ==
\* RwTxExecuteAction ==
\*     /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxRequest
        \* Check transaction has not already been added to a ledger
        /\ \A view \in DOMAIN ledgerBranches: 
            \A seqnum \in DOMAIN ledgerBranches[view]: 
                "tx" \in DOMAIN ledgerBranches[view][seqnum]
                => history[i].tx /= ledgerBranches[view][seqnum].tx
        \* Note that a transaction can be added to any ledger, simulating the fact
        \* that it can be picked up by the current leader or any former leader
        /\ \E view \in FirstBranch..Len(ledgerBranches):
                ledgerBranches' = [ledgerBranches EXCEPT ![view] = 
                    Append(@,[view |-> view, tx |-> history[i].tx])]
        /\ UNCHANGED history

LedgerBranchTxOnly(branch) ==
    LET SubBranch == MySelectSeq(branch, LAMBDA e : "tx" \in DOMAIN e)
    IN [i \in DOMAIN SubBranch |-> SubBranch[i].tx]

\* Response to a read-write transaction
RwTxResponseAction(i) ==
\* RwTxResponseAction ==
\*     /\ \E i \in DOMAIN history :
        \* Check request has been received and executed but not yet responded to
        /\ history[i].type = RwTxRequest
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RwTxResponse
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in FirstBranch..Len(ledgerBranches):
            /\ \E seqnum \in DOMAIN ledgerBranches[view]: 
                /\ "tx" \in DOMAIN ledgerBranches[view][seqnum]
                /\ history[i].tx = ledgerBranches[view][seqnum].tx
                /\ history' = Append(
                    history,[
                        type |-> RwTxResponse, 
                        tx |-> history[i].tx, 
                        observed |-> LedgerBranchTxOnly(SubSeq(ledgerBranches[view],1,seqnum)),
                        tx_id |-> <<ledgerBranches[view][seqnum].view, seqnum>>] )
    /\ UNCHANGED ledgerBranches

\* Sending a committed status message
\* Note that a request could only be committed if it's in the highest view's ledger
StatusCommittedResponseAction(i) ==
\* StatusCommittedResponseAction ==
\*     /\ \E i \in DOMAIN history :
           /\ history[i].type = RwTxResponse
           /\ Len(Last(ledgerBranches)) >= history[i].tx_id[2]
           /\ Last(ledgerBranches)[history[i].tx_id[2]].view = history[i].tx_id[1]
           \* There is no future InvalidStatus that's incompatible with this commit
           \* This is to accomodate StatusInvalidResponseAction making future commits invalid,
           \* and is an unnecessary complication for model checking. It does facilitate trace
           \* validation though, by allowing immediate processing of Invalids without
           \* needing to wait for the commit history knowledge to catch up.
           /\ \lnot \E j \in DOMAIN history:
                /\ history[j].type = TxStatusReceived
                /\ history[j].status = InvalidStatus
                /\ history[j].tx_id[1] = history[i].tx_id[1]
                /\ history[j].tx_id[2] <= history[i].tx_id[2]
           \* Reply
           /\ history' = Append(
              history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> CommittedStatus]
              )
    /\ UNCHANGED ledgerBranches

\* Append a transaction to the ledger which does not impact the state we are considering
AppendOtherTxnAction ==
    /\ \E view \in FirstBranch..Len(ledgerBranches):
        ledgerBranches' = [ledgerBranches EXCEPT ![view] = 
                    Append(@,[view |-> view])]
    /\ UNCHANGED history


\* Submit new read-only transaction
RoTxRequestAction ==
    /\ history' = Append(
        history, 
        [type |-> RoTxRequest, tx |-> NextRequestId]
        )
    /\ UNCHANGED ledgerBranches

\* Response to a read-only transaction request
\* Assumes read-only transactions are always forwarded
\* TODO: Separate execution and response
RoTxResponseAction(i) ==
\* RoTxResponseAction ==
\*     /\ \E i \in DOMAIN history :
        \* Check request has been received but not yet responded to
        /\ history[i].type = RoTxRequest
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = RoTxResponse
            /\ history[j].tx = history[i].tx} = {}
        /\ \E view \in FirstBranch..Len(ledgerBranches):
            /\ Len(ledgerBranches[view]) > 0
            /\ history' = Append(
                history,[
                    type |-> RoTxResponse, 
                    tx |-> history[i].tx, 
                    observed |-> LedgerBranchTxOnly(ledgerBranches[view]),
                    tx_id |-> <<ledgerBranches[view][Len(ledgerBranches[view])].view, Len(ledgerBranches[view])>>] )
    /\ UNCHANGED ledgerBranches

\* The set of views where the corresponding terms have all committed log entries
ViewWithAllCommitted ==
    {view \in DOMAIN ledgerBranches: 
        /\ Len(ledgerBranches[view]) >= CommitSeqNum
        /\  \/ CommitSeqNum = 0
            \/ <<ledgerBranches[view][CommitSeqNum].view, CommitSeqNum>> \in CommittedTxIDs }    

\* Simulates leader election by rolling back some number of uncommitted transactions and updating view
TruncateLedgerAction ==
    /\ \E view \in ViewWithAllCommitted:
        /\ \E i \in CommitSeqNum..Len(ledgerBranches[view]) :
            /\ ledgerBranches' = Append(ledgerBranches, SubSeq(ledgerBranches[view], 1, i))
            /\ UNCHANGED history

\* Sends status invalid message
StatusInvalidResponseAction(i) ==
\* StatusInvalidResponseAction ==
\*     /\ \E i \in DOMAIN history :
        /\ history[i].type = RwTxResponse
        \* either commit has passed seqnum but committed another transaction
        /\ \/ /\ CommitSeqNum >= history[i].tx_id[2]
              /\ Len(ledgerBranches[Len(ledgerBranches)]) >= history[i].tx_id[2]
              /\ ledgerBranches[Len(ledgerBranches)][history[i].tx_id[2]].view # history[i].tx_id[1]
        \* or commit hasn't reached seqnum but never will as current view is higher
            \/ /\ CommitSeqNum > 0
               /\ CommitSeqNum < history[i].tx_id[2]
               /\ ledgerBranches[Len(ledgerBranches)][CommitSeqNum].view > history[i].tx_id[1]
        \* or commit hasn't reached there,... but can never reach there
        \* note that this effectively allows StatusInvalidResponseAction to "declare" future transactions
        \* invalid, and requires a corresponding change in SingleNode::StatusCommittedResponseAction to
        \* constrain future commits. This combined change is unnecessary for model checking, but greatly
        \* simplifies trace validation. 
            \/ /\ history[i].tx_id[1] = Len(ledgerBranches)
               /\ history[i].tx_id[2] > CommitSeqNum
        \* Reply
        /\ history' = Append(
            history,[
                type |-> TxStatusReceived, 
                tx_id |-> history[i].tx_id,
                status |-> InvalidStatus]
            )
    /\ UNCHANGED ledgerBranches

\* A CCF service with a single node will never have a view change
\* so the log will never be rolled back and thus transaction IDs cannot be invalid
Next ==
    \/ TruncateLedgerAction
    \/ AppendOtherTxnAction
    \/ RwTxRequestAction
    \/ RoTxRequestAction
    \/ \E i \in DOMAIN history :
        \/ RwTxExecuteAction(i)
        \/ RwTxResponseAction(i)
        \/ RoTxResponseAction(i)
        \/ StatusCommittedResponseAction(i)
        \/ StatusInvalidResponseAction(i)

Spec == Init /\ [][Next]_vars

====