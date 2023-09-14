---- MODULE Consistency ----
\* A lightweight specification to define the externally visible behaviour of CCF
\* Where possible, naming should be consistent with https://microsoft.github.io/CCF/main/index.html

EXTENDS Naturals, Sequences, SequencesExt

CONSTANTS HistoryLimit

VARIABLES history

VARIABLES ledger 

\* High water mark for the commit sequence number across all CCF nodes and time
\* This commit sequence number is therefore monontonically increasing
VARIABLES commit_seqnum

vars == << history, ledger, commit_seqnum >>

TypeOK ==
    /\ \A i \in DOMAIN history:
        \/  /\ history[i].type = "TxSent"
            /\ history[i].id \in Nat
        \/  /\ history[i].type = "TxReceived"
            /\ history[i].id \in Nat
            /\ history[i].observed \in Seq(Nat)
            /\ history[i].tx_id \in Nat \X Nat
        \/  /\ history[i].type = "StatusReceived"
            /\ history[i].tx_id \in Nat \X Nat
            /\ history[i].status \in {"Pending","Committed"}
    /\ ledger \in Seq(Nat)
    /\ commit_seqnum \in Nat

Init ==
    /\ history = <<>>
    /\ ledger = <<>>
    /\ commit_seqnum = 0

IndexOfLastSent ==
    SelectLastInSeq(history, LAMBDA e : e.type = "TxSent")

NextRequestId ==
    IF IndexOfLastSent = 0 THEN 0 ELSE history[IndexOfLastSent].id+1

SendTxRequest ==
    /\ Len(history) < HistoryLimit
    /\ history' = Append(
        history, 
        [type |-> "TxSent", id |-> NextRequestId]
        )
    /\ UNCHANGED <<ledger, commit_seqnum>>

SendTxResponse ==
    /\ Len(history) < HistoryLimit
    /\ \E i \in DOMAIN history :
        /\ history[i].type = "TxSent"
        /\ {j \in DOMAIN history: 
            /\ j > i 
            /\ history[j].type = "TxReceived"
            /\ history[j].id = history[i].id} = {}
        /\ ledger' = Append(ledger, history[i].id)
        /\ history' = Append(
            history,[
                type |-> "TxReceived", 
                id |-> history[i].id, 
                observed |-> ledger,
                tx_id |-> <<1,Len(ledger)+1>>]
            )
        /\ UNCHANGED commit_seqnum

SendStatusResponse ==
    /\ Len(history) < HistoryLimit
    /\ \/ \E seqnum \in 1..Len(ledger):
            history' = Append(
                history,[
                    type |-> "StatusReceived", 
                    tx_id |-> <<1,seqnum>>,
                    status |-> "Pending"]
                )
       \/  /\ commit_seqnum # 0
           /\ \E seqnum \in 1..commit_seqnum:
            history' = Append(
                history,[
                    type |-> "StatusReceived", 
                    tx_id |-> <<1,seqnum>>,
                    status |-> "Committed"]
                )
    /\ UNCHANGED <<ledger, commit_seqnum>>

IncreaseCommitSeqnum ==
    /\ commit_seqnum' \in commit_seqnum..Len(ledger)
    /\ UNCHANGED <<ledger, history>>

TruncateLedger ==
    \E i \in (commit_seqnum + 1)..Len(ledger) :
        /\ ledger' = SubSeq(ledger, 1, i - 1)
        /\ UNCHANGED <<commit_seqnum, history>>

Next ==
    \/ SendTxRequest
    \/ SendTxResponse
    \/ SendStatusResponse
    \/ IncreaseCommitSeqnum
    \/ TruncateLedger


\* This debugging action allows committed transaction to be rolled back
DecreaseCommitSeqnumUnsafe ==
    /\ commit_seqnum' \in 0..commit_seqnum
    /\ UNCHANGED <<ledger, history>>

NextUnsafe == 
    \/ Next
    \/ DecreaseCommitSeqnumUnsafe

MonontonicRequests ==
    \/ Len(history) <= 1
    \/ \A i \in 1..Len(history)-1 : 
        history[i].id < history[i+1].id

\* All responses must have an associated request earlier in the history
AllReceivedIsFirstSentInv ==
    \A i \in {x \in DOMAIN history : history[x].type = "TxReceived"} :
        \E j \in DOMAIN history : 
            /\ j < i 
            /\ history[j].type = "TxSent"
            /\ history[j].id = history[i].id


\* All responses observe all previously successful requests
AllSuccessfulRequestObserveredInv ==
    \A i, j, k \in DOMAIN history :
        /\ history[i].type = "TxReceived"
        /\ history[j].type = "StatusReceived"
        /\ history[j].status = "Committed"
        /\ history[j].tx_id = history[i].tx_id
        /\ k > j 
        /\ history[k].type = "TxReceived"
        => history[i].id \in ToSet(history[k].observed)

\* Responses never observe requests that have not been sent
OnlyObserveSentRequestsInv ==
    \A i \in {x \in DOMAIN history : history[x].type = "TxReceived"} :
        ToSet(history[i].observed) \subseteq 
        {history[j].id : j \in {k \in DOMAIN history : 
            /\ k < i 
            /\ history[k].type = "TxSent"}}


Spec == Init /\ [][Next]_vars

SpecUnsafe == Init /\ [][NextUnsafe]_vars

====