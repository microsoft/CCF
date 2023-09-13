---- MODULE Consistency ----

EXTENDS Naturals, Sequences, SequencesExt

CONSTANTS RequestLimit

VARIABLES clientHistory, log

vars == <<clientHistory, log>>

TypeOK ==
    /\ \A i \in DOMAIN clientHistory:
        /\ clientHistory[i].type \in {"Sent","Received"}
        /\ clientHistory[i].id \in Nat
        /\ clientHistory[i].type = "Recieved"  
            => ToSet(clientHistory[i].observed) \subseteq Nat
    /\ ToSet(log) \subseteq Nat

Init ==
    /\ clientHistory = <<>>
    /\ log = <<>>

IndexOfLastSent ==
    SelectLastInSeq(clientHistory, LAMBDA e : e.type = "Sent")

NextRequestId ==
    IF IndexOfLastSent = 0 THEN 0 ELSE clientHistory[IndexOfLastSent].id

SendRequest ==
    /\ NextRequestId < RequestLimit
    /\ clientHistory' = Append(
        clientHistory, 
        [type |-> "Sent", id |-> NextRequestId]
        )
    /\ UNCHANGED <<log>>

SendResponse ==
    \E i \in DOMAIN clientHistory :
        /\ clientHistory[i].type = "Sent"
        /\ {j \in DOMAIN clientHistory: 
            /\ j > i 
            /\ clientHistory[j].type = "Received"
            /\ clientHistory[j].id = clientHistory[i].id} = {}
        /\ log' = Append(log, clientHistory[i].id)
        /\ clientHistory' = Append(
            clientHistory,
            [type |-> "Received", id |-> clientHistory[i].id, observed |-> log]
            )

Next ==
    \/ SendRequest
    \/ SendResponse

MonontonicRequests ==
    \/ Len(clientHistory) <= 1
    \/ \A i \in 1..Len(clientHistory)-1 : 
        clientHistory[i].id < clientHistory[i+1].id

\* All responses must have an associated request earlier in the history
AllReceivedIsFirstSentInv ==
    \A i \in {x \in DOMAIN clientHistory : clientHistory[x].type = "Received"} :
        \E j \in DOMAIN clientHistory : 
            /\ j < i 
            /\ clientHistory[j].type = "Sent"
            /\ clientHistory[j].id = clientHistory[i].id

\* All responses observe all previous successful requests
AllSuccessfulRequestObserveredInv ==
    \A i \in {x \in DOMAIN clientHistory : clientHistory[x].type = "Received"} :
        \A j \in DOMAIN clientHistory : 
            /\ j > i 
            /\ clientHistory[j].type = "Received"
            => clientHistory[i].id \in ToSet(clientHistory[j].observed)

\* Responses never observe requests that have not been sent
OnlyObserveSentRequestsInv ==
    \A i \in {x \in DOMAIN clientHistory : clientHistory[x].type = "Received"} :
        ToSet(clientHistory[i].observed) \subseteq 
        {clientHistory[j].id : j \in {k \in DOMAIN clientHistory : 
            /\ k < i 
            /\ clientHistory[k].type = "Sent"}}


Spec == Init /\ [][Next]_vars

====