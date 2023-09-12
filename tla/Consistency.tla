---- MODULE Consistency ----

EXTENDS Naturals, Sequences, SequencesExt

CONSTANTS RequestTotal

VARIABLES clientHistory, requestNumber, log

vars == <<clientHistory, requestNumber, log>>

TypeOK ==
    /\ \A i \in DOMAIN clientHistory:
        /\ clientHistory[i].type \in {"Sent","Received"}
        /\ clientHistory[i].id \in Nat
        /\ clientHistory[i].type = "Recieved"  
            => ToSet(clientHistory[i].observed) \subseteq Nat
    /\ requestNumber \in Nat
    /\ ToSet(log) \subseteq Nat

Init ==
    /\ clientHistory = <<>>
    /\ requestNumber = 0
    /\ log = <<>>

SendRequest ==
    /\ requestNumber < RequestTotal 
    /\ clientHistory' = Append(
        clientHistory, 
        [type |-> "Sent", id |-> requestNumber]
        )
    /\ requestNumber' = requestNumber + 1
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
        /\ UNCHANGED requestNumber

Next ==
    \/ SendRequest
    \/ SendResponse

MonontonicRequests ==
    \/ Len(clientHistory) <= 1
    \/ \A i \in 1..Len(clientHistory)-1 : 
        clientHistory[i].id < clientHistory[i+1].id

AllReceivedIsFirstSentInv ==
    \A i \in {x \in DOMAIN clientHistory : clientHistory[x].type = "Received"} :
        \E j \in DOMAIN clientHistory : 
            /\ j < i 
            /\ clientHistory[j].type = "Sent"
            /\ clientHistory[j].id = clientHistory[i].id

Spec == Init /\ [][Next]_vars

====