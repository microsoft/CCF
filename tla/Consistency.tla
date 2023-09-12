---- MODULE Consistency ----

EXTENDS Naturals, Sequences

CONSTANTS Requests

VARIABLES clientHistory, requestNumber

vars == <<clientHistory, requestNumber>>

Init ==
    /\ clientHistory = <<>>
    /\ requestNumber = 0

SendRequest ==
    /\ requestNumber < Requests 
    /\ clientHistory' = Append(clientHistory, requestNumber)
    /\ requestNumber' = requestNumber + 1

Next ==
    /\ SendRequest

MonontonicRequests ==
    \/ Len(clientHistory) <= 1
    \/ \A i \in 1..Len(clientHistory)-1 : 
        clientHistory[i] < clientHistory[i+1]

Spec == Init /\ [][Next]_vars

====