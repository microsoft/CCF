---- MODULE abs ----
\* Abstract specification for a distributed consensus algorithm.
\* Assumes that any node can atomically inspect the state of all other nodes. 

EXTENDS Sequences, SequencesExt, Naturals, FiniteSets, FiniteSetsExt

CONSTANT Servers, Terms, MaxLogLength

\* Commit logs from each node
\* Each log is append-only and the logs will never diverge.
VARIABLE cLogs

TypeOK ==
    /\ cLogs \in [Servers -> 
        UNION {[1..l -> Terms] : l \in 0..MaxLogLength}]

StartTerm == Min(Terms)

InitialLogs == {
    <<>>,
    <<StartTerm, StartTerm>>,
    <<StartTerm, StartTerm, StartTerm, StartTerm>>}
    
Init ==
    cLogs \in [Servers -> InitialLogs]

\* A node i can copy a ledger suffix from another node j.
Copy(i) ==
    \E j \in Servers : 
        /\ Len(cLogs[j]) > Len(cLogs[i])
        /\ \E l \in 1..(Len(cLogs[j]) - Len(cLogs[i])) : 
                cLogs' = [cLogs EXCEPT ![i] = @ \o SubSeq(cLogs[j], Len(@) + 1, Len(@) + l)]

\* A node i with the longest log can extend its log upto length k.
Extend(i, k) ==
    /\ \A j \in Servers : Len(cLogs[j]) \leq Len(cLogs[i])
    /\ \E l \in 0..(k - Len(cLogs[i])) : 
        \E s \in [1..l -> Terms] :
            cLogs' = [cLogs EXCEPT ![i] = @ \o s]

ExtendToMax(i) == Extend(i, MaxLogLength)

\* The only possible actions are to append log entries.
\* By construction there cannot be any conflicting log entries
\* Log entries are copied if the node's log is not the longest.
Next ==
    \E i \in Servers : 
        \/ Copy(i) 
        \/ ExtendToMax(i)

AbsSpec == Init /\ [][Next]_cLogs

AppendOnlyProp ==
    [][\A i \in Servers : IsPrefix(cLogs[i], cLogs'[i])]_cLogs

NoConflicts ==
    \A i, j \in Servers : 
        \/ IsPrefix(cLogs[i], cLogs[j]) 
        \/ IsPrefix(cLogs[j], cLogs[i])

====