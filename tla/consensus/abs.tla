---- MODULE abs ----
\* Abstract specification for a distributed consensus algorithm.

EXTENDS Sequences, SequencesExt, Naturals, FiniteSets, SequencesExt

CONSTANT Servers, Terms, RequestLimit, StartTerm

\* Commit logs from each node
\* Each log is append-only
VARIABLE CLogs

\* Max log length
MaxLogLength == 4 + (RequestLimit*2) + Cardinality(Terms)

\* All possible completed logs
Logs == [1..MaxLogLength -> Terms] 

Init ==
    CLogs \in [Servers -> {
        << >>,
        << StartTerm, StartTerm >>,
        << StartTerm, StartTerm, StartTerm, StartTerm >>}]

\* A node can copy a ledger suffix from another node.
Copy(i) ==
    \E j \in Servers : 
        /\ Len(CLogs[j]) > Len(CLogs[i])
        /\ \E l \in 1..(Len(CLogs[j]) - Len(CLogs[i])) : 
                CLogs' = [CLogs EXCEPT ![i] = CLogs[i] \o SubSeq(CLogs[j], Len(CLogs[i]) + 1, Len(CLogs[i]) + l)]

\* The node with the longest log can extend its log.
Extend(i) ==
    /\ \A j \in Servers : Len(CLogs[j]) \leq Len(CLogs[i])
    /\ \E l \in 0..(MaxLogLength - Len(CLogs[i])) : 
        \E s \in [1..l -> Terms] :
            CLogs' = [CLogs EXCEPT ![i] = CLogs[i] \o s]

\* The only possible actions are to append log entries.
\* By construction there cannot be any conflicting log entries
\* Log entries are copied if the node is not the longest.
Next ==
    \E i \in Servers : 
        \/ Copy(i) 
        \/ Extend(i)

AbsSpec == Init /\ [][Next]_CLogs


AppendOnlyProp ==
    [][\A i \in Servers : IsPrefix(CLogs[i], CLogs'[i])]_CLogs

NoConflicts ==
    \A i, j \in Servers : 
        \/ IsPrefix(CLogs[i], CLogs[j]) 
        \/ IsPrefix(CLogs[j], CLogs[i])

====