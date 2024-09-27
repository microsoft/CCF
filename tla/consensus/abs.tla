---- MODULE abs ----
\* Abstract specification for a distributed consensus algorithm.
\* Assumes that any node can atomically inspect the state of all other nodes. 

EXTENDS Sequences, SequencesExt, Naturals, FiniteSets, FiniteSetsExt, Relation

CONSTANT Servers
ASSUME IsFiniteSet(Servers)

\* Terms is (strictly) totally ordered with a smallest element.
CONSTANT Terms
ASSUME /\ IsStrictlyTotallyOrderedUnder(<, Terms) 
       /\ \E min \in Terms : \A t \in Terms : t <= min

\* See `max_uncommitted_tx_count` in raft.h: Maximum number of
\* uncommitted transactions allowed before the primary refuses
\* new transactions. Unlimited if set to 0.
CONSTANT MaxUncommittedCount
ASSUME MaxUncommittedCount \in Nat

\* Commit logs from each node
\* Each log is append-only and the logs will never diverge.
VARIABLE cLogs

TypeOK ==
    cLogs \in [Servers -> Seq(Terms)]

StartTerm == Min(Terms)

InitialLogs == 
    UNION {[ 1..n -> {StartTerm} ] : n \in {0,2,4}}
    
Init ==
    cLogs \in [Servers -> InitialLogs]

\* A node i can copy a ledger suffix from another node j.
Copy(i) ==
    \E j \in Servers : 
        /\ Len(cLogs[j]) > Len(cLogs[i])
        /\ \E l \in 1..(Len(cLogs[j]) - Len(cLogs[i])) : 
                cLogs' = [cLogs EXCEPT ![i] = @ \o SubSeq(cLogs[j], Len(@) + 1, Len(@) + l)]

\* A node i with the longest log can non-deterministically extend
\* its log by any finite number of log entries.  An implementation
\* may choose a particular number of log entries by which to extend
\* the log to prevent the leader from racing ahead of the followers.
Extend(i) ==
    /\ \A j \in Servers : Len(cLogs[j]) \leq Len(cLogs[i])
    /\ \E s \in BoundedSeq(Terms, MaxUncommittedCount) :
            cLogs' = [cLogs EXCEPT ![i] = @ \o s]

\* Copy one of the longest logs (from whoever server
\* has it) and extend it further upto length k. This
\* is equivalent to  Copy(i) \cdot Extend(i, k)  ,
\* that TLC cannot handle.
CopyMaxAndExtend(i) ==
    \E j \in Servers :
        /\ \A r \in Servers: Len(cLogs[r]) \leq Len(cLogs[j])
        /\ \E s \in BoundedSeq(Terms, MaxUncommittedCount) :
            cLogs' = [cLogs EXCEPT ![i] = cLogs[j] \o s]

\* The only possible actions are to append log entries.
\* By construction there cannot be any conflicting log entries
\* Log entries are copied if the node's log is not the longest.
Next ==
    \E i \in Servers : 
        \/ Copy(i) 
        \/ Extend(i)
        \/ CopyMaxAndExtend(i)

AbsSpec == Init /\ [][Next]_cLogs

AppendOnlyProp ==
    [][\A i \in Servers : IsPrefix(cLogs[i], cLogs'[i])]_cLogs

NoConflicts ==
    \A i, j \in Servers : 
        \/ IsPrefix(cLogs[i], cLogs[j]) 
        \/ IsPrefix(cLogs[j], cLogs[i])

====