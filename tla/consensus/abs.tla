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

CONSTANT StartTerm
ASSUME /\ StartTerm \in Terms
       /\ \A t \in Terms : StartTerm <= t

\* Commit logs from each node
\* Each log is append-only and the logs will never diverge.
VARIABLE cLogs

TypeOK ==
    cLogs \in [Servers -> Seq(Terms)]

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
    /\ \E s \in Seq(Terms) :
            cLogs' = [cLogs EXCEPT ![i] = @ \o s]

ExtendAxiom(i) ==
    \* i has the longest log.
    /\ \A j \in Servers : Len(cLogs[j]) \leq Len(cLogs[i])
    \* cLogs remains a function mapping from servers to logs.
    /\ cLogs' \in [Servers -> Seq(Terms)]
    \* i *extends* its log
    /\ IsPrefix(cLogs[i], cLogs'[i])
    \* The other logs remain the same.
    /\ \A j \in Servers \ {i} : cLogs'[j] = cLogs[j]

\* Extend and ExtendAxiom are logically equivalent definitions.  However,
\* TLC can check ExtendAxiom more efficiently when checking refinement,
\* due to the absence of the existential quantifier in the definition.
\* The same is true for CopyMaxAndExtend and CopyMaxAndExtendAxiom below.
LEMMA ASSUME NEW i \in Servers PROVE
    ExtendAxiom(i) <=> Extend(i)
OMITTED 

\* Copy one of the longest logs (from whoever server
\* has it) and extend it further upto length k. This
\* is equivalent to  Copy(i) \cdot Extend(i, k)  ,
\* that TLC cannot handle.
CopyMaxAndExtend(i) ==
    \E j \in Servers :
        /\ \A r \in Servers: Len(cLogs[r]) \leq Len(cLogs[j])
        /\ \E s \in Seq(Terms) :
            cLogs' = [cLogs EXCEPT ![i] = cLogs[j] \o s]

CopyMaxAndExtendAxiom(i) ==
    \E s \in Servers :
        /\ \A r \in Servers: Len(cLogs[r]) \leq Len(cLogs[s])
        \* cLogs remains a function mapping from servers to logs.
        /\ cLogs' \in [Servers -> Seq(Terms)]
        \* i *extends* s' log
        /\ IsPrefix(cLogs[s], cLogs'[i])
        \* The other logs remain the same.
        /\ \A j \in Servers \ {i} : cLogs'[j] = cLogs[j]

LEMMA ASSUME NEW i \in Servers PROVE
    CopyMaxAndExtendAxiom(i) <=> CopyMaxAndExtend(i)
OMITTED 

\* The only possible actions are to append log entries.
\* By construction there cannot be any conflicting log entries
\* Log entries are copied if the node's log is not the longest.
NextAxiom ==
    \E i \in Servers : 
        \/ Copy(i) 
        \/ ExtendAxiom(i)
        \/ CopyMaxAndExtendAxiom(i)

SpecAxiom == Init /\ [][NextAxiom]_cLogs

Next ==
    \E i \in Servers : 
        \/ Copy(i) 
        \/ Extend(i)
        \/ CopyMaxAndExtend(i)

Spec ==
    Init /\ [][Next]_cLogs

THEOREM Spec <=> SpecAxiom

----

InSync ==
    []<>(\A i, j \in Servers : cLogs[i] = cLogs[j])

FairSpec ==
    /\ Spec
    /\ WF_cLogs(Next) /\ \A s \in Servers: <>[][Copy(s)]_cLogs

THEOREM FairSpec => InSync

MachineClosedFairSpec ==
    /\ Spec
    /\ WF_cLogs(Next)

Syncing ==
    \* At the level of ccfraft, the desired property is that commitIndex of
    \* all (active) nodes repeatedly increases, i.e., 
    \*      []<>(\A s \in Servers: commitIndex[s] < commitIndex'[s]) 
    \* . Note the \le and not \leq comparison!  This is stronger (and a liveness
    \* property) compared to 
    \*      [][\A s \in Servers: commitIndex[s] < commitIndex'[s]]_commitIndex
    []<><<\E s \in Servers: IsStrictPrefix(cLogs[s], cLogs'[s])>>_cLogs

THEOREM MachineClosedFairSpec => Syncing

AllSyncing ==
    []<><<\A s \in Servers: IsStrictPrefix(cLogs[s], cLogs'[s])>>_cLogs

\* NOT A THEOREM:  MachineClosedFairSpec => AllSyncing
----

\* abs models ccfraft's logs up to the commitIndex and the extension of the
\* leader’s log past the commitIndex.  However, contrary to ccfraft, the
\* leader’s log in abs is never trimmed.  The corresponding property in
\* ccfraft is CommittedLogAppendOnlyProp.
AppendOnlyProp ==
    [][\A i \in Servers : IsPrefix(cLogs[i], cLogs'[i])]_cLogs

NoConflicts ==
    \A i, j \in Servers : 
        \/ IsPrefix(cLogs[i], cLogs[j]) 
        \/ IsPrefix(cLogs[j], cLogs[i])

EquivExtendProp ==
    [][\A i \in Servers : 
        Extend(i) <=> ExtendAxiom(i)]_cLogs

EquivCopyMaxAndExtendProp ==
    [][\A i \in Servers : 
        CopyMaxAndExtend(i) <=> CopyMaxAndExtendAxiom(i)]_cLogs
====