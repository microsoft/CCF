---------- MODULE MCccfraft ----------
EXTENDS ccfraft, StatsFile, MCAliases

CONSTANTS
    NodeOne, NodeTwo, NodeThree

\* No reconfiguration
1Configuration == <<{NodeOne, NodeTwo, NodeThree}>>
\* Atomic reconfiguration from NodeOne to NodeTwo
2Configurations == <<{NodeOne}, {NodeTwo}>>
\* Incremental reconfiguration from NodeOne to NodeOne and NodeTwo, and then to NodeTwo
3Configurations == <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>

CONSTANT Configurations
ASSUME Configurations \in Seq(SUBSET Servers)

CONSTANT MaxTermLimit
ASSUME MaxTermLimit \in Nat

\* Limit on client requests
CONSTANT RequestLimit
ASSUME RequestLimit \in Nat


ToServers ==
    UNION Range(Configurations)

CCF == INSTANCE ccfraft

\* This file controls the constants as seen below.
\* In addition to basic settings of how many nodes are to be model checked,
\* the model allows to place additional limitations on the state space of the program.

\* Limit the reconfigurations to the next configuration in Configurations
MCChangeConfigurationInt(i, newConfiguration) ==
    /\ Len(Configurations) > 1
    /\ configurations[i] # <<>>
    /\ \E configCount \in 1..Len(Configurations)-1:
        /\ Configurations[configCount] = CCF!MaxConfiguration(i)
        /\ CCF!ChangeConfigurationInt(i, Configurations[configCount+1])

\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
MCTimeout(i) ==
    \* Limit the term of each server to reduce state space
    /\ currentTerm[i] < MaxTermLimit
    \* Limit max number of simultaneous candidates
    \* We made several restrictions to the state space of Raft. However since we
    \* made these restrictions, Deadlocks can occur at places that Raft would in
    \* real-world deployments handle graciously.
    \* One example of this is if a Quorum of nodes becomes Candidate but can not
    \* timeout anymore since we constrained the terms. Then, an artificial Deadlock
    \* is reached. We solve this below. If TermLimit is set to any number >2, this is
    \* not an issue since breadth-first search will make sure that a similar
    \* situation is simulated at term==1 which results in a term increase to 2.
    /\ Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : leadershipState[s] = Candidate}) < 1
    /\ CCF!Timeout(i)

\* Limit number of requests (new entries) that can be made
MCClientRequest(i) ==
    \* Allocation-free variant of Len(SelectSeq(log[i], LAMBDA e: e.contentType = TypeEntry)) < RequestLimit
    /\ FoldSeq(LAMBDA e, count: IF e.contentType = TypeEntry THEN count + 1 ELSE count, 0, log[i]) < RequestLimit
    /\ CCF!ClientRequest(i)

MCSignCommittableMessages(i) ==
    \* The implementation periodically emits a signature for the current log, potentially causing consecutive
    \* signatures.  However, modeling consecutive sigs would result in a state space explosion, i.e., an infinite
    \* number of states.  Thus, we prevent a leader from creating consecutive sigs in the same term.  We assume
    \* that consecutive sigs will not violate safety or liveness.
    /\ log[i] # <<>> => \lnot (Last(log[i]).contentType = TypeSignature /\ Last(log[i]).term = currentTerm[i])
    /\ CCF!SignCommittableMessages(i)

\* CCF: Limit how many identical append entries messages each node can send to another
\* Limit number of duplicate messages sent to the same server
MCSend(msg) ==
    \* One AppendEntriesRequest per node-pair at a time:
    \* a) No AppendEntries request from i to j.
    /\ ~ \E n \in Network!Messages:
        /\ n.dest = msg.dest
        /\ n.source = msg.source
        /\ n.term = msg.term
    \* b) No (corresponding) AppendEntries response from j to i.
    /\ ~ \E n \in Network!Messages:
        /\ n.dest = msg.source
        /\ n.source = msg.dest
        /\ n.term = msg.term
        /\ n.type = AppendEntriesResponse
    /\ CCF!Send(msg)

\* Disable CheckQuorum when model checking in CI to keep execution time manageable
MCCheckQuorum(i) ==
    UNCHANGED vars

MCInit ==
    /\ InitMessagesVars
    /\ InitCandidateVars
    /\ InitLeaderVars
    /\ IF Cardinality(Configurations[1]) = 1
       \* If the first config is just one node, we can start with a two-tx log and a single config.
       THEN InitLogConfigServerVars(Configurations[1], StartLog)
       \* If we want to start with multiple nodes, we can start with a four-tx log with a reconfiguration already appended.
       ELSE InitLogConfigServerVars(Configurations[1], JoinedLog)

\* Alternative to CCF!Spec that uses the above MCInit
mc_spec ==   
    /\ MCInit
    /\ [][Next]_vars

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers)

\* Include all variables in the view, which is similar to defining no view.
View == << reconfigurationVars, <<messages>>, serverVars, candidateVars, leaderVars, logVars >>

----

AllReconfigurationsCommitted == 
    \E s \in ToServers:
        \A c \in ToSet(Tail(Configurations)):
            \E i \in DOMAIN Committed(s):
                /\ HasTypeReconfiguration(Committed(s)[i])
                /\ Committed(s)[i].configuration = c

DebugAllReconfigurationsReachableInv ==
    ~AllReconfigurationsCommitted



===================================