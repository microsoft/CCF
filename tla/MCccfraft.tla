---------- MODULE MCccfraft ----------
EXTENDS ccfraft, TLC

1Configuration == <<{NodeOne, NodeTwo, NodeThree}>>
3Configurations == <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>

CONSTANT Configurations
ASSUME Configurations \in Seq(SUBSET Servers)

CONSTANT MaxTermLimit
ASSUME MaxTermLimit \in Nat

CONSTANT MaxCommitsNotified
ASSUME MaxCommitsNotified \in Nat

ToServers ==
    UNION Range(Configurations)

CCF == INSTANCE ccfraft

\* This file controls the constants as seen below.
\* In addition to basic settings of how many nodes are to be model checked,
\* the model allows to place additional limitations on the state space of the program.
MCChangeConfigurationInt(i, newConfiguration) ==
    /\ reconfigurationCount < Len(Configurations)-1
    \* +1 because TLA+ sequences are 1-index
    \* +1 to lookup the *next* and not the current configuration. 
    /\ newConfiguration = Configurations[reconfigurationCount+2]
    /\ CCF!ChangeConfigurationInt(i, newConfiguration)

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
    /\ Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : state[s] = Candidate}) < 1
    /\ CCF!Timeout(i)

\* Limit on client requests
RequestLimit == 2

\* Limit number of requests (new entries) that can be made
MCClientRequest(i) ==
    /\ clientRequests <= RequestLimit
    /\ CCF!ClientRequest(i)

\* Limit on number of request votes that can be sent to each other node
MCRequestVote(i,j) ==
    /\ votesRequested[i][j] < 1
    /\ CCF!RequestVote(i,j)

\* CCF: Limit how many identical append entries messages each node can send to another
\* Limit number of duplicate messages sent to the same server
MCSend(msg) ==
    \* One AppendEntriesRequest per node-pair at a time:
    \* a) No AppendEntries request from i to j.
    /\ ~ \E n \in Messages:
        /\ n.dest = msg.dest
        /\ n.source = msg.source
        /\ n.term = msg.term
    \* b) No (corresponding) AppendEntries response from j to i.
    /\ ~ \E n \in Messages:
        /\ n.dest = msg.source
        /\ n.source = msg.dest
        /\ n.term = msg.term
        /\ n.type = AppendEntriesResponse
    /\ CCF!Send(msg)

\* CCF: Limit the number of times a RetiredLeader server sends commit
\* notifications per commit Index and server
MCNotifyCommit(i,j) ==
    /\ \/ commitsNotified[i][1] < commitIndex[i]
       \/ commitsNotified[i][2] < MaxCommitsNotified
    /\ CCF!NotifyCommit(i,j)

\* Limit max number of simultaneous candidates
MCInMaxSimultaneousCandidates(i) ==
    Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : state[s] = Candidate}) < 1

mc_spec == Spec

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers)

\* Include all variables in the view, which is similar to defining no view.
View == << reconfigurationVars, <<messages, commitsNotified>>, serverVars, candidateVars, leaderVars, logVars >>

----

\* Returns true if server i has committed value v, false otherwise
IsCommittedByServer(v,i) ==
    IF commitIndex[i]  = 0
    THEN FALSE
    ELSE \E k \in 1..commitIndex[i] :
        /\ log[i][k].contentType = TypeEntry
        /\ log[i][k].request = v

\* This invariant shows that at least one value is committed on at least one server
DebugInvAnyCommitted ==
    \lnot (\E v \in 1..RequestLimit : \E i \in Servers : IsCommittedByServer(v,i))

\* This invariant shows that all values are committed on at least one server each
DebugInvAllCommitted ==
    \lnot (\A v \in 1..RequestLimit : \E i \in Servers : IsCommittedByServer(v,i))

===================================