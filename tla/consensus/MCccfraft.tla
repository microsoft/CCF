---------- MODULE MCccfraft ----------
EXTENDS ccfraft, MCAliases, TLC, IOUtils

CONSTANTS
    NodeOne, NodeTwo, NodeThree

Configurations ==
    LET default == <<{NodeOne, NodeTwo}>> IN
    IF "RAFT_CONFIGS" \in DOMAIN IOEnv THEN
          \* Don't parse and process the string Configurations but keep it simple and just check for known values.
          CASE IOEnv.RAFT_CONFIGS = "1C1N" -> <<{NodeOne}>>
            [] IOEnv.RAFT_CONFIGS = "1C2N" -> default
            [] IOEnv.RAFT_CONFIGS = "1C3N" -> <<{NodeOne, NodeTwo, NodeThree}>>
            [] IOEnv.RAFT_CONFIGS = "2C2N" -> <<{NodeOne}, {NodeTwo}>>
            [] IOEnv.RAFT_CONFIGS = "2C3N" -> <<{NodeOne, NodeTwo}, {NodeTwo, NodeThree}>>
            [] IOEnv.RAFT_CONFIGS = "3C2N" -> <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>
            [] OTHER -> Print("Unsupported value for RAFT_CONFIGS, defaulting to 1C2N: <<{NodeOne, NodeTwo}>>.", default)
    ELSE Print("RAFT_CONFIGS is not set, defaulting to 1C2N: <<{NodeOne, NodeTwo}>>.", default)
ASSUME Configurations \in Seq(SUBSET Servers)

TermCount ==
    IF "TERM_COUNT" \in DOMAIN IOEnv
    THEN atoi(IOEnv.TERM_COUNT)
    ELSE Print("TERM_COUNT is not set, defaulting to 0", 0)
ASSUME TermCount \in Nat

\* Limit on client requests
RequestCount ==
    IF "REQUEST_COUNT" \in DOMAIN IOEnv
    THEN atoi(IOEnv.REQUEST_COUNT)
    ELSE Print("REQUEST_COUNT is not set, defaulting to 3", 3)
ASSUME RequestCount \in Nat

ToServers ==
    UNION Range(Configurations)

CCF == INSTANCE ccfraft

MCCheckQuorum(i) ==
    IF "DISABLE_CHECK_QUORUM" \in DOMAIN IOEnv THEN FALSE ELSE CCF!CheckQuorum(i)

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
    /\ currentTerm[i] < StartTerm + TermCount
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

\* Limit the number of terms that can be reached
MCRcvProposeVoteRequest(i, j) ==
    /\ currentTerm[i] < StartTerm + TermCount
    /\ CCF!RcvProposeVoteRequest(i, j)

\* Limit number of requests (new entries) that can be made
MCClientRequest(i) ==
    \* Allocation-free variant of Len(SelectSeq(log[i], LAMBDA e: e.contentType = TypeEntry)) <= RequestCount
    /\ FoldSeq(LAMBDA e, count: IF e.contentType = TypeEntry THEN count + 1 ELSE count, 0, log[i]) <= RequestCount
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
        /\ n.type = AppendEntriesRequest
    \* b) No (corresponding) AppendEntries response from j to i.
    /\ ~ \E n \in Network!Messages:
        /\ n.dest = msg.source
        /\ n.source = msg.dest
        /\ n.term = msg.term
        /\ n.type = AppendEntriesResponse
    /\ CCF!Send(msg)

MCInitPreVoteStatus == PreVoteStatusTypeInv

MCInit ==
    /\ InitMessagesVars
    /\ InitCandidateVars
    /\ InitLeaderVars
    /\ MCInitPreVoteStatus
    /\ IF Cardinality(Configurations[1]) = 1
       \* If the first config is just one node, we can start with a two-tx log and a single config.
       THEN InitLogConfigServerVars(Configurations[1], StartLog)
       \* If we want to start with multiple nodes, we can start with a four-tx log with a reconfiguration already appended.
       ELSE InitLogConfigServerVars(Configurations[1], JoinedLog)

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers)

\* Include all variables in the view, which is similar to defining no view.
View == << reconfigurationVars, messageVars, serverVars, candidateVars, leaderVars, logVars >>

----

AllReconfigurationsCommitted == 
    \E s \in ToServers:
        \A c \in ToSet(Tail(Configurations)):
            \E i \in DOMAIN Committed(s):
                /\ HasTypeReconfiguration(Committed(s)[i])
                /\ Committed(s)[i].configuration = c

DebugAllReconfigurationsReachableInv ==
    \/ Len(Configurations) = 1 \* Prevent bogus violations if there is only one configuration.
    \/ ~AllReconfigurationsCommitted

DebugNotTooManySigsInv ==
    \A i \in Servers:
        FoldSeq(LAMBDA e, count: IF e.contentType = TypeSignature THEN count + 1 ELSE count, 0, log[i]) < 8

----

\* Initialize the counters for the Debug invariants to 0.
ASSUME TLCSet(0, [ DebugInvLeaderCannotStepDown |-> 0,
                   DebugInvSuccessfulCommitAfterReconfig |-> 0,
                   DebugInvRetirementReachable |-> 0,
                   DebugAppendEntriesRequests |-> 0,
                   DebugCommittedEntriesTermsInv |-> 0,
                   DebugNotTooManySigsInv |-> 0,  
                   DebugAllReconfigurationsReachableInv |-> 0 ])

\* A TLC state constraint that is always TRUE.  As a side-effect, it increments the counter for the given Debug invariant.
CoverageExpressions ==
    /\ DebugInvLeaderCannotStepDown => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugInvLeaderCannotStepDown = @ + 1 ] )
    /\ DebugInvSuccessfulCommitAfterReconfig => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugInvSuccessfulCommitAfterReconfig = @ + 1 ] )
    /\ DebugInvRetirementReachable => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugInvRetirementReachable = @ + 1 ] )
    /\ DebugAppendEntriesRequests => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugAppendEntriesRequests = @ + 1 ] )
    /\ DebugCommittedEntriesTermsInv => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugCommittedEntriesTermsInv = @ + 1 ] )
    /\ DebugNotTooManySigsInv => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugNotTooManySigsInv = @ + 1 ] )
    /\ DebugAllReconfigurationsReachableInv => TLCSet(0, [ TLCGet(0) EXCEPT !.DebugAllReconfigurationsReachableInv = @ + 1 ] )

\* AreAllCovered is a postcondition that will be violated if any of the CoverageExpressions above are uncovered, i.e., they
\* are *never* TRUE.
AreAllCovered ==
    \E s \in DOMAIN TLCGet(0) : TLCGet(0)[s] = 0 => Print(<<"Debug Invariant violations: ", ToString(TLCGet(0))>>, FALSE)

----

PostConditions ==
    AreAllCovered

----
\* Refinement

ABSExtend(i) == MappingToAbs!ExtendAxiom(i)
ABSCopyMaxAndExtend(i) == MappingToAbs!CopyMaxAndExtendAxiom(i)

===================================
