---------- MODULE MCccfraft ----------
EXTENDS ccfraft, TLC

Servers_mc == {NodeOne, NodeTwo, NodeThree}
Configurations == <<{NodeOne, NodeTwo, NodeThree}>>

\*  SNIPPET_START: mc_config
MCIsInConfigurations(i, newConfiguration) ==
    /\ reconfigurationCount < Len(Configurations)-1
    /\ newConfiguration = Configurations[reconfigurationCount+2]

\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
MCInTermLimit(i) ==
    currentTerm[i] < 2

\* Limit number of requests (new entries) that can be made
RequestLimit == 1
MCInRequestLimit ==
    clientRequests <= RequestLimit

\* Limit on number of request votes that can be sent to each other node
MCInRequestVoteLimit(i,j) ==
    votesRequested[i][j] < 1

\* Limit number of duplicate messages sent to the same server
MCInMessagesLimit(i, j, index) ==
    IF Len(messagesSent[i][j]) >= index
    THEN messagesSent[i][j][index] < 1
    ELSE TRUE

\* Limit number of times a RetiredLeader server sends commit notifications
MCInCommitNotificationLimit(i) ==
    commitsNotified[i][2] < 0

\* Limit max number of simultaneous candidates
MCInMaxSimultaneousCandidates(i) ==
    Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : state[s] = Candidate}) < 1
\* SNIPPET_END: mc_config

mc_spec == Spec

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers_mc)

----

\* Returns true if server i has committed value v, false otherwise
IsCommittedByServer(v,i) ==
    IF commitIndex[i]  = 0
    THEN FALSE
    ELSE \E k \in 1..commitIndex[i] :
        /\ log[i][k].contentType = TypeEntry
        /\ log[i][k].value = v

\* This invariant shows that at least one value is committed on at least one server
DebugInvAnyCommitted ==
    \lnot (\E v \in 1..RequestLimit : \E i \in Servers : IsCommittedByServer(v,i))

\* This invariant shows that all values are committed on at least one server each
DebugInvAllCommitted ==
    \lnot (\A v \in 1..RequestLimit : \E i \in Servers : IsCommittedByServer(v,i))

===================================