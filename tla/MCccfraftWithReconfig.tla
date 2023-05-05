---------- MODULE MCccfraftWithReconfig ----------
EXTENDS ccfraft, TLC

Servers_mc == {NodeOne, NodeTwo}
Configurations == <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>

\*  SNIPPET_START: mc_config

MCIsInConfigurations(i, newConfiguration) ==
    /\ reconfigurationCount < Len(Configurations)-1
    \* +1 because TLA+ sequences are 1-index
    \* +1 to lookup the *next* and not the current configuration. 
    /\ newConfiguration = Configurations[reconfigurationCount+2]

\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
MCInTermLimit(i) ==
    currentTerm[i] < 2

\* Limit number of requests (new entries) that can be made
MCInRequestLimit ==
    clientRequests <= 2

\* Limit on number of request votes that can be sent to each other node
MCInRequestVoteLimit(i,j) ==
    votesRequested[i][j] < 1

\* Limit number of duplicate messages sent to the same server
MCInMessagesLimit(i, j, index, msg) ==
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

\* Limit number of times a RetiredLeader server sends commit notifications
MCInCommitNotificationLimit(i) ==
    commitsNotified[i][2] < 2

\* Limit max number of simultaneous candidates
MCInMaxSimultaneousCandidates(i) ==
    Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : state[s] = Candidate}) < 1
\* SNIPPET_END: mc_config

mc_spec == Spec

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers_mc)

\* Exclude messagesSent variable s.t. two states are considered equal if they only differ in the number of messages sent.
View == << reconfigurationVars, <<messages, commitsNotified>>, serverVars, candidateVars, leaderVars, logVars >>

===================================