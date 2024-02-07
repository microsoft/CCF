---------- MODULE SIMccfraft ----------
EXTENDS ccfraft, TLC, Integers, StatsFile, IOUtils, MCAliases

CONSTANTS
    NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive

Servers_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}

----

SIMInit ==
/\ removedFromConfiguration = {}
/\ leadershipState = (NodeOne :> Follower @@ NodeTwo :> Leader @@ NodeThree :> Follower @@ NodeFour :> Follower @@ NodeFive :> Follower)
/\ matchIndex = (NodeOne :> (NodeOne :> 0 @@ NodeTwo :> 9 @@ NodeThree :> 9 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeTwo :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeThree :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeFour :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeFive :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0))
/\ votedFor = (NodeOne :> NodeTwo @@ NodeTwo :> NodeTwo @@ NodeThree :> NodeTwo @@ NodeFour :> NodeTwo @@ NodeFive :> Nil)
/\ commitIndex = (NodeOne :> 9 @@ NodeTwo :> 4 @@ NodeThree :> 4 @@ NodeFour :> 4 @@ NodeFive :> 4)
/\ membershipState = (NodeOne :> Active @@ NodeTwo :> Active @@ NodeThree :> Active @@ NodeFour :> Active @@ NodeFive :> Active)
/\ messages = (NodeOne :> <<>> @@ NodeTwo :> <<[type |-> AppendEntriesResponse, dest |-> NodeTwo, source |-> NodeThree, term |-> 3, success |-> FALSE, lastLogIndex |-> 4], [type |-> RequestVoteResponse, dest |-> NodeTwo, source |-> NodeThree, term |-> 5, voteGranted |-> TRUE]>> @@ NodeThree :> <<>> @@ NodeFour :> <<[type |-> AppendEntriesRequest, dest |-> NodeFour, source |-> NodeOne, term |-> 2, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<[term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature]>>, prevLogIndex |-> 4], [type |-> RequestVoteRequest, dest |-> NodeFour, source |-> NodeOne, term |-> 4, lastCommittableIndex |-> 8, lastCommittableTerm |-> 2], [type |-> AppendEntriesRequest, dest |-> NodeFour, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<>>, prevLogIndex |-> 8], [type |-> AppendEntriesRequest, dest |-> NodeFour, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<[term |-> 4, contentType |-> TypeSignature]>>, prevLogIndex |-> 8], [type |-> AppendEntriesRequest, dest |-> NodeFour, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 4, entries |-> <<>>, prevLogIndex |-> 9], [type |-> AppendEntriesRequest, dest |-> NodeFour, source |-> NodeTwo, term |-> 5, commitIndex |-> 4, prevLogTerm |-> 4, entries |-> <<>>, prevLogIndex |-> 9]>> @@ NodeFive :> <<[type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeOne, term |-> 2, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<[term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature]>>, prevLogIndex |-> 4], [type |-> RequestVoteRequest, dest |-> NodeFive, source |-> NodeTwo, term |-> 3, lastCommittableIndex |-> 8, lastCommittableTerm |-> 2], [type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeTwo, term |-> 3, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<>>, prevLogIndex |-> 8], [type |-> RequestVoteRequest, dest |-> NodeFive, source |-> NodeOne, term |-> 4, lastCommittableIndex |-> 8, lastCommittableTerm |-> 2], [type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<>>, prevLogIndex |-> 8], [type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<[term |-> 4, contentType |-> TypeSignature]>>, prevLogIndex |-> 8], [type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeOne, term |-> 4, commitIndex |-> 4, prevLogTerm |-> 4, entries |-> <<>>, prevLogIndex |-> 9], [type |-> RequestVoteRequest, dest |-> NodeFive, source |-> NodeTwo, term |-> 5, lastCommittableIndex |-> 9, lastCommittableTerm |-> 4], [type |-> AppendEntriesRequest, dest |-> NodeFive, source |-> NodeTwo, term |-> 5, commitIndex |-> 4, prevLogTerm |-> 4, entries |-> <<>>, prevLogIndex |-> 9]>>)
/\ isNewFollower = (NodeOne :> TRUE @@ NodeTwo :> FALSE @@ NodeThree :> TRUE @@ NodeFour :> TRUE @@ NodeFive :> FALSE)
/\ currentTerm = (NodeOne :> 5 @@ NodeTwo :> 5 @@ NodeThree :> 5 @@ NodeFour :> 5 @@ NodeFive :> 2)
/\ log = (NodeOne :> <<[term |-> 2, configuration |-> {NodeOne}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, configuration |-> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 4, contentType |-> TypeSignature]>> @@ NodeTwo :> <<[term |-> 2, configuration |-> {NodeOne}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, configuration |-> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 4, contentType |-> TypeSignature]>> @@ NodeThree :> <<[term |-> 2, configuration |-> {NodeOne}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, configuration |-> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, contentType |-> TypeEntry, request |-> 42], [term |-> 2, contentType |-> TypeSignature], [term |-> 4, contentType |-> TypeSignature]>> @@ NodeFour :> <<[term |-> 2, configuration |-> {NodeOne}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, configuration |-> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature]>> @@ NodeFive :> <<[term |-> 2, configuration |-> {NodeOne}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature], [term |-> 2, configuration |-> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}, contentType |-> TypeReconfiguration], [term |-> 2, contentType |-> TypeSignature]>>)
/\ sentIndex = (NodeOne :> (NodeOne :> 8 @@ NodeTwo :> 9 @@ NodeThree :> 9 @@ NodeFour :> 9 @@ NodeFive :> 9) @@ NodeTwo :> (NodeOne :> 9 @@ NodeTwo :> 9 @@ NodeThree :> 9 @@ NodeFour :> 9 @@ NodeFive :> 9) @@ NodeThree :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeFour :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0) @@ NodeFive :> (NodeOne :> 0 @@ NodeTwo :> 0 @@ NodeThree :> 0 @@ NodeFour :> 0 @@ NodeFive :> 0))
/\ votesGranted = (NodeOne :> {NodeOne, NodeTwo, NodeThree} @@ NodeTwo :> {NodeOne, NodeTwo, NodeFour} @@ NodeThree :> {} @@ NodeFour :> {} @@ NodeFive :> {})
/\ configurations = (NodeOne :> (3 :> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}) @@ NodeTwo :> (3 :> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}) @@ NodeThree :> (3 :> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}) @@ NodeFour :> (3 :> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}) @@ NodeFive :> (3 :> {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}))

CCF == INSTANCE ccfraft

SIMInitReconfigurationVars ==
    \* Start with all servers in the active configuration.
    \/ CCF!InitLogConfigServerVars(Servers, JoinedLog)
    \* Start with any subset of servers in the active configuration.
    \/ CCF!InitReconfigurationVars

SIMCheckQuorum(i) ==
    /\ 1 = RandomElement(1..10)
    /\ CCF!CheckQuorum(i)

SIMChangeConfigurationInt(i, newConfiguration) ==
    /\ 1 = RandomElement(1..100)
    /\ CCF!ChangeConfigurationInt(i, newConfiguration)

SIMTimeout(i) ==
    /\ \/ 1 = RandomElement(1..100)
       \* Always allow Timeout if no messages are in the network
       \* and no node is a candidate or leader.  Otherise, the system
       \* will deadlock if 1 # RandomElement(...).
       \/ /\ \A s \in Servers: leadershipState[s] \notin {Leader, Candidate}
          /\ Network!Messages = {}
    /\ CCF!Timeout(i)

\* The state constraint  StopAfter  stops TLC after the alloted
\* time budget is up, unless TLC encounteres an error first.
StopAfter ==
    LET timeout == IF ("SIM_TIMEOUT" \in DOMAIN IOEnv) /\ IOEnv.SIM_TIMEOUT # "" THEN atoi(IOEnv.SIM_TIMEOUT) ELSE 1200
    (* The smoke test has a time budget of 20 minutes. *)
    IN TLCSet("exit", TLCGet("duration") > timeout)

DebugInvUpToDepth ==
    \* The following invariant causes TLC to terminate with a counterexample of length
    \* -depth after generating the first trace.
    TLCGet("level") < TLCGet("config").depth
=============================================================================

------------------------------- MODULE SIMPostCondition -------------------------------
LOCAL INSTANCE TLC
LOCAL INSTANCE TLCExt
LOCAL INSTANCE FiniteSets
LOCAL INSTANCE Sequences
LOCAL INSTANCE IOUtils
LOCAL INSTANCE Integers

SIMPostCondition ==
    IF CounterExample.state = {} THEN TRUE ELSE
        /\ PrintT("Length of counterexample: " \o ToString(Cardinality(CounterExample.state)))
        /\ Serialize(ToString(Cardinality(CounterExample.state) - 1), 
                "depth.txt",
                [format |-> "TXT", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "TRUNCATE_EXISTING">>]
            ).exitValue = 0

=============================================================================

## Repeatedly run TLC in simulation mode to shorten a counterexample (the depth parameter will consequtively be reduced based on the length of the previous counterexample).
$ echo 500 > depth.txt
## Loop while the depth.txt file exists and is not empty.
$ while [ -s depth.txt ];
    do 
        TS=$(date +%s) && tlc SIMccfraft -simulate -workers auto -depth $(cat depth.txt) -postcondition 'SIMPostCondition!SIMPostCondition' 2>&1 | tee SIMccfraft_TTrace_$TS.out && sleep 5; 
    done
