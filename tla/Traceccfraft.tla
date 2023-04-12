-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils, Sequences

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    << AppendEntriesRequest, AppendEntriesResponse, 
       RequestVoteRequest, RequestVoteResponse >>

LeadershipState ==
    Leader :> "Leader" @@ Follower :> "Follower" @@ Candidate :> "Candidate" @@ Pending :> "Pending"

\* In:  <<[idx |-> 0, nodes |-> [0 |-> [address |-> ":"]], rid |-> 0]>>
\* Out: (0 :> {0})
ToConfigurations(c) ==
    FoldSeq(LAMBDA x,y: (x.idx :> DOMAIN x.nodes) @@ y, <<>>, c)

ToReplicatedDataType(data) ==
    \* TODO Add a signature enum to aft::ReplicatedDataType::signature in logging_stub.h to remove
     \* TODO matching on the data string "signature" in driver.h::emit_signature.
    IF data = "eyJkYXRhIjoiYzJsbmJtRjBkWEpsIiwidHlwZSI6InJhdyJ9"
    THEN TypeSignature
    ELSE TypeEntry \* TODO Handle TypeReconfiguration.

-------------------------------------------------------------------------------------

\* Trace validation has been designed for TLC running in default model-checking
 \* mode, i.e., breadth-first search.
ASSUME TLCGet("config").mode = "bfs"

JsonFile ==
    IF "JSON" \in DOMAIN IOEnv THEN IOEnv.JSON ELSE "traces/bad_network.ndjson"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
     \* Run TLC with (assuming a suitable "tlc" shell alias):
     \* $ JSON=../tests/raft_scenarios/4582.ndjson tlc -note Traceccfraft
     \* Fall back to trace.ndjson if the JSON environment variable is not set.
    ndJsonDeserialize(JsonFile)

TraceLog ==
    SelectSeq(JsonLog, LAMBDA l: l.tag = "tla")

JsonServers ==
    atoi(Deserialize(JsonFile \o ".nodes", [format |-> "TXT", charset |-> "UTF-8"]).stdout)
ASSUME JsonServers \in Nat \ {0}

TraceServers ==
    Range(SubSeq(<<NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive>>, 1, JsonServers))
ASSUME TraceServers \subseteq Servers

-------------------------------------------------------------------------------------

TraceAppendEntriesBatchsize(i, j) ==
    \* 0.. instead of 1.. to explicitly model heartbeats, i.e. a message with zero entries.
    0..Len(log[i])

TraceInitMessagesVars ==
    /\ messages = <<>>
    /\ messagesSent = [i \in Servers |-> [j \in Servers |-> << >>] ]
    /\ commitsNotified = [i \in Servers |-> <<0,0>>] \* i.e., <<index, times of notification>>

TraceWithMessage(m, msgs) == 
    IF m \notin (DOMAIN msgs) THEN
        msgs @@ (m :> 1)
    ELSE
        [ msgs EXCEPT ![m] = @ + 1 ]

TraceWithoutMessage(m, msgs) == 
    IF msgs[m] = 1 THEN
        [ msg \in ((DOMAIN msgs) \ {m}) |-> msgs[msg] ]
    ELSE
        [ msgs EXCEPT ![m] = @ - 1 ]

TraceMessages ==
    DOMAIN messages

-------------------------------------------------------------------------------------

TraceInit ==
    /\ Init
    \* Constraint the set of initial states to the ones that match the nodes
     \* that are members of the initial configuration
     \* (see  \E c \in SUBSET Servers: ...  in ccraft!InitReconfigurationVars).
    /\ TraceLog[1].msg.event = [ component |-> "raft", function |-> "add_configuration" ]
    /\ ToConfigurations(TraceLog[1].msg.configurations) = configurations[TraceLog[1].msg.node]

\* The following sub-actions all leave the variables unchanged, and a single, generic sub-action
 \* would be sufficient.  However, the sub-actions are useful for debugging, as they make sure
 \* the log event's identifier shows up in TLC counterexamples.
IsEvent(e) ==
    /\ TLCGet("level") + 1 \in 1..Len(TraceLog)
    /\ TraceLog[TLCGet("level") + 1].msg.event = e

become_follower ==
    /\ IsEvent([ component |-> "raft", function |-> "become_follower" ])
    /\ UNCHANGED vars

send_request_vote_response ==
    /\IsEvent([ component |-> "raft", function |-> "send_request_vote_response" ])
    /\ UNCHANGED vars

send_append_entries_response ==
    /\ IsEvent([ component |-> "raft", function |-> "send_append_entries_response" ])
    /\ UNCHANGED vars

commit ==
    /\ IsEvent([ component |-> "raft", function |-> "commit" ])
    /\ UNCHANGED vars

add_configuration ==
    /\ IsEvent([ component |-> "raft", function |-> "add_configuration" ])
    /\ UNCHANGED vars

truncate ==
    /\ IsEvent([ component |-> "ledger", function |-> "truncate" ])
    /\ UNCHANGED vars

append ==
    /\ IsEvent([ component |-> "ledger", function |-> "append" ])
    /\ UNCHANGED vars
    
TraceRcvUpdateTermReqVote ==
    RcvUpdateTerm \cdot RcvRequestVoteRequest

TraceRcvUpdateTermReqAppendEntries ==
    RcvUpdateTerm \cdot RcvAppendEntriesRequest

TraceRcvUpdateTermRcvRequestVoteResponse ==
    RcvUpdateTerm \cdot RcvRequestVoteResponse

TraceNext ==
    \/ Next
    
    \/ become_follower
    \/ send_request_vote_response
    \/ send_append_entries_response
    \/ commit
    \/ add_configuration
    \/ truncate
    \/ append

    \/ TraceRcvUpdateTermReqVote
    \/ TraceRcvUpdateTermReqAppendEntries
    \/ TraceRcvUpdateTermRcvRequestVoteResponse

TraceSpec ==
    TraceInit /\ [][TraceNext]_vars

-------------------------------------------------------------------------------------

\* Beware to only prime e.g. inbox in inbox'[rcv] and *not* also rcv, i.e.,
 \* inbox[rcv]'.  rcv is defined in terms of TLCGet("level") that correctly
 \* handles priming, which causes for rcv' to equal rcv of the next log line.


IsTimeout(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_candidate" ]
    /\ logline.msg.leadership = "Candidate"
    /\ <<Timeout(logline.msg.node)>>_vars

IsBecomeLeader(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_leader" ]
    /\ logline.msg.leadership = "Leader"
    /\ <<BecomeLeader(logline.msg.node)>>_vars
    
IsClientRequest(logline) ==
    /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
    /\ ToReplicatedDataType(logline.msg.data) = TypeEntry
    /\ <<ClientRequest(logline.msg.node)>>_vars
    \* TODO Consider creating a mapping from clientRequests to actual values in the system trace.
    \* TODO Alternatively, extract the written values from the system trace and redefine clientRequests at startup.

IsSendAppendEntries(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "send_authenticated" ]
    /\ LET n == logline.msg.node 
           m == logline.msg.to
       IN /\ <<AppendEntries(n, m)>>_vars
             \* The  AppendEntries  action models the leader sending a message to some other node.  Thus, we could add a 
              \* constraint s.t.  Cardinality(messages') > Cardinality(messages)  .  However, the variable  messages  is
              \* a set and, thus, the variable  messages  remains unchanged if the leaders resend the same message, which
              \* it may.
          /\ \/ UNCHANGED messages
             \/ /\ \E msg \in (Messages' \ Messages):
                     /\ msg.mtype = RaftMsgType[logline.msg.paket.msg + 1]
                     /\ msg.mdest   = m
                     /\ msg.msource = n
                     /\ msg.mcommitIndex = logline.msg.paket.leader_commit_idx
                     /\ Len(msg.mentries) = logline.msg.mentries

IsRcvAppendEntriesRequest(logline) ==
    \/ /\ logline.msg.event = [ component |-> "raft", function |-> "recv_append_entries" ]
       /\ LET n == logline.msg.node
              m == logline.msg.from
          IN /\ \E msg \in Messages: 
                 /\ msg.mtype = AppendEntriesRequest
                 /\ msg.mdest   = n
                 /\ msg.msource = m
                 /\ \/ <<HandleAppendEntriesRequest(n, m, msg)>>_vars
                    \/ <<UpdateTerm(n, m, msg) \cdot HandleAppendEntriesRequest(n, m, msg)>>_vars 
             /\ \E msg \in Messages' :
                 /\ msg.mtype = AppendEntriesResponse
                 /\ msg.mdest   = m
                 /\ msg.msource = n
    \/ \* Skip saer because ccfraft!HandleAppendEntriesRequest atomcially handles the request and sends the response.
       \* Find a similar pattern in Traceccfraft!IsRcvRequestVoteRequest below.
       /\ logline.msg.event = [ component |-> "raft", function |-> "send_append_entries_response" ]
       /\ UNCHANGED vars
    \/ \*
       /\ logline.msg.event = [ component |-> "raft", function |-> "add_configuration" ]
       /\ state[logline.msg.node] = Follower
       /\ UNCHANGED vars


IsSignCommittableMessages(logline) ==
    /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
    /\ ToReplicatedDataType(logline.msg.data) = TypeSignature
    /\ <<SignCommittableMessages(logline.msg.node)>>_vars

IsAdvanceCommitIndex(logline) ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    \/ /\ logline.msg.event = [ component |-> "raft", function |-> "commit" ]
       /\ logline.msg.leadership = "Leader"
       /\ LET n == logline.msg.node
          IN /\ <<AdvanceCommitIndex(n)>>_vars
             /\ commitIndex'[n] >= logline.msg.state.commit_idx
    \/ /\ logline.msg.event = [ component |-> "raft", function |-> "commit" ]
       /\ logline.msg.leadership = "Follower"
       /\ UNCHANGED vars

IsChangeConfiguration(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "add_configuration" ]
    /\ LET n == logline.msg.node
           conf == ToConfigurations(logline.msg.configurations)
           domConf  == DOMAIN conf
           currConf == Min(domConf)
           nextConf == Min(domConf \ {currConf})
       IN <<ChangeConfigurationInt(n, conf[nextConf])>>_vars

IsRcvAppendEntriesResponse(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "recv_append_entries_response" ]
    /\ LET n == logline.msg.node
           m == logline.msg.from
       IN \E msg \in Messages : 
               /\ msg.mtype = AppendEntriesResponse
               /\ msg.mtype = RaftMsgType[logline.msg.paket.msg + 1]
               /\ msg.mdest   = n
               /\ msg.msource = m
               /\ msg \notin Messages'
               /\ <<HandleAppendEntriesResponse(n, m, msg)>>_vars

IsSendRequestVote(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "send_request_vote" ]
    /\ LET n == logline.msg.node
           m == logline.msg.to
       IN <<RequestVote(n, m)>>_vars

IsRcvRequestVoteRequest(logline) ==
    \/ /\ logline.msg.event = [ component |-> "raft", function |-> "recv_request_vote" ]
       /\ LET n == logline.msg.node
              m == logline.msg.from
          IN \E msg \in Messages:
               /\ msg.mtype = RequestVoteRequest
               /\ msg.mdest   = n
               /\ msg.msource = m
               /\ \/ <<HandleRequestVoteRequest(n, m, msg)>>_vars
                  \* Below formula is a decomposed TraceRcvUpdateTermReqVote step, i.e.,
                  \* a (ccfraft!UpdateTerm \cdot ccfraft!HandleRequestVoteRequest) step.
                  \* (see https://github.com/microsoft/CCF/issues/5057#issuecomment-1487279316)
                  \/ <<UpdateTerm(n, m, msg) \cdot HandleRequestVoteRequest(n, m, msg)>>_vars 
    \/ \* Skip srvr because ccfraft!HandleRequestVoteRequest atomcially handles the request and sends the response.
       \* Alternatively, rrv could be mapped to UpdateTerm and srvr to HandleRequestVoteRequest.  However, this
       \* causes problems if an UpdateTerm step is *not* enabled because the node's term is already up-to-date.
       /\ logline.msg.event = [ component |-> "raft", function |-> "send_request_vote_response" ]
       /\ UNCHANGED vars
    \/ \* Skip append because ccfraft!HandleRequestVoteRequest atomcially handles the request, sends the response,
       \* and appends the entry to the ledger.
       /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
       /\ LET n == logline.msg.node
          IN /\ state[n] = Follower
             /\ state'[n] = Follower
             /\ currentTerm[n] = logline.msg.term
             /\ currentTerm'[n] = logline.msg.term
       /\ UNCHANGED vars

IsRcvRequestVoteResponse(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "recv_request_vote_response" ]
    /\ LET n == logline.msg.node
           m == logline.msg.from
       IN \E msg \in Messages:
            /\ msg.mtype = RequestVoteResponse
            /\ msg.mdest   = n
            /\ msg.msource = m
            /\ msg.mterm = logline.msg.paket.term
            /\ msg.mvoteGranted = logline.msg.paket.vote_granted
            /\ \/ <<HandleRequestVoteResponse(n, m, msg)>>_vars
               \/ <<UpdateTerm(n, m, msg) \cdot HandleRequestVoteResponse(n, m, msg)>>_vars 

IsBecomeFollower(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_follower" ]
    /\ state[logline.msg.node] = Follower
    /\ configurations[logline.msg.node] = ToConfigurations(logline.msg.configurations)
    /\ UNCHANGED vars \* UNCHANGED implies that it doesn't matter if we prime the previous variables.

IsCheckQuorum(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_follower" ]
    /\ <<CheckQuorum(logline.msg.node)>>_vars
    
IsStuttering(logline) ==
    /\ logline.msg.event \in {
                                \* Add unhandled/ignored log statements here!
                                 [component |-> "store",  function |-> "initialize_term"]
                                ,[component |-> "store",  function |-> "rollback"]
                                ,[component |-> "ledger", function |-> "truncate"]
                            } 
    /\ UNCHANGED vars

TraceNextConstraint ==
    \* We could have used an auxiliary spec variable for i  , but TLCGet("level") has the
     \* advantage that TLC continues to show the high-level action names instead of just  Next.
     \* However, it is imparative to run TLC with the TraceView above configured as a VIEW in
     \* TLC's config file.  Otherwise, TLC will stop model checking when a high-level state
     \* appears a second time in the trace.
    LET i == TLCGet("level") + 1
    IN \* Equals FALSE if we get past the end of the log, causing model checking to stop.
       /\ i <= Len(TraceLog)
       /\ LET logline == TraceLog[i]
          IN \* If the postcondition  TraceAccepted  is violated, adding a TLA+ debugger
              \* breakpoint with a hit count copied from TLC's error message on the 
              \* BP:: line below is the first step towards diagnosing a divergence. Once
              \* hit, advance evaluation with step over (F10) and step into (F11).
              BP::
              /\ \/ IsTimeout(logline)
                 \/ IsBecomeLeader(logline)
                 \/ IsBecomeFollower(logline)
                 \/ IsCheckQuorum(logline)

                 \/ IsClientRequest(logline)

                 \/ IsSignCommittableMessages(logline)
                 \/ IsAdvanceCommitIndex(logline)

                 \/ IsChangeConfiguration(logline)

                 \/ IsSendAppendEntries(logline)
                 \/ IsRcvAppendEntriesRequest(logline)
                 \/ IsRcvAppendEntriesResponse(logline)

                 \/ IsSendRequestVote(logline)
                 \/ IsRcvRequestVoteRequest(logline)
                 \/ IsRcvRequestVoteResponse(logline)

                 \/ IsStuttering(logline)

-------------------------------------------------------------------------------------

TraceView ==
    \* A high-level state  s  can appear multiple times in a system trace.  Including the
     \* current level in TLC's view ensures that TLC will not stop model checking when  s
     \* appears the second time in the trace.  Put differently,  TraceView  causes TLC to
     \* consider  s_i  and s_j  , where  i  and  j  are the positions of  s  in the trace,
     \* to be different states.
    <<vars, TLCGet("level")>>

-------------------------------------------------------------------------------------

TraceStats ==
    TLCGet("stats")

TraceAccepted ==
    \* If the prefix of the TLA+ behavior is shorter than the trace, TLC will
     \* report a violation of this postcondition.  But why do we need a postcondition
     \* at all?  Couldn't we use an ordinary property such as
     \*  <>[](TLCGet("level") >= Len(TraceLog))  ?  The answer is that an ordinary
     \* property is true of a single behavior, whereas  TraceAccepted  is true of a
     \* set of behaviors; it is essentially a poor man's hyperproperty.
    LET d == TraceStats.diameter IN
    IF d = Len(TraceLog) THEN
            \* TODO This can be removed when Traceccfraft is done.
            JsonFile \in {"traces/election.ndjson",
                          "traces/replicate.ndjson",
                          "traces/check_quorum.ndjson",
                          "traces/reconnect.ndjson",
                          "traces/reconnect_node.ndjson"} 
                         => TraceStats.distinct = Len(TraceLog)
    ELSE Print(<<"Failed matching the trace to (a prefix of) a behavior:", TraceLog[d+1], 
                    "TLA+ debugger breakpoint hit count " \o ToString(d+1)>>, FALSE)

TraceInv ==
    \* This invariant may or may not hold depending on the level of non-determinism because
     \* of holes in the log file.
    TraceStats.distinct <= TraceStats.diameter

TraceAlias ==
    [
        lvl |-> TLCGet("level"),
        reconfigurationCount |-> reconfigurationCount,
        removedFromConfiguration |-> removedFromConfiguration,
        configurations |-> configurations,
        messages |-> messages,
        messagesSent |-> messagesSent,
        commitsNotified |-> commitsNotified,
        currentTerm |-> currentTerm,
        state |-> state,
        votedFor |-> votedFor,
        log |-> log,
        commitIndex |-> commitIndex,
        clientRequests |-> clientRequests,
        committedLog |-> committedLog,
        votesGranted |-> votesGranted,
        votesRequested |-> votesRequested,
        nextIndex |-> nextIndex,
        matchIndex |-> matchIndex,
        _ENABLED |-> 
            [
                Timeout                 |-> [ i \in Servers   |-> ENABLED Timeout(i) ],
                RequestVote             |-> [ i,j \in Servers |-> ENABLED RequestVote(i, j) ],
                BecomeLeader            |-> [ i \in Servers   |-> ENABLED BecomeLeader(i) ],
                ClientRequest           |-> [ i \in Servers   |-> ENABLED ClientRequest(i) ],
                SignCommittableMessages |-> [ i \in Servers   |-> ENABLED SignCommittableMessages(i) ],
                ChangeConfiguration     |-> [ i \in Servers   |-> ENABLED ChangeConfiguration(i) ],
                NotifyCommit            |-> [ i,j \in Servers |-> ENABLED NotifyCommit(i,j) ],
                AdvanceCommitIndex      |-> [ i \in Servers   |-> ENABLED AdvanceCommitIndex(i) ],
                AppendEntries           |-> [ i,j \in Servers |-> ENABLED AppendEntries(i, j) ],
                CheckQuorum             |-> [ i \in Servers   |-> ENABLED CheckQuorum(i) ],
                Receive                 |-> ENABLED Receive,
                RcvAppendEntriesRequest |-> ENABLED RcvAppendEntriesRequest,
                RcvAppendEntriesResponse|-> ENABLED RcvAppendEntriesResponse,
                RcvUpdateTerm           |-> ENABLED RcvUpdateTerm,
                RcvRequestVoteRequest   |-> ENABLED RcvRequestVoteRequest,
                RcvRequestVoteResponse  |-> ENABLED RcvRequestVoteResponse,
                TraceRcvUpdateTermReqVote  |-> ENABLED TraceRcvUpdateTermReqVote
            ]
    ]
==================================================================================

Smoke testing:

export TLC_OPTS='-Dtlc2.tool.impl.Tool.cdot=true' && \  
JSON=traces/replicate.ndjson tlc -note Traceccfraft > /dev/null && \
JSON=traces/election.ndjson tlc -note Traceccfraft > /dev/null || \
JSON=traces/check_quorum.ndjson tlc -note Traceccfraft > /dev/null || \
JSON=traces/reconnect.ndjson tlc -note Traceccfraft > /dev/null || \
JSON=traces/reconnect_node.ndjson tlc -note Traceccfraft > /dev/null || \
echo '\033[31mFAILURE'