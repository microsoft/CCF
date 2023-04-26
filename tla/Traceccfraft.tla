-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils, Sequences

KnownScenarios ==
    {"traces/election.ndjson",
     "traces/replicate.ndjson",
     "traces/check_quorum.ndjson",
     "traces/reconnect.ndjson",
     "traces/reconnect_node.ndjson"}

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    "raft_append_entries" :> AppendEntriesRequest @@ "raft_append_entries_response" :> AppendEntriesResponse @@
    "RequestVoteRequest" :> RequestVoteRequest @@ "RequestVoteResponse" :> RequestVoteResponse

LeadershipState ==
    Leader :> "Leader" @@ Follower :> "Follower" @@ Candidate :> "Candidate" @@ Pending :> "Pending"

\* In:  <<[idx |-> 0, nodes |-> [0 |-> [address |-> ":"]], rid |-> 0]>>
\* Out: (0 :> {0})
ToConfigurations(c) ==
    IF c = <<>> 
    THEN (0 :> {})
    ELSE FoldSeq(LAMBDA x,y: (x.idx :> DOMAIN x.nodes) @@ y, <<>>, c)

IsAppendEntriesRequest(msg, dst, src, logline) ==
    /\ msg.type = AppendEntriesRequest
    /\ msg.type = RaftMsgType[logline.msg.packet.msg]
    /\ msg.dest   = dst
    /\ msg.source = src
    /\ msg.term = logline.msg.packet.term
    /\ msg.commitIndex = logline.msg.packet.leader_commit_idx
    /\ msg.prevLogTerm = logline.msg.packet.prev_term
    /\ Len(msg.entries) = logline.msg.packet.idx - logline.msg.packet.prev_idx
    /\ msg.prevLogIndex = logline.msg.packet.prev_idx

IsAppendEntriesResponse(msg, dst, src, logline) ==
    /\ msg.type = AppendEntriesResponse
    /\ msg.type = RaftMsgType[logline.msg.packet.msg]
    /\ msg.dest   = dst
    /\ msg.source = src
    /\ msg.term = logline.msg.packet.term
    \* raft_types.h enum AppendEntriesResponseType
    /\ msg.success = (logline.msg.packet.success = "OK")
    /\ msg.lastLogIndex = logline.msg.packet.last_log_idx

-------------------------------------------------------------------------------------

\* Trace validation has been designed for TLC running in default model-checking
 \* mode, i.e., breadth-first search.
ASSUME TLCGet("config").mode = "bfs"

JsonFile ==
    IF "JSON" \in DOMAIN IOEnv THEN IOEnv.JSON ELSE "traces/election.ndjson"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
     \* Run TLC with (assuming a suitable "tlc" shell alias):
     \* $ JSON=../tests/raft_scenarios/4582.ndjson tlc -note Traceccfraft
     \* Fall back to trace.ndjson if the JSON environment variable is not set.
    ndJsonDeserialize(JsonFile)

TraceLog ==
    SelectSeq(JsonLog, LAMBDA l: l.tag = "raft_trace")

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

OneMoreMessage(msg) ==
    \/ msg \notin Messages /\ msg \in Messages'
    \/ msg \in Messages /\ messages'[msg] > messages[msg]

-------------------------------------------------------------------------------------

TraceInit ==
    /\ Init
    \* Constraint the set of initial states to the ones that match the nodes
     \* that are members of the initial configuration
     \* (see  \E c \in SUBSET Servers: ...  in ccraft!InitReconfigurationVars).
    /\ TraceLog[1].msg.function = "add_configuration"
    /\ ToConfigurations(<<TraceLog[1].msg.new_configuration>>) = configurations[TraceLog[1].msg.state.node_id]

\* The following sub-actions all leave the variables unchanged, and a single, generic sub-action
 \* would be sufficient.  However, the sub-actions are useful for debugging, as they make sure
 \* the log event's identifier shows up in TLC counterexamples.
IsEvent(e) ==
    /\ TLCGet("level")' \in 1..Len(TraceLog)
    /\ TraceLog[TLCGet("level")'].msg.function = e

become_follower ==
    /\ IsEvent("become_follower")
    /\ UNCHANGED vars

send_request_vote_response ==
    /\IsEvent("send_request_vote_response")
    /\ UNCHANGED vars

send_append_entries_response ==
    /\ IsEvent("send_append_entries_response")
    /\ UNCHANGED vars

commit ==
    /\ IsEvent("commit")
    /\ UNCHANGED vars

add_configuration ==
    /\ IsEvent("add_configuration")
    /\ UNCHANGED vars
    
execute_append_entries_sync ==
    /\ IsEvent("execute_append_entries_sync")
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
    \/ execute_append_entries_sync

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
    /\ logline.msg.function = "become_candidate"
    /\ logline.msg.state.leadership_state = "Candidate"
    /\ <<Timeout(logline.msg.state.node_id)>>_vars

IsBecomeLeader(logline) ==
    /\ logline.msg.function = "become_leader"
    /\ logline.msg.state.leadership_state = "Leader"
    /\ <<BecomeLeader(logline.msg.state.node_id)>>_vars
    
IsClientRequest(logline) ==
    /\ logline.msg.function = "replicate"
    /\ ~logline.msg.globally_committable
    /\ <<ClientRequest(logline.msg.state.node_id)>>_vars
    \* TODO Consider creating a mapping from clientRequests to actual values in the system trace.
    \* TODO Alternatively, extract the written values from the system trace and redefine clientRequests at startup.

IsSendAppendEntries(logline) ==
    /\ logline.msg.function = "send_append_entries" \* send_append_entries
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ <<AppendEntries(i, j)>>_vars
             \* The  AppendEntries  action models the leader sending a message to some other node.  Thus, we could add a 
              \* constraint s.t.  Cardinality(messages') > Cardinality(messages)  .  However, the variable  messages  is
              \* a set and, thus, the variable  messages  remains unchanged if the leaders resend the same message, which
              \* it may.
          /\ \E msg \in Messages':
                /\ IsAppendEntriesRequest(msg, j, i, logline)
                \* There is now one more message of this type.
                /\ OneMoreMessage(msg)

IsRcvAppendEntriesRequest(logline) ==
    \/ /\ logline.msg.function = "recv_append_entries"
       /\ LET i == logline.msg.state.node_id
              j == logline.msg.from_node_id
          IN /\ \E m \in Messages:
                 /\ IsAppendEntriesRequest(m, i, j, logline)
                 /\ \/ <<HandleAppendEntriesRequest(i, j, m)>>_vars
                    \/ <<UpdateTerm(i, j, m) \cdot HandleAppendEntriesRequest(i, j, m)>>_vars 
             /\ logline'.msg.function = "send_append_entries_response"
                    \* Match on logline', which is log line of saer below.
                    => \E msg \in Messages':
                            IsAppendEntriesResponse(msg, logline'.msg.to_node_id, logline'.msg.state.node_id, logline')
    \/ \* Skip saer because ccfraft!HandleAppendEntriesRequest atomcially handles the request and sends the response.
       \* Find a similar pattern in Traceccfraft!IsRcvRequestVoteRequest below.
       /\ logline.msg.function = "send_append_entries_response"
       /\ UNCHANGED vars
    \/ \*
       /\ logline.msg.function = "add_configuration"
       /\ state[logline.msg.state.node_id] = Follower
       /\ UNCHANGED vars

IsSignCommittableMessages(logline) ==
    /\ logline.msg.function = "replicate"
    /\ logline.msg.globally_committable
    /\ <<SignCommittableMessages(logline.msg.state.node_id)>>_vars

IsAdvanceCommitIndex(logline) ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    \/ /\ logline.msg.function = "commit"
       /\ logline.msg.state.leadership_state = "Leader"
       /\ LET i == logline.msg.state.node_id
          IN /\ <<AdvanceCommitIndex(i)>>_vars
             /\ commitIndex'[i] >= logline.msg.state.commit_idx
    \/ /\ logline.msg.function = "commit"
       /\ logline.msg.state.leadership_state = "Follower"
       /\ UNCHANGED vars

IsChangeConfiguration(logline) ==
    /\ logline.msg.function = "add_configuration"
    /\ state[logline.msg.state.node_id] = Leader
    /\ LET i == logline.msg.state.node_id
           newConfiguration == logline.msg.new_configuration
       IN <<ChangeConfigurationInt(i, newConfiguration)>>_vars

IsRcvAppendEntriesResponse(logline) ==
    /\ logline.msg.function = "recv_append_entries_response"
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN \E m \in Messages : 
               /\ IsAppendEntriesResponse(m, i, j, logline)
               /\ <<HandleAppendEntriesResponse(i, j, m)>>_vars

IsSendRequestVote(logline) ==
    /\ logline.msg.function = "send_request_vote"
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN <<RequestVote(i, j)>>_vars

IsRcvRequestVoteRequest(logline) ==
    \/ /\ logline.msg.function = "recv_request_vote"
       /\ LET i == logline.msg.state.node_id
              j == logline.msg.from_node_id
          IN \E m \in Messages:
               /\ m.type = RequestVoteRequest
               /\ m.dest   = i
               /\ m.source = j
               /\ \/ <<HandleRequestVoteRequest(i, j, m)>>_vars
                  \* Below formula is a decomposed TraceRcvUpdateTermReqVote step, i.e.,
                  \* a (ccfraft!UpdateTerm \cdot ccfraft!HandleRequestVoteRequest) step.
                  \* (see https://github.com/microsoft/CCF/issues/5057#issuecomment-1487279316)
                  \/ <<UpdateTerm(i, j, m) \cdot HandleRequestVoteRequest(i, j, m)>>_vars 
    \/ \* Skip srvr because ccfraft!HandleRequestVoteRequest atomcially handles the request and sends the response.
       \* Alternatively, rrv could be mapped to UpdateTerm and srvr to HandleRequestVoteRequest.  However, this
       \* causes problems if an UpdateTerm step is *not* enabled because the node's term is already up-to-date.
       /\ logline.msg.function = "send_request_vote_response"
       /\ UNCHANGED vars
    \/ \* Skip append because ccfraft!HandleRequestVoteRequest atomcially handles the request, sends the response,
       \* and appends the entry to the ledger.
       /\ logline.msg.function = "execute_append_entries_sync"
       /\ state[logline.msg.state.node_id] = Follower
       /\ currentTerm[logline.msg.state.node_id] = logline.msg.state.current_view
       /\ UNCHANGED vars

IsRcvRequestVoteResponse(logline) ==
    /\ logline.msg.function = "recv_request_vote_response"
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN \E m \in Messages:
            /\ m.type = RequestVoteResponse
            /\ m.dest   = i
            /\ m.source = j
            /\ m.term = logline.msg.packet.term
            /\ m.voteGranted = logline.msg.packet.vote_granted
            /\ \/ <<HandleRequestVoteResponse(i, j, m)>>_vars
               \/ <<UpdateTerm(i, j, m) \cdot HandleRequestVoteResponse(i, j, m)>>_vars 

IsBecomeFollower(logline) ==
    /\ logline.msg.function = "become_follower"
    /\ state[logline.msg.state.node_id] \in {Follower, Pending}
    /\ configurations[logline.msg.state.node_id] = ToConfigurations(logline.msg.configurations)
    /\ UNCHANGED vars \* UNCHANGED implies that it doesn't matter if we prime the previous variables.

IsCheckQuorum(logline) ==
    /\ logline.msg.function = "become_follower"
    /\ state[logline.msg.state.node_id] = Leader
    /\ <<CheckQuorum(logline.msg.state.node_id)>>_vars

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

TraceMatched ==
    \* If the prefix of the TLA+ behavior is shorter than the trace, TLC will
     \* report a violation of this postcondition.  But why do we need a postcondition
     \* at all?  Couldn't we use an ordinary property such as
     \*  <>[](TLCGet("level") >= Len(TraceLog))  ?  The answer is that an ordinary
     \* property is true of a single behavior, whereas  TraceAccepted  is true of a
     \* set of behaviors; it is essentially a poor man's hyperproperty.
    LET d == TraceStats.diameter IN
    d # Len(TraceLog) => Print(<<"Failed matching the trace to (a prefix of) a behavior:", TraceLog[d+1], 
                                    "TLA+ debugger breakpoint hit count " \o ToString(d+1)>>, FALSE)

TraceStateSpace ==
    \* TODO This can be removed when Traceccfraft is done.
    /\ JsonFile \in KnownScenarios => TraceStats.distinct = Len(TraceLog)

TraceAccepted ==
    /\ TraceMatched
    /\ TraceStateSpace

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
        votesGranted |-> votesGranted,
        votesRequested |-> votesRequested,
        nextIndex |-> nextIndex,
        matchIndex |-> matchIndex,
        _ENABLED |-> 
            [
                Timeout                    |-> [ i \in Servers   |-> ENABLED Timeout(i) ],
                RequestVote                |-> [ i,j \in Servers |-> ENABLED RequestVote(i, j) ],
                BecomeLeader               |-> [ i \in Servers   |-> ENABLED BecomeLeader(i) ],
                ClientRequest              |-> [ i \in Servers   |-> ENABLED ClientRequest(i) ],
                SignCommittableMessages    |-> [ i \in Servers   |-> ENABLED SignCommittableMessages(i) ],
                ChangeConfiguration        |-> [ i \in Servers   |-> ENABLED ChangeConfiguration(i) ],
                NotifyCommit               |-> [ i,j \in Servers |-> ENABLED NotifyCommit(i,j) ],
                AdvanceCommitIndex         |-> [ i \in Servers   |-> ENABLED AdvanceCommitIndex(i) ],
                AppendEntries              |-> [ i,j \in Servers |-> ENABLED AppendEntries(i, j) ],
                CheckQuorum                |-> [ i \in Servers   |-> ENABLED CheckQuorum(i) ],
                Receive                    |-> ENABLED Receive,
                RcvAppendEntriesRequest    |-> ENABLED RcvAppendEntriesRequest,
                RcvAppendEntriesResponse   |-> ENABLED RcvAppendEntriesResponse,
                RcvUpdateTerm              |-> ENABLED RcvUpdateTerm,
                RcvRequestVoteRequest      |-> ENABLED RcvRequestVoteRequest,
                RcvRequestVoteResponse     |-> ENABLED RcvRequestVoteResponse,
                TraceRcvUpdateTermReqVote  |-> ENABLED TraceRcvUpdateTermReqVote
            ]
    ]
==================================================================================

Smoke testing:

export TLC_OPTS='-Dtlc2.tool.impl.Tool.cdot=true' && \  
(JSON=traces/replicate.ndjson tlc -note Traceccfraft > /dev/null && \
JSON=traces/election.ndjson tlc -note Traceccfraft > /dev/null && \
JSON=traces/check_quorum.ndjson tlc -note Traceccfraft > /dev/null && \
JSON=traces/reconnect.ndjson tlc -note Traceccfraft > /dev/null && \
JSON=traces/reconnect_node.ndjson tlc -note Traceccfraft > /dev/null) || \
echo '\033[31mFAILURE'