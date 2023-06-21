-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils, Sequences

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    "raft_append_entries" :> AppendEntriesRequest @@ "raft_append_entries_response" :> AppendEntriesResponse @@
    "raft_request_vote" :> RequestVoteRequest @@ "raft_request_vote_response" :> RequestVoteResponse

LeadershipState ==
    Leader :> "Leader" @@ Follower :> "Follower" @@ Candidate :> "Candidate" @@ Pending :> "Pending"

\* In:  <<[idx |-> 0, nodes |-> [0 |-> [address |-> ":"]], rid |-> 0]>>
\* Out: (0 :> {0})
ToConfigurations(c) ==
    IF c = <<>> 
    THEN (0 :> {})
    ELSE FoldSeq(LAMBDA x,y: (x.idx :> DOMAIN x.nodes) @@ y, <<>>, c)

IsAppendEntriesRequest(msg, dst, src, logline) ==
    (*
    | ccfraft.tla   | json               | raft.h             |
    |---------------|--------------------|--------------------|
    | type          | .msg               | raftType           |
    | term          | .term              | state->currentTerm |
    | prevLogTerm   | .prev_term         | prev_term          |
    | prevLogIndex  | .prev_idx          | prev_idx           |
    | commitIndex   | .leader_commit_idx | state->commit_idx  |
    |               | .idx               | end_idx            |
    |               | .term_of_idx       | term_of_idx        |
    |               | .contains_new_view | contains_new_view  |
    *)
    /\ msg.type = AppendEntriesRequest
    /\ msg.type = RaftMsgType[logline.msg.packet.msg]
    /\ msg.dest   = dst
    /\ msg.source = src
    /\ msg.term = logline.msg.packet.term
    /\ msg.commitIndex = logline.msg.packet.leader_commit_idx
    /\ msg.prevLogTerm = logline.msg.packet.prev_term
    /\ Len(msg.entries) = logline.msg.packet.idx - logline.msg.packet.prev_idx
    /\ msg.prevLogIndex + Len(msg.entries) = logline.msg.packet.idx
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

ASSUME PrintT(<< "Trace:", JsonFile, "Length:", Len(TraceLog)>>)

JsonServers ==
    atoi(Deserialize(JsonFile \o ".nodes", [format |-> "TXT", charset |-> "UTF-8"]).stdout)
ASSUME JsonServers \in Nat \ {0}

TraceServers ==
    Range(SubSeq(<<NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive>>, 1, JsonServers))
ASSUME TraceServers \subseteq Servers

-------------------------------------------------------------------------------------

TraceAppendEntriesBatchsize(i, j) ==
    \* -1) .. to explicitly model heartbeats, i.e. a message with zero entries.
    (nextIndex[i][j] - 1) .. Len(log[i])

TraceInitMessagesVars ==
    /\ messages = <<>>
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

VARIABLE l, ts

TraceInit ==
    /\ l = 1
    /\ Init
    \* Constraint the set of initial states to the ones that match the nodes
     \* that are members of the initial configuration
     \* (see  \E c \in SUBSET Servers: ...  in ccraft!InitReconfigurationVars).
    /\ TraceLog[1].msg.function = "add_configuration"
    /\ ts = TraceLog[1].h_ts
    /\ ToConfigurations(<<TraceLog[1].msg.new_configuration>>) = configurations[TraceLog[1].msg.state.node_id]

-------------------------------------------------------------------------------------

logline ==
    TraceLog[l]

\* Beware to only prime e.g. inbox in inbox'[rcv] and *not* also rcv, i.e.,
 \* inbox[rcv]'.  rcv is defined in terms of TLCGet("level") that correctly
 \* handles priming, which causes for rcv' to equal rcv of the next log line.
IsEvent(e) ==
    \* Equals FALSE if we get past the end of the log, causing model checking to stop.
    /\ l \in 1..Len(TraceLog)
    /\ logline.msg.function = e
    /\ l' = l + 1
    /\ ts' = logline.h_ts

IsTimeout ==
    /\ IsEvent("become_candidate")
    /\ logline.msg.state.leadership_state = "Candidate"
    /\ Timeout(logline.msg.state.node_id)

IsBecomeLeader ==
    /\ IsEvent("become_leader")
    /\ logline.msg.state.leadership_state = "Leader"
    /\ BecomeLeader(logline.msg.state.node_id)
    
IsClientRequest ==
    /\ IsEvent("replicate")
    /\ ~logline.msg.globally_committable
    /\ ClientRequest(logline.msg.state.node_id)
    \* TODO Consider creating a mapping from clientRequests to actual values in the system trace.
    \* TODO Alternatively, extract the written values from the system trace and redefine clientRequests at startup.

IsSendAppendEntries ==
    /\ IsEvent("send_append_entries")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ AppendEntries(i, j)
             \* The  AppendEntries  action models the leader sending a message to some other node.  Thus, we could add a 
              \* constraint s.t.  Cardinality(messages') > Cardinality(messages)  .  However, the variable  messages  is
              \* a set and, thus, the variable  messages  remains unchanged if the leaders resend the same message, which
              \* it may.
          /\ \E msg \in Messages':
                /\ IsAppendEntriesRequest(msg, j, i, logline)
                \* There is now one more message of this type.
                /\ OneMoreMessage(msg)
          /\ logline.msg.sent_idx + 1 = nextIndex[i][j]
          /\ logline.msg.match_idx = matchIndex[i][j]

IsRcvAppendEntriesRequest ==
    /\ IsEvent("recv_append_entries")
    /\ logline.msg.function = "recv_append_entries"
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN /\ \E m \in Messages:
              /\ IsAppendEntriesRequest(m, i, j, logline)
              /\ \/ HandleAppendEntriesRequest(i, j, m)
                 \/ UpdateTerm(i, j, m) \cdot HandleAppendEntriesRequest(i, j, m)
                 \* ConflictAppendEntriesRequest truncates the log but does *not* consume the AE request.    
                 \/ RAERRAER(m):: (UNCHANGED <<candidateVars, leaderVars>> /\ ConflictAppendEntriesRequest(i, m.prevLogIndex + 1, m)) \cdot HandleAppendEntriesRequest(i, j, m)
          /\ logline'.msg.function = "send_append_entries_response"
                 \* Match on logline', which is log line of saer below.
                 => \E msg \in Messages':
                         IsAppendEntriesResponse(msg, logline'.msg.to_node_id, logline'.msg.state.node_id, logline')

IsSendAppendEntriesResponse ==
    \* Skip saer because ccfraft!HandleAppendEntriesRequest atomcially handles the request and sends the response.
       \* Find a similar pattern in Traceccfraft!IsRcvRequestVoteRequest below.
    /\ IsEvent("send_append_entries_response")
    /\ UNCHANGED vars
 
IsAddConfiguration ==
    /\ IsEvent("add_configuration")
    /\ state[logline.msg.state.node_id] = Follower
    /\ UNCHANGED vars

IsSignCommittableMessages ==
    /\ IsEvent("replicate")
    /\ logline.msg.globally_committable
    /\ SignCommittableMessages(logline.msg.state.node_id)

IsAdvanceCommitIndex ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    \/ /\ IsEvent("commit")
       /\ logline.msg.state.leadership_state = "Leader"
       /\ LET i == logline.msg.state.node_id
          IN /\ AdvanceCommitIndex(i)
             /\ commitIndex'[i] >= logline.msg.state.commit_idx
    \/ /\ IsEvent("commit")
       /\ logline.msg.state.leadership_state = "Follower"
       /\ UNCHANGED vars

IsChangeConfiguration ==
    /\ IsEvent("add_configuration")
    /\ state[logline.msg.state.node_id] = Leader
    /\ LET i == logline.msg.state.node_id
           newConfiguration == DOMAIN logline.msg.new_configuration.nodes
       IN ChangeConfigurationInt(i, newConfiguration)

IsRcvAppendEntriesResponse ==
    /\ IsEvent("recv_append_entries_response")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN /\ logline.msg.sent_idx + 1 = nextIndex[i][j]
          /\ logline.msg.match_idx = matchIndex[i][j]
          /\ \E m \in Messages : 
               /\ IsAppendEntriesResponse(m, i, j, logline)
               /\ \/ HandleAppendEntriesResponse(i, j, m)
                  \/ UpdateTerm(i, j, m) \cdot HandleAppendEntriesResponse(i, j, m)
                  \/ UpdateTerm(i, j, m) \cdot DropResponseWhenNotInState(i, j, m, Leader)
                  \/ DropResponseWhenNotInState(i, j, m, Leader)

IsSendRequestVote ==
    /\ IsEvent("send_request_vote")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ RequestVote(i, j)
          /\ \E m \in Messages':
                /\ m.type = RequestVoteRequest
                /\ m.type = RaftMsgType[logline.msg.packet.msg]
                /\ m.term = logline.msg.packet.term
                /\ m.lastCommittableIndex = logline.msg.packet.last_committable_idx
                /\ m.lastCommittableTerm = logline.msg.packet.term_of_last_committable_idx
                \* There is now one more message of this type.
                /\ OneMoreMessage(m)

IsRcvRequestVoteRequest ==
    \/ /\ IsEvent("recv_request_vote")
       /\ LET i == logline.msg.state.node_id
              j == logline.msg.from_node_id
          IN \E m \in Messages:
               /\ m.type = RequestVoteRequest
               /\ m.dest   = i
               /\ m.source = j
               /\ m.term = logline.msg.packet.term
               /\ m.lastCommittableIndex = logline.msg.packet.last_committable_idx
               /\ m.lastCommittableTerm = logline.msg.packet.term_of_last_committable_idx
               /\ \/ HandleRequestVoteRequest(i, j, m)
                  \* Below formula is a decomposed TraceRcvUpdateTermReqVote step, i.e.,
                  \* a (ccfraft!UpdateTerm \cdot ccfraft!HandleRequestVoteRequest) step.
                  \* (see https://github.com/microsoft/CCF/issues/5057#issuecomment-1487279316)
                  \/ UpdateTerm(i, j, m) \cdot HandleRequestVoteRequest(i, j, m)

IsExecuteAppendEntries ==
    \* Skip append because ccfraft!HandleRequestVoteRequest atomcially handles the request, sends the response,
       \* and appends the entry to the ledger.
       /\ IsEvent("execute_append_entries_sync")
       /\ state[logline.msg.state.node_id] = Follower
       /\ currentTerm[logline.msg.state.node_id] = logline.msg.state.current_view
       /\ UNCHANGED vars

IsRcvRequestVoteResponse ==
    /\ IsEvent("recv_request_vote_response")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN \E m \in Messages:
            /\ m.type = RequestVoteResponse
            /\ m.dest   = i
            /\ m.source = j
            /\ m.term = logline.msg.packet.term
            /\ m.voteGranted = logline.msg.packet.vote_granted
            /\ \/ HandleRequestVoteResponse(i, j, m)
               \/ UpdateTerm(i, j, m) \cdot HandleRequestVoteResponse(i, j, m)
               \/ UpdateTerm(i, j, m) \cdot DropResponseWhenNotInState(i, j, m, Candidate)
               \/ DropResponseWhenNotInState(i, j, m, Candidate)

IsBecomeFollower ==
    /\ IsEvent("become_follower")
    /\ state[logline.msg.state.node_id] \in {Follower, Pending}
    /\ configurations[logline.msg.state.node_id] = ToConfigurations(logline.msg.configurations)
    /\ UNCHANGED vars \* UNCHANGED implies that it doesn't matter if we prime the previous variables.

IsCheckQuorum ==
    /\ IsEvent("become_follower")
    /\ state[logline.msg.state.node_id] = Leader
    /\ CheckQuorum(logline.msg.state.node_id)

TraceNext ==
    \/ IsTimeout
    \/ IsBecomeLeader
    \/ IsBecomeFollower
    \/ IsCheckQuorum

    \/ IsClientRequest

    \/ IsSignCommittableMessages
    \/ IsAdvanceCommitIndex

    \/ IsChangeConfiguration
    \/ IsAddConfiguration

    \/ IsSendAppendEntries
    \/ IsSendAppendEntriesResponse
    \/ IsRcvAppendEntriesRequest
    \/ IsRcvAppendEntriesResponse

    \/ IsSendRequestVote
    \/ IsRcvRequestVoteRequest
    \/ IsRcvRequestVoteResponse
    \/ IsExecuteAppendEntries

TraceSpec ==
    TraceInit /\ [][TraceNext]_<<l, ts, vars>>

-------------------------------------------------------------------------------------

TraceView ==
    \* A high-level state  s  can appear multiple times in a system trace.  Including the
     \* current level in TLC's view ensures that TLC will not stop model checking when  s
     \* appears the second time in the trace.  Put differently,  TraceView  causes TLC to
     \* consider  s_i  and s_j  , where  i  and  j  are the positions of  s  in the trace,
     \* to be different states.
    <<vars, l, ts>>

-------------------------------------------------------------------------------------

TraceMatched ==
    \* We force TLC to check TraceMatched as a temporal property because TLC checks temporal
    \* properties after generating all successor states of the current state, unlike
    \* invariants that are checked after generating a successor state.
    \* If the queue is empty after generating all successors of the current state,
    \* and l is less than the length of the trace, then TLC failed to validate the trace.
    \*
    \* We allow more than a single successor state to accept traces like suffix_collision.1
    \* and fancy_election.1.  The trace suffix_collision.1 at h_ts 466 has a follower receiving
    \* an AppendEntries request.  At that point in time, there are two AE requests contained in
    \* the variable messages. However, the loglines before h_ts 506 do not allow us to determine
    \* which request it is.
    [](l <= Len(TraceLog) => [](TLCGet("queue") \in {1,2} \/ l > Len(TraceLog)))

-------------------------------------------------------------------------------------

TraceAlias ==
    [
        lvl |-> TLCGet("level"),
        ts |-> ts,
        logline |-> logline.msg,
        reconfigurationCount |-> reconfigurationCount,
        removedFromConfiguration |-> removedFromConfiguration,
        configurations |-> configurations,
        messages |-> messages,
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
                RcvRequestVoteResponse     |-> ENABLED RcvRequestVoteResponse
            ]
    ]

-------------------------------------------------------------------------------------

VoteResponse ==
    { msg \in Messages: msg.type = RequestVoteResponse }

VoteRequests ==
    { msg \in Messages: msg.type = RequestVoteRequest }

AppendEntriesRequests ==
    { msg \in Messages: msg.type = AppendEntriesRequest }

AppendEntriesResponses ==
    { msg \in Messages: msg.type = AppendEntriesResponse }

-------------------------------------------------------------------------------------

RcvUpdateTermReqVote ==
    RcvUpdateTerm \cdot RcvRequestVoteRequest

RcvUpdateTermRcvRequestVoteResponse ==
    RcvUpdateTerm \cdot RcvRequestVoteResponse

RcvUpdateTermReqAppendEntries ==
    RcvUpdateTerm \cdot RcvAppendEntriesRequest

RcvUpdateTermRcvAppendEntriesResponse ==
    RcvUpdateTerm \cdot RcvAppendEntriesResponse

RcvAppendEntriesRequestRcvAppendEntriesRequest ==
    RcvAppendEntriesRequest \cdot RcvAppendEntriesRequest

ComposedNext ==
    \* The implementation raft.h piggybacks UpdateTerm messages on the AppendEntries
     \* and Vote messages.  Thus, we need to compose the UpdateTerm action with the
     \* corresponding AppendEntries and RequestVote actions.  This is a reasonable
     \* code-level optimization that we do not want to model explicitly in TLA+.
    \/ RcvUpdateTermReqVote
    \/ RcvUpdateTermRcvRequestVoteResponse
    \/ RcvUpdateTermReqAppendEntries
    \/ RcvUpdateTermRcvAppendEntriesResponse
    \* The sub-action IsRcvAppendEntriesRequest requires a disjunct composing two 
     \* successive RcvAppendEntriesRequest to validate suffix_collision.1 and fancy_election.1.
     \* The trace validation fails with violations of property CCFSpec if we do not
     \* conjoin the composed action below. See the (marker) label RAERRAER above.
    \/ RcvAppendEntriesRequestRcvAppendEntriesRequest

CCF == INSTANCE ccfraft
CCFSpec == CCF!Init /\ [][CCF!Next \/ ComposedNext]_CCF!vars

==================================================================================
