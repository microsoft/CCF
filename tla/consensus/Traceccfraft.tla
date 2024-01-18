-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils, Sequences

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    "raft_append_entries" :> AppendEntriesRequest @@ "raft_append_entries_response" :> AppendEntriesResponse @@
    "raft_request_vote" :> RequestVoteRequest @@ "raft_request_vote_response" :> RequestVoteResponse @@
    "raft_propose_request_vote" :> ProposeVoteRequest

LeadershipState ==
    Leader :> "Leader" @@ Follower :> "Follower" @@ Candidate :> "Candidate" @@ None :> "None"

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
    IF "JSON" \in DOMAIN IOEnv THEN IOEnv.JSON ELSE "../../build/startup.ndjson"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
    \* Run TLC from under the tla/ directory with:
    \* $ JSON=../build/startup.ndjson ./tlc.sh consensus/Traceccfraft.tla
    \* Traces can be generated with: ./make_traces.sh, also under the tla/ directory.
    ndJsonDeserialize(JsonFile)

TraceLog ==
    SelectSeq(JsonLog, LAMBDA l: l.tag = "raft_trace")

JsonServers ==
    LET Card == Cardinality({ TraceLog[i].msg.state.node_id: i \in DOMAIN TraceLog })
    IN Print(<< "Trace:", JsonFile, "Length:", IF Card = 0 THEN "EMPTY" ELSE Len(TraceLog)>>, Card)
    
ASSUME JsonServers \in Nat \ {0}

CONSTANTS
    NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive

TraceServers ==
    Range(SubSeq(<<NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive>>, 1, JsonServers))
ASSUME TraceServers \subseteq Servers

-------------------------------------------------------------------------------------

TraceAppendEntriesBatchsize(i, j) ==
    \* -1) .. to explicitly model heartbeats, i.e. a message with zero entries.
    sentIndex[i][j] .. Len(log[i])

TraceInitReconfigurationVars ==
    /\ removedFromConfiguration = {}
    /\ InitLogConfigServerVars({TraceLog[1].msg.state.node_id}, StartLog)

-------------------------------------------------------------------------------------

VARIABLE l, ts

TraceInit ==
    /\ l = 2
    /\ Init
    \* Constraint the set of initial states to the ones that match the nodes
     \* that are members of the initial configuration
     \* (see  \E c \in SUBSET Servers: ...  in ccraft!InitReconfigurationVars).
    /\ TraceLog[1].msg.function = "bootstrap"
    /\ ts = TraceLog[1].h_ts

-------------------------------------------------------------------------------------

logline ==
    TraceLog[l]

\* ccfraft assumes ordered point-to-point communication. In other words, we should
\* only receive the first pending message from j at i.  However, it is possible
\* that a prefix of the messages sent by j to i have been lost -- the network is
\* unreliable.  Thus, we allow to receive any message but drop the prefix up to
\* that message.
\* We could add a Traceccfraft!DropMessage action that non-deterministically drops
\* messages at every step of the system.  However, that would lead to massive state
\* space explosion.  OTOH, it would have the advantage that we could assert that
\* messages is all empty at the end of the trace.  Right now, messages will contain
\* all messages, even those that have been lost by the real system.  Another trade
\* off is that the length of the TLA+ trace will be longer than the system trace
\* (due to the extra DropMessage actions).
\* Instead, we could compose a DropMessage action with all receiver actions such
\* as HandleAppendEntriesResponse that allows the receiver's inbox to equal any
\* SubSeq of the receives current inbox (where inbox is messages[receiver]).  That
\* way, we can leave the other server's inboxes unchanged (resulting in fewer work for
\* TLC).  A trade off of this variant is that we have to non-deterministically pick
\* the next message from the inbox instead of via Network!MessagesTo (which always
\* picks the first message in a server's inbox).
\* 
\* Lastly, we can weaken Traceccfraft trace validation and simply ignore lost messages
\* accepting that lost messages remain in messages.
DropMessages ==
    /\ l \in 1..Len(TraceLog)
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, leaderVars, logVars>>
    /\ UNCHANGED <<l, ts>>
    \* Only drop messages when processing message events
    /\ \/ /\ "from_node_id" \in DOMAIN logline.msg
          /\ Network!DropMessagesTo(logline.msg.state.node_id, logline.msg.from_node_id)
       \/ /\ "from_node_id" \notin DOMAIN logline.msg
          /\ UNCHANGED <<messageVars>>

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
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsBecomeLeader ==
    /\ IsEvent("become_leader")
    /\ logline.msg.state.leadership_state = "Leader"
    /\ BecomeLeader(logline.msg.state.node_id)
    /\ committableIndices'[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)
    
IsClientRequest ==
    /\ IsEvent("replicate")
    /\ ClientRequest(logline.msg.state.node_id)
    /\ ~logline.msg.globally_committable
    \* TODO Consider creating a mapping from clientRequests to actual values in the system trace.
    \* TODO Alternatively, extract the written values from the system trace and redefine clientRequests at startup.
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsSendAppendEntries ==
    /\ IsEvent("send_append_entries")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ AppendEntries(i, j)
             \* The  AppendEntries  action models the leader sending a message to some other node.  Thus, we could add a 
              \* constraint s.t.  Cardinality(messages') > Cardinality(messages)  .  However, the variable  messages  is
              \* a set and, thus, the variable  messages  remains unchanged if the leader resends the same message, which
              \* it may.
          /\ \E msg \in Network!Messages':
                /\ IsAppendEntriesRequest(msg, j, i, logline)
                \* There is now one more message of this type.
                /\ Network!OneMoreMessage(msg)
\* TODO revisit once nextIndex-related changes are merged in the spec
\*          /\ logline.msg.sent_idx = nextIndex[i][j]
          /\ logline.msg.match_idx = matchIndex[i][j]
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsRcvAppendEntriesRequest ==
    /\ IsEvent("recv_append_entries")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN /\ \E m \in Network!MessagesTo(i, j):
              /\ m.type = AppendEntriesRequest
              /\ \/ HandleAppendEntriesRequest(i, j, m)
                 \/ UpdateTerm(i, j, m) \cdot HandleAppendEntriesRequest(i, j, m)
                 \* ConflictAppendEntriesRequest truncates the log but does *not* consume the AE request. In other words, there is a
                  \* HandleAppendEntriesRequest step that leaves messages unchanged.
                 \/ RAERRAER(m):: (UNCHANGED messages /\ HandleAppendEntriesRequest(i, j, m)) \cdot HandleAppendEntriesRequest(i, j, m)
              /\ IsAppendEntriesRequest(m, i, j, logline)

IsSendAppendEntriesResponse ==
    \* Skip saer because ccfraft!HandleAppendEntriesRequest atomcially handles the request and sends the response.
       \* Find a similar pattern in Traceccfraft!IsRcvRequestVoteRequest below.
    /\ IsEvent("send_append_entries_response")
    /\ UNCHANGED vars
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)
 
IsAddConfiguration ==
    /\ IsEvent("add_configuration")
    /\ leadershipState[logline.msg.state.node_id] = Follower
    /\ UNCHANGED vars
\* This won't work in situations where we receive an AE range that contains a configuration at first followed by committable indices:
\* recv_append_entries will update the committable indices in the spec, but not in the impl state, which then goes on to handle an
\* add_configuration event on which state->committable_indices is (correctly) empty.
\*    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsSignCommittableMessages ==
    /\ IsEvent("replicate")
    /\ SignCommittableMessages(logline.msg.state.node_id)
    /\ logline.msg.globally_committable
    \* It is tempting to assert the effect of SignCommittableMessages(...node_id) here, i.e., 
     \* committableIndices'[logline.msg.state.node_id] = Range(logline'.msg.committable_indices).
     \* However, this assumes logline', i.e., TraceLog[l'], is less than or equal Len(TraceLog),
     \* which is not the case if the logs ends after this "replicate" line.  If it does not end,
     \* the subsequent send_append_entries will assert the effect of SignCommittableMessages anyway.
     \* Also see IsExecuteAppendEntries below.
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsAdvanceCommitIndex ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    \/ /\ IsEvent("commit")
       /\ logline.msg.state.leadership_state = "Leader"
       /\ LET i == logline.msg.state.node_id
          IN /\ AdvanceCommitIndex(i)
             /\ commitIndex'[i] = logline.msg.state.commit_idx
             /\ committableIndices'[i] = Range(logline.msg.state.committable_indices)
    \/ /\ IsEvent("commit")
       /\ UNCHANGED vars
       /\ logline.msg.state.leadership_state = "Follower"

IsChangeConfiguration ==
    /\ IsEvent("add_configuration")
    /\ leadershipState[logline.msg.state.node_id] = Leader
    /\ LET i == logline.msg.state.node_id
           newConfiguration == DOMAIN logline.msg.new_configuration.nodes
       IN ChangeConfigurationInt(i, newConfiguration)
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsRcvAppendEntriesResponse ==
    /\ IsEvent("recv_append_entries_response")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN /\ logline.msg.sent_idx = sentIndex[i][j]
          /\ logline.msg.match_idx = matchIndex[i][j]
          /\ \E m \in Network!MessagesTo(i, j):
               /\ m.type = AppendEntriesResponse
               /\ \/ HandleAppendEntriesResponse(i, j, m)
                  \/ UpdateTerm(i, j, m) \cdot HandleAppendEntriesResponse(i, j, m)
                  \/ UpdateTerm(i, j, m) \cdot DropResponseWhenNotInState(i, j, m)
                  \/ DropResponseWhenNotInState(i, j, m)
               /\ IsAppendEntriesResponse(m, i, j, logline)
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsSendRequestVote ==
    /\ IsEvent("send_request_vote")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ RequestVote(i, j)
          /\ \E m \in Network!Messages':
                /\ m.type = RequestVoteRequest
                /\ m.type = RaftMsgType[logline.msg.packet.msg]
                /\ m.term = logline.msg.packet.term
                /\ m.lastCommittableIndex = logline.msg.packet.last_committable_idx
                /\ m.lastCommittableTerm = logline.msg.packet.term_of_last_committable_idx
                \* There is now one more message of this type.
                /\ Network!OneMoreMessage(m)
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsRcvRequestVoteRequest ==
    \/ /\ IsEvent("recv_request_vote")
       /\ LET i == logline.msg.state.node_id
              j == logline.msg.from_node_id
          IN \E m \in Network!MessagesTo(i, j):
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
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsExecuteAppendEntries ==
    \* Skip append because ccfraft!HandleRequestVoteRequest atomcially handles the request, sends the response,
       \* and appends the entry to the ledger.
       /\ IsEvent("execute_append_entries_sync")
       \* Not asserting committableIndices here because the impl and spec will only be in sync upon the subsequent send_append_entries.
       \* Also see IsSignCommittableMessages above.
       /\ UNCHANGED vars
       /\ leadershipState[logline.msg.state.node_id] = Follower
       /\ currentTerm[logline.msg.state.node_id] = logline.msg.state.current_view

IsRcvRequestVoteResponse ==
    /\ IsEvent("recv_request_vote_response")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.from_node_id
       IN \E m \in Network!MessagesTo(i, j):
            /\ m.type = RequestVoteResponse
            /\ m.dest   = i
            /\ m.source = j
            /\ m.term = logline.msg.packet.term
            /\ m.voteGranted = logline.msg.packet.vote_granted
            /\ \/ HandleRequestVoteResponse(i, j, m)
               \/ UpdateTerm(i, j, m) \cdot HandleRequestVoteResponse(i, j, m)
               \/ UpdateTerm(i, j, m) \cdot DropResponseWhenNotInState(i, j, m)
               \/ DropResponseWhenNotInState(i, j, m)
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsBecomeFollower ==
    /\ IsEvent("become_follower")
    /\ UNCHANGED vars \* UNCHANGED implies that it doesn't matter if we prime the previous variables.
    /\ leadershipState[logline.msg.state.node_id] # Leader
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsCheckQuorum ==
    /\ IsEvent("become_follower")
    /\ CheckQuorum(logline.msg.state.node_id)
    /\ leadershipState[logline.msg.state.node_id] = Leader
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

IsRcvProposeVoteRequest ==
    /\ IsEvent("recv_propose_request_vote")
    /\ leadershipState[logline.msg.state.node_id] = Leader
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ \E m \in Network!Messages':
                /\ m.type = ProposeVoteRequest
                /\ RcvProposeVoteRequest(i, j)
                /\ m.type = RaftMsgType[logline.msg.packet.msg]
                /\ m.term = logline.msg.packet.term
                \* There is now one more message of this type.
                /\ Network!OneMoreMessage(m)
    /\ committableIndices[logline.msg.state.node_id] = Range(logline.msg.state.committable_indices)

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

    \/ IsRcvProposeVoteRequest

TraceSpec ==
    \* In an ideal world with extremely fast compute and a sophisticated TLC evaluator, we would simply compose  DropMessage and
    \* TraceNext, i.e.,  DropMessage ⋅ TraceNext.  However, we are not in an ideal world, and, thus, we have to resort to the 
    \* ~ENABLED TraceNext... workaround that mitigates state-space explosion by constraining the loss of messages to when a behavior
    \* cannot be extended without losing/dropping messages. TLC handles the state-space explosion due to DropMessages at the level
    \* of TraceSpec just fine. Instead, the bottleneck is rather checking refinement of ccfraft, which involves evaluating the big
    \* formula  DropMessages ⋅ CCF!Next many times, which becomes prohibitively expensive with only modest state-space explosion.
    \*
    \* Other techniques, such as using an action constraint to ignore successors that unnecessarily discard messages, proved difficult
    \* to express. Excluding the variable 'messages' in TraceView also proved ineffective. In the end, it seems as if it needs a new
    \* mode in TLC that checks refinement only for the set of traces whose length equals Len(TraceLog). This means delaying the
    \* refinement check until after the log has been matched. The class tlc2.tool.CheckImplFile might be a good starting point, although
    \* its current implementation doesn't account for non-determinism arising from log gaps or missed messages.
    TraceInit /\ [][(IF ~ENABLED TraceNext THEN DropMessages \cdot TraceNext ELSE TraceNext)]_<<l, ts, vars>>

-------------------------------------------------------------------------------------

TraceView ==
    \* A high-level state  s  can appear multiple times in a system trace.  Including the
     \* current level in TLC's view ensures that TLC will not stop model checking when  s
     \* appears the second time in the trace.  Put differently,  TraceView  causes TLC to
     \* consider  s_i  and s_j  , where  i  and  j  are the positions of  s  in the trace,
     \* to be different states.
    <<vars, l, ts>>

-------------------------------------------------------------------------------------

\* The property TraceMatched below will be violated if TLC runs with more than a single worker.
ASSUME TLCGet("config").worker = 1

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
    \*
    \* Note: Consider changing {1,2,3} to (Nat \ {0}) while validating traces with holes.
    [](l <= Len(TraceLog) => [](TLCGet("queue") \in Nat \ {0} \/ l > Len(TraceLog)))

-------------------------------------------------------------------------------------

TraceDifferentialInv ==
    \* Differential trace validation, i.e., compare the current run to an earlier, recorded TLA+ trace:
     \* First run:
     \* 1) Enable deadlock checking to make TLC report a counterexample
     \* 2) Run TLC with -dumptrace TLCplain trace.tla
     \* 3) Add EXTENDS ccfraft to top of trace.tla
     \* Second Run:
     \* 1) Toggle comments of TRUE and the LET/IN below
    TRUE
    \* LET t == INSTANCE trace d == t!Trace[l]
    \* IN /\ d.removedFromConfiguration = removedFromConfiguration
    \*    /\ d.configurations = configurations
    \*    /\ d.messages = messages
    \*    /\ d.currentTerm = currentTerm
    \*    /\ d.state = state
    \*    /\ d.votedFor = votedFor
    \*    /\ d.log = log
    \*    /\ d.commitIndex = commitIndex
    \*    /\ d.clientRequests = clientRequests
    \*    /\ d.votesGranted = votesGranted
    \*    /\ d.votesRequested = votesRequested
    \*    /\ d.sentIndex = sentIndex
    \*    /\ d.matchIndex = matchIndex

-------------------------------------------------------------------------------------

TraceAlias ==
    DebugAlias @@
    [
        _logline |-> TraceLog[l-1]

        \* Uncomment _ENABLED when debugging the enablement state of ccfraft's actions.
        \* ,_ENABLED |-> 
        \*     [
        \*         Timeout                    |-> [ i \in Servers   |-> ENABLED Timeout(i) ],
        \*         RequestVote                |-> [ i,j \in Servers |-> ENABLED RequestVote(i, j) ],
        \*         BecomeLeader               |-> [ i \in Servers   |-> ENABLED BecomeLeader(i) ],
        \*         ClientRequest              |-> [ i \in Servers   |-> ENABLED ClientRequest(i) ],
        \*         SignCommittableMessages    |-> [ i \in Servers   |-> ENABLED SignCommittableMessages(i) ],
        \*         ChangeConfiguration        |-> [ i \in Servers   |-> ENABLED ChangeConfiguration(i) ],
        \*         AdvanceCommitIndex         |-> [ i \in Servers   |-> ENABLED AdvanceCommitIndex(i) ],
        \*         AppendEntries              |-> [ i,j \in Servers |-> ENABLED AppendEntries(i, j) ],
        \*         CheckQuorum                |-> [ i \in Servers   |-> ENABLED CheckQuorum(i) ],
        \*         Receive                    |-> [ m,n \in Servers |-> ENABLED Receive(m, n) ],
        \*         RcvAppendEntriesRequest    |-> [ m,n \in Servers |-> ENABLED RcvAppendEntriesRequest(m, n) ],
        \*         RcvAppendEntriesResponse   |-> [ m,n \in Servers |-> ENABLED RcvAppendEntriesResponse(m, n) ],
        \*         RcvUpdateTerm              |-> [ m,n \in Servers |-> ENABLED RcvUpdateTerm(m, n) ],
        \*         RcvRequestVoteRequest      |-> [ m,n \in Servers |-> ENABLED RcvRequestVoteRequest(m, n) ],
        \*         RcvRequestVoteResponse     |-> [ m,n \in Servers |-> ENABLED RcvRequestVoteResponse(m, n) ]
        \*     ]

        \* See TraceDifferentialInv above.
        \* ,_TraceDiffState |-> LET t == INSTANCE trace IN t!Trace[l]
    ]

-------------------------------------------------------------------------------------

VoteResponse ==
    { msg \in Network!Messages: msg.type = RequestVoteResponse }

VoteRequests ==
    { msg \in Network!Messages: msg.type = RequestVoteRequest }

AppendEntriesRequests ==
    { msg \in Network!Messages: msg.type = AppendEntriesRequest }

AppendEntriesResponses ==
    { msg \in Network!Messages: msg.type = AppendEntriesResponse }

-------------------------------------------------------------------------------------

RcvUpdateTermReqVote(i, j) ==
    RcvUpdateTerm(i, j) \cdot RcvRequestVoteRequest(i, j)

RcvUpdateTermRcvRequestVoteResponse(i, j) ==
    RcvUpdateTerm(i, j) \cdot RcvRequestVoteResponse(i, j)

RcvUpdateTermReqAppendEntries(i, j) ==
    RcvUpdateTerm(i, j) \cdot RcvAppendEntriesRequest(i, j)

RcvUpdateTermRcvAppendEntriesResponse(i, j) ==
    RcvUpdateTerm(i, j) \cdot RcvAppendEntriesResponse(i, j)

RcvAppendEntriesRequestRcvAppendEntriesRequest(i, j) ==
    RcvAppendEntriesRequest(i, j) \cdot RcvAppendEntriesRequest(i, j)

ComposedNext ==
    \* The implementation raft.h piggybacks UpdateTerm messages on the AppendEntries
     \* and Vote messages.  Thus, we need to compose the UpdateTerm action with the
     \* corresponding AppendEntries and RequestVote actions.  This is a reasonable
     \* code-level optimization that we do not want to model explicitly in TLA+.
    \E i, j \in Servers:
        \/ RcvUpdateTermReqVote(i, j)
        \/ RcvUpdateTermRcvRequestVoteResponse(i, j)
        \/ RcvUpdateTermReqAppendEntries(i, j)
        \/ RcvUpdateTermRcvAppendEntriesResponse(i, j)
        \* The sub-action IsRcvAppendEntriesRequest requires a disjunct composing two 
        \* successive RcvAppendEntriesRequest to validate suffix_collision.1 and fancy_election.1.
        \* The trace validation fails with violations of property CCFSpec if we do not
        \* conjoin the composed action below. See the (marker) label RAERRAER above.
        \/ RcvAppendEntriesRequestRcvAppendEntriesRequest(i, j)

CCF == INSTANCE ccfraft

DropAndReceive(i, j) ==
    DropMessages \cdot CCF!Receive(i, j)

CCFSpec == CCF!Init /\ [][CCF!Next \/ (DropMessages \cdot ComposedNext)]_CCF!vars

==================================================================================
