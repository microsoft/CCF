-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    << AppendEntriesRequest, AppendEntriesResponse, 
       RequestVoteRequest, RequestVoteResponse >>

LeadershipState ==
    Leader :> "Leader" @@ Follower :> "Follower" @@ Candidate :> "Candidate" @@ Pending :> "Pending"

\* Trace validation has been designed for TLC running in default model-checking
 \* mode, i.e., breadth-first search.
ASSUME TLCGet("config").mode = "bfs"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
     \* Run TLC with (assuming a suitable "tlc" shell alias):
     \* $ JSON=../tests/raft_scenarios/4582.ndjson tlc -note Traceccfraft
     \* Fall back to trace.ndjson if the JSON environment variable is not set.
    ndJsonDeserialize(IF "JSON" \in DOMAIN IOEnv THEN IOEnv.JSON ELSE "replicate.ndjson")

TraceServers ==
    { NodeOne, NodeTwo, NodeThree }

TraceLog ==
    SelectSeq(JsonLog, LAMBDA l: l.tag = "tla")

\* In:  <<[idx |-> 0, nodes |-> [0 |-> [address |-> ":"]], rid |-> 0]>>
\* Out: (0 :> {0})
ToConfigurations(c) ==
    FoldSeq(LAMBDA x,y: (x.idx :> DOMAIN x.nodes) @@ y, <<>>, c)

-------------------------------------------------------------------------------------

TraceInit ==
    /\ Init
    \* Constraint the set of initial states to the ones that match the nodes
     \* that are members of the initial configuration
     \* (see  \E c \in SUBSET Servers: ...  in ccraft!InitReconfigurationVars).
    /\ TraceLog[1].msg.event = [ component |-> "raft", function |-> "add_configuration" ]
    /\ ToConfigurations(TraceLog[1].msg.configurations) = configurations[TraceLog[1].msg.node]

TraceStutter ==
    /\ UNCHANGED vars

TraceSpec ==
    \* Because of  [A]_v <=> A \/ v=v'  , the following formula is logically
     \* equivalent to the (canonical) Spec formual  Init /\ [][Next]_vars  .  
     \* However, TLC's breadth-first algorithm does not explore successor
     \* states of a *seen* state.  Since one or more states may appear one or 
     \* more times in the the trace, the  UNCHANGED vars  combined with the
     \*  TraceView  that includes  TLCGet("level")  is our workaround. 
    TraceInit /\ [][Next \/ TraceStutter \/ RcvUpdateTerm \cdot RcvUpdateTerm]_vars

-------------------------------------------------------------------------------------

\* Beware to only prime e.g. inbox in inbox'[rcv] and *not* also rcv, i.e.,
 \* inbox[rcv]'.  rcv is defined in terms of TLCGet("level") that correctly
 \* handles priming, which causes for rcv' to equal rcv of the next log line.


IsTimeout(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_candidate" ]
    /\ logline.msg.leadership = "Candidate"
    /\ UNCHANGED <<reconfigurationVars, messageVars, leaderVars, logVars>>
    /\ LET n == logline.msg.node
       IN
       /\ configurations[n] = ToConfigurations(logline.msg.configurations)
       /\ state[n] \in {Follower, Candidate}
       /\ state'[n] = Candidate

IsBecomeLeader(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_leader" ]
    /\ logline.msg.leadership = "Leader"
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, messageVars, currentTerm, votedFor,
                   votesRequested, candidateVars, commitIndex, clientRequests, committedLog>>
    /\ state'[logline.msg.node] = Leader
    
IsClientRequest(logline) ==
    /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
    /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars,
                   leaderVars, commitIndex, committedLog>>
    /\ LET n == logline.msg.node IN
       /\ Len(log'[n]) > Len(log[n])
       /\ Len(log'[n]) = logline.msg.index
       /\ Last(log'[n]).contentType = TypeEntry
       \* ??? Why does term need to be offset? Hypothesis: ccfraft!InitServerVars inits
        \* ??? currentTerm to 1.  Perhaps, raft.h initializes it to 0.
       /\ Last(log'[n]).term = logline.msg.term + 1
       \* Cannot match value because ccfraft models clientRequests as a monotonically
        \* increasing number.
       \* TODO Consider creating a mapping from clientRequests to actual values in the system trace.
        \* TODO Alternatively, extract the written values from the system trace and redefine clientRequests at startup.

IsAppendEntries(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "send_authenticated" ]
    /\ UNCHANGED <<reconfigurationVars, commitsNotified, serverVars, candidateVars, leaderVars, logVars>>
    /\ LET n == logline.msg.node IN
       \* The  AppendEntries  action models the leader sending a message to some other node.  Thus, we could add a 
        \* constraint s.t.  Cardinality(messages') > Cardinality(messages)  .  However, the variable  messages  is
        \* a set and, thus, the variable  messages  remains unchanged if the leaders resend the same message, which
        \* it may.
       /\ Cardinality(messages') >= Cardinality(messages)
       /\ \E m \in messages':
            /\ m.mdest = logline.msg.to
            /\ m.mtype = RaftMsgType[logline.msg.paket.msg + 1]
            \* TODO node_to_node.h does not correctly log the sender's id.
            \* TODO/\ m.msource = logline.msg.node

IsSignCommittableMessages(logline) ==
    /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
    /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog>>
    /\ LET n == logline.msg.node
       IN /\ state[n] = Leader
          /\ log'[n] # <<>>
          \* ??? Can currentTerm increase independently?
          \* TODO logline.msg.term missing in the current TraceLog!
          \* TODO/\ currentTerm'[n] = logline.msg.term
          /\ LET entry == Last(log'[n])
             IN /\ entry.contentType = TypeSignature
                /\ entry.value = Nil
                \* TODO logline.msg.term missing in the current TraceLog!
                \* TODO/\ entry.term  = log.msg.term

IsAdvanceCommitIndex(logline) ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    /\ logline.msg.event = [ component |-> "store", function |-> "compact" ]
    /\ UNCHANGED <<messageVars, candidateVars, leaderVars, log, clientRequests>>
    /\ LET n == logline.msg.node
       IN /\ state[n] = Leader
          \* We should be matching logline.msg.state.commit_idx to n's commitIndex.
           \*   commitIndex'[n] = logline.msg.state.commit_idx
           \* However, the TLA+ models signatures as explicit log entries whereas
           \* the code does not add entries to the log when signing. We approximate
           \* the previous statement instead:
          /\ commitIndex'[n] > commitIndex[n]
          /\ commitIndex'[n] >= logline.msg.state.commit_idx

IsChangeConfiguration(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "add_configuration" ]
    /\ UNCHANGED <<messageVars, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog>>
    /\ reconfigurationCount' = reconfigurationCount + 1
    /\ removedFromConfiguration' # removedFromConfiguration
    /\ LET n == logline.msg.node
       IN /\ state[n] = Leader
          /\ Last(log'[n]).contentType = TypeReconfiguration
          /\ Last(log'[n]).term = logline.msg.state.current_view

IsChangeConfigurationLedger(logline) ==
    /\ logline.msg.event = [ component |-> "ledger", function |-> "append" ]
    \* TODO driver::put_entry should include the type of the data in the log entry, such as "raw" or "reconfiguration".
    /\ UNCHANGED vars

IsRcvUpdateTerm(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "recv_append_entries" ]
    /\ UNCHANGED <<reconfigurationVars, messageVars, candidateVars, leaderVars, logVars>>
    /\ LET n == logline.msg.node
       IN /\ currentTerm'[n] = logline.msg.paket.term
          /\ \E m \in messages':
              /\ m.mdest   = n
              /\ m.msource = logline.msg.from
              /\ m.mtype   = RaftMsgType[logline.msg.paket.msg + 1]

IsNoConflictAppendEntriesRequest(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "become_follower" ]
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, messagesSent, commitsNotified, currentTerm, votedFor, clientRequests, committedLog>>
    /\ LET n == logline.msg.node
       IN /\ LeadershipState[state'[n]] = logline.msg.leadership

IsRequestVote(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "send_request_vote" ]
    /\ LET n == logline.msg.node
           m == logline.msg.to
       IN <<RequestVote(n, m)>>_vars \* TODO Just  A  or indeed  <<A>>_v  , and what variables to include in  v?

IsRcvRequestVote(logline) ==
    /\ logline.msg.event = [ component |-> "raft", function |-> "recv_request_vote" ]
    /\ LET n == logline.msg.node
           m == logline.msg.from
       IN \E msg \in messages:
            /\ msg.mtype = RequestVoteRequest
            /\ msg.mdest   = n
            /\ msg.msource = m
            /\ TRUE
            /\ <<HandleRequestVoteRequest(n, m, msg)>>_vars

IsStuttering(logline) ==
    /\ logline.msg.event \in {
                                \* Add unhandled/ignored log statements here!
                                [component |-> "store", function |-> "initialize_term"]
                                \* ,
                                \* [component |-> "raft", function |-> "replicate"]
                                \* ,
                                \* [component |-> "node_to_node", function |-> "send_authenticated"],
                                \* [component |-> "channel", function |-> "send_authenticated"],
                                \* [component |-> "node_to_node", function |-> "recv_authenticated"],
                                \* [component |-> "channel", function |-> "recv_authenticated"]
                                ,[component |-> "store", function |-> "rollback"]
                                ,[component |-> "ledger", function |-> "truncate"]
                                \* ,[component |-> "raft", function |-> "become_follower"]
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
                 \/ IsClientRequest(logline)
                 \/ IsSignCommittableMessages(logline)
                 \/ IsAdvanceCommitIndex(logline)
                 \/ IsAppendEntries(logline)
                 \/ IsChangeConfiguration(logline)
                 \/ IsChangeConfigurationLedger(logline)
                 \/ IsRcvUpdateTerm(logline)
                 \/ IsNoConflictAppendEntriesRequest(logline)
                 \/ IsRequestVote(logline)
                 \/ IsRcvRequestVote(logline)
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

TraceAccepted ==
    \* If the prefix of the TLA+ behavior is shorter than the trace, TLC will
     \* report a violation of this postcondition.  But why do we need a postcondition
     \* at all?  Couldn't we use an ordinary property such as
     \*  <>[](TLCGet("level") >= Len(TraceLog))  ?  The answer is that an ordinary
     \* property is true of a single behavior, whereas  TraceAccepted  is true of a
     \* set of behaviors; it is essentially a poor man's hyperproperty.
    LET d == TLCGet("stats").diameter IN
    IF d = Len(TraceLog) THEN TRUE
    ELSE Print(<<"Failed matching the trace to (a prefix of) a behavior:", TraceLog[d+1], 
                    "TLA+ debugger breakpoint hit count " \o ToString(d+1)>>, FALSE)

TraceAlias ==
    [
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
                Timeout                 |-> ENABLED \E i \in Servers : Timeout(i),
                RequestVote             |-> ENABLED \E i, j \in Servers : RequestVote(i, j),
                BecomeLeader            |-> ENABLED \E i \in Servers : BecomeLeader(i),
                ClientRequest           |-> ENABLED \E i \in Servers : ClientRequest(i),
                SignCommittableMessages |-> ENABLED \E i \in Servers : SignCommittableMessages(i),
                ChangeConfiguration     |-> ENABLED \E i \in Servers : \E c \in SUBSET(Servers \ removedFromConfiguration) : ChangeConfiguration(i, c),
                NotifyCommit            |-> ENABLED \E i, j \in Servers : NotifyCommit(i,j),
                AdvanceCommitIndex      |-> ENABLED \E i \in Servers : AdvanceCommitIndex(i),
                AppendEntries           |-> ENABLED \E i, j \in Servers : AppendEntries(i, j),
                CheckQuorum             |-> ENABLED \E i \in Servers : CheckQuorum(i),
                Receive                 |-> ENABLED Receive 
            ]
    ]
==================================================================================
