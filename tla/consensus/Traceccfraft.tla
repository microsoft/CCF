-------------------------------- MODULE Traceccfraft -------------------------------
EXTENDS ccfraft, Json, IOUtils, Sequences, MCAliases

\* raft_types.h enum RaftMsgType
RaftMsgType ==
    "raft_append_entries" :> AppendEntriesRequest @@ "raft_append_entries_response" :> AppendEntriesResponse @@
    "raft_request_vote" :> RequestVoteRequest @@ "raft_request_pre_vote" :> RequestVoteRequest @@ 
    "raft_request_vote_response" :> RequestVoteResponse @@ "raft_request_pre_vote_response" :> RequestVoteResponse @@
    "raft_propose_request_vote" :> ProposeVoteRequest

ToLeadershipState ==
    "Follower" :>  Follower @@ 
    "PreVoteCandidate" :> PreVoteCandidate @@
    "Candidate" :> Candidate @@
    "Leader" :> Leader @@
    "None" :> None

ToMembershipState ==
    \* https://github.com/microsoft/CCF/blob/61bc8ef25ba636b6f5915dfc69647e2ae9cf47c7/tla/consensus/ccfraft.tla#L54
    "Active" :> {Active} @@
    "Retired" :> {RetirementOrdered, RetirementSigned, RetirementCompleted, RetiredCommitted}

IsHeader(msg, dst, src, logline, type) ==
    /\ msg.type = type
    /\ msg.type = RaftMsgType[logline.msg.packet.msg]
    /\ msg.dest   = dst
    /\ msg.source = src
    /\ msg.term = logline.msg.packet.term

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
    /\ IsHeader(msg, dst, src, logline, AppendEntriesRequest)
    /\ msg.commitIndex = logline.msg.packet.leader_commit_idx
    /\ msg.prevLogTerm = logline.msg.packet.prev_term
    /\ Len(msg.entries) = logline.msg.packet.idx - logline.msg.packet.prev_idx
    /\ msg.prevLogIndex + Len(msg.entries) = logline.msg.packet.idx
    /\ msg.prevLogIndex = logline.msg.packet.prev_idx

IsAppendEntriesResponse(msg, dst, src, logline) ==
    /\ IsHeader(msg, dst, src, logline, AppendEntriesResponse)
    \* raft_types.h enum AppendEntriesResponseType
    /\ msg.success = (logline.msg.packet.success = "OK")
    /\ msg.lastLogIndex = logline.msg.packet.last_log_idx

IsRequestVoteRequest(msg, dst, src, logline) ==
    /\ IsHeader(msg, dst, src, logline, RequestVoteRequest)
    /\ msg.lastCommittableIndex = logline.msg.packet.last_committable_idx
    /\ msg.lastCommittableTerm = logline.msg.packet.term_of_last_committable_idx
    /\ IF logline.msg.packet.msg = "raft_request_vote"
       THEN msg.isPreVote = FALSE
       ELSE msg.isPreVote = TRUE

IsRequestVoteResponse(msg, dst, src, logline) ==
    /\ IsHeader(msg, dst, src, logline, RequestVoteResponse)
    /\ msg.voteGranted = logline.msg.packet.vote_granted

IsProposeVoteRequest(msg, dst, src, logline) ==
    /\ IsHeader(msg, dst, src, logline, ProposeVoteRequest)
    
IsMessage(msg, dst, src, logline) ==
    CASE msg.type = AppendEntriesResponse -> IsAppendEntriesResponse(msg, dst, src, logline)
      [] msg.type = AppendEntriesRequest  -> IsAppendEntriesRequest(msg, dst, src, logline)
      [] msg.type = RequestVoteRequest    -> IsRequestVoteRequest(msg, dst, src, logline)
      [] msg.type = RequestVoteResponse   -> IsRequestVoteResponse(msg, dst, src, logline)
      [] msg.type = ProposeVoteRequest    -> IsProposeVoteRequest(msg, dst, src, logline)

-------------------------------------------------------------------------------------

\* Trace validation has been designed for TLC running in default model-checking
 \* mode, i.e., breadth-first search.
ASSUME TLCGet("config").mode = "bfs"

JsonFile ==
    IF "CCF_RAFT_TRACE" \in DOMAIN IOEnv THEN IOEnv.CCF_RAFT_TRACE ELSE "../traces/consensus/append.ndjson"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
    \* Run TLC from under the tla/ directory with:
    \* ./tlc.py --ccf-raft-trace ../build/startup.ndjson consensus/Traceccfraft.tla
    \* Traces can be generated with: ./make_traces.sh, also under the tla/ directory.
    ndJsonDeserialize(JsonFile)

TraceLog ==
    SelectSeq(JsonLog, LAMBDA l: l.tag = "raft_trace")

JsonServers ==
    TLCEval(LET Card == Cardinality({ TraceLog[i].msg.state.node_id: i \in DOMAIN TraceLog })
            IN Print(<< "Trace:", JsonFile, "Length:", IF Card = 0 THEN "EMPTY" ELSE Len(TraceLog)>>, Card))
    
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
    /\ InitLogConfigServerVars({TraceLog[1].msg.state.node_id}, StartLog)

TraceInitPreVoteStatus == PreVoteStatusTypeInv

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

\* Beware to only prime e.g. inbox in inbox'[rcv] and *not* also rcv, i.e.,
 \* inbox[rcv]'.  rcv is defined in terms of TLCGet("level") that correctly
 \* handles priming, which causes for rcv' to equal rcv of the next log line.
IsEvent(e) ==
    \* Equals FALSE if we get past the end of the log, causing model checking to stop.
    /\ l \in 1..Len(TraceLog)
    /\ logline.msg.function = e
    /\ l' = l + 1
    /\ ts' = logline.h_ts

\* Message loss is known in controlled environments, such as raft (driver) scenarios. However, this assumption
\* does not hold for traces collected from production workloads.  In these instances, message loss must be
\* modeled in non-deterministically.  For example, by composing message loss to the next-state relation:
\*   Network!DropMessages(logline.msg.state.node_id) \cdot TraceNext 
\* and
\*   Network!DropMessages(logline.msg.state.node_id) \cdot CCF!Next
IsDropPendingTo ==
    /\ IsEvent("drop_pending_to")
    /\ Network!DropMessage(logline.msg.to_node_id,
                LAMBDA msg: IsMessage(msg, logline.msg.to_node_id, logline.msg.from_node_id, logline))
    /\ UNCHANGED <<preVoteStatus, reconfigurationVars, serverVars, candidateVars, leaderVars, logVars>>

IsTimeout ==
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])
    /\ \/ /\ IsEvent("become_pre_vote_candidate")
          /\ logline.msg.state.leadership_state = "PreVoteCandidate"
       \/ /\ IsEvent("become_candidate")
          /\ logline.msg.state.leadership_state = "Candidate"
    /\ Timeout(logline.msg.state.node_id)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState'[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx

IsBecomeCandidate ==
    /\ IsEvent("become_candidate")
    /\ logline.msg.state.leadership_state = "Candidate"
    /\ logline.msg.state.pre_vote_enabled /\ PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id]
    /\ BecomeCandidateFromPreVoteCandidate(logline.msg.state.node_id)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState'[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx

IsRcvProposeVoteRequest ==
  /\ IsEvent("recv_propose_request_vote")
  /\ LET i == logline.msg.state.node_id
     IN
     \E j \in Servers:
     \E m \in Network!MessagesTo(i,j):
        /\ m.type = ProposeVoteRequest
        /\ m.term = logline.msg.packet.term
        /\ RcvProposeVoteRequest(i,j)
  /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
  /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
  /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsBecomeLeader ==
    /\ IsEvent("become_leader")
    /\ logline.msg.state.leadership_state = "Leader"
    /\ BecomeLeader(logline.msg.state.node_id)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState'[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])
    
IsClientRequest ==
    /\ IsEvent("replicate")
    /\ ClientRequest(logline.msg.state.node_id)
    /\ ~logline.msg.globally_committable
    /\ logline.cmd_prefix # "cleanup_nodes" 
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsCleanupNodes ==
    /\ IsEvent("replicate")
    /\ AppendRetiredCommitted(logline.msg.state.node_id)
    /\ ~logline.msg.globally_committable
    /\ logline.cmd_prefix = "cleanup_nodes"
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

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
          /\ logline.msg.match_idx = matchIndex[i][j]
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

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
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsSendAppendEntriesResponse ==
    \* Skip saer because ccfraft!HandleAppendEntriesRequest atomcially handles the request and sends the response.
       \* Find a similar pattern in Traceccfraft!IsRcvRequestVoteRequest below.
    /\ IsEvent("send_append_entries_response")
    /\ UNCHANGED vars
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])
 
IsAddConfiguration ==
    /\ IsEvent("add_configuration")
    /\ leadershipState[logline.msg.state.node_id] = Follower
    /\ UNCHANGED vars
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

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
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsAdvanceCommitIndex ==
    \* This is enabled *after* a SignCommittableMessages because ACI looks for a 
     \* TypeSignature entry in the log.
    \/ /\ IsEvent("commit")
       /\ logline.msg.state.leadership_state = "Leader"
       /\ LET i == logline.msg.state.node_id
          IN /\ AdvanceCommitIndex(i)
             /\ commitIndex'[i] = logline.msg.args.idx
             /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
       /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
       /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
       /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
       /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
       /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])
    \/ /\ IsEvent("commit")
       /\ UNCHANGED vars
       /\ logline.msg.state.leadership_state = "Follower"
       /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
       /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
       /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsChangeConfiguration ==
    /\ IsEvent("add_configuration")
    /\ leadershipState[logline.msg.state.node_id] = Leader
    /\ LET i == logline.msg.state.node_id
           newConfiguration == DOMAIN logline.msg.args.configuration.nodes
       IN ChangeConfigurationInt(i, newConfiguration)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

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
                  \* See comment on RcvAppendEntriesResponse in ccfraft
                  \/ /\ m.success
                     /\ DropStaleResponse(i, j, m)
               /\ IsAppendEntriesResponse(m, i, j, logline)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsSendRequestVote ==
    /\ IsEvent("send_request_vote")
    /\ LET i == logline.msg.state.node_id
           j == logline.msg.to_node_id
       IN /\ RequestVote(i, j)
          /\ \E m \in Network!Messages':
                \* Assert that as a result of RequestVote above, the variable messages is changed to contain
                \* a RequestVoteRequest message sent from i to j.
                /\ IsRequestVoteRequest(m, j, i, logline)
                /\ Network!OneMoreMessage(m)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsRcvRequestVoteRequest ==
    \/ /\ IsEvent("recv_request_vote")
       /\ LET i == logline.msg.state.node_id
              j == logline.msg.from_node_id
          IN \E m \in Network!MessagesTo(i, j):
               /\ IsRequestVoteRequest(m, i, j, logline)
               /\ \/ HandleRequestVoteRequest(i, j, m)
                  \* Below formula is a decomposed TraceRcvUpdateTermReqVote step, i.e.,
                  \* a (ccfraft!UpdateTerm \cdot ccfraft!HandleRequestVoteRequest) step.
                  \* (see https://github.com/microsoft/CCF/issues/5057#issuecomment-1487279316)
                  \/ UpdateTerm(i, j, m) \cdot HandleRequestVoteRequest(i, j, m)
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsExecuteAppendEntries ==
    \* Skip append because ccfraft!HandleRequestVoteRequest atomically handles the request, sends the response,
       \* and appends the entry to the ledger.
       /\ IsEvent("execute_append_entries_sync")
       \* Not asserting CommittableIndices here because the impl and spec will only be in sync upon the subsequent send_append_entries.
       \* Also see IsSignCommittableMessages above.
       /\ UNCHANGED vars
       /\ leadershipState[logline.msg.state.node_id] = Follower
       /\ currentTerm[logline.msg.state.node_id] = logline.msg.state.current_view
       /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
       /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
       /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsRcvRequestVoteResponse ==
    /\ \/ IsEvent("recv_request_vote_response")
       \/ IsEvent("recv_request_pre_vote_response")
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
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsBecomeFollower ==
    /\ IsEvent("become_follower")
    /\ UNCHANGED vars \* UNCHANGED implies that it doesn't matter if we prime the previous variables.
    \* We don't assert committable and last idx here, as the spec and implementation are out of sync until
    \* IsSendAppendEntriesResponse or IsSendRequestVote (in the candidate path)
    /\ leadershipState[logline.msg.state.node_id] # Leader
    /\ leadershipState[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

IsCheckQuorum ==
    /\ IsEvent("become_follower")
    /\ CheckQuorum(logline.msg.state.node_id)
    /\ leadershipState[logline.msg.state.node_id] = Leader
    /\ Range(logline.msg.state.committable_indices) \subseteq CommittableIndices(logline.msg.state.node_id)
    /\ commitIndex[logline.msg.state.node_id] = logline.msg.state.commit_idx
    /\ leadershipState'[logline.msg.state.node_id] = ToLeadershipState[logline.msg.state.leadership_state]
    /\ membershipState[logline.msg.state.node_id] \in ToMembershipState[logline.msg.state.membership_state]
    /\ Len(log[logline.msg.state.node_id]) = logline.msg.state.last_idx
    /\ (logline.msg.state.pre_vote_enabled => PreVoteEnabled \in preVoteStatus[logline.msg.state.node_id])

TraceNext ==
    \/ IsTimeout
    \/ IsBecomeCandidate
    \/ IsBecomeLeader
    \/ IsBecomeFollower
    \/ IsCheckQuorum

    \/ IsClientRequest
    \/ IsCleanupNodes

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

    \/ IsDropPendingTo

TraceSpec ==
    TraceInit /\ [][TraceNext]_<<l, ts, vars>>

-------------------------------------------------------------------------------------

Termination ==
    l = Len(TraceLog) => TLCSet("exit", TRUE)

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
    \* Note: Consider strengthening (Nat \ {0}) to {1} when validating traces with no nondeterminism.
    [](l <= Len(TraceLog) => [](TLCGet("queue") \in Nat \ {0} \/ l > Len(TraceLog)))

TraceMatchedNonTrivially ==
    \* If, e.g., the FALSE state constraint excludes all states, TraceMatched won't be violated.
    TLCGet("stats").diameter = Len(TraceLog)

TraceMatchesConstraints ==
    \* ccfraft's invariants become (state) constraints in Traceccfraft.  When validating traces,
    \* the constraints exclude all states that do not satisfy the "invariants".  If no states
    \* remain and the level  l  is less than the length of the trace log, i.e.,  Len(TraceLog),
    \* TraceMatched  above will be violated and TLC will print a counterexample.
    /\ LogInv
    /\ MoreThanOneLeaderInv
    /\ CandidateTermNotInLogInv
    /\ ElectionSafetyInv
    /\ LogMatchingInv
    /\ QuorumLogInv
    /\ LeaderCompletenessInv
    /\ SignatureInv
    /\ TypeInv
    /\ MonoTermInv
    /\ MonoLogInv
    /\ NoLeaderBeforeInitialTerm
    /\ LogConfigurationConsistentInv
    /\ MembershipStateConsistentInv
    /\ CommitCommittableIndices

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
    \* IN /\ d.configurations = configurations
    \*    /\ d.messages = messages
    \*    /\ d.currentTerm = currentTerm
    \*    /\ d.state = leadershipState
    \*    /\ d.votedFor = votedFor
    \*    /\ d.log = log
    \*    /\ d.commitIndex = commitIndex
    \*    /\ d.votesGranted = votesGranted
    \*    /\ d.sentIndex = sentIndex
    \*    /\ d.matchIndex = matchIndex

-------------------------------------------------------------------------------------

TraceAlias ==
    DebugAlias @@
    [
        l |-> l,
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
    \* Differential trace validation, i.e., compare the current run to an earlier, recorded TLA+ trace:
     \* First run:
     \* 1) Enable deadlock checking to make TLC report a counterexample
     \* 2) Run TLC with -dumptrace TLCplain trace.tla
     \* 3) Add EXTENDS ccfraft to top of trace.tla
     \* Second Run:
     \* 1) Toggle comments below and adjust record definition to your needs. 
    \* @@
    \* LET t == INSTANCE trace d == t!Trace[l] IN
    \* [
    \*     \* here and there are the messages in the current run that are not in the previous run and vice versa.
    \*     here  |-> Network!Messages \ UNION { UNION { Range(d.messages[src][dst]) : dst \in Servers } : src \in Servers },
    \*     there |-> UNION { UNION { Range(d.messages[src][dst]) : dst \in Servers } : src \in Servers } \ Network!Messages
    \* ]

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

ComposedNext ==
    \* The implementation raft.h piggybacks UpdateTerm messages on the AppendEntries
     \* and Vote messages.  Thus, we need to compose the UpdateTerm action with the
     \* corresponding AppendEntries and RequestVote actions.  This is a reasonable
     \* code-level optimization that we do not want to model explicitly in TLA+.
    \E i, j \in Servers:
        \/ RcvUpdateTerm(i, j) \cdot
            \/ RcvRequestVoteRequest(i, j)
            \/ RcvRequestVoteResponse(i, j)
            \/ RcvAppendEntriesRequest(i, j)
            \/ RcvAppendEntriesResponse(i, j)
        \* The sub-action IsRcvAppendEntriesRequest requires a disjunct composing two 
        \* successive RcvAppendEntriesRequest to validate suffix_collision.1 and fancy_election.1.
        \* The trace validation fails with violations of property CCFSpec if we do not
        \* conjoin the composed action below. See the (marker) label RAERRAER above.
        \/ RcvAppendEntriesRequest(i, j) \cdot RcvAppendEntriesRequest(i, j)

CCF == INSTANCE ccfraft

CCFSpec == CCF!Init /\ [][CCF!Next \/ ComposedNext \/ IsDropPendingTo]_CCF!vars

==================================================================================
