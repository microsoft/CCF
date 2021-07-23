--------------------------------- MODULE ccfraft ---------------------------------
\* This is the formal specification for the Raft consensus algorithm.
\*
\* Copyright 2014 Diego Ongaro.
\* Modifications Copyright 2021 Microsoft.
\* This work is licensed under the Creative Commons Attribution-4.0
\* International License https://creativecommons.org/licenses/by/4.0/

\* Modified for CCF by Microsoft Research
\* Author of these modifications: Fritz Alder <fritz.alder@acm.org>
\* Partially based on
\* - https://github.com/ongardie/raft.tla/blob/master/raft.tla
\*   (base spec, modified)
\* - https://github.com/jinlmsft/raft.tla/blob/master/raft.tla
\*   (e.g. clientRequests, committedLog, committedLogDecrease)
\* - https://github.com/dricketts/raft.tla/blob/master/raft.tla
\*   (e.g. certain invariants)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS PossibleServer

\* The set and state of servers that we start with
CONSTANTS InitialServer, InitialConfig

\* Server states.
CONSTANTS Follower, Candidate, Leader, RetiredLeader, Pending

\* A reserved value.
CONSTANTS Nil

\* Message types:
CONSTANTS RequestVoteRequest, RequestVoteResponse,
          AppendEntriesRequest, AppendEntriesResponse,
          NotifyCommitMessage

\* CCF: Content types (Normal message or signature that signs
\*      previous messages)
CONSTANTS TypeEntry, TypeSignature, TypeReconfiguration

\* CCF: Limit on vote requests to be sent to each other node
CONSTANTS RequestVoteLimit

\* Limit on terms
CONSTANTS TermLimit

\* Limit on client requests
CONSTANTS RequestLimit

\* Limit for number of reconfigurations to be triggered
CONSTANTS ReconfigurationLimit

\* Limit max number of simultaneous candidates
CONSTANTS MaxSimultaneousCandidates

\* CCF: Limit how many messages each node can send to another
CONSTANTS MessagesLimit

\* CCF: Limit the number of commit notifications per commit Index and server
CONSTANTS CommitNotificationLimit

CONSTANTS NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive

----
\* Global variables

\* Keep track of current number of reconfigurations to limit it through the MC
VARIABLE ReconfigurationCount
\* Each server keeps track of the pending configurations
VARIABLE Configurations
reconfigurationVars == <<ReconfigurationCount, Configurations>>

\* A set representing requests and responses sent from one server
\* to another. With CCF, we have message integrity and can ensure unique messages.
VARIABLE messages
\* CCF: Keep track of each message sent from each server to each other server
\* and cap it to a maximum
VARIABLE messagesSent
\* CCF: After reconfiguration, a RetiredLeader leader may need to notify servers
\* of the current commit level to ensure that no deadlock is reached through 
\* leaving the network after retirement (as that would lead to endless leader 
\* re-elects and drop-outs until f is reached and network fails).
VARIABLE commitsNotified
messageVars == <<messages, messagesSent, commitsNotified>>
----
\* The following variables are all per server (functions with domain Server).

\* The server's term number.
VARIABLE currentTerm
\* The server's state (Follower, Candidate, or Leader).
VARIABLE state
\* The candidate the server voted for in its current term, or
\* Nil if it hasn't voted for any.
VARIABLE votedFor
serverVars == <<currentTerm, state, votedFor>>

\* The set of requests that can go into the log
VARIABLE clientRequests

\* A Sequence of log entries. The index into this sequence is the index of the
\* log entry. Unfortunately, the Sequence module defines Head(s) as the entry
\* with index 1, so be careful not to use that!
VARIABLE log
\* The index of the latest entry in the log the state machine may apply.
VARIABLE commitIndex
\* The index that gets committed
VARIABLE committedLog
\* Does the commited Index decrease
VARIABLE committedLogDecrease
logVars == <<log, commitIndex, clientRequests, committedLog, committedLogDecrease >>

\* The following variables are used only on candidates:
\* The set of servers from which the candidate has received a RequestVote
\* response in its currentTerm.
VARIABLE votesSent
\* The set of servers from which the candidate has received a vote in its
\* currentTerm.
VARIABLE votesGranted
\* State space limitation: Restrict each node to send a limited amount 
\* of requests to other nodes
VARIABLE votesRequested
candidateVars == <<votesSent, votesGranted, votesRequested>>

\* The following variables are used only on leaders:
\* The next entry to send to each follower.
VARIABLE nextIndex
\* The latest entry that each follower has acknowledged is the same as the
\* leader's. This is used to calculate commitIndex on the leader.
VARIABLE matchIndex
leaderVars == <<nextIndex, matchIndex>>

\* End of per server variables.
----

\* All variables; used for stuttering (asserting state hasn't changed).
vars == <<reconfigurationVars, messageVars, serverVars, candidateVars, leaderVars, logVars>>

----
\* Helpers

\* The term of the last entry in a log, or 0 if the log is empty.
LastTerm(xlog) == IF Len(xlog) = 0 THEN 0 ELSE xlog[Len(xlog)].term

\* Helper for Send and Reply. Given a message m and set of messages, return a
\* new set of messages with one more m in it.
WithMessage(m, msgs) == msgs \union {m}

\* Helper for Discard and Reply. Given a message m and bag of messages, return
\* a new bag of messages with one less m in it.
WithoutMessage(m, msgs) == msgs \ {m}

\* Add a message to the bag of messages.
\* But only if this exact messages does not already exist 
Send(m) == messages' = 
    WithMessage(m, messages)

\* Remove a message from the bag of messages. Used when a server is done
\* processing a message.
Discard(m) == messages' = WithoutMessage(m, messages)

\* Combination of Send and Discard
Reply(response, request) ==
    messages' = WithoutMessage(request, WithMessage(response, messages))

\* Return the minimum value from a set, or undefined if the set is empty.
Min(s) == CHOOSE x \in s : \A y \in s : x <= y
\* Return the maximum value from a set, or undefined if the set is empty.
Max(s)         == CHOOSE x \in s          : \A y \in s : x >= y
MaxWithZero(s) == CHOOSE x \in s \cup {0} : \A y \in s : x >= y

\* CCF: Return the index of the latest committable message 
\*      (i.e., the last one that was signed by a leader)
MaxCommittableIndex(xlog) == 
    \* If the log contains messages and has at least one signature message
    IF Len(xlog) > 0 /\ \E s \in 1..Len(xlog) : xlog[s].contentType = TypeSignature
    THEN
    \* Choose that index..
    CHOOSE x \in 1..Len(xlog) : 
        \* That points to a signature message in log of node i
        /\ xlog[x].contentType = TypeSignature 
        \* And that is either the largest index in log of i
        /\ \A y \in 1..Len(xlog) : 
            \/ x >= y 
            \* Or that is only succeeeded by a postfix of unsigned commits
            \/ xlog[y].contentType /= TypeSignature
    ELSE 0

CalculateQuorum(s) == 
    \* Helper function to calculate the Quorum. Needed on each reconfiguration
    {i \in SUBSET(s) : Cardinality(i) * 2 > Cardinality(s)}

GetServerSetForIndex(server, index) ==
    \* Pick the sets of servers (aka configs) up to that index
    UNION 
    {Configurations[server][relevant_configs][2] : relevant_configs \in 
        {c \in 1..Len(Configurations[server]) : Configurations[server][c][1] <= index} \cup {}}

GetServerSet(server) ==
    \* Pick the union of all servers across all configurations
    UNION {Configurations[server][relevant_configs][2] : relevant_configs \in 1..Len(Configurations[server])}

----
\*  SNIPPET_START: init_values
\* Define initial values for all variables
InitReconfigurationVars == /\ ReconfigurationCount = 0
                           /\ Configurations = [i \in PossibleServer |-> << << 0, InitialServer >> >> ]
InitMessagesVars == /\ messages = {}
                    /\ messagesSent = [i \in PossibleServer |-> [j \in PossibleServer |-> << >>] ]
                    /\ commitsNotified = [i \in PossibleServer |-> <<0,0>>] \* i.e., <<index, times of notification>>
InitServerVars == /\ currentTerm = [i \in PossibleServer |-> 1]
                  /\ state       = [i \in PossibleServer |-> InitialConfig[i]]
                  /\ votedFor    = [i \in PossibleServer |-> Nil]
InitCandidateVars == /\ votesSent = [i \in PossibleServer |-> FALSE ]
                     /\ votesGranted   = [i \in PossibleServer |-> {}]
                     /\ votesRequested = [i \in PossibleServer |-> [j \in PossibleServer |-> 0]]
\* The values nextIndex[i][i] and matchIndex[i][i] are never read, since the
\* leader does not send itself messages. It's still easier to include these
\* in the functions.
InitLeaderVars == /\ nextIndex  = [i \in PossibleServer |-> [j \in PossibleServer |-> 1]]
                  /\ matchIndex = [i \in PossibleServer |-> [j \in PossibleServer |-> 0]]
InitLogVars == /\ log          = [i \in PossibleServer |-> << >>]
               /\ commitIndex  = [i \in PossibleServer |-> 0]
               /\ clientRequests = 1
               /\ committedLog = << >>
               /\ committedLogDecrease = FALSE
Init == /\ InitReconfigurationVars
        /\ InitMessagesVars
        /\ InitServerVars
        /\ InitCandidateVars
        /\ InitLeaderVars
        /\ InitLogVars
\* SNIPPET_END: init_values

----
\* Define state transitions

\*  SNIPPET_START: timeout
\* Server i times out and starts a new election.
Timeout(i) == \* Limit the term of each server to reduce state space
              /\ currentTerm[i] < TermLimit
              \* Limit number of candidates in our relevant server set 
              \* (i.e., simulate that not more than a given limit of servers in each configuration times out)
              /\ Cardinality({ s \in GetServerSetForIndex(i, commitIndex[i]) : state[s] = Candidate}) < MaxSimultaneousCandidates
              \* Only servers that are not already leaders can become candidates  
              /\ state[i] \in {Follower, Candidate}
              /\ state' = [state EXCEPT ![i] = Candidate]
              /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
              \* Most implementations would probably just set the local vote
              \* atomically, but messaging localhost for it is weaker.
              \*   CCF change: We do this atomically to reduce state space
              /\ votedFor' = [votedFor EXCEPT ![i] = i]
              /\ votesRequested' = [votesRequested EXCEPT ![i] = [j \in PossibleServer |-> 0]]
              /\ votesSent' = [votesSent EXCEPT ![i] = TRUE ]
              /\ votesGranted'   = [votesGranted EXCEPT ![i] = {i}]
              /\ UNCHANGED <<reconfigurationVars, messageVars, leaderVars, logVars>>
\* SNIPPET_END: timeout

\* Candidate i sends j a RequestVote request.
RequestVote(i,j) ==
    LET 
        msg == [mtype         |-> RequestVoteRequest,
                mterm         |-> currentTerm[i],
                mlastLogTerm  |-> LastTerm(log[i]),
                \*  CCF extension: Use last signature message and not last log index in elections
                mlastLogIndex |-> MaxCommittableIndex(log[i]),
                msource       |-> i,
                mdest         |-> j]
        relevantServers == GetServerSetForIndex(i, commitIndex[i])
    IN
    \* Timeout votes for itself atomically. Thus we do not need to request our own vote.
    /\ i /= j
    \* Only requests vote if we are candidate
    /\ state[i] = Candidate
    \* Reconfiguration: Make sure j is in a current relevant configuration of i
    \* However we only considered configurations that are already committed here
    /\ j \in relevantServers
    \* State limitation: Limit requested votes
    /\ votesRequested[i][j] < RequestVoteLimit
    /\ votesRequested' = [votesRequested EXCEPT ![i][j] = votesRequested[i][j] + 1]
    /\ Send(msg)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, votesGranted, leaderVars, logVars, votesSent>>

\* Leader i sends j an AppendEntries request containing up to 1 entry.
\* While implementations may want to send more than 1 at a time, this spec uses
\* just 1 because it minimizes atomic regions without loss of generality.
AppendEntries(i, j) ==
    LET
        relevantServers == GetServerSetForIndex(i, nextIndex[i][j])
    IN
    \* No messages to itself and sender is primary
    /\ state[i] = Leader
    /\ i /= j
    \* Recipient must exist in one configuration relevant to that index
    /\ j \in relevantServers
    \* There must be an index to send
    /\ Len(log[i]) >= nextIndex[i][j]
    /\ LET prevLogIndex == nextIndex[i][j] - 1
           prevLogTerm == IF prevLogIndex > 0 /\ prevLogIndex <= Len(log[i]) THEN
                              log[i][prevLogIndex].term
                          ELSE
                              0
           \* Send up to 1 entry, constrained by the end of the log.
           lastEntry == Min({Len(log[i]), nextIndex[i][j]})
           entries == SubSeq(log[i], nextIndex[i][j], lastEntry)
           msg == [mtype          |-> AppendEntriesRequest,
                   mterm          |-> currentTerm[i],
                   mprevLogIndex  |-> prevLogIndex,
                   mprevLogTerm   |-> prevLogTerm,
                   mentries       |-> entries,
                   mcommitIndex   |-> Min({commitIndex[i], MaxCommittableIndex(SubSeq(log[i],1,lastEntry))}),
                   msource        |-> i,
                   mdest          |-> j]
           index == nextIndex[i][j]
       IN 
       /\ IF Len(messagesSent[i][j]) >= index 
          THEN messagesSent[i][j][index] < MessagesLimit
          ELSE TRUE
       /\ messagesSent' =
            IF Len(messagesSent[i][j]) < index 
            THEN [messagesSent EXCEPT ![i][j] = Append(messagesSent[i][j], 1) ]
            ELSE [messagesSent EXCEPT ![i][j][index] = messagesSent[i][j][index] + 1 ]
       /\ Send(msg)
    /\ UNCHANGED <<reconfigurationVars, commitsNotified, serverVars, candidateVars, leaderVars, logVars>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
    /\ state[i] = Candidate
    /\  \* To become leader, a Quorum of _all_ known nodes must have voted for this server (across configurations)
        LET relevantServers == GetServerSet(i)
        IN (votesGranted[i] \cap relevantServers) \in CalculateQuorum(relevantServers)
    /\ state'      = [state EXCEPT ![i] = Leader]
    /\ nextIndex'  = [nextIndex EXCEPT ![i] =
                         [j \in PossibleServer |-> Len(log[i]) + 1]]
    /\ matchIndex' = [matchIndex EXCEPT ![i] =
                         [j \in PossibleServer |-> 0]]
    \* CCF: We reset our own log to its committable subsequence, throwing out
    \* all unsigned log entries of the previous leader.
    /\ LET new_max_index == MaxCommittableIndex(log[i])
           \* The new max config index either depends on the max configuration index in the log 
           \*   or is 1 if we only keep the current config (i.e., if there is no config chage in the log)
           new_conf_index == Max({c_i \in 1..Len(Configurations[i]) : Configurations[i][c_i][1] < new_max_index} \cup {1})
       IN
        /\ log' = [log EXCEPT ![i] = SubSeq(log[i],1,new_max_index)]
        \* Potentially also shorten the Configurations if the removed index contained a configuration 
        /\ Configurations' = [Configurations EXCEPT ![i] = SubSeq(@, 1, new_conf_index)]
    /\ UNCHANGED <<ReconfigurationCount, messageVars, currentTerm, votedFor, votesRequested, candidateVars, commitIndex, clientRequests, committedLog, committedLogDecrease>>

\* Leader i receives a client request to add v to the log.
ClientRequest(i) ==
    \* Limit number of client requests 
    /\ clientRequests <= RequestLimit
    \* Only leaders receive client requests
    /\ state[i] = Leader
    /\ LET entry == [term  |-> currentTerm[i],
                     value |-> clientRequests,
              contentType  |-> TypeEntry]
           newLog == Append(log[i], entry)
       IN  /\ log' = [log EXCEPT ![i] = newLog]
           \* Make sure that each request is unique, reduce state space to be explored
           /\ clientRequests' = clientRequests + 1
    /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars,
                   leaderVars, commitIndex, committedLog, committedLogDecrease>>

\*  SNIPPET_START: signing
\* CCF extension: Signed commits
\* Leader i signs the previous messages in its log to make them committable
\* This is done as a separate entry in the log that has a different
\* message contentType than messages entered by the client.
SignCommittableMessages(i) ==
    /\ LET 
        log_len == Len(log[i])
       IN
        \* Only applicable to Leaders with a log that contains at least one message
        /\ state[i] = Leader
        /\ log_len > 0
        \* Make sure the leader does not create two signatures in a row
        /\ log[i][log_len].contentType /= TypeSignature
        /\ LET
            \* Create a new entry in the log that has the contentType Signature and append it
            entry == [term  |-> currentTerm[i],
                      value |-> clientRequests-1,
               contentType  |-> TypeSignature]
            newLog == Append(log[i], entry)
            IN log' = [log EXCEPT ![i] = newLog]
        /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog, committedLogDecrease>>
\* SNIPPET_END: signing

\*  SNIPPET_START: reconfig
\* CCF extension: Reconfiguration of servers
\* Leader can propose a change in the current configuration.
\* This will switch the current set of servers to the proposed set, ONCE BOTH
\* sets of servers have committed this message (in the adjusted configuration
\* this means waiting for the signature to be committed)
ChangeConfiguration(i, newConfiguration) == 
    \* Limit reconfigurations
    /\ ReconfigurationCount < ReconfigurationLimit
    \* Only leader can propose changes
    /\ state[i] = Leader
    \* Configuration is non empty
    /\ newConfiguration /= {}
    \* Configuration is a proper subset ob the Possible Servers
    /\ newConfiguration \subseteq PossibleServer
    \* Configuration is not equal to current configuration
    /\ newConfiguration /= Configurations[i][1][2]
    \* Keep track of running reconfigurations to limit state space
    /\ ReconfigurationCount' = ReconfigurationCount + 1
    /\ LET
           entry == [term |-> currentTerm[i],
                    value |-> newConfiguration,
                    contentType |-> TypeReconfiguration]
           newLog == Append(log[i], entry)
           \* Note: New configuration gets the index of its entry. I.e.,
            \* configurations are valid immediately on their own index
           newConf== Append(Configurations[i], << Len(log[i]) + 1, newConfiguration >>)
           IN 
           /\ log' = [log EXCEPT ![i] = newLog]
           /\ Configurations' = [Configurations EXCEPT ![i] = newConf]
    /\ UNCHANGED <<messageVars, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog, committedLogDecrease>>
\* SNIPPET_END: reconfig


\* Leader i advances its commitIndex to the next possible Index.
\* This is done as a separate step from handling AppendEntries responses,
\* in part to minimize atomic regions, and in part so that leaders of
\* single-server clusters are able to mark entries committed.
\* In CCF and with reconfiguration, the following limitations apply:
\*  - An index can only be committed if it is agreed upon by a Quorum in the
\*    old AND in the new configuration. This means that for any given index,
\*    all configurations of at least that index need to have a quorum of
\*    servers agree on the index before it can be seen as committed.
AdvanceCommitIndex(i) ==
    /\ state[i] = Leader
    \* Since the below computation is expensive, make sure that there is even
    \* an entry we can advance to
    /\ \E log_index \in 1..Len(log[i]) : 
            /\ log_index > commitIndex[i] 
            /\ log[i][log_index].contentType = TypeSignature
    /\ LET
        \* We want to get the smallest such index forward that is a signature
        new_index == Min( {index \in 1..Len(log[i]) :
            /\ index > commitIndex[i]
            /\ log[i][index].contentType = TypeSignature} )
        new_log ==
            IF new_index > 1 THEN 
               [ j \in 1..new_index |-> log[i][j] ] 
            ELSE 
                  << >>
        IN
        /\  \* Select those configs that need to have a quorum to agree on this leader
            \A config_index \in 
            {c \in 1..Len(Configurations[i]) : new_index >= Configurations[i][c][1] } :
                \* In all of these configs, we now need a quorum in the servers that have the correct matchIndex
                LET config_servers == Configurations[i][config_index][2]
                    required_quorum == CalculateQuorum(config_servers)
                    agree_servers == {i} \cup {k \in PossibleServer :
                                            matchIndex[i][k] >= new_index}
                IN (agree_servers \cap config_servers) \in required_quorum
         \* only advance if necessary (this is basically a sanity check after the Min above)
        /\ commitIndex[i] < new_index 
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_index]
        /\ committedLogDecrease' = \/ ( new_index < Len(new_log) )
                                   \/ \E j \in 1..Len(committedLog) : new_log[j] /= committedLog[j]
        /\ committedLog' = new_log
        \* If commit index surpasses the next configuration, pop the first config, and eventually retire as leader
        /\ \/ /\ Len(Configurations[i]) > 1
              /\ new_index >= Configurations[i][2][1]
              /\ Configurations' = [Configurations EXCEPT ![i] = Tail(@)]
              \* Get the set of relevant servers of all configurations after the first
              /\ \/ /\ \lnot i \in UNION {Configurations[i][relevant_configs][2] : relevant_configs \in 
                             {c \in 2..Len(Configurations[i]) : new_index >= Configurations[i][c][1]} \cup {}}
                    \* Retire if i is not in next configuration anymore
                    /\ state' = [state EXCEPT ![i] = RetiredLeader]    
                    /\ UNCHANGED << currentTerm, votedFor, ReconfigurationCount >>
                 \* Otherwise, states remain unchanged 
                 \/ UNCHANGED <<serverVars, ReconfigurationCount>>
              \* Otherwise, Configuration and states remain unchanged
           \/ UNCHANGED <<reconfigurationVars, serverVars>> 
    /\ UNCHANGED <<messageVars, candidateVars, leaderVars, log, clientRequests>>

\* CCF reconfiguration change:
\*  RetiredLeader server i notifies the current commit level to server j
\*  This allows to retire gracefully instead of deadlocking the system through removing itself from the network.
NotifyCommit(i,j) ==
    \* Only RetiredLeader servers send these commit messages
    /\ state[i] = RetiredLeader
    \* Only send notifications of commit to servers in the server set
    /\ j \in GetServerSetForIndex(i, commitIndex[i])
    /\ \/ commitsNotified[i][1] < commitIndex[i]
       \/ commitsNotified[i][2] < CommitNotificationLimit
    /\ LET new_notified == IF commitsNotified[i][1] = commitIndex[i]
                           THEN <<commitsNotified[i][1], commitsNotified[i][2] + 1>>
                           ELSE <<commitIndex[i], 1>>
       IN  commitsNotified' = [commitsNotified EXCEPT ![i] = new_notified]
    /\ LET msg == [mtype          |-> NotifyCommitMessage,
                   mcommitIndex   |-> commitIndex[i],
                   mterm          |-> currentTerm[i],
                   msource        |-> i,
                   mdest          |-> j] 
       IN Send(msg)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, serverVars, candidateVars, leaderVars, logVars >>
                
----
\* Message handlers
\* i = recipient, j = sender, m = message

\* Server i receives a RequestVote request from server j with
\* m.mterm <= currentTerm[i].
HandleRequestVoteRequest(i, j, m) ==
    LET logOk == \/ m.mlastLogTerm > LastTerm(log[i])
                 \/ /\ m.mlastLogTerm = LastTerm(log[i])
                    \* CCF change: Log is only okay up to signatures, 
                    \*  not any message in the log
                    /\ m.mlastLogIndex >= MaxCommittableIndex(log[i]) 
        grant == /\ m.mterm = currentTerm[i]
                 /\ logOk
                 /\ votedFor[i] \in {Nil, j}
    IN /\ m.mterm <= currentTerm[i]
       /\ \/ grant  /\ votedFor' = [votedFor EXCEPT ![i] = j]
          \/ ~grant /\ UNCHANGED votedFor
       /\ Reply([mtype        |-> RequestVoteResponse,
                 mterm        |-> currentTerm[i],
                 mvoteGranted |-> grant,
                 msource      |-> i,
                 mdest        |-> j],
                 m)
       /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, state, currentTerm, candidateVars, leaderVars, logVars>>

\* Server i receives a RequestVote response from server j with
\* m.mterm = currentTerm[i].
HandleRequestVoteResponse(i, j, m) ==
    \* This tallies votes even when the current state is not Candidate, but
    \* they won't be looked at, so it doesn't matter.
    \* It also tallies votes from servers that are not in the configuration but that is filtered out in BecomeLeader
    /\ m.mterm = currentTerm[i]
    /\ \/ /\ m.mvoteGranted
          /\ votesGranted' = [votesGranted EXCEPT ![i] =
                                  votesGranted[i] \cup {j}]
          /\ UNCHANGED <<votesSent>>
       \/ /\ ~m.mvoteGranted
          /\ UNCHANGED <<votesSent, votesGranted>>
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, votedFor, votesRequested, leaderVars, logVars>>

\* Server i receives a RequestVote request from server j with
\* m.mterm < currentTerm[i].
RejectAppendEntriesRequest(i, j, m, logOk) ==
    /\ \/ m.mterm < currentTerm[i]
       \/ /\ m.mterm = currentTerm[i]
          /\ state[i] = Follower
          /\ \lnot logOk
    /\ Reply([mtype           |-> AppendEntriesResponse,
              mterm           |-> currentTerm[i],
              msuccess        |-> FALSE,
              mmatchIndex     |-> 0,
              msource         |-> i,
              mdest           |-> j],
              m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, logVars>>

ReturnToFollowerState(i, m) ==
    /\ m.mterm = currentTerm[i]
    /\ state[i] = Candidate
    /\ state' = [state EXCEPT ![i] = Follower]
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, currentTerm, votedFor, logVars, messages>>

AppendEntriesAlreadyDone(i, j, index, m) ==
    /\ \/ m.mentries = << >>
       \/ /\ m.mentries /= << >>
          /\ Len(log[i]) >= index
          /\ log[i][index].term = m.mentries[1].term
    \* In normal Raft, this could make our commitIndex decrease (for
    \* example if we process an old, duplicated request)
    \* In CCF however, messages are encrypted and integrity protected
    \*  which also prevents message replays and duplications.
    /\ commitIndex' = [commitIndex EXCEPT ![i] = m.mcommitIndex]
    /\ Reply([mtype           |-> AppendEntriesResponse,
              mterm           |-> currentTerm[i],
              msuccess        |-> TRUE,
              mmatchIndex     |-> m.mprevLogIndex + Len(m.mentries),
              msource         |-> i,
              mdest           |-> j],
              m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, log, clientRequests, committedLog, committedLogDecrease>>

ConflictAppendEntriesRequest(i, index, m) ==
    /\ m.mentries /= << >>
    /\ Len(log[i]) >= index
    /\ log[i][index].term /= m.mentries[1].term
    /\ LET new_log == [index2 \in 1..(Len(log[i]) - 1) |-> log[i][index2]]
           new_conf_index == Max({c_i \in 1..Len(Configurations[i]) : Configurations[i][c_i][1] < index})
       IN /\ log' = [log EXCEPT ![i] = new_log]
        \* Potentially also shorten the Configurations if the removed index contained a configuration 
          /\ Configurations' = [Configurations EXCEPT ![i] = SubSeq(@, 1, new_conf_index)]
    \* On conflicts, we shorten the log. This means we also want to reset the
    \*  sent messages that we track to limit the state space
    /\ LET newCounts == [j \in PossibleServer 
                |-> [n \in 1..Min({Len(messagesSent[i][j]) - 1, index - 1}) 
                |-> messagesSent[i][j][n]]]
       IN messagesSent' = [messagesSent EXCEPT ![i] = newCounts ]
    /\ UNCHANGED <<ReconfigurationCount, serverVars, commitIndex, messages, commitsNotified, clientRequests, committedLog, committedLogDecrease>>

NoConflictAppendEntriesRequest(i, j, m) ==
    /\ m.mentries /= << >>
    /\ Len(log[i]) = m.mprevLogIndex
    /\ log' = [log EXCEPT ![i] = Append(log[i], m.mentries[1])]
    \* If this is a reconfiguration, update Configuration list
    \* Also, if the commitIndex is updated, we may pop an old config at the same time
    /\ LET
        have_added_config   == m.mentries[1].contentType = TypeReconfiguration
        added_config        == IF have_added_config
                               THEN << m.mprevLogIndex + 1, m.mentries[1].value >>
                               ELSE << >>
        new_commit_index    == Max({m.mcommitIndex, commitIndex[i]})
        \* A config can be removed if the new commit index reaches at least the next config index.
        \* This happens either on configs that are already in the Configurations list or on new configs that 
        \* are already committed.
        have_removed_config == IF Len(Configurations[i]) > 1
                               THEN new_commit_index >= Configurations[i][2][1]
                               ELSE IF have_added_config
                                    THEN new_commit_index >= m.mprevLogIndex + 1
                                    ELSE FALSE
        base_config         == IF have_removed_config
                               THEN IF Len(Configurations[i]) > 1
                                    THEN Tail(Configurations[i])
                                    ELSE << >>
                               ELSE Configurations[i]
        new_config          == IF have_added_config
                               THEN Append(base_config, added_config)
                               ELSE base_config
        IN        
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_commit_index]
        /\ Configurations' = [Configurations EXCEPT  ![i] = new_config]
        \* If we added a new configuration that we are in and were pending, we are now follower
        /\ \/ /\ state[i] = Pending
              /\ i \in UNION {new_config[conf_index][2] : conf_index \in 1..Len(new_config)}
              /\ state' = [state EXCEPT ![i] = Follower ]
           \/ UNCHANGED <<state>>
    /\ Reply([mtype           |-> AppendEntriesResponse,
              mterm           |-> currentTerm[i],
              msuccess        |-> TRUE,
              mmatchIndex     |-> m.mprevLogIndex + Len(m.mentries),
              msource         |-> i,
              mdest           |-> j],
              m)
    /\ UNCHANGED <<ReconfigurationCount, messagesSent, commitsNotified, currentTerm, votedFor, clientRequests, committedLog, committedLogDecrease>>

AcceptAppendEntriesRequest(i, j, logOk, m) ==
    \* accept request
    /\ m.mterm = currentTerm[i]
    /\ state[i] \in {Follower, Pending}
    /\ logOk
    /\ LET index == m.mprevLogIndex + 1
       IN \/ AppendEntriesAlreadyDone(i, j, index, m)
          \/ ConflictAppendEntriesRequest(i, index, m)
          \/ NoConflictAppendEntriesRequest(i, j, m)

\* Server i receives an AppendEntries request from server j with
\* m.mterm <= currentTerm[i]. This just handles m.entries of length 0 or 1, but
\* implementations could safely accept more by treating them the same as
\* multiple independent requests of 1 entry.
HandleAppendEntriesRequest(i, j, m) ==
    LET logOk == \/ m.mprevLogIndex = 0
                 \/ /\ m.mprevLogIndex > 0
                    /\ m.mprevLogIndex <= Len(log[i])
                    /\ m.mprevLogTerm = log[i][m.mprevLogIndex].term
    IN /\ m.mterm <= currentTerm[i]
       /\ \/ RejectAppendEntriesRequest(i, j, m, logOk)
          \/ ReturnToFollowerState(i, m)
          \/ AcceptAppendEntriesRequest(i, j, logOk, m)
       /\ UNCHANGED <<candidateVars, leaderVars>>

\* Server i receives an AppendEntries response from server j with
\* m.mterm = currentTerm[i].
HandleAppendEntriesResponse(i, j, m) ==
    /\ m.mterm = currentTerm[i]
    /\ \/ /\ m.msuccess \* successful
          /\ nextIndex'  = [nextIndex  EXCEPT ![i][j] = m.mmatchIndex + 1]
          /\ matchIndex' = [matchIndex EXCEPT ![i][j] = m.mmatchIndex]
       \/ /\ \lnot m.msuccess \* not successful
          /\ nextIndex' = [nextIndex EXCEPT ![i][j] =
                               Max({nextIndex[i][j] - 1, 1})]
          /\ UNCHANGED <<matchIndex>>
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, candidateVars, logVars>>

\* Any RPC with a newer term causes the recipient to advance its term first.
UpdateTerm(i, j, m) ==
    /\ m.mterm > currentTerm[i]
    /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.mterm]
    /\ state'          = [state       EXCEPT ![i] = IF @ \in {Leader, Candidate} THEN Follower ELSE @]
    /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
       \* messages is unchanged so m can be processed further.
    /\ UNCHANGED <<reconfigurationVars, messageVars, candidateVars, leaderVars, logVars>>

\* Responses with stale terms are ignored.
DropStaleResponse(i, j, m) ==
    /\ m.mterm < currentTerm[i]
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, messagesSent, commitsNotified, candidateVars, leaderVars, logVars>>

\* Drop messages if they are irrelevant to the node
DropIgnoredMessage(i,j,m) ==
    \* Drop messages if...
    /\ 
       \* .. recipient is still Pending..   
       \/ /\ state[i] = Pending
          \* .. and the message is anything other than an append entries request
          /\ m.mtype /= AppendEntriesRequest
       \*  OR if message is to a server that has surpassed the Pending stage ..
       \/ /\ state[i] /= Pending
        \* .. and it comes from a server outside of the configuration
          /\ \lnot j \in GetServerSet(i)
       \*  OR if recipient is RetiredLeader and this is not a request to vote
       \/ /\ state[i] = RetiredLeader
          /\ m.mtype /= RequestVoteRequest
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, messagesSent, commitsNotified, candidateVars, leaderVars, logVars>>

\* RetiredLeader leaders send notify commit messages to update all nodes about the commit level
UpdateCommitIndex(i,j,m) ==
    /\ m.mcommitIndex > commitIndex[i]
    /\ LET
        new_commit_index    == m.mcommitIndex
        \* Old config can be dropped when we reach the index of the next config
        can_drop_config == IF Len(Configurations[i]) > 1
                           THEN new_commit_index >= Configurations[i][2][1]
                           ELSE FALSE
        new_config      == IF can_drop_config
                           THEN Tail(Configurations[i])
                           ELSE Configurations[i]
        IN
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_commit_index]
        /\ Configurations' = [Configurations EXCEPT  ![i] = new_config]
    /\ UNCHANGED <<ReconfigurationCount, messages, messagesSent, commitsNotified, currentTerm, 
                   votedFor, candidateVars, leaderVars, log, clientRequests, committedLog, committedLogDecrease >> 

\* Receive a message.
Receive(m) ==
  LET i == m.mdest
      j == m.msource
  IN 
  \/ /\ m.mtype = NotifyCommitMessage
     /\ UpdateCommitIndex(i,j,m)
     /\ Discard(m)
  \* Drop any message that are to be ignored by the recipient
  \/ DropIgnoredMessage(i,j,m)
  \* Any RPC with a newer term causes the recipient to advance
  \* its term first. Responses with stale terms are ignored.
  \/ UpdateTerm(i, j, m)
  \/ /\ m.mtype = RequestVoteRequest
     /\ HandleRequestVoteRequest(i, j, m)
  \/ /\ m.mtype = RequestVoteResponse
     /\ \/ DropStaleResponse(i, j, m)
        \/ HandleRequestVoteResponse(i, j, m)
  \/ /\ m.mtype = AppendEntriesRequest
     /\ HandleAppendEntriesRequest(i, j, m)
  \/ /\ m.mtype = AppendEntriesResponse
     /\ \/ DropStaleResponse(i, j, m)
        \/ HandleAppendEntriesResponse(i, j, m)

\* End of message handlers.
----
\* Network state transitions

\* The network drops a message
DropMessage(m) ==
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, candidateVars, leaderVars, logVars>>

----
\*  SNIPPET_START: next_states
\* Defines how the variables may transition.
Next == \/ \E i \in PossibleServer : Timeout(i)
        \/ \E i, j \in PossibleServer : RequestVote(i, j)
        \/ \E i \in PossibleServer : BecomeLeader(i)
        \/ \E i \in PossibleServer : ClientRequest(i)
        \/ \E i \in PossibleServer : SignCommittableMessages(i)
        \/ \E i \in PossibleServer : \E c \in SUBSET(PossibleServer) : ChangeConfiguration(i, c)
        \/ \E i,j \in PossibleServer : NotifyCommit(i,j)
        \/ \E i \in PossibleServer : AdvanceCommitIndex(i)
        \/ \E i,j \in PossibleServer : AppendEntries(i, j)
        \/ \E m \in messages : Receive(m)
\* SNIPPET_END: next_states
        \* Dropping messages is disabled by default in this spec but preserved for the future.
        \* Since liveness is not checked, dropping of messages is left out to reduce the state space.
        \* \/ \E m \in messages : DropMessage(m)

\* The specification must start with the initial state and transition according
\* to Next.
Spec == Init /\ [][Next]_vars

LogInv == \lnot committedLogDecrease

\* The following are partially based on a set of invariants by
\* https://github.com/dricketts/raft.tla/blob/master/raft.tla
\* Helpers
\* The invariants below use IsPrefix on sequences. We utilize the 
\* IsPrefix from the TLA community modules here (MIT license): 
\* https://github.com/tlaplus/CommunityModules/blob/master/modules/SequencesExt.tla
IsPrefix(s, t) ==
  (**************************************************************************)
  (* TRUE iff the sequence s is a prefix of the sequence t, s.t.            *)
  (* \E u \in Seq(Range(t)) : t = s \o u. In other words, there exists      *)
  (* a suffix u that with s prepended equals t.                             *)
  (**************************************************************************)
  IF s = << >>
  THEN TRUE
  ELSE DOMAIN s \subseteq DOMAIN t /\ \A i \in DOMAIN s: s[i] = t[i]

----
\* Debugging invariants
\* These invariants should give error traces and are useful for debugging to see if important situations are possible

\* With reconfig, it should be possible for Node 4 or 5 to become leader
DebugInvReconfigLeader == 
    /\ state[NodeFour] /= Leader
    /\ state[NodeFive] /= Follower

\* Check that eventually all messages can be dropped or processed and we did not forget a message
DebugInvAllMessagesProcessable == 
    Len(messages) > 0 ~> Len(messages) = 0

\* The Retirement state is reached by Leaders that remove themselves from the configuration. It should be reachable.
DebugInvRetirementReachable ==
    \A i \in PossibleServer : state[i] /= RetiredLeader

----
\* Correctness invariants

\* The prefix of the log of server i that has been committed
Committed(i) == IF commitIndex[i] = 0
                THEN << >>
                ELSE SubSeq(log[i],1,commitIndex[i])

\* If a candidate has a chance of being elected, there
\* are no committed log entries with that candidate's term
CandidateTermNotInLogInv ==
    \A i \in PossibleServer :
        (/\ state[i] = Candidate
         /\ LET relevantServers == GetServerSet(i)
            IN 
            {j \in PossibleServer : 
                /\ currentTerm[j] = currentTerm[i] 
                /\ votedFor[j] = i
            } \cap relevantServers \in CalculateQuorum(relevantServers)
        )
        =>
        \A j \in PossibleServer :
        \A n \in DOMAIN log[j] :
             log[j][n].term /= currentTerm[i]

\* A leader always has the greatest index for its current term (this does not 
\* mean all of its log will survive if it is not committed + signed yet)
ElectionSafetyInv ==
    \A i \in PossibleServer :
        state[i] = Leader =>
        \A j \in PossibleServer :
            MaxWithZero({n \in DOMAIN log[i] : log[i][n].term = currentTerm[i]}) >=
            MaxWithZero({n \in DOMAIN log[j] : log[j][n].term = currentTerm[i]})
----
\* Every (index, term) pair determines a log prefix
LogMatchingInv ==
    \A i, j \in PossibleServer :
        \A n \in (1..Len(log[i])) \cap (1..Len(log[j])) :
            log[i][n].term = log[j][n].term =>
            SubSeq(log[i],1,n) = SubSeq(log[j],1,n)
----
\* A leader has all committed entries in its log. This is expressed
\* by LeaderCompleteness below. The inductive invariant for
\* that property is the conjunction of LeaderCompleteness with the
\* other three properties below.

\* All committed entries are contained in the log
\* of at least one server in every quorum
QuorumLogInv ==
    \A i \in PossibleServer :
    \A S \in CalculateQuorum(GetServerSetForIndex(i, commitIndex[i])) :
        \E j \in S :
            IsPrefix(Committed(i), log[j])
        
\* The "up-to-date" check performed by servers
\* before issuing a vote implies that i receives
\* a vote from j only if i has all of j's committed
\* entries
MoreUpToDateCorrectInv ==
    \A i, j \in PossibleServer :
       (\/ LastTerm(log[i]) > LastTerm(log[j])
        \/ /\ LastTerm(log[i]) = LastTerm(log[j])
           /\ Len(log[i]) >= Len(log[j])) =>
       IsPrefix(Committed(j), log[i])

\* In CCF, only signature messages should ever be committed 
SignatureInv == 
    \A i \in PossibleServer :
        \/ commitIndex[i] = 0
        \/ log[i][commitIndex[i]].contentType = TypeSignature

===============================================================================

\* Changelog:
\* CCF version of TLA model
\* 2021-05:
\* - Removed the following features from the model:
\*   - Restart (In CCF, no restart possible. Crashed nodes will not recover but
\*     will need to be added again in a configuration change.)
\*   - DuplicateMessage (In CCF, message encryption catches duplicated messages
\*     before they are passed on to the Raft protocol level)
\*   - DropMessage disabled (but not removed), due to state explosion we do not 
\*     consider this in our model.
\* - Added the following features to the model:
\*   - SignCommittableMessages: In CCF the leader signs the last messages which
\*     only makes them committed after this signature has been committed.
\*   - Reconfiguration of running servers through ChangeConfiguration, added 
\*     Retired Leader and Pending states
\*   - NotifyCommit for RetiredLeader to keep notifying of known commitIndex
\*   - Limits on most perpetrators for state explosion
\* - Changed the following behavior:
\*   - Messages are now a set which removes duplicates but simplifies states
\* 
\* Original Raft changelog:
\* 2014-12-02:
\* - Fix AppendEntries to only send one entry at a time, as originally
\*   intended. Since SubSeq is inclusive, the upper bound of the range should
\*   have been nextIndex, not nextIndex + 1. Thanks to Igor Kovalenko for
\*   reporting the issue.
\* - Change matchIndex' to matchIndex (without the apostrophe) in
\*   AdvanceCommitIndex. This apostrophe was not intentional and perhaps
\*   confusing, though it makes no practical difference (matchIndex' equals
\*   matchIndex). Thanks to Hugues Evrard for reporting the issue.
\*
\* 2014-07-06:
\* - Version from PhD dissertation