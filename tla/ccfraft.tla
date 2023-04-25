--------------------------------- MODULE ccfraft ---------------------------------
\* This is the formal specification for the consensus algorithm in CCF.
\*
\* Copyright 2014 Diego Ongaro.
\* Modifications Copyright 2021 Microsoft.
\* This work is licensed under the Creative Commons Attribution-4.0
\* International License https://creativecommons.org/licenses/by/4.0/

\* Modified for CCF by Microsoft Research
\* Author of these modifications:
\*      Fritz Alder <fritz.alder@acm.org>
\*      Heidi Howard <heidi.howard@microsoft.com>
\*      Markus Alexander Kuppe <makuppe@microsoft.com>
\* Partially based on
\* - https://github.com/ongardie/raft.tla/blob/master/raft.tla
\*   (base spec, modified)
\* - https://github.com/jinlmsft/raft.tla/blob/master/raft.tla
\*   (e.g. clientRequests, committedLog)
\* - https://github.com/dricketts/raft.tla/blob/master/raft.tla
\*   (e.g. certain invariants)

EXTENDS Naturals, FiniteSets, Sequences, TLC, FiniteSetsExt, SequencesExt, Functions

------------------------------------------------------------------------------
\* Constants

\* Server states
CONSTANTS
    \* See original Raft paper (https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf)
    \* and comments for leadership_state in../src/consensus/aft/raft.h for details on the Follower,
    \* Candidate, and Leader states.
    Follower,
    Candidate,
    Leader,
    \* CCF adds the RetiredLeader state to the protocol: A Leader transitions to RetiredLeader
    \* after committing a reconfiguration transaction which removes the Leader from the
    \* configuration (see also ../src/consensus/aft/raft.h).
    \* More formally: 
    \*   /\ [][\E s \in Servers: state'[s] = RetiredLeader => state[s] = Leader]_state
    \*   /\ [][\A s \in Servers:
    \*          /\ state[s] = Leader
    \*          /\  CurrentConfiguration(s) \ CurrentConfiguration(s)' = {s}
    \*          => state'[s] = RetiredLeader]_state
    RetiredLeader,
    \* The node has passed attestation checks, but is waiting for member confirmation, 
    \* and just isn't part of any configurations at all, nor has a communication channel
    \* with other nodes in the network.
    \*
    \* More formally:
    \*   \A i \in Servers : state[i] = Pending => i \notin { GetServerSet(s) : s \in Servers}
    Pending

States == {
    Follower,
    Candidate,
    Leader,
    RetiredLeader,
    Pending
    }

\* A reserved value
CONSTANTS Nil

\* Message types:
CONSTANTS
    RequestVoteRequest,
    RequestVoteResponse,
    AppendEntriesRequest,
    AppendEntriesResponse,
    NotifyCommitMessage

\* CCF: Content types (Normal entry or a signature that signs
\*      previous entries or a reconfiguration entry)
CONSTANTS
    TypeEntry,
    TypeSignature,
    TypeReconfiguration

CONSTANTS
    NodeOne,
    NodeTwo,
    NodeThree,
    NodeFour,
    NodeFive

AllServers == {
    NodeOne,
    NodeTwo,
    NodeThree,
    NodeFour,
    NodeFive
}

\* Set of nodes for this model
CONSTANTS Servers
ASSUME Servers /= {}
ASSUME Servers \subseteq AllServers

------------------------------------------------------------------------------
\* Global variables

\* Keep track of current number of reconfigurations to limit it through the MC.
\* TLC: Finite state space.
VARIABLE reconfigurationCount

ReconfigurationCountTypeInv == 
    reconfigurationCount \in Nat

\* Each server keeps track of the active configurations.
\* This includes the current configuration plus any pending configurations.
\* The current configuration is the initial configuration or the last committed reconfiguration.
\* The pending configurations are reconfiguration transactions that are not yet committed.
\* Each server's configurations is indexed by the reconfiguration transaction index,
\* except for the initial configuration which has index 0 (note that the log in 1-indexed).
\* Refer to LogConfigurationConsistentInv for more on configurations
VARIABLE configurations

ConfigurationsTypeInv ==
    \A i \in Servers : 
        /\ \A c \in DOMAIN configurations[i] :
            configurations[i][c] \subseteq Servers
        /\ DOMAIN configurations[i] # {}

\* The set of servers that have been removed from configurations.  The implementation
\* assumes that a server refrains from rejoining a configuration if it has been removed
\* from an earlier configuration (relying on the TEE and absent Byzantine fault). Here,
\* we model removedFromConfiguration as a global variable. In the implementation, this
\* state has to be maintained by each node separately.
\* Note that we cannot determine the removed servers from configurations because a prefix
\* of configurations is removed from the configuration on a change of configuration.
\* TODO: How does the implementation keep track of removed servers?  Can we remove and
\* TODO: re-add a server in a raft_scenario test?
VARIABLE removedFromConfiguration

RemovedFromConfigurationTypeInv ==
    removedFromConfiguration \subseteq Servers

reconfigurationVars == <<
    reconfigurationCount, 
    removedFromConfiguration, 
    configurations
>>

ReconfigurationVarsTypeInv ==
    /\ ReconfigurationCountTypeInv
    /\ ConfigurationsTypeInv
    /\ RemovedFromConfigurationTypeInv

\* A set representing requests and responses sent from one server
\* to another. With CCF, we have message integrity and can ensure unique messages.
\* Messages only records messages that are currently in-flight, actions should
\* removed messages once received.
VARIABLE messages

\* Helper function for checking the type safety of log entries
EntryTypeOK(entry) ==
    /\ entry.term \in Nat \ {0}
    /\ \/ /\ entry.contentType = TypeEntry
          /\ entry.request \in Nat \ {0}
       \/ entry.contentType = TypeSignature
       \/ /\ entry.contentType = TypeReconfiguration
          /\ entry.configuration \subseteq Servers

AppendEntriesRequestTypeOK(m) ==
    /\ m.type = AppendEntriesRequest
    /\ m.prevLogIndex \in Nat
    /\ m.prevLogTerm \in Nat
    /\ m.commitIndex \in Nat
    /\ \A k \in DOMAIN m.entries: EntryTypeOK(m.entries[k])

AppendEntriesResponseTypeOK(m) ==
    /\ m.type = AppendEntriesResponse
    /\ m.success \in BOOLEAN
    /\ m.lastLogIndex \in Nat

RequestVoteRequestTypeOK(m) ==
    /\ m.type = RequestVoteRequest
    /\ m.lastCommittableTerm \in Nat
    /\ m.lastCommittableIndex \in Nat

RequestVoteResponseTypeOK(m) ==
    /\ m.type = RequestVoteResponse
    /\ m.voteGranted \in BOOLEAN

NotifyCommitMessageTypeOK(m) ==
    /\ m.type = NotifyCommitMessage
    /\ m.commitIndex \in Nat

MessagesTypeInv ==
    \A m \in messages :
        /\ m.source \in Servers
        /\ m.dest \in Servers
        /\ m.term \in Nat \ {0}
        /\  \/ AppendEntriesRequestTypeOK(m)
            \/ AppendEntriesResponseTypeOK(m)
            \/ RequestVoteRequestTypeOK(m)
            \/ RequestVoteResponseTypeOK(m)
            \/ NotifyCommitMessageTypeOK(m)

\* CCF: Keep track of each append entries message sent from each server to each other server
\* and cap it to a maximum to constrain the state-space for model-checking.
\* TLC: Finite state space.
VARIABLE messagesSent

MessagesSentTypeInv ==
    \A i,j \in Servers : i /= j =>
        \A k \in DOMAIN messagesSent[i][j] :
            messagesSent[i][j][k] \in Nat \ {0}

\* CCF: After reconfiguration, a RetiredLeader leader may need to notify servers
\* of the current commit level to ensure that no deadlock is reached through
\* leaving the network after retirement (as that would lead to endless leader
\* re-elects and drop-outs until f is reached and network fails).
VARIABLE commitsNotified

CommitsNotifiedTypeInv ==
    \A i \in Servers :
        /\ commitsNotified[i][1] \in Nat
        /\ commitsNotified[i][2] \in Nat

messageVars == <<
    messages, 
    messagesSent, 
    commitsNotified
>>

MessageVarsTypeInv ==
    /\ MessagesTypeInv
    /\ MessagesSentTypeInv
    /\ CommitsNotifiedTypeInv


------------------------------------------------------------------------------
\* The following variables are all per server (functions with domain Servers).

\* The server's term number.
VARIABLE currentTerm

CurrentTermTypeInv ==
    \A i \in Servers : currentTerm[i] \in Nat

\* The server's state.
VARIABLE state

StateTypeInv ==
    \A i \in Servers : state[i] \in States

\* The candidate the server voted for in its current term, or
\* Nil if it hasn't voted for any.
VARIABLE votedFor

VotedForTypeInv ==
    \A i \in Servers : votedFor[i] \in {Nil} \cup Servers

serverVars == <<currentTerm, state, votedFor>>

ServerVarsTypeInv ==
    /\ CurrentTermTypeInv
    /\ StateTypeInv
    /\ VotedForTypeInv

\* A Sequence of log entries. The index into this sequence is the index of the
\* log entry. Sequences in TLA+ are 1-indexed.
VARIABLE log

LogTypeInv ==
    \A i \in Servers : 
        \A k \in DOMAIN log[i]: EntryTypeOK(log[i][k])

\* The index of the latest entry in the log the state machine may apply.
VARIABLE commitIndex

CommitIndexTypeInv ==
    \A i \in Servers : commitIndex[i] \in Nat

\* The set of requests that can go into the log. 
\* TLC: Finite state space.
VARIABLE clientRequests

ClientRequestsTypeInv ==
    clientRequests \in Nat \ {0}

\* The log and index denoting the operations that have been committed. Instead
\* of copying the committed prefix of the current leader's log, remember the
\* node and the index (up to which the operations have been committed) into its log.
\* This variable is a history variable in TLA+ jargon. It does not exist in an implementation.
VARIABLE committedLog

CommittedLogTypeInv ==
    committedLog \in [ node: Servers, index: Nat ]

logVars == <<log, commitIndex, clientRequests, committedLog>>

LogVarsTypeInv ==
    /\ LogTypeInv
    /\ CommitIndexTypeInv
    /\ ClientRequestsTypeInv
    /\ CommittedLogTypeInv

\* The set of servers from which the candidate has received a vote in its
\* currentTerm.
VARIABLE votesGranted

VotesGrantedTypeInv ==
    \A i \in Servers :
        votesGranted[i] \subseteq Servers

\* State space limitation: Restrict each node to send a limited amount
\* of requests to other nodes.
\* TLC: Finite state space.
VARIABLE votesRequested

VotesRequestedTypeInv ==
    \A i, j \in Servers : i /= j =>
        votesRequested[i][j] \in Nat

candidateVars == <<votesGranted, votesRequested>>

CandidateVarsTypeInv ==
    /\ VotesGrantedTypeInv
    /\ VotesRequestedTypeInv

\* The following variables are used only on leaders:
\* The next entry to send to each follower.
VARIABLE nextIndex

NextIndexTypeInv ==
    \A i, j \in Servers : i /= j =>
        /\ nextIndex[i][j] \in Nat \ {0}

\* The latest entry that each follower has acknowledged is the same as the
\* leader's. This is used to calculate commitIndex on the leader.
VARIABLE matchIndex

MatchIndexTypeInv ==
    \A i, j \in Servers : i /= j =>
        matchIndex[i][j] \in Nat

leaderVars == <<nextIndex, matchIndex>>

LeaderVarsTypeInv ==
    /\ NextIndexTypeInv
    /\ MatchIndexTypeInv

\* End of per server variables.
------------------------------------------------------------------------------

\* All variables; used for stuttering (asserting state hasn't changed).
vars == <<
    reconfigurationVars, 
    messageVars, 
    serverVars, 
    candidateVars, 
    leaderVars, 
    logVars 
>>

\* Invariant to check the type safety of all variables
TypeInv ==
    /\ ReconfigurationVarsTypeInv
    /\ MessageVarsTypeInv
    /\ ServerVarsTypeInv
    /\ CandidateVarsTypeInv
    /\ LeaderVarsTypeInv
    /\ LogVarsTypeInv

------------------------------------------------------------------------------
\* Fine-grained state constraint "hooks" for model-checking with TLC.

\* State limitation: Limit requested votes
InRequestVoteLimit(i,j) ==
    TRUE

\* Limit on terms
\* By default, all servers start as followers in term 0
InTermLimit(i) ==
    TRUE

\* CCF: Limit how many identical append entries messages each node can send to another
InMessagesLimit(i, j, index) ==
    TRUE

\* CCF: Limit the number of commit notifications per commit Index and server
InCommitNotificationLimit(i) ==
    TRUE

\* Limit max number of simultaneous candidates
\* We made several restrictions to the state space of Raft. However since we
\* made these restrictions, Deadlocks can occur at places that Raft would in
\* real-world deployments handle graciously.
\* One example of this is if a Quorum of nodes becomes Candidate but can not
\* timeout anymore since we constrained the terms. Then, an artificial Deadlock
\* is reached. We solve this below. If TermLimit is set to any number >2, this is
\* not an issue since breadth-first search will make sure that a similar
\* situation is simulated at term==1 which results in a term increase to 2.
InMaxSimultaneousCandidates(i) ==
    TRUE

\* Limit on client requests
InRequestLimit ==
    TRUE

IsInConfigurations(i, newConfiguration) ==
    TRUE

------------------------------------------------------------------------------
\* Helpers

min(a, b) == IF a < b THEN a ELSE b

max(a, b) == IF a > b THEN a ELSE b

RestrictPred(f, Test(_)) ==
    Restrict(f, { x \in DOMAIN f : Test(x) })

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

HasTypeSignature(e) == e.contentType = TypeSignature
HasTypeReconfiguration(e) == e.contentType = TypeReconfiguration

\* CCF: Return the index of the latest committable message
\*      (i.e., the last one that was signed by a leader)
MaxCommittableIndex(xlog) ==
    SelectLastInSeq(xlog, HasTypeSignature)

\* CCF: Returns the term associated with the MaxCommittableIndex(xlog)
MaxCommittableTerm(xlog) ==
    LET iMax == MaxCommittableIndex(xlog)
    IN IF iMax = 0 THEN 0 ELSE xlog[iMax].term

Quorums ==
    \* Helper function to calculate the Quorum. Needed on each reconfiguration
    [ s \in SUBSET Servers |-> {i \in SUBSET(s) : Cardinality(i) * 2 > Cardinality(s)} ]
    

GetServerSetForIndex(server, index) ==
    \* Pick the sets of servers (aka configs) up to that index
    \* The union of all ranges/co-domains of the configurations for server up to and including the index.
    UNION { configurations[server][f] : f \in { i \in DOMAIN configurations[server] : i <= index } }

IsInServerSetForIndex(candidate, server, index) ==
    \E i \in { i \in DOMAIN configurations[server] : index >= i } :
        candidate \in configurations[server][i]

\* Pick the union of all servers across all configurations
GetServerSet(server) ==
    UNION (Range(configurations[server]))

IsInServerSet(candidate, server) ==
    \E i \in DOMAIN (configurations[server]) :
        candidate \in configurations[server][i]

CurrentConfigurationIndex(server) ==
    \* The configuration with the smallest index is the current configuration
    Min(DOMAIN configurations[server])

CurrentConfiguration(server) ==
    configurations[server][CurrentConfigurationIndex(server)]

MaxConfigurationIndex(server) ==
    \* The configuration with the greatest index will be current configuration
    \* after all pending reconfigurations have been committed
    Max(DOMAIN configurations[server])

MaxConfiguration(server) ==
    configurations[server][MaxConfigurationIndex(server)]

NextConfigurationIndex(server) ==
    \* The configuration with the 2nd smallest index is the first of the pending configurations
    LET dom == DOMAIN configurations[server]
    IN Min(dom \ {Min(dom)})

\* The configurations for a server up to (and including) a given index
\* Useful for rolling back configurations when the log is truncated
ConfigurationsToIndex(server, index) ==
     RestrictPred(configurations[server], LAMBDA c : c <= index)

\* Index of the last reconfiguration up to (and including) the given index,
\* assuming the given index is after the commit index
LastConfigurationToIndex(server, index) ==
    Max({c \in DOMAIN configurations[server] : c <= index})

\* The prefix of the log of server i that has been committed
Committed(i) ==
    IF commitIndex[i] = 0
    THEN << >>
    ELSE SubSeq(log[i],1,commitIndex[i])

\* The prefix of the log of server i that is committable
Committable(i) ==
    IF MaxCommittableIndex(log[i]) = 0
    THEN << >>
    ELSE SubSeq(log[i],1,MaxCommittableIndex(log[i]))

\* The prefix of the log of server i that has been committed up to term x
CommittedTermPrefix(i, x) ==
    \* Only if log of i is non-empty, and if there exists an entry up to the term x
    IF Len(log[i]) /= 0 /\ \E y \in DOMAIN log[i] : log[i][y].term <= x
    THEN
      \* then, we use the subsequence up to the maximum committed term of the leader
      LET maxTermIndex ==
          CHOOSE y \in DOMAIN log[i] :
            /\ log[i][y].term <= x
            /\ \A z \in DOMAIN log[i] : log[i][z].term <= x  => y >= z
      IN SubSeq(log[i], 1, min(maxTermIndex, commitIndex[i]))
    \* Otherwise the prefix is the empty tuple
    ELSE << >>

AppendEntriesBatchsize(i, j) ==
    {nextIndex[i][j]}

------------------------------------------------------------------------------
\* Define initial values for all variables

InitReconfigurationVars ==
    /\ reconfigurationCount = 0
    /\ removedFromConfiguration = {}
    \* Note that CCF has a bootstrapping procedure to start a new network and to join new nodes to the network (see 
    \* https://microsoft.github.io/CCF/main/operations/start_network.html). In both cases, a node has the current (see 
    \* https://microsoft.github.io/CCF/main/operations/ledger_snapshot.html#join-or-recover-from-snapshot) or some stale configuration
    \* such as the initial configuration. A node's configuration is *never* "empty", i.e., the equivalent of configuration[node] = {} here. 
    \* For simplicity, the set of servers/nodes all have the same initial configuration at startup.
    /\ \E c \in SUBSET Servers \ {{}}:
        configurations = [i \in Servers |-> [ j \in {0} |-> c ] ]

InitMessagesVars ==
    /\ messages = {}
    /\ messagesSent = [i \in Servers |-> [j \in Servers |-> << >>] ]
    /\ commitsNotified = [i \in Servers |-> <<0,0>>] \* i.e., <<index, times of notification>>

InitServerVars ==
    /\ currentTerm = [i \in Servers |-> 0]
    /\ state       = [i \in Servers |-> IF i \in configurations[i][0] THEN Follower ELSE Pending]
    /\ votedFor    = [i \in Servers |-> Nil]

InitCandidateVars ==
    /\ votesGranted   = [i \in Servers |-> {}]
    /\ votesRequested = [i \in Servers |-> [j \in Servers |-> 0]]

\* The values nextIndex[i][i] and matchIndex[i][i] are never read, since the
\* leader does not send itself messages. It's still easier to include these
\* in the functions.
InitLeaderVars ==
    /\ nextIndex  = [i \in Servers |-> [j \in Servers |-> 1]]
    /\ matchIndex = [i \in Servers |-> [j \in Servers |-> 0]]

InitLogVars ==
    /\ log          = [i \in Servers |-> << >>]
    /\ commitIndex  = [i \in Servers |-> 0]
    /\ clientRequests = 1
    /\ committedLog = [ node |-> NodeOne, index |-> 0]

Init ==
    /\ InitReconfigurationVars
    /\ InitMessagesVars
    /\ InitServerVars
    /\ InitCandidateVars
    /\ InitLeaderVars
    /\ InitLogVars

------------------------------------------------------------------------------
\* Define state transitions

\* Server i times out and starts a new election.
Timeout(i) ==
    \* Limit the term of each server to reduce state space
    /\ InTermLimit(i)
    \* Only servers that are followers/candidates can become candidates
    /\ state[i] \in {Follower, Candidate}
    \* Limit number of candidates in our relevant server set
    \* (i.e., simulate that not more than a given limit of servers in each configuration times out)
    /\ InMaxSimultaneousCandidates(i)
    \* Check that the reconfiguration which added this node is at least committable
    /\ \E c \in DOMAIN configurations[i] :
        /\ i \in configurations[i][c]
        /\ MaxCommittableIndex(log[i]) >= c
    /\ state' = [state EXCEPT ![i] = Candidate]
    /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
    \* Candidate votes for itself
    /\ votedFor' = [votedFor EXCEPT ![i] = i]
    /\ votesRequested' = [votesRequested EXCEPT ![i] = [j \in Servers |-> 0]]
    /\ votesGranted'   = [votesGranted EXCEPT ![i] = {i}]
    /\ UNCHANGED <<reconfigurationVars, messageVars, leaderVars, logVars>>

\* Candidate i sends j a RequestVote request.
RequestVote(i,j) ==
    LET
        msg == [type         |-> RequestVoteRequest,
                term         |-> currentTerm[i],
                \*  CCF: Use last signature entry and not last log entry in elections
                lastCommittableTerm  |-> MaxCommittableTerm(log[i]),
                lastCommittableIndex |-> MaxCommittableIndex(log[i]),
                source       |-> i,
                dest         |-> j]
    IN
    \* Timeout votes for itself atomically. Thus we do not need to request our own vote.
    /\ i /= j
    \* Only requests vote if we are candidate
    /\ state[i] = Candidate
    /\ InRequestVoteLimit(i, j)
    \* Reconfiguration: Make sure j is in a configuration of i
    /\ IsInServerSet(j, i)
    /\ votesRequested' = [votesRequested EXCEPT ![i][j] = votesRequested[i][j] + 1]
    /\ Send(msg)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, votesGranted, leaderVars, logVars>>

\* Leader i sends j an AppendEntries request
AppendEntries(i, j) ==
    \* No messages to itself and sender is primary
    /\ state[i] = Leader
    /\ i /= j
    \* AppendEntries must be sent for historical entries, unless
    \* snapshots are used. Whether the node is in configuration at
    \* that index makes no difference.
    \* /\ IsInServerSetForIndex(j, i, nextIndex[i][j])
    /\ LET prevLogIndex == nextIndex[i][j] - 1
           prevLogTerm == IF prevLogIndex > 0 /\ prevLogIndex <= Len(log[i]) THEN
                              log[i][prevLogIndex].term
                          ELSE
                              0
           \* Send a number of entries (constrained by the end of the log).
           lastEntry(idx) == min(Len(log[i]), idx)
           index == nextIndex[i][j]
           msg(idx) == 
               [type          |-> AppendEntriesRequest,
                term          |-> currentTerm[i],
                prevLogIndex  |-> prevLogIndex,
                prevLogTerm   |-> prevLogTerm,
                entries       |-> SubSeq(log[i], index, lastEntry(idx)),
                commitIndex   |-> min(commitIndex[i], MaxCommittableIndex(SubSeq(log[i],1,lastEntry(idx)))),
                source        |-> i,
                dest          |-> j]
       IN
       /\ messagesSent' =
            IF Len(messagesSent[i][j]) < index
            THEN [messagesSent EXCEPT ![i][j] = Append(messagesSent[i][j], 1) ]
            ELSE [messagesSent EXCEPT ![i][j][index] = messagesSent[i][j][index] + 1 ]
       /\ \E b \in AppendEntriesBatchsize(i, j):
            /\ InMessagesLimit(i, j, b)
            /\ Send(msg(b))
    /\ UNCHANGED <<reconfigurationVars, commitsNotified, serverVars, candidateVars, leaderVars, logVars>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
    /\ state[i] = Candidate
    \* To become leader, the candidate must have received votes from a majority in each active configuration
    /\ \A c \in DOMAIN configurations[i] : votesGranted[i] \in Quorums[configurations[i][c]]
    /\ state'      = [state EXCEPT ![i] = Leader]
    /\ nextIndex'  = [nextIndex EXCEPT ![i] =
                         [j \in Servers |-> Len(log[i]) + 1]]
    /\ matchIndex' = [matchIndex EXCEPT ![i] =
                         [j \in Servers |-> 0]]
    \* CCF: We reset our own log to its committable subsequence, throwing out
    \* all unsigned log entries of the previous leader.
    /\ LET new_max_index == MaxCommittableIndex(log[i])
       IN
        /\ log' = [log EXCEPT ![i] = SubSeq(log[i],1,new_max_index)]
        \* Shorten the configurations if the removed txs contained reconfigurations
        /\ configurations' = [configurations EXCEPT ![i] = ConfigurationsToIndex(i, new_max_index)]
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, messageVars, currentTerm, votedFor,
        votesRequested, candidateVars, commitIndex, clientRequests, committedLog>>

\* Leader i receives a client request to add v to the log.
ClientRequest(i) ==
    \* Limit number of client requests
    /\ InRequestLimit
    \* Only leaders receive client requests
    /\ state[i] = Leader
    /\ LET entry == [
            term  |-> currentTerm[i],
            request |-> clientRequests,
            contentType  |-> TypeEntry]
        newLog == Append(log[i], entry)
       IN  /\ log' = [log EXCEPT ![i] = newLog]
           \* Make sure that each request is unique, reduce state space to be explored
           /\ clientRequests' = clientRequests + 1
    /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars,
                   leaderVars, commitIndex, committedLog>>

\* CCF: Signed commits
\* In CCF, the leader periodically signs the latest log prefix. Only these signatures are committable in CCF.
\* We model this via special ``TypeSignature`` log entries and ensure that the commitIndex can only be moved to these special entries.

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
            entry == [
                term  |-> currentTerm[i],
                contentType  |-> TypeSignature]
            newLog == Append(log[i], entry)
            IN log' = [log EXCEPT ![i] = newLog]
        /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog>>

\* CCF: Reconfiguration of servers
\* In the TLA+ model, a reconfiguration is initiated by the Leader which appends an arbitrary new configuration to its own log.
\* This also triggers a change in the Configurations variable which keeps track of all running configurations.
\* In the following, this Configurations variable is then checked to calculate a quorum and to check which nodes should be contacted or received messages from.

\* Leader can propose a change in the current configuration.
\* This will switch the current set of servers to the proposed set, ONCE BOTH
\* sets of servers have committed this message (in the adjusted configuration
\* this means waiting for the signature to be committed)
ChangeConfigurationInt(i, newConfiguration) ==
        \* Only leader can propose changes
        /\ state[i] = Leader
        \* Limit reconfigurations
        /\ IsInConfigurations(i, newConfiguration)
        \* Configuration is non empty
        /\ newConfiguration /= {}
        \* Configuration is a proper subset of the Servers
        /\ newConfiguration \subseteq Servers
        \* Configuration is not equal to the previous configuration
        /\ newConfiguration /= MaxConfiguration(i)
        \* Keep track of running reconfigurations to limit state space
        /\ reconfigurationCount' = reconfigurationCount + 1
        /\ removedFromConfiguration' = removedFromConfiguration \cup (CurrentConfiguration(i) \ newConfiguration)
        /\ LET
            entry == [
                term |-> currentTerm[i],
                configuration |-> newConfiguration,
                contentType |-> TypeReconfiguration]
            newLog == Append(log[i], entry)
            IN
            /\ log' = [log EXCEPT ![i] = newLog]
            /\ configurations' = [configurations EXCEPT ![i] = @ @@ Len(log[i]) + 1 :> newConfiguration]
        /\ UNCHANGED <<messageVars, serverVars, candidateVars, clientRequests,
                        leaderVars, commitIndex, committedLog>>

ChangeConfiguration(i) ==
    \E newConfiguration \in SUBSET(Servers \ removedFromConfiguration) :
        ChangeConfigurationInt(i, newConfiguration)

\* Leader i advances its commitIndex to the next possible Index.
\* This is done as a separate step from handling AppendEntries responses,
\* in part to minimize atomic regions, and in part so that leaders of
\* single-server clusters are able to mark entries committed.
\* In CCF and with reconfiguration, the following limitations apply:
\*  - An index can only be committed if it is agreed upon by a Quorum in the
\*    old AND in the new configurations. This means that for any given index,
\*    all configurations of at least that index need to have a quorum of
\*    servers agree on the index before it can be seen as committed.
AdvanceCommitIndex(i) ==
    /\ state[i] = Leader
    /\ LET
        \* We want to get the smallest such index forward that is a signature
        \* This index must be from the current term, 
        \* as explained by Figure 8 and Section 5.4.2 of https://raft.github.io/raft.pdf
        new_index == SelectInSubSeq(log[i], commitIndex[i]+1, Len(log[i]),
            LAMBDA e : e.contentType = TypeSignature /\ e.term = currentTerm[i])
        new_log ==
            IF new_index > 1 THEN
               [ j \in 1..new_index |-> log[i][j] ]
            ELSE
                  << >>
        new_config_index == LastConfigurationToIndex(i, new_index)
        new_configurations == RestrictPred(configurations[i], LAMBDA c : c >= new_config_index)
        IN
        /\  \* Select those configs that need to have a quorum to agree on this leader
            \A config \in {c \in DOMAIN(configurations[i]) : new_index >= c } :
                \* In all of these configs, we now need a quorum in the servers that have the correct matchIndex
                LET config_servers == configurations[i][config]
                    required_quorum == Quorums[config_servers]
                    agree_servers == {k \in config_servers : matchIndex[i][k] >= new_index}
                IN (IF i \in config_servers THEN {i} ELSE {}) \cup agree_servers \in required_quorum
         \* only advance if necessary (this is basically a sanity check after the Min above)
        /\ commitIndex[i] < new_index
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_index]
        /\ committedLog' = IF new_index > committedLog.index THEN [ node |-> i, index |-> new_index ] ELSE committedLog
        \* If commit index surpasses the next configuration, pop configs, and retire as leader if removed
        /\ IF /\ Cardinality(DOMAIN configurations[i]) > 1
              /\ new_index >= NextConfigurationIndex(i)
           THEN
              /\ configurations' = [configurations EXCEPT ![i] = new_configurations]
              \* Retire if i is not in active configuration anymore
              /\ IF i \notin configurations[i][Min(DOMAIN new_configurations)]
                 THEN /\ state' = [state EXCEPT ![i] = RetiredLeader]
                      /\ UNCHANGED << currentTerm, votedFor, reconfigurationCount, removedFromConfiguration >>
                 \* Otherwise, states remain unchanged
                 ELSE UNCHANGED <<serverVars, reconfigurationCount, removedFromConfiguration>>
           \* Otherwise, Configuration and states remain unchanged
           ELSE UNCHANGED <<serverVars, reconfigurationVars>>
    /\ UNCHANGED <<messageVars, candidateVars, leaderVars, log, clientRequests>>

\* CCF: RetiredLeader server i notifies the current commit level to server j
\*  This allows to retire gracefully instead of deadlocking the system through removing itself from the network.
NotifyCommit(i,j) ==
    \* Only RetiredLeader servers send these commit messages
    /\ state[i] = RetiredLeader
    \* Only send notifications of commit to servers in the server set
    /\ IsInServerSetForIndex(j, i, commitIndex[i])
    /\ \/ commitsNotified[i][1] < commitIndex[i]
       \/ InCommitNotificationLimit(i)
    /\ LET new_notified == IF commitsNotified[i][1] = commitIndex[i]
                           THEN <<commitsNotified[i][1], commitsNotified[i][2] + 1>>
                           ELSE <<commitIndex[i], 1>>
       IN  commitsNotified' = [commitsNotified EXCEPT ![i] = new_notified]
    /\ LET msg == [type          |-> NotifyCommitMessage,
                   commitIndex   |-> commitIndex[i],
                   term          |-> currentTerm[i],
                   source        |-> i,
                   dest          |-> j]
       IN Send(msg)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, serverVars, candidateVars, leaderVars, logVars >>

\* CCF supports checkQuorum which enables a leader to choose to abdicate leadership.
CheckQuorum(i) ==
    /\ state[i] = Leader
    /\ state' = [state EXCEPT ![i] = Follower]
    /\ UNCHANGED <<reconfigurationVars, messageVars, currentTerm, votedFor, candidateVars, leaderVars, logVars>>

------------------------------------------------------------------------------
\* Message handlers
\* i = recipient, j = sender, m = message

\* Server i receives a RequestVote request from server j with
\* m.term <= currentTerm[i].
HandleRequestVoteRequest(i, j, m) ==
    LET logOk == \/ m.lastCommittableTerm > MaxCommittableTerm(log[i])
                 \/ /\ m.lastCommittableTerm = MaxCommittableTerm(log[i])
                    \* CCF change: Log is only okay up to signatures,
                    \*  not any message in the log
                    /\ m.lastCommittableIndex >= MaxCommittableIndex(log[i])
        grant == /\ m.term = currentTerm[i]
                 /\ logOk
                 /\ votedFor[i] \in {Nil, j}
    IN /\ m.term <= currentTerm[i]
       /\ \/ grant  /\ votedFor' = [votedFor EXCEPT ![i] = j]
          \/ ~grant /\ UNCHANGED votedFor
       /\ Reply([type        |-> RequestVoteResponse,
                 term        |-> currentTerm[i],
                 voteGranted |-> grant,
                 source      |-> i,
                 dest        |-> j],
                 m)
       /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, state, currentTerm, candidateVars, leaderVars, logVars>>

\* Server i receives a RequestVote response from server j with
\* m.term = currentTerm[i].
HandleRequestVoteResponse(i, j, m) ==
    \* This tallies votes even when the current state is not Candidate, but
    \* they won't be looked at, so it doesn't matter.
    \* It also tallies votes from servers that are not in the configuration but that is filtered out in BecomeLeader
    /\ m.term = currentTerm[i]
    /\ \/ /\ m.voteGranted
          /\ votesGranted' = [votesGranted EXCEPT ![i] =
                                  votesGranted[i] \cup {j}]
       \/ /\ ~m.voteGranted
          /\ UNCHANGED votesGranted
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, votedFor, votesRequested, leaderVars, logVars>>

\* Server i receives a RequestVote request from server j with
\* m.term < currentTerm[i].
RejectAppendEntriesRequest(i, j, m, logOk) ==
    /\ \/ m.term < currentTerm[i]
       \/ /\ m.term = currentTerm[i]
          /\ state[i] = Follower
          /\ \lnot logOk
    /\ Reply([type           |-> AppendEntriesResponse,
              term           |-> currentTerm[i],
              success        |-> FALSE,
              lastLogIndex   |-> 0,
              source         |-> i,
              dest           |-> j],
              m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, logVars>>

ReturnToFollowerState(i, m) ==
    /\ m.term = currentTerm[i]
    /\ state[i] = Candidate
    /\ state' = [state EXCEPT ![i] = Follower]
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, currentTerm, votedFor, logVars, messages>>

AppendEntriesAlreadyDone(i, j, index, m) ==
    /\ \/ m.entries = << >>
       \/ /\ m.entries /= << >>
          /\ Len(log[i]) >= index + (Len(m.entries) - 1)
          /\ \A idx \in 1..Len(m.entries) :
                log[i][index + (idx - 1)].term = m.entries[idx].term
    \* See condition guards in commit() and commit_if_possible(), raft.h
    /\ LET newCommitIndex == max(commitIndex[i],m.commitIndex)
           newConfigurationIndex == LastConfigurationToIndex(i, newCommitIndex)
       IN /\ commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
          \* Pop any newly committed reconfigurations, except the most recent
          /\ configurations' = [configurations EXCEPT ![i] = RestrictPred(@, LAMBDA c : c >= newConfigurationIndex)]
    /\ Reply([type           |-> AppendEntriesResponse,
              term           |-> currentTerm[i],
              success        |-> TRUE,
              lastLogIndex   |-> m.prevLogIndex + Len(m.entries),
              source         |-> i,
              dest           |-> j],
              m)
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, messagesSent, commitsNotified, serverVars, log, clientRequests, committedLog>>

ConflictAppendEntriesRequest(i, index, m) ==
    /\ m.entries /= << >>
    /\ Len(log[i]) >= index
    /\ log[i][index].term /= m.entries[1].term
    /\ LET new_log == [index2 \in 1..(Len(log[i]) - 1) |-> log[i][index2]]
       IN /\ log' = [log EXCEPT ![i] = new_log]
        \* Potentially also shorten the configurations if the removed txns contained reconfigurations
          /\ configurations' = [configurations EXCEPT ![i] = ConfigurationsToIndex(i,Len(new_log))]
    \* On conflicts, we shorten the log. This means we also want to reset the
    \*  sent messages that we track to limit the state space
    /\ LET newCounts == [j \in Servers
                |-> [n \in 1..min(Len(messagesSent[i][j]) - 1, index - 1)
                |-> messagesSent[i][j][n]]]
       IN messagesSent' = [messagesSent EXCEPT ![i] = newCounts ]
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, serverVars, commitIndex, messages, commitsNotified, clientRequests, committedLog>>

NoConflictAppendEntriesRequest(i, j, m) ==
    /\ m.entries /= << >>
    /\ Len(log[i]) = m.prevLogIndex
    /\ log' = [log EXCEPT ![i] = @ \o m.entries]
    \* If new txs include reconfigurations, add them to configurations
    \* Also, if the commitIndex is updated, we may pop some old configs at the same time
    /\ LET
        new_commit_index == max(m.commitIndex, commitIndex[i])
        new_indexes == m.prevLogIndex + 1 .. m.prevLogIndex + Len(m.entries)
        \* log entries to be added to the log
        new_log_entries == 
            [idx \in new_indexes |-> m.entries[idx - m.prevLogIndex]]
        \* filter for reconfigurations
        reconfig_indexes == 
            {idx \in DOMAIN new_log_entries : HasTypeReconfiguration(new_log_entries[idx])}
        \* extended configurations with any new configurations
        new_configs == 
            configurations[i] @@ [idx \in reconfig_indexes |-> new_log_entries[idx].configuration]
        new_conf_index == 
            Max({c \in DOMAIN new_configs : c <= new_commit_index})
        IN
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_commit_index]
        /\ configurations' = 
                [configurations EXCEPT ![i] = RestrictPred(new_configs, LAMBDA c : c >= new_conf_index)]
        \* If we added a new configuration that we are in and were pending, we are now follower
        /\ IF /\ state[i] = Pending
              /\ \E conf_index \in DOMAIN(new_configs) : i \in new_configs[conf_index]
           THEN state' = [state EXCEPT ![i] = Follower ]
           ELSE UNCHANGED state
    /\ Reply([type           |-> AppendEntriesResponse,
              term           |-> currentTerm[i],
              success        |-> TRUE,
              lastLogIndex     |-> m.prevLogIndex + Len(m.entries),
              source         |-> i,
              dest           |-> j],
              m)
    /\ UNCHANGED <<reconfigurationCount, removedFromConfiguration, messagesSent, commitsNotified, currentTerm, votedFor, clientRequests, committedLog>>

AcceptAppendEntriesRequest(i, j, logOk, m) ==
    \* accept request
    /\ m.term = currentTerm[i]
    /\ state[i] \in {Follower, Pending}
    /\ logOk
    /\ LET index == m.prevLogIndex + 1
       IN \/ AppendEntriesAlreadyDone(i, j, index, m)
          \/ ConflictAppendEntriesRequest(i, index, m)
          \/ NoConflictAppendEntriesRequest(i, j, m)

\* Server i receives an AppendEntries request from server j with
\* m.term <= currentTerm[i].
HandleAppendEntriesRequest(i, j, m) ==
    LET logOk == \/ m.prevLogIndex = 0
                 \/ /\ m.prevLogIndex > 0
                    /\ m.prevLogIndex <= Len(log[i])
                    /\ m.prevLogTerm = log[i][m.prevLogIndex].term
    IN /\ m.term <= currentTerm[i]
       /\ \/ RejectAppendEntriesRequest(i, j, m, logOk)
          \/ ReturnToFollowerState(i, m)
          \/ AcceptAppendEntriesRequest(i, j, logOk, m)
       /\ UNCHANGED <<candidateVars, leaderVars>>

\* Server i receives an AppendEntries response from server j with
\* m.term = currentTerm[i].
HandleAppendEntriesResponse(i, j, m) ==
    /\ m.term = currentTerm[i]
    /\ \/ /\ m.success \* successful
          /\ nextIndex'  = [nextIndex  EXCEPT ![i][j] = m.lastLogIndex + 1]
          /\ matchIndex' = [matchIndex EXCEPT ![i][j] = m.lastLogIndex]
       \/ /\ \lnot m.success \* not successful
          /\ nextIndex' = [nextIndex EXCEPT ![i][j] =
                               Max({nextIndex[i][j] - 1, 1})]
          /\ UNCHANGED matchIndex
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, messagesSent, commitsNotified, serverVars, candidateVars, logVars>>

\* Any RPC with a newer term causes the recipient to advance its term first.
UpdateTerm(i, j, m) ==
    /\ m.term > currentTerm[i]
    /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.term]
    /\ state'          = [state       EXCEPT ![i] = IF @ \in {Leader, Candidate} THEN Follower ELSE @]
    /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
       \* messages is unchanged so m can be processed further.
    /\ UNCHANGED <<reconfigurationVars, messageVars, candidateVars, leaderVars, logVars>>

\* Responses with stale terms are ignored.
DropStaleResponse(i, j, m) ==
    /\ m.term < currentTerm[i]
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, messagesSent, commitsNotified, candidateVars, leaderVars, logVars>>

\* Drop messages if they are irrelevant to the node
DropIgnoredMessage(i,j,m) ==
    \* Drop messages if...
    /\
       \* .. recipient is still Pending..
       \/ /\ state[i] = Pending
          \* .. and the message is anything other than an append entries request
          /\ m.type /= AppendEntriesRequest
       \*  OR if message is to a server that has surpassed the Pending stage ..
       \/ /\ state[i] /= Pending
        \* .. and it comes from a server outside of the configuration
          /\ \lnot IsInServerSet(j, i)
       \*  OR if recipient is RetiredLeader and this is not a request to vote
       \/ /\ state[i] = RetiredLeader
          /\ m.type /= RequestVoteRequest
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, messagesSent, commitsNotified, candidateVars, leaderVars, logVars>>

\* RetiredLeader leaders send notify commit messages to update all nodes about the commit level
UpdateCommitIndex(i,j,m) ==
    /\ m.commitIndex > commitIndex[i]
    /\ LET
        new_config_index == LastConfigurationToIndex(i,m.commitIndex)
        new_configurations == RestrictPred(configurations[i], LAMBDA c : c >= new_config_index)
        IN
        /\ commitIndex' = [commitIndex EXCEPT ![i] = m.commitIndex]
        /\ configurations' = [configurations EXCEPT ![i] = new_configurations]
    /\ UNCHANGED <<reconfigurationCount, messages, messagesSent, commitsNotified, currentTerm,
                   votedFor, candidateVars, leaderVars, log, clientRequests, committedLog>>

\* Receive a message.
Messages ==
    \* The definition  Messages  may be redefined along with  WithMessages  and  WithoutMessages  above.  For example,
    \* one might want to model  messages  , i.e., the network as a bag (multiset) instead of a set.  The Traceccfraft.tla
    \* spec does this.
    messages

RcvDropIgnoredMessage ==
    \* Drop any message that are to be ignored by the recipient
    \E m \in Messages : DropIgnoredMessage(m.dest,m.source,m)

RcvUpdateTerm ==
    \* Any RPC with a newer term causes the recipient to advance
    \* its term first. Responses with stale terms are ignored.
    \E m \in Messages : UpdateTerm(m.dest, m.source, m)

RcvRequestVoteRequest ==
    \E m \in Messages : 
        /\ m.type = RequestVoteRequest
        /\ HandleRequestVoteRequest(m.dest, m.source, m)

RcvRequestVoteResponse ==
    \E m \in Messages : 
        /\ m.type = RequestVoteResponse
        /\ \/ HandleRequestVoteResponse(m.dest, m.source, m)
           \/ DropStaleResponse(m.dest, m.source, m)

RcvAppendEntriesRequest ==
    \E m \in Messages : 
        /\ m.type = AppendEntriesRequest
        /\ HandleAppendEntriesRequest(m.dest, m.source, m)

RcvAppendEntriesResponse ==
    \E m \in Messages : 
        /\ m.type = AppendEntriesResponse
        /\ \/ HandleAppendEntriesResponse(m.dest, m.source, m)
           \/ DropStaleResponse(m.dest, m.source, m)

RcvUpdateCommitIndex ==
    \E m \in Messages : 
        /\ m.type = NotifyCommitMessage
        /\ UpdateCommitIndex(m.dest, m.source, m)
        /\ Discard(m)

Receive ==
    \/ RcvDropIgnoredMessage
    \/ RcvUpdateTerm
    \/ RcvRequestVoteRequest
    \/ RcvRequestVoteResponse
    \/ RcvAppendEntriesRequest
    \/ RcvAppendEntriesResponse
    \/ RcvUpdateCommitIndex

\* End of message handlers.
------------------------------------------------------------------------------

\* During the model check, the model checker will search through all possible state transitions.
\* Each of these transitions has additional constraints that have to be fulfilled for the state to be an allowed step.
\* For example, ``BecomeLeader`` is only a possible step if the selected node has enough votes to do so.

\* Defines how the variables may transition.
Next ==
    \/ \E i \in Servers : Timeout(i)
    \/ \E i, j \in Servers : RequestVote(i, j)
    \/ \E i \in Servers : BecomeLeader(i)
    \/ \E i \in Servers : ClientRequest(i)
    \/ \E i \in Servers : SignCommittableMessages(i)
    \/ \E i \in Servers : ChangeConfiguration(i)
    \/ \E i, j \in Servers : NotifyCommit(i,j)
    \/ \E i \in Servers : AdvanceCommitIndex(i)
    \/ \E i, j \in Servers : AppendEntries(i, j)
    \/ \E i \in Servers : CheckQuorum(i)
    \/ Receive

\* The specification must start with the initial state and transition according
\* to Next.
Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* Correctness invariants
\* These invariants should be true for all possible states

\* Committed log entries should not conflict
LogInv ==
    /\ \A i \in Servers : IsPrefix(Committed(i),SubSeq(log[committedLog.node],1,committedLog.index))

\* There should not be more than one leader per term at the same time
\* Note that this does not rule out multiple leaders in the same term at different times
MoreThanOneLeaderInv ==
    \A i,j \in Servers :
        (/\ currentTerm[i] = currentTerm[j]
         /\ state[i] = Leader
         /\ state[j] = Leader)
        => i = j

\* If a candidate has a chance of being elected, there
\* are no log entries with that candidate's term
CandidateTermNotInLogInv ==
    \A i \in Servers :
        (/\ state[i] = Candidate
        /\ \A k \in DOMAIN (configurations[i]) :
            {j \in Servers :
                /\ currentTerm[j] = currentTerm[i]
                /\ votedFor[j] = i
            } \in Quorums[configurations[i][k]]
        )
        =>
        \A j \in Servers :
        \A n \in DOMAIN log[j] :
             log[j][n].term /= currentTerm[i]

\* A leader always has the greatest index for its current term (this does not
\* mean all of its log will survive if it is not committed + signed yet)
ElectionSafetyInv ==
    \A i \in Servers :
        state[i] = Leader =>
        \A j \in Servers : i /= j =>
            LET FilterAndMax(a, b) == 
                    IF a.term = currentTerm[i] THEN max(a.term, b) ELSE b
            IN FoldSeq(FilterAndMax, 0, log[i]) >= FoldSeq(FilterAndMax, 0, log[j])

----
\* Every (index, term) pair determines a log prefix.
\* From page 8 of the Raft paper: "If two logs contain an entry with the same index and term, then the logs are identical in all preceding entries."
LogMatchingInv ==
    \A i, j \in Servers : i /= j =>
        \A n \in 1..min(Len(log[i]), Len(log[j])) :
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
    \A i \in Servers :
        \A S \in Quorums[CurrentConfiguration(i)] :
            \E j \in S :
                IsPrefix(Committed(i), log[j])

\* The "up-to-date" check performed by servers
\* before issuing a vote implies that i receives
\* a vote from j only if i has all of j's committed
\* entries
MoreUpToDateCorrectInv ==
    \A i, j \in Servers : i /= j =>
        ((\/ MaxCommittableTerm(log[i]) > MaxCommittableTerm(log[j])
         \/ /\ MaxCommittableTerm(log[i]) = MaxCommittableTerm(log[j])
            /\ MaxCommittableIndex(log[i]) >= MaxCommittableIndex(log[j])) =>
        IsPrefix(Committed(j), log[i]))

\* The committed entries in every log are a prefix of the
\* leader's log up to the leader's term (since a next Leader may already be
\* elected without the old leader stepping down yet)
LeaderCompletenessInv ==
    \A i \in Servers :
        state[i] = Leader =>
        \A j \in Servers : i /= j =>
            IsPrefix(CommittedTermPrefix(j, currentTerm[i]),log[i])

\* In CCF, only signature messages should ever be committed
SignatureInv ==
    \A i \in Servers :
        \/ commitIndex[i] = 0
        \/ log[i][commitIndex[i]].contentType = TypeSignature

\* Each server's term should be equal to or greater than the terms of messages it has sent
MonoTermInv ==
    \A m \in messages: currentTerm[m.source] >= m.term

\* Terms in logs should be monotonically increasing
MonoLogInv ==
    \A i \in Servers :
        \/ Len(log[i]) = 0
        \/ /\ log[i][Len(log[i])].term <= currentTerm[i]
           /\ \/ Len(log[i]) = 1
              \/ \A k \in 1..Len(log[i])-1 :
                \* Terms in logs should only increase after a signature
                \/ log[i][k].term = log[i][k+1].term
                \/ /\ log[i][k].term < log[i][k+1].term
                   /\ log[i][k].contentType = TypeSignature

\* Each server's active configurations should be consistent with its own log and commit index
LogConfigurationConsistentInv ==
    \A i \in Servers :
        \* Configurations should have associated reconfiguration txs in the log
        \* The only exception is the initial configuration (which has index 0)
        /\ \A idx \in DOMAIN (configurations[i]) :
            idx # 0 => 
            /\ log[i][idx].contentType = TypeReconfiguration            
            /\ log[i][idx].configuration = configurations[i][idx]
        \* Current configuration should be committed
        \* This is trivially true for the initial configuration (index 0)
        /\ commitIndex[i] >= CurrentConfigurationIndex(i)
        \* Pending configurations should not be committed yet
        /\ Cardinality(DOMAIN configurations[i]) > 1 
            => commitIndex[i] < NextConfigurationIndex(i)
        \* There should be no committed reconfiguration txs since current configuration
        /\ commitIndex[i] > CurrentConfigurationIndex(i)
            => \A idx \in CurrentConfigurationIndex(i)+1..commitIndex[i] :
                log[i][idx].contentType # TypeReconfiguration
        \* There should be no uncommitted reconfiguration txs except pending configurations
        /\ Len(log[i]) > commitIndex[i]
            => \A idx \in commitIndex[i]+1..Len(log[i]) :
                log[i][idx].contentType = TypeReconfiguration 
                => configurations[i][idx] = log[i][idx].configuration

NoLeaderInTermZeroInv ==
    \A i \in Servers :
        currentTerm[i] = 0 => state[i] # Leader

------------------------------------------------------------------------------
\* Properties

MonotonicTermProp ==
    [][\A i \in Servers :
        currentTerm[i]' >= currentTerm[i]]_vars

MonotonicCommitIndexProp ==
    [][\A i \in Servers :
        commitIndex[i]' >= commitIndex[i]]_vars

CommittedLogNeverChangesProp ==
    [][\A i \in Servers :
        IsPrefix(Committed(i), Committed(i)')]_vars

PermittedLogChangesProp ==
    [][\A i \in Servers :
        log[i] # log[i]' =>
            \/ state[i]' = Pending
            \/ state[i]' = Follower
            \* Established leader adding new entries
            \/ /\ state[i] = Leader
               /\ state[i]' = Leader
               /\ IsPrefix(log[i], log[i]')
            \* Newly elected leader is truncating its log
            \/ /\ state[i] = Candidate
               /\ state[i]' = Leader
               /\ log[i]' = Committable(i)
        ]_vars

StateTransitionsProp ==
    [][\A i \in Servers :
        /\ state[i] = Pending => state[i]' \in {Pending, Follower}
        /\ state[i] = Follower => state[i]' \in {Follower, Candidate}
        /\ state[i] = Candidate => state[i]' \in {Follower, Candidate, Leader}
        /\ state[i] = Leader => state[i]' \in {Follower, Leader, RetiredLeader}
        /\ state[i] = RetiredLeader => state[i]' = RetiredLeader
        ]_vars

PendingBecomesFollowerProp ==
    \* A pending node that becomes part of any configuration immediately transitions to Follower.
    [][\A s \in { s \in Servers : state[s] = Pending } : 
            s \in GetServerSet(s)' => 
                state[s]' = Follower]_vars

------------------------------------------------------------------------------
\* Debugging invariants
\* These invariants should give error traces and are useful for debugging to see if important situations are possible
\* These invariants are not checked unless specified in the .cfg file

\* This invariant is false with checkQuorum enabled but true with checkQuorum disabled
DebugInvLeaderCannotStepDown ==
    \A m \in messages :
        /\ m.type = AppendEntriesRequest
        /\ currentTerm[m.source] = m.term
        => state[m.source] = Leader

\* This invariant shows that it should be possible for Node 4 or 5 to become leader
\* Note that symmetry for the set of servers should be disabled to check this debug invariant
DebugInvReconfigLeader ==
    /\ state[NodeFour] /= Leader
    /\ state[NodeFive] /= Leader

\* This invariant shows that a txn can be committed after a reconfiguration
DebugInvSuccessfulCommitAfterReconfig ==
    \lnot (
        \E i \in Servers:
            \E k_1,k_2 \in DOMAIN log[i] :
                /\ k_1 < k_2
                /\ log[i][k_1].contentType = TypeReconfiguration
                /\ log[i][k_2].contentType = TypeEntry
                /\ commitIndex[i] > k_2
    )

\* Check that eventually all messages can be dropped or processed and we did not forget a message
DebugInvAllMessagesProcessable ==
    Len(messages) > 0 ~> Len(messages) = 0

\* The Retirement state is reached by Leaders that remove themselves from the configuration.
\* It should be reachable if a leader is removed.
DebugInvRetirementReachable ==
    \A i \in Servers : state[i] /= RetiredLeader

===============================================================================