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
\*   (e.g. clientRequests)
\* - https://github.com/dricketts/raft.tla/blob/master/raft.tla
\*   (e.g. certain invariants)

EXTENDS Naturals, FiniteSets, Sequences, TLC, FiniteSetsExt, SequencesExt, Functions

------------------------------------------------------------------------------
\* Constants

CONSTANT
    OrderedNoDup,
    Ordered,
    ReorderedNoDup,
    Reordered,
    Guarantee

\* Leadership states
CONSTANTS
    \* See original Raft paper (https://www.usenix.org/system/files/conference/atc14/atc14-paper-ongaro.pdf)
    \* and comments for leadership_state in ../src/consensus/aft/raft.h for details on the Follower,
    \* Candidate, and Leader states.
    Follower,
    Candidate,
    Leader,
    \* Initial state for a joiner node, until it has received a first message
    \* from another node.
    None

LeadershipStates == {
    Follower,
    Candidate,
    Leader,
    None
    }

\* Membership states, defined in ../src/kv/kv_types.h
\* In this specification, the membership state of Retired also describes the
\* retirement phase (also defined in ../src/kv/kv_types.h) to avoid the need for an additional variable
CONSTANTS
    \* Node is not in the process of leaving the CCF service.
    Active,
    \* Node has added its own retirement to its log, but it is not yet committed or even signed
    \* The node can still revert to Active upon rollback
    \* RetirementOrdered does not change the behavior of the node
    RetirementOrdered,
    \* Node has added its own retirement to its log and it has been signed but it is not yet committed
    \* The node can still revert to RetirementOrdered or Active upon rollback
    \* If the node is a leader, it will stop accepting new client requests
    RetirementSigned,
    \* Node retirement has been committed and it is no longer part of the network
    \* If this node was a leader, it will step down. It will not run for election again.
    \* This node will continue to respond to AppendEntries and RequestVote messages
    \* Note that this spec does not model when nodes can be safely removed
    \* RetirementCompleted is a terminal state
    RetirementCompleted

MembershipStates == {
    Active,
    RetirementOrdered,
    RetirementSigned,
    RetirementCompleted
    }

\* Message types:
CONSTANTS
    RequestVoteRequest,
    RequestVoteResponse,
    AppendEntriesRequest,
    AppendEntriesResponse,
    ProposeVoteRequest

\* CCF: Content types (Normal entry or a signature that signs
\*      previous entries or a reconfiguration entry)
CONSTANTS
    TypeEntry,
    TypeSignature,
    TypeReconfiguration

\* Set of nodes for this model
CONSTANTS Servers
ASSUME Servers /= {} /\ IsFiniteSet(Servers)

\* Initial term used by the Start node in the network
StartTerm == 2

Nil ==
  (*************************************************************************)
  (* This defines Nil to be an unspecified value that is not a server.     *)
  (*************************************************************************)
  CHOOSE v : v \notin Servers

------------------------------------------------------------------------------
\* Global variables

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
    removedFromConfiguration, 
    configurations
>>

ReconfigurationVarsTypeInv ==
    /\ ConfigurationsTypeInv
    /\ RemovedFromConfigurationTypeInv

\* A set representing requests and responses sent from one server
\* to another. With CCF, we have message integrity and can ensure unique messages.
\* Messages only records messages that are currently in-flight, actions should
\* remove messages once received.
\* We model messages as a single (unsorted) set and do not assume ordered message delivery between nodes.
\* Node-to-node channels use TCP but out-of-order delivery could be observed due to reconnection or a malicious host.
VARIABLE messages

\* Network semantics:
Network == INSTANCE Network

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

ProposeVoteRequestTypeOK(m) ==
    /\ m.type = ProposeVoteRequest
    /\ m.term \in Nat

MessagesTypeInv ==
    \A m \in Network!Messages :
        /\ m.source \in Servers
        /\ m.dest \in Servers
        /\ m.source /= m.dest
        /\ m.term \in Nat \ {0}
        /\  \/ AppendEntriesRequestTypeOK(m)
            \/ AppendEntriesResponseTypeOK(m)
            \/ RequestVoteRequestTypeOK(m)
            \/ RequestVoteResponseTypeOK(m)
            \/ ProposeVoteRequestTypeOK(m)

messageVars == <<
    messages
>>

MessageVarsTypeInv ==
    /\ MessagesTypeInv

------------------------------------------------------------------------------
\* The following variables are all per server (functions with domain Servers).

\* The server's term number.
VARIABLE currentTerm

CurrentTermTypeInv ==
    \A i \in Servers : currentTerm[i] \in Nat

\* The leadership state.
VARIABLE leadershipState

LeadershipStateTypeInv ==
    \A i \in Servers : leadershipState[i] \in LeadershipStates

\* The membership state.
VARIABLE membershipState

MembershipStateTypeInv ==
    \A i \in Servers : membershipState[i] \in MembershipStates

\* The candidate the server voted for in its current term, or
\* Nil if it hasn't voted for any.
VARIABLE votedFor

VotedForTypeInv ==
    \A i \in Servers : votedFor[i] \in {Nil} \cup Servers

serverVars == <<currentTerm, leadershipState, membershipState, votedFor>>

ServerVarsTypeInv ==
    /\ CurrentTermTypeInv
    /\ LeadershipStateTypeInv
    /\ MembershipStateTypeInv
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

logVars == <<log, commitIndex>>

\* The indices of the committable entries in the log of server i
CommittableIndices(i) ==
    {idx \in DOMAIN log[i] : log[i][idx].contentType = TypeSignature}

LogVarsTypeInv ==
    /\ LogTypeInv
    /\ CommitIndexTypeInv

\* The set of servers from which the candidate has received a vote in its
\* currentTerm.
VARIABLE votesGranted

VotesGrantedTypeInv ==
    \A i \in Servers :
        votesGranted[i] \subseteq Servers

candidateVars == <<votesGranted>>

CandidateVarsTypeInv ==
    /\ VotesGrantedTypeInv

\* The following variables are used only on leaders:

\* The last entry sent to each follower.
\* sentIndex in CCF is similar in function to nextIndex in Raft
\* In CCF, the leader updates nextIndex optimistically when an AE message is dispatched
\* In contrast, in Raft the leader only updates nextIndex when an AE response is received
VARIABLE sentIndex


SentIndexTypeInv ==
    \A i, j \in Servers : i /= j =>
        /\ sentIndex[i][j] \in Nat

\* The latest entry that each follower has acknowledged is the same as the
\* leader's. This is used to calculate commitIndex on the leader.
VARIABLE matchIndex

MatchIndexTypeInv ==
    \A i, j \in Servers : i /= j =>
        matchIndex[i][j] \in Nat

leaderVars == <<sentIndex, matchIndex>>

LeaderVarsTypeInv ==
    /\ SentIndexTypeInv
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
\* Helpers

min(a, b) == IF a < b THEN a ELSE b

max(a, b) == IF a > b THEN a ELSE b

\* Add a message to the bag of messages.
\* But only if this exact messages does not already exist
Send(m) == messages' =
    Network!WithMessage(m, messages)

\* Remove a message from the bag of messages. Used when a server is done
\* processing a message.
Discard(m) == messages' = Network!WithoutMessage(m, messages)

\* Combination of Send and Discard
Reply(response, request) ==
    messages' = Network!WithoutMessage(request, Network!WithMessage(response, messages))

HasTypeSignature(e) == e.contentType = TypeSignature
HasTypeReconfiguration(e) == e.contentType = TypeReconfiguration

LastCommittableIndex(i) ==
    \* raft.h::last_committable_index
    Max({commitIndex[i]} \cup CommittableIndices(i))

LastCommittableTerm(i) ==
    \* raft.h::get_term_internal
    IF LastCommittableIndex(i) = 0 THEN 0 ELSE log[i][LastCommittableIndex(i)].term

\* CCF: Return the index of the latest committable message
\*      (i.e., the last one that was signed by a leader)
MaxCommittableIndex(xlog) ==
    SelectLastInSeq(xlog, HasTypeSignature)

\* CCF: Returns the term associated with the MaxCommittableIndex(xlog)
MaxCommittableTerm(xlog) ==
    LET iMax == MaxCommittableIndex(xlog)
    IN IF iMax = 0 THEN 0 ELSE xlog[iMax].term

FindHighestPossibleMatch(xlog, index, term) ==
    \* See find_highest_possible_match in raft.h
    SelectLastInSeq(SubSeq(xlog, 1, min(index, Len(xlog))), LAMBDA e: e.term <= term)

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

HighestConfigurationWithNode(server, node) ==
    \* Highest configuration index, known to server, that includes node
    Max({configIndex \in DOMAIN configurations[server] : node \in configurations[server][configIndex]} \union {0})

NextConfigurationIndex(server) ==
    \* The configuration with the 2nd smallest index is the first of the pending configurations
    LET dom == DOMAIN configurations[server]
    IN Min(dom \ {Min(dom)})

\* The configurations for a server up to (and including) a given index
\* Useful for rolling back configurations when the log is truncated
ConfigurationsToIndex(server, index) ==
     RestrictDomain(configurations[server], LAMBDA c : c <= index)

\* Index of the last reconfiguration up to (and including) the given index,
\* assuming the given index is after the commit index
LastConfigurationToIndex(server, index) ==
    LET configsBeforeIndex == {c \in DOMAIN configurations[server] : c <= index}
    IN IF configsBeforeIndex = {} THEN 0 ELSE Max(configsBeforeIndex)

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

\* RetirementIndexLog is the index at which node i is first removed from node_log, 0 otherwise
RetirementIndexLog(node_log, i) ==
    LET 
        inIndexes == {index \in DOMAIN node_log: 
            /\ node_log[index].contentType = TypeReconfiguration
            /\ i \in node_log[index].configuration}
        outIndexes == {index \in DOMAIN node_log: 
            /\ node_log[index].contentType = TypeReconfiguration
            /\ i \notin node_log[index].configuration}
    IN IF 
        \* At least one configuration with node i
        inIndexes # {}
    THEN 
        LET retiredIndexes == {k \in outIndexes: k > Max(inIndexes)}
        IN IF retiredIndexes = {} 
        THEN 0 
        ELSE Min(retiredIndexes)
    ELSE 0

\* RetirementIndex is the index at which node i is first removed from the 
\* configuration according to the log of node i. 0 iff the node i has not been removed (or even added)
\* Note that is spec does not explicitly track retirement_idx like raft.h, instead it calculates it as needed
\* The same is true of retirement_committable_idx
RetirementIndex(i) ==
    RetirementIndexLog(log[i], i)

\* Returns the membership state of a node i given its log and commit index
CalcMembershipState(log_i, commit_index_i, i) ==
    LET retirement_index == RetirementIndexLog(log_i,i)
    IN IF retirement_index # 0
       THEN IF retirement_index <= commit_index_i 
            THEN RetirementCompleted
            ELSE IF retirement_index < MaxCommittableIndex(log_i)
                 THEN RetirementSigned
                 ELSE RetirementOrdered
       ELSE Active

AppendEntriesBatchsize(i, j) ==
    \* The Leader is modeled to send zero to one entries per AppendEntriesRequest.
     \* This can be redefined to send bigger batches of entries.
    {sentIndex[i][j] + 1}


PlausibleSucessorNodes(i) ==
    \* Find plausible successor nodes for i
    LET
        activeServers == Servers \ removedFromConfiguration
        highestMatchServers == {n \in activeServers : \A m \in activeServers : matchIndex[i][n] >= matchIndex[i][m]}
    IN {n \in highestMatchServers : \A m \in highestMatchServers: HighestConfigurationWithNode(i, n) >= HighestConfigurationWithNode(i, m)} \ {i}

StartLog(startNode, _ignored) ==
    << [term |-> StartTerm, contentType |-> TypeReconfiguration, configuration |-> startNode],
       [term |-> StartTerm, contentType |-> TypeSignature] >>

JoinedLog(startNode, nextNodes) ==
    StartLog(startNode, nextNodes) \o
        << [term |-> StartTerm, contentType |-> TypeReconfiguration, configuration |-> nextNodes],
           [term |-> StartTerm, contentType |-> TypeSignature] >>

InitLogConfigServerVars(startNodes, logPrefix(_,_)) ==
    /\ removedFromConfiguration = {}
    /\ votedFor    = [i \in Servers |-> Nil]
    /\ currentTerm = [i \in Servers |-> IF i \in startNodes THEN StartTerm ELSE 0]
    /\ \E sn \in startNodes:
        \* We make the following assumption about logPrefix, whose violation would violate SignatureInv and LogConfigurationConsistentInv.
        \* Alternative, we could have conjoined this formula to Init, but this would have caused TLC to generate no initial states on a
        \* bogus logPrefix.
        \* <<[term |-> StartTerm, contentType |-> TypeReconfiguration, configuration |-> startNodes], 
        \*   [term |-> StartTerm, contentType |-> TypeSignature]>> \in Suffixes(logPrefix({sn}, startNodes))
        /\ log         = [i \in Servers |-> IF i \in startNodes THEN logPrefix({sn}, startNodes) ELSE << >>]
        /\ leadershipState = [i \in Servers |-> IF i = sn THEN Leader ELSE IF i \in startNodes THEN Follower ELSE None]
        /\ membershipState = [i \in Servers |-> Active]
        /\ commitIndex = [i \in Servers |-> IF i \in startNodes THEN Len(logPrefix({sn}, startNodes)) ELSE 0]
    /\ configurations = [i \in Servers |-> IF i \in startNodes  THEN (Len(log[i])-1 :> startNodes) ELSE << >>]
    
------------------------------------------------------------------------------
\* Define initial values for all variables

InitReconfigurationVars ==
    \E startNode \in Servers:
        InitLogConfigServerVars({startNode}, StartLog)

InitMessagesVars ==
    /\ Network!InitMessageVar

InitCandidateVars ==
    /\ votesGranted   = [i \in Servers |-> {}]

\* The values sentIndex[i][i] and matchIndex[i][i] are never read, since the
\* leader does not send itself messages. It's still easier to include these
\* in the functions.
InitLeaderVars ==
    /\ sentIndex  = [i \in Servers |-> [j \in Servers |-> 0]]
    /\ matchIndex = [i \in Servers |-> [j \in Servers |-> 0]]

Init ==
    /\ InitReconfigurationVars
    /\ InitMessagesVars
    /\ InitCandidateVars
    /\ InitLeaderVars

------------------------------------------------------------------------------
\* Define state transitions

\* Server i times out and starts a new election.
Timeout(i) ==
    \* Only servers that haven't completed retirement can become candidates
    /\ membershipState[i] # RetirementCompleted
    \* Only servers that are followers/candidates can become candidates
    /\ leadershipState[i] \in {Follower, Candidate}
    \* Check that the reconfiguration which added this node is at least committable
    /\ \E c \in DOMAIN configurations[i] :
        /\ i \in configurations[i][c]
        /\ MaxCommittableIndex(log[i]) >= c
    /\ leadershipState' = [leadershipState EXCEPT ![i] = Candidate]
    /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
    \* Candidate votes for itself
    /\ votedFor' = [votedFor EXCEPT ![i] = i]
    /\ votesGranted'   = [votesGranted EXCEPT ![i] = {i}]
    /\ UNCHANGED <<reconfigurationVars, messageVars, leaderVars, logVars, membershipState>>

\* Candidate i sends j a RequestVote request.
RequestVote(i,j) ==
    LET
        msg == [type         |-> RequestVoteRequest,
                term         |-> currentTerm[i],
                \*  CCF: Use last signature entry and not last log entry in elections.
                \* See raft.h::send_request_vote
                lastCommittableTerm  |-> LastCommittableTerm(i),
                lastCommittableIndex |-> LastCommittableIndex(i),
                source       |-> i,
                dest         |-> j]
    IN
    \* Timeout votes for itself atomically. Thus we do not need to request our own vote.
    /\ i /= j
    \* Only requests vote if we are already a candidate (and therefore have not completed retirement)
    /\ leadershipState[i] = Candidate
    \* Reconfiguration: Make sure j is in a configuration of i
    /\ IsInServerSet(j, i)
    /\ Send(msg)
    /\ UNCHANGED <<reconfigurationVars, serverVars, votesGranted, leaderVars, logVars, membershipState>>

\* Leader i sends j an AppendEntries request
AppendEntries(i, j) ==
    \* Sender is primary (and therefore has not completed retirement)
    /\ leadershipState[i] = Leader
    \* No messages to itself 
    /\ i /= j
    /\ j \in GetServerSet(i)
    \* AppendEntries must be sent for historical entries, unless
    \* snapshots are used. Whether the node is in configuration at
    \* that index makes no difference.
    \* /\ IsInServerSetForIndex(j, i, sentIndex[i][j])
    /\ LET prevLogIndex == sentIndex[i][j]
           prevLogTerm == IF prevLogIndex \in DOMAIN log[i] THEN
                              log[i][prevLogIndex].term
                          ELSE
                              \* state.h::view_at (:64) indices before the version of the first view are unknown
                              0
           \* Send a number of entries (constrained by the end of the log).
           lastEntry(idx) == min(Len(log[i]), idx)
           index == sentIndex[i][j] + 1
           msg(idx) == 
               [type          |-> AppendEntriesRequest,
                term          |-> currentTerm[i],
                prevLogIndex  |-> prevLogIndex,
                prevLogTerm   |-> prevLogTerm,
                entries       |-> SubSeq(log[i], index, lastEntry(idx)),
                commitIndex   |-> commitIndex[i],
                source        |-> i,
                dest          |-> j]
       IN
       /\ \E b \in AppendEntriesBatchsize(i, j):
            LET m == msg(b) IN
            \* The implementation does not allow a leader with their retirement signed to send heartbeats, see raft.h:L928
            \* TODO: how does this interact with a new leader's AE message? or a existing leader's first AE to a new node?
            \* The former cannot happen in the implementation as a node which is not Active cannot become leader
            /\ \/ membershipState[i] # RetirementSigned
               \/ m.entries # <<>>
            /\ Send(m)
            \* Record the most recent index we have sent to this node.
            \* (see https://github.com/microsoft/CCF/blob/9fbde45bf5ab856ca7bcf655e8811dc7baf1e8a3/src/consensus/aft/raft.h#L935-L936)
            /\ sentIndex' = [sentIndex EXCEPT ![i][j] = @ + Len(m.entries)]
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, matchIndex, logVars, membershipState>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
    \* Node should already be a candidate (and therefore hasn't completed retirement)
    /\ leadershipState[i] = Candidate
    \* To become leader, the candidate must have received votes from a majority in each active configuration
    \* Only votes by nodes part of a given configuration should be tallied against it
    /\ \A c \in DOMAIN configurations[i] : (votesGranted[i] \intersect configurations[i][c]) \in Quorums[configurations[i][c]]
    /\ leadershipState' = [leadershipState EXCEPT ![i] = Leader]
    \* CCF: We reset our own log to its committable subsequence, throwing out
    \* all unsigned log entries of the previous leader.
    \* See occurrence of last_committable_index() in raft.h::become_leader.
    /\ log' = [log EXCEPT ![i] = SubSeq(log[i],1, MaxCommittableIndex(log[i]))]
    \* Reset our sentIndex to the end of the *new* log.
    /\ sentIndex'  = [sentIndex EXCEPT ![i] = [j \in Servers |-> Len(log'[i])]]
    /\ matchIndex' = [matchIndex EXCEPT ![i] = [j \in Servers |-> 0]]
    \* Shorten the configurations if the removed txs contained reconfigurations
    /\ configurations' = [configurations EXCEPT ![i] = ConfigurationsToIndex(i, Len(log'[i]))]
    \* If the leader was in the RetirementOrdered state, then its retirement has
    \* been rolled back as it was unsigned
    /\ membershipState' = [membershipState EXCEPT ![i] = 
        IF @ = RetirementOrdered THEN Active ELSE @]
    /\ UNCHANGED <<removedFromConfiguration, messageVars, currentTerm, votedFor, candidateVars, commitIndex>>

\* Leader i receives a client request to add 42 to the log.
ClientRequest(i) ==
    \* Only leaders receive client requests (and therefore they have not yet completed retirement)
    /\ leadershipState[i] = Leader
    \* ... and the leader should not have its retirement signed
    /\ membershipState[i] # RetirementSigned
    \* Add new request to leader's log
    /\ log' = [log EXCEPT ![i] = Append(@, [term  |-> currentTerm[i], request |-> 42, contentType |-> TypeEntry]) ]
    /\ UNCHANGED <<reconfigurationVars, messageVars, serverVars, candidateVars, leaderVars, commitIndex>>

\* CCF: Signed commits
\* In CCF, the leader periodically signs the latest log prefix. Only these signatures are committable in CCF.
\* We model this via special ``TypeSignature`` log entries and ensure that the commitIndex can only be moved to these special entries.

\* Leader i signs the previous entries in its log to make them committable.
\* This is done as a separate entry in the log that has contentType Signature
\* compared to ordinary entries with contentType Entry.
\* See history::start_signature_emit_timer
SignCommittableMessages(i) ==
    \* Only applicable to Leaders with a log that contains at least one entry.
    /\ leadershipState[i] = Leader
    \* The first log entry cannot be a signature.
    /\ log[i] # << >>
    \* Create a new entry in the log that has the contentType Signature and append it
    /\ log' = [log EXCEPT ![i] = @ \o <<[term  |-> currentTerm[i], contentType  |-> TypeSignature]>>]
    \* If membershipState was RetirementOrdered then its now RetirementSigned
    /\ IF membershipState[i] = RetirementOrdered
       THEN membershipState' = [membershipState EXCEPT ![i] = RetirementSigned]
       ELSE UNCHANGED membershipState
    /\ UNCHANGED <<reconfigurationVars, messageVars, currentTerm, leadershipState, votedFor, candidateVars, leaderVars, commitIndex>>

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
    /\ leadershipState[i] = Leader
    \* Configuration is not equal to the previous configuration.
    /\ newConfiguration /= MaxConfiguration(i)
    \* CCF's integrity demands that a previously removed server cannot rejoin the network,
    \* i.e., be re-added to a new configuration.  Instead, the node has to rejoin with a
    \* "fresh" identity (compare sec 6.2, page 8, https://arxiv.org/abs/2310.11559).
    /\ \A s \in newConfiguration: s \notin removedFromConfiguration
    \* See raft.h:2401, nodes are only sent future entries initially, they will NACK if necessary.
    \* This is because they are expected to start from a fairly recent snapshot, not from scratch.
    /\ LET
        addedNodes == newConfiguration \ CurrentConfiguration(i)
        newSentIndex == [ k \in Servers |-> IF k \in addedNodes THEN Len(log[i]) ELSE sentIndex[i][k]]
       IN sentIndex' = [sentIndex EXCEPT ![i] = newSentIndex]
    /\ removedFromConfiguration' = removedFromConfiguration \cup (MaxConfiguration(i) \ newConfiguration)
    /\ log' = [log EXCEPT ![i] = Append(log[i], 
                                            [term |-> currentTerm[i],
                                             configuration |-> newConfiguration,
                                             contentType |-> TypeReconfiguration])]
    /\ configurations' = [configurations EXCEPT ![i] = configurations[i] @@ Len(log'[i]) :> newConfiguration]
    \* Check if node is starting its own retirement
    /\ IF /\ membershipState[i] = Active
          /\ i \notin newConfiguration
        THEN membershipState' = [membershipState EXCEPT ![i] = RetirementOrdered]
        ELSE UNCHANGED membershipState
    /\ UNCHANGED <<messageVars, currentTerm, leadershipState, votedFor, candidateVars, matchIndex, commitIndex>>

ChangeConfiguration(i) ==
    \* Reconfigure to any *non-empty* subset of servers.  ChangeConfigurationInt checks that the new
    \* configuration newConfiguration does not reintroduce nodes that have been removed previously.
    \E newConfiguration \in SUBSET(Servers) \ {{}}:
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
    /\ leadershipState[i] = Leader
    /\ LET
            \* Select those configs that need to have a quorum to agree on this leader.
            \* Compare https://github.com/microsoft/CCF/blob/75670480c53519fcec1a09d36aefc11b23a597f9/src/consensus/aft/raft.h#L2081
            HasConsensusWatermark(idx) ==
                \A config \in {c \in DOMAIN(configurations[i]) : idx >= c } :
                    \* In all of these configs, we now need a quorum in the servers that have the correct matchIndex
                    LET config_servers == configurations[i][config]
                        required_quorum == Quorums[config_servers]
                        agree_servers == {k \in config_servers : matchIndex[i][k] >= idx}
                    IN (IF i \in config_servers THEN {i} ELSE {}) \cup agree_servers \in required_quorum
            \* The function find_highest_possible_committable_index in raft.h returns the largest committable index
            \* in the current term (Figure 8 and Section 5.4.2 of https://raft.github.io/raft.pdf explains why it has
            \* to be the *current* term).  Finding the largest index is an (implementation-level) optimization that
            \* reduces the number of AdvanceCommitIndex calls, but this optimization also shrinks this spec's state-space.
            \*
            \* Theoretically, any committable index in the current term works, i.e., highestCommittableIndex could be
            \* defined non-deterministically as:
            \*       \E idx \in { j \in (commitIndex[i]+1)..Len(log[i]) : /\ log[i][j].term = currentTerm[i] 
            \*                                                            /\ log[i][j].contentType = TypeSignature }
            \*          /\ HasConsensusWatermark(idx)
            \*          /\ ...
            \* 
            \* Max({0} \cup {...}) to default to 0 if no committable index is found.
            highestCommittableIndex == Max({0} \cup { j \in (commitIndex[i]+1)..Len(log[i]) : 
                                                                    /\ log[i][j].term = currentTerm[i] 
                                                                    /\ log[i][j].contentType = TypeSignature
                                                                    /\ HasConsensusWatermark(j) })
        IN
         \* only advance if necessary (this is basically a sanity)
        /\ commitIndex[i] < highestCommittableIndex
        /\ commitIndex' = [commitIndex EXCEPT ![i] = highestCommittableIndex]
        \* If commit index surpasses the next configuration, pop configs, and retire as leader if removed
        /\ IF /\ Cardinality(DOMAIN configurations[i]) > 1
              /\ highestCommittableIndex >= NextConfigurationIndex(i)
           THEN
              LET new_configurations == RestrictDomain(configurations[i], 
                                            LAMBDA c : c >= LastConfigurationToIndex(i, highestCommittableIndex))
              IN
              /\ configurations' = [configurations EXCEPT ![i] = new_configurations]
              \* Retire if i is not in active configuration anymore
              /\ IF i \notin configurations[i][Min(DOMAIN configurations'[i])]
                 THEN \E j \in PlausibleSucessorNodes(i) :
                    /\ membershipState' = [membershipState EXCEPT ![i] = RetirementCompleted]
                    \* TODO: implementation steps down to None instead of Follower
                    /\ leadershipState' = [leadershipState EXCEPT ![i] = Follower]
                    /\ LET msg == [type          |-> ProposeVoteRequest,
                                    term          |-> currentTerm[i],
                                    source        |-> i,
                                    dest          |-> j ]
                        IN Send(msg)
                    /\ UNCHANGED <<currentTerm, votedFor>>
                 \* Otherwise, states remain unchanged
                 ELSE UNCHANGED <<messages, serverVars>>
           \* Otherwise, Configuration and states remain unchanged
           ELSE UNCHANGED <<messages, serverVars, reconfigurationVars, leadershipState>>
    /\ UNCHANGED <<candidateVars, leaderVars, log, removedFromConfiguration>>

\* CCF supports checkQuorum which enables a leader to choose to abdicate leadership.
CheckQuorum(i) ==
    \* Check node is a leader (and therefore has not completed retirement)
    /\ leadershipState[i] = Leader
    /\ leadershipState' = [leadershipState EXCEPT ![i] = Follower]
    /\ UNCHANGED <<reconfigurationVars, messageVars, currentTerm, votedFor, candidateVars, leaderVars, logVars, membershipState>>

------------------------------------------------------------------------------
\* Message handlers
\* i = recipient, j = sender, m = message

\* Server i receives a RequestVote request from server j with
\* m.term <= currentTerm[i].
\* Note that nodes can reply to RequestVotes even if they have completed retirement
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
       /\ UNCHANGED <<reconfigurationVars, leadershipState, currentTerm, 
        candidateVars, leaderVars, logVars, membershipState>>

\* Server i receives a RequestVote response from server j with
\* m.term = currentTerm[i].
HandleRequestVoteResponse(i, j, m) ==
    /\ m.term = currentTerm[i]
    \* Only Candidates need to tally votes
    /\ leadershipState[i] = Candidate
    /\ \/ /\ m.voteGranted
          /\ votesGranted' = [votesGranted EXCEPT ![i] =
                                  votesGranted[i] \cup {j}]
       \/ /\ ~m.voteGranted
          /\ UNCHANGED votesGranted
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, votedFor, leaderVars, 
        logVars, membershipState>>

\* Server i replies to a AppendEntries request from server j with a NACK
\* A NACK is sent if either:
\* (1) the leader's term is behind the follower's term 
\* (2) the follower log does not have the m.prevLogTerm at m.prevLogIndex
RejectAppendEntriesRequest(i, j, m, logOk) ==
    \* See recv_append_entries and send_append_entries_response in raft.h.
    /\ \/ /\ m.term < currentTerm[i]
          /\ Reply([type        |-> AppendEntriesResponse,
                 success        |-> FALSE,
                 term           |-> currentTerm[i],
                 lastLogIndex   |-> Len(log[i]),
                 source         |-> i,
                 dest           |-> j],
                 m)
       \/ /\ m.term >= currentTerm[i]
          /\ leadershipState[i] = Follower
          /\ ~logOk
          \* raft.h::send_append_entries_response:1348 AppendEntriesResponse messages with answer == FAIL set their term to the term of index
          \* for the last entry in the backup's log, not the term of the current leader
          /\ LET prevTerm == IF m.prevLogIndex = 0 THEN 0
                             ELSE IF m.prevLogIndex > Len(log[i]) THEN 0 ELSE log[i][Len(log[i])].term
             IN /\ m.prevLogTerm # prevTerm
                /\ \/ /\ prevTerm = 0
                      /\ Reply([type        |-> AppendEntriesResponse,
                             success        |-> FALSE,
                             term           |-> currentTerm[i],
                             lastLogIndex   |-> Len(log[i]),
                             source         |-> i,
                             dest           |-> j],
                             m)
                   \/ /\ prevTerm # 0
                      /\ LET lli == FindHighestPossibleMatch(log[i], m.prevLogIndex, m.term)
                         IN Reply([type        |-> AppendEntriesResponse,
                                success        |-> FALSE,
                                term           |-> IF lli = 0 THEN StartTerm ELSE log[i][lli].term,
                                lastLogIndex   |-> lli,
                                source         |-> i,
                                dest           |-> j],
                                m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, logVars, membershipState>>

\* Candidate i steps down to follower in the same term after receiving a message m from a leader in the current term
\* Must check that m is an AppendEntries message before returning to follower state
ReturnToFollowerState(i, m) ==
    /\ m.term = currentTerm[i]
    /\ leadershipState[i] = Candidate
    /\ leadershipState' = [leadershipState EXCEPT ![i] = Follower]
    \* Note that the set of message is unchanged as m is discarded
    /\ UNCHANGED <<reconfigurationVars, currentTerm, votedFor, logVars, 
        messages, membershipState>>

\* Follower i receives a AppendEntries from leader j for log entries it already has
AppendEntriesAlreadyDone(i, j, index, m) ==
    /\ \/ m.entries = << >>
       \/ /\ m.entries /= << >>
          /\ Len(log[i]) >= index + (Len(m.entries) - 1)
          /\ \A idx \in 1..Len(m.entries) :
                log[i][index + (idx - 1)].term = m.entries[idx].term
    \* See condition guards in commit() and commit_if_possible(), raft.h
    /\ LET newCommitIndex == max(min(MaxCommittableIndex(log[i]), m.commitIndex), commitIndex[i])
           newConfigurationIndex == LastConfigurationToIndex(i, newCommitIndex)
       IN /\ commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
          \* Pop any newly committed reconfigurations, except the most recent
          /\ configurations' = [configurations EXCEPT ![i] = RestrictDomain(@, LAMBDA c : c >= newConfigurationIndex)]
          \* Check if updating the commit index completes a pending retirement
          \* Note the node is already a follower so leadershipState remains unchanged
          /\ membershipState' = [membershipState EXCEPT ![i] = 
                IF membershipState = RetirementSigned /\ commitIndex' > RetirementIndex(i) 
                THEN RetirementCompleted 
                ELSE @]
    /\ Reply([type           |-> AppendEntriesResponse,
              term           |-> currentTerm[i],
              success        |-> TRUE,
              lastLogIndex   |-> m.prevLogIndex + Len(m.entries),
              source         |-> i,
              dest           |-> j],
              m)
    /\ UNCHANGED <<removedFromConfiguration, currentTerm, leadershipState, votedFor, log>>

\* Follower i receives an AppendEntries request m where it has conflicting entries
\* This action rolls back the log and leaves m in messages for further processing
ConflictAppendEntriesRequest(i, index, m) ==
    /\ m.entries /= << >>
    /\ Len(log[i]) >= index
    /\ log[i][index].term /= m.entries[1].term
    /\ LET new_log == [index2 \in 1..m.prevLogIndex |-> log[i][index2]] \* Truncate log
       IN /\ log' = [log EXCEPT ![i] = new_log]
          \* Potentially also shorten the configurations if the removed txns contained reconfigurations
          /\ configurations' = [configurations EXCEPT ![i] = ConfigurationsToIndex(i,Len(new_log))]
          /\ membershipState' = [membershipState EXCEPT ![i] = CalcMembershipState(log'[i], commitIndex[i], i)]
    /\ UNCHANGED <<removedFromConfiguration, currentTerm, leadershipState, votedFor, commitIndex, messages>>

\* Follower i receives an AppendEntries request m from leader j for log entries which directly follow its log
NoConflictAppendEntriesRequest(i, j, m) ==
    /\ m.entries /= << >>
    /\ Len(log[i]) = m.prevLogIndex
    /\ log' = [log EXCEPT ![i] = @ \o m.entries]
    \* If new txs include reconfigurations, add them to configurations
    \* Also, if the commitIndex is updated, we may pop some old configs at the same time
    /\ LET
        new_commit_index == max(min(MaxCommittableIndex(log'[i]), m.commitIndex), commitIndex[i])
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
        new_commmitted_configs == {c \in DOMAIN new_configs : c <= new_commit_index}
        new_conf_index == IF new_commmitted_configs = {} THEN 0 ELSE
            Max(new_commmitted_configs)
        new_retirement_index == RetirementIndexLog(log'[i],i)
        IN
        /\ commitIndex' = [commitIndex EXCEPT ![i] = new_commit_index]
        /\ configurations' = 
                [configurations EXCEPT ![i] = RestrictDomain(new_configs, LAMBDA c : c >= new_conf_index)]
        \* If we added a new configuration that we are in and were pending, we are now follower
        /\ IF /\ leadershipState[i] = None
              /\ \E conf_index \in DOMAIN(new_configs) : i \in new_configs[conf_index]
           THEN leadershipState' = [leadershipState EXCEPT ![i] = Follower ]
           ELSE UNCHANGED leadershipState
          \* Recalculate membership state based on log' and commitIndex'
          /\ membershipState' = [membershipState EXCEPT ![i] = CalcMembershipState(log'[i], commitIndex'[i], i)]
    /\ Reply([type           |-> AppendEntriesResponse,
              term           |-> currentTerm[i],
              success        |-> TRUE,
              lastLogIndex   |-> Len(log'[i]),
              source         |-> i,
              dest           |-> j],
              m)
    /\ UNCHANGED <<removedFromConfiguration, currentTerm, 
        votedFor>>

AcceptAppendEntriesRequest(i, j, logOk, m) ==
    \* accept request
    /\ m.term = currentTerm[i]
    /\ leadershipState[i] \in {Follower, None}
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
    /\ \/ /\ m.term = currentTerm[i]
          /\ leadershipState[i] = Leader \* Only Leaders need to tally append entries responses
          /\ m.success \* successful
          \* max(...) because why would we ever want to go backwards on a success response?!
          /\ matchIndex' = [matchIndex EXCEPT ![i][j] = max(@, m.lastLogIndex)]
          \* sentIndex is unchanged on successful AE response as it was already updated when the AE was dispatched
          /\ UNCHANGED sentIndex
       \/ /\ \lnot m.success \* not successful
          /\ LET tm == FindHighestPossibleMatch(log[i], m.lastLogIndex, m.term)
             IN sentIndex' = [sentIndex EXCEPT ![i][j] = max(min(tm, sentIndex[i][j]), matchIndex[i][j])]
          \* UNCHANGED matchIndex is implied by the following statement in figure 2, page 4 in the raft paper:
           \* "If AppendEntries fails because of log inconsistency: decrement nextIndex (aka sentIndex +1) and retry"
          /\ UNCHANGED matchIndex
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, logVars>>

\* Any message with a newer term causes the recipient to advance its term first.
\* Note that UpdateTerm does not discard message m from the set of messages so this 
\* message can be parsed again by the receiver. Note that all other message parsing actions should
\* check that m.term <= currentTerm[i] to ensure that this action is the only one ENABLED.
\* Analogous to raft.h::become_aware_of_new_term
UpdateTerm(i, j, m) ==
    /\ m.term > currentTerm[i]
    /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.term]
    \* See become_aware_of_new_term() in raft.h:1915
    /\ leadershipState' = [leadershipState EXCEPT ![i] = IF @ \in {Leader, Candidate, None} THEN Follower ELSE @]
    /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
    \* See rollback(last_committable_index()) in raft::become_follower
    /\ log'            = [log         EXCEPT ![i] = SubSeq(@, 1, LastCommittableIndex(i))]
    \* Potentially also shorten the configurations if the removed txns contained reconfigurations
    /\ configurations' = [configurations EXCEPT ![i] = ConfigurationsToIndex(i,Len(log'[i]))]
    \* If the leader was in the RetirementOrdered state, then its retirement has
    \* been rolled back as it was unsigned
    /\ membershipState' = [membershipState EXCEPT ![i] = 
        IF @ = RetirementOrdered THEN Active ELSE @]
    \* messages is unchanged so m can be processed further.
    /\ UNCHANGED <<removedFromConfiguration, messageVars, 
        candidateVars, leaderVars, commitIndex>>

\* Responses with stale terms are ignored.
DropStaleResponse(i, j, m) ==
    /\ m.term < currentTerm[i]
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, leaderVars,
        logVars, membershipState>>

DropResponseWhenNotInState(i, j, m) ==
    \/ /\ m.type = AppendEntriesResponse
       /\ leadershipState[i] \in LeadershipStates \ { Leader }
    \/ /\ m.type = RequestVoteResponse
       /\ leadershipState[i] \in LeadershipStates \ { Candidate }
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, leaderVars, logVars>>

\* Drop messages if they are irrelevant to the node
DropIgnoredMessage(i,j,m) ==
    \* Drop messages if...
    /\
       \* .. recipient is still None..
       \/ /\ leadershipState[i] = None
          \* .. and the message is anything other than an append entries request
          /\ m.type /= AppendEntriesRequest
       \*  OR if message is to a server that has surpassed the None stage ..
       \/ /\ leadershipState[i] /= None
        \* .. and it comes from a server outside of the configuration
          /\ \lnot IsInServerSet(j, i)
       \*  OR if recipient has completed retirement and this is not a request to vote or append entries request
       \* This spec requires that a retired node still helps with voting and appending entries to ensure 
       \* the next configurations learns that its retirement has been committed.
       \* TODO: the spec diverges from implementation here, in the implementation is seems that a 
       \* node stops helping with append entries (sends NACKs) if they pass its retirement_committable_idx
       \/ /\ membershipState[i] = RetirementCompleted
          /\ m.type \notin {RequestVoteRequest, AppendEntriesRequest}
    /\ Discard(m)
    /\ UNCHANGED <<reconfigurationVars, serverVars, candidateVars, leaderVars, logVars>>

\* Retired leaders send notify commit messages to update all nodes about the commit level
UpdateCommitIndex(i,j,m) ==
    /\ m.commitIndex > commitIndex[i]
    /\ LET
        new_config_index == LastConfigurationToIndex(i,m.commitIndex)
        new_configurations == RestrictDomain(configurations[i], LAMBDA c : c >= new_config_index)
        IN
        /\ commitIndex' = [commitIndex EXCEPT ![i] = m.commitIndex]
        /\ configurations' = [configurations EXCEPT ![i] = new_configurations]
    /\ UNCHANGED <<messages, currentTerm,
        votedFor, candidateVars, leaderVars, log, membershipState>>

\* Receive a message.

RcvDropIgnoredMessage(i, j) ==
    \* Drop any message that are to be ignored by the recipient
    \E m \in Network!MessagesTo(i, j) :
        /\ j = m.source
        /\ DropIgnoredMessage(m.dest,m.source,m)

RcvUpdateTerm(i, j) ==
    \* Any RPC with a newer term causes the recipient to advance
    \* its term first. Responses with stale terms are ignored.
    \E m \in Network!MessagesTo(i, j) : 
        /\ j = m.source
        /\ UpdateTerm(m.dest, m.source, m)

RcvRequestVoteRequest(i, j) ==
    \E m \in Network!MessagesTo(i, j) : 
        /\ j = m.source
        /\ m.type = RequestVoteRequest
        /\ HandleRequestVoteRequest(m.dest, m.source, m)

RcvRequestVoteResponse(i, j) ==
    \E m \in Network!MessagesTo(i, j) : 
        /\ j = m.source
        /\ m.type = RequestVoteResponse
        /\ \/ HandleRequestVoteResponse(m.dest, m.source, m)
           \/ DropResponseWhenNotInState(m.dest, m.source, m)
           \/ DropStaleResponse(m.dest, m.source, m)

RcvAppendEntriesRequest(i, j) ==
    \E m \in Network!MessagesTo(i, j) : 
        /\ j = m.source
        /\ m.type = AppendEntriesRequest
        /\ HandleAppendEntriesRequest(m.dest, m.source, m)

RcvAppendEntriesResponse(i, j) ==
    \E m \in Network!MessagesTo(i, j) : 
        /\ j = m.source
        /\ m.type = AppendEntriesResponse
        /\ \/ HandleAppendEntriesResponse(m.dest, m.source, m)
           \/ DropResponseWhenNotInState(m.dest, m.source, m)
          \* CCF does not drop NACKs under the same conditions as ACKS, because it re-uses the term
          \* field as an optimisation to convey the term of the last matching entry. See #5927.
           \/ /\ m.success
              /\ DropStaleResponse(m.dest, m.source, m)

RcvProposeVoteRequest(i, j) ==
    \E m \in Network!MessagesTo(i, j) :
        /\ j = m.source
        /\ m.type = ProposeVoteRequest
        /\ m.term = currentTerm[i]
        /\ Timeout(m.dest)
        /\ Discard(m)

\* Node i receives a message from node j.
Receive(i, j) ==
    \/ RcvDropIgnoredMessage(i, j)
    \/ RcvUpdateTerm(i, j)
    \/ RcvRequestVoteRequest(i, j)
    \/ RcvRequestVoteResponse(i, j)
    \/ RcvAppendEntriesRequest(i, j)
    \/ RcvAppendEntriesResponse(i, j)
    \/ RcvProposeVoteRequest(i, j)

\* End of message handlers.
------------------------------------------------------------------------------

\* During the model check, the model checker will search through all possible state transitions.
\* Each of these transitions has additional constraints that have to be fulfilled for the state to be an allowed step.
\* For example, ``BecomeLeader`` is only a possible step if the selected node has enough votes to do so.

\* Defines how the variables may transition, given an node i.
NextInt(i) ==
    \/ Timeout(i)
    \/ BecomeLeader(i)
    \/ ClientRequest(i)
    \/ SignCommittableMessages(i)
    \/ ChangeConfiguration(i)
    \/ AdvanceCommitIndex(i)
    \/ CheckQuorum(i)
    \/ \E j \in Servers : RequestVote(i, j)
    \/ \E j \in Servers : AppendEntries(i, j)
    \/ \E j \in Servers : Receive(i, j)

Next ==
    \E i \in Servers: NextInt(i)

\* The specification must start with the initial state and transition according
\* to Next.
Spec == 
    /\ Init
    /\ [][Next]_vars
    \* Network actions
    /\ \A i, j \in Servers : WF_vars(RcvDropIgnoredMessage(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvUpdateTerm(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvRequestVoteRequest(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvRequestVoteResponse(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvAppendEntriesRequest(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvAppendEntriesResponse(i, j))
    /\ \A i, j \in Servers : WF_vars(RcvProposeVoteRequest(i, j))
    \* Node actions
    /\ \A s, t \in Servers : WF_vars(AppendEntries(s, t))
    /\ \A s, t \in Servers : WF_vars(RequestVote(s, t))
    /\ \A s \in Servers : WF_vars(SignCommittableMessages(s))
    /\ \A s \in Servers : WF_vars(AdvanceCommitIndex(s))
    /\ \A s \in Servers : WF_vars(BecomeLeader(s))
    /\ \A s \in Servers : WF_vars(Timeout(s))

------------------------------------------------------------------------------
\* Correctness invariants
\* These invariants should be true for all possible states

\* Committed log entries should never conflict between servers
LogInv ==
    \A i, j \in Servers :
        \/ IsPrefix(Committed(i),Committed(j)) 
        \/ IsPrefix(Committed(j),Committed(i))

\* Note that LogInv checks for safety violations across space
\* This is a key safety invariant and should always be checked
THEOREM Spec => []LogInv

\* There is only ever one leader per term.  However, this does not preclude multiple
\* servers being leader at the same time, i.e., |{s \in Servers: leadershipState[s] = Leader}| > 1,
\* as long as each server is leader in a different term.
\*
\* However, this invariant is not violated if two servers *atomically* trade places as
\* leader in the same term, i.e., leadershipState' = [leadershipState EXCEPT ![s] = Follower, ![t] = Leader]
\* with leadershipState[s]=Leader /\ leadershipState[t]#Leader.  For that, we would need a suitable action
\* property.
MoreThanOneLeaderInv ==
    \A i,j \in Servers :
        (/\ currentTerm[i] = currentTerm[j]
         /\ leadershipState[i] = Leader
         /\ leadershipState[j] = Leader)
        => i = j

\* If a candidate has a chance of being elected, there
\* are no log entries with that candidate's term
CandidateTermNotInLogInv ==
    \A i \in Servers :
        (/\ leadershipState[i] = Candidate
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
        leadershipState[i] = Leader =>
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
        configurations[i] # << >> =>
            \A S \in Quorums[CurrentConfiguration(i)] :
                \E j \in S :
                    IsPrefix(Committed(i), log[j])

\* True if server i could receive a vote from server j based on the up-to-date check
\* The "up-to-date" check performed by servers before issuing a vote implies that i receives
\* a vote from j only if i has all of j's committed entries
UpToDateCheck(i, j) ==
    \/ MaxCommittableTerm(log[i]) > MaxCommittableTerm(log[j])
    \/ /\ MaxCommittableTerm(log[i]) = MaxCommittableTerm(log[j])
       /\ MaxCommittableIndex(log[i]) >= MaxCommittableIndex(log[j])

\* If a server i might request a vote from j, receives it and counts it then i 
\* has all of j's committed entries
\* This is not an invariant, it is possible for j to vote for i despite i not
\* having all of j's committed entries. What isn't possible is for i to win
\* an election without having all of j's committed entries.
DebugMoreUpToDateCorrectInv ==
    \A i \in { s \in Servers : leadershipState[s] = Candidate } :
        \A j \in GetServerSet(i) :
            /\ i /= j 
            /\ UpToDateCheck(i, j)
            => IsPrefix(Committed(j), log[i])

\* The committed entries in every log are a prefix of the
\* leader's log up to the leader's term (since a next Leader may already be
\* elected without the old leader stepping down yet)
LeaderCompletenessInv ==
    \A i \in Servers :
        leadershipState[i] = Leader =>
        \A j \in Servers : i /= j =>
            IsPrefix(CommittedTermPrefix(j, currentTerm[i]),log[i])

\* In CCF, only signature messages should ever be committed
SignatureInv ==
    \A i \in Servers :
        commitIndex[i] > 0 => log[i][commitIndex[i]].contentType = TypeSignature

\* Each server's term should be equal to or greater than the terms of messages it has sent
MonoTermInv ==
    \A m \in Network!Messages: currentTerm[m.source] >= m.term

\* Terms in logs increase monotonically. When projecting out TypeSignature entries, the 
\* terms even increase in a *strictly* monotonic manner.
MonoLogInv ==
    \A i \in Servers :
       log[i] # <<>> => 
           /\ Last(log[i]).term <= currentTerm[i]
           /\ \A k \in 1..Len(log[i])-1 :
                \* Terms in logs should only increase after a signature
                \/ log[i][k].term = log[i][k+1].term
                \/ /\ log[i][k].term < log[i][k+1].term
                   /\ log[i][k].contentType = TypeSignature

\* Each server's active configurations should be consistent with its own log and commit index
LogConfigurationConsistentInv ==
    \A i \in Servers :
        \/ leadershipState[i] = None
        \* Follower, but no known configurations yet
        \/ /\ leadershipState[i] = Follower
           /\ Cardinality(DOMAIN configurations[i]) = 0
        \/
            \* Configurations should have associated reconfiguration txs in the log
            /\ \A idx \in DOMAIN (configurations[i]) : 
                /\ log[i][idx].contentType = TypeReconfiguration            
                /\ log[i][idx].configuration = configurations[i][idx]
            \* Pending configurations should not be committed yet
            /\ Cardinality(DOMAIN configurations[i]) > 1 
                => commitIndex[i] < NextConfigurationIndex(i)
            \* There should be no committed reconfiguration txs since current configuration
            /\ commitIndex[i] > CurrentConfigurationIndex(i)
                => \A idx \in CurrentConfigurationIndex(i)+1..commitIndex[i] :
                    log[i][idx].contentType # TypeReconfiguration
            \* \* There should be no uncommitted reconfiguration txs except pending configurations
            /\ Len(log[i]) > commitIndex[i]
                => \A idx \in commitIndex[i]+1..Len(log[i]) :
                    log[i][idx].contentType = TypeReconfiguration 
                    => configurations[i][idx] = log[i][idx].configuration

\* Check each node's retirement phase is consistent with its local state
MembershipStateConsistentInv ==
    \A i \in Servers :
        \/ /\ membershipState[i] = Active 
           /\ RetirementIndex(i) = 0
        \* RetirementOrdered - node's retirement in its log
        \/ /\ membershipState[i] = RetirementOrdered 
           /\ RetirementIndex(i) # 0
        \* RetirementSigned - node' retirement is signed 
        \/ /\ membershipState[i] = RetirementSigned
           /\ RetirementIndex(i) # 0
           /\ RetirementIndex(i) <= MaxCommittableIndex(log[i])
        \* RetirementCompleted - node's retired is committed
        \/ /\ membershipState[i] = RetirementCompleted
           /\ RetirementIndex(i) # 0
           /\ RetirementIndex(i) <= commitIndex[i]
           /\ leadershipState[i] \notin {Candidate, Leader}

NoLeaderBeforeInitialTerm ==
    \A i \in Servers :
        currentTerm[i] < StartTerm => leadershipState[i] # Leader

\* MatchIndexLowerBoundNextIndexInv is not currently an invariant but 
\* we might wish to add it in the future. This could be achieved by updating 
\* nextIndex to max of current nextIndex and matchIndex when an AE ACK is received.
MatchIndexLowerBoundSentIndexInv ==
    \A i,j \in Servers :
        leadershipState[i] = Leader =>
            sentIndex[i][j] >= matchIndex[i][j]

CommitCommittableIndices ==
    \A i \in Servers :
        \/
            /\ commitIndex[i] = 0
            /\ CommittableIndices(i) = {}
        \/ commitIndex[i] \in CommittableIndices(i)

------------------------------------------------------------------------------
\* Properties

\* Each server's committed log is append-only
CommittedLogAppendOnlyProp ==
    [][\A i \in Servers :
        IsPrefix(Committed(i), Committed(i)')]_vars

\* Note that CommittedLogAppendOnlyProp checks for safety violations across time
\* This is a key safety invariant and should always be checked
THEOREM Spec => CommittedLogAppendOnlyProp

\* Each server's commit index is monotonically increasing
\* This is weaker form of CommittedLogAppendOnlyProp so it is not checked by default
MonotonicCommitIndexProp ==
    [][\A i \in Servers :
        commitIndex[i]' >= commitIndex[i]]_vars

MonotonicTermProp ==
    [][\A i \in Servers :
        currentTerm[i]' >= currentTerm[i]]_vars

MonotonicMatchIndexProp ==
    \* Figure 2, page 4 in the raft paper:
     \* "Volatile state on leaders, reinitialized after election. For each server,
     \*  index of the highest log entry known to be replicated on server. Initialized
     \*  to 0, increases monotonically".  In other words, matchIndex never decrements
     \* unless the current action is a node becoming leader.
    [][(~ \E i \in Servers: <<BecomeLeader(i)>>_vars) => 
            (\A i,j \in Servers : matchIndex[i][j]' >= matchIndex[i][j])]_vars

PermittedLogChangesProp ==
    [][\A i \in Servers :
        log[i] # log[i]' =>
            \/ leadershipState[i]' = None
            \/ leadershipState[i]' = Follower
            \* Established leader adding new entries
            \/ /\ leadershipState[i] = Leader
               /\ leadershipState[i]' = Leader
               /\ IsPrefix(log[i], log[i]')
            \* Newly elected leader is truncating its log
            \/ /\ leadershipState[i] = Candidate
               /\ leadershipState[i]' = Leader
               /\ log[i]' = Committable(i)
        ]_vars

StateTransitionsProp ==
    [][\A i \in Servers :
        /\ leadershipState[i] = None => leadershipState[i]' \in {None, Follower}
        /\ leadershipState[i] = Follower => leadershipState[i]' \in {Follower, Candidate}
        /\ leadershipState[i] = Candidate => leadershipState[i]' \in {Follower, Candidate, Leader}
        /\ leadershipState[i] = Leader => leadershipState[i]' \in {Follower, Leader}
        ]_vars

MembershipStateTransitionsProp ==
    [][\A i \in Servers :
        \* RetirementCompleted is the terminal state
        membershipState[i] = RetirementCompleted 
        => membershipState[i]' = RetirementCompleted]_vars
        \* Note that all other transitions between retirement phases are permitted
        \* For instance, a node could go from Active to RetirementCompleted in one step if it 
        \* receives an append entries with its retirement signed and committed

PendingBecomesFollowerProp ==
    \* A pending node that becomes aware it is part of a configuration immediately transitions to Follower.
    [][\A s \in { s \in Servers : leadershipState[s] = None } : 
            s \in GetServerSet(s)' => 
                leadershipState[s]' = Follower]_vars

\* Raft Paper section 5.4.2: "[A leader] never commits log entries from previous terms...".
NeverCommitEntryPrevTermsProp ==
    [][\A i \in { s \in Servers : leadershipState[s] = Leader }:
        \* If the commitIndex of a leader changes, the log entry's term that the new commitIndex
        \* points to equals the leader's term.
        commitIndex'[i] > commitIndex[i] => log[i][commitIndex'[i]].term = currentTerm'[i] ]_vars

LogMatchingProp ==
    \A i, j \in Servers : []<>(log[i] = log[j])

LeaderProp ==
    []<><<\E i \in Servers : leadershipState[i] = Leader>>_vars

------------------------------------------------------------------------------
\* Debugging invariants
\* These invariants should give error traces and are useful for debugging to see if important situations are possible
\* These invariants are not checked unless specified in the .cfg file

\* This invariant is false with checkQuorum enabled but true with checkQuorum disabled
DebugInvLeaderCannotStepDown ==
    \A m \in Network!Messages :
        /\ m.type = AppendEntriesRequest
        /\ currentTerm[m.source] = m.term
        => leadershipState[m.source] = Leader

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
    Network!Messages # {} ~> Network!Messages = {}

\* The Retirement state is reached by nodes that are removed from the configuration.
\* It should be reachable if any node is removed.
DebugInvRetirementReachable ==
    \A i \in Servers : membershipState[i] /= RetirementCompleted

\* The Leader may send any number of entries per AppendEntriesRequest.  This spec assumes that
 \* the Leader only sends zero or one entries.
DebugAppendEntriesRequests ==
    \A m \in { m \in Network!Messages: m.type = AppendEntriesRequest } :
        Len(m.entries) <= 1

\* The following is an invariant of Multi-Paxos but is not an invariant of Raft
\* DebugCommittedEntriesTermsInv states that if a log entry is committed, then there should 
\* not be conflicting entries from higher terms.
\* In Raft, this situation can occur, following a fork, when a leader commits entries from a previous term.
\* This is safe because the leader will only commit a log entry from a previous term after sealing it
\* with a committed log entry from the current term
\* See https://dl.acm.org/doi/abs/10.1145/3380787.3393681 for further details
DebugCommittedEntriesTermsInv ==
    \A i, j \in Servers :
        \A k \in DOMAIN log[i] \intersect DOMAIN log[j] :
            k <= commitIndex[i]
            => log[i][k].term >= log[j][k].term

===============================================================================