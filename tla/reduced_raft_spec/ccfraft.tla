--------------------------------- MODULE ccfraft ---------------------------------
\* This is the formal specification for the Raft consensus algorithm.
\*
\* Copyright 2014 Diego Ongaro.
\* This work is licensed under the Creative Commons Attribution-4.0
\* International License https://creativecommons.org/licenses/by/4.0/

\* Modified for CCF by Microsoft Research
\* Author of these modifications: Fritz Alder
\* Partially based on
\* - https://github.com/dricketts/raft.tla/blob/master/raft.tla
\* - https://github.com/jinlmsft/raft.tla/blob/master/raft.tla
\* - https://github.com/ongardie/raft.tla/blob/master/raft.tla

EXTENDS Naturals, FiniteSets, Sequences, TLC

\* The set of server IDs
CONSTANTS Server

\* Server states.
CONSTANTS Follower, Candidate, Leader

\* A reserved value.
CONSTANTS Nil

\* Message types:
CONSTANTS RequestVoteRequest, RequestVoteResponse,
          AppendEntriesRequest, AppendEntriesResponse

\* CCF: Content types (Normal message or signature that signs
\*      previous messages)
CONSTANTS TypeEntry, TypeSignature

\* CCF: Limit on vote requests to be sent to each other node
CONSTANTS RequestVoteLimit

\* CCF: Limit how many messages each node can send to another
CONSTANTS MessagesLimit

CONSTANTS NodeOne, NodeTwo, NodeThree

----
\* Global variables

\* A set representing requests and responses sent from one server
\* to another. With CCF, we have message integrity and can ensure unique messages.
VARIABLE messages
\* CCF: Keep track of each message sent from each server to each other server
\* and cap it to a maximum
VARIABLE messagesSent
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
vars == <<messages, messagesSent, serverVars, candidateVars, leaderVars, logVars>>

----
\* Helpers

\* The set of all quorums. This just calculates simple majorities, but the only
\* important property is that every quorum overlaps with every other.
Quorum == {i \in SUBSET(Server) : Cardinality(i) * 2 > Cardinality(Server)}

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
            \/ xlog[y].contentType = TypeEntry
    ELSE 0
----
\* Define initial values for all variables

InitServerVars == /\ currentTerm = [i \in Server |-> 1]
                  /\ state       = [i \in Server |-> Follower]
                  /\ votedFor    = [i \in Server |-> Nil]
InitCandidateVars == /\ votesSent = [i \in Server |-> FALSE ]
                     /\ votesGranted   = [i \in Server |-> {}]
                     /\ votesRequested = [i \in Server |-> [j \in Server |-> 0]]
\* The values nextIndex[i][i] and matchIndex[i][i] are never read, since the
\* leader does not send itself messages. It's still easier to include these
\* in the functions.
InitLeaderVars == /\ nextIndex  = [i \in Server |-> [j \in Server |-> 1]]
                  /\ matchIndex = [i \in Server |-> [j \in Server |-> 0]]
InitLogVars == /\ log          = [i \in Server |-> << >>]
               /\ commitIndex  = [i \in Server |-> 0]
               /\ clientRequests = 1
               /\ committedLog = << >>
               /\ committedLogDecrease = FALSE
Init == /\ messages = {}
        /\ messagesSent = [i \in Server |-> [j \in Server |-> << >>] ]
        /\ InitServerVars
        /\ InitCandidateVars
        /\ InitLeaderVars
        /\ InitLogVars

----
\* Define state transitions

\* Server i times out and starts a new election.
Timeout(i) == /\ state[i] \in {Follower, Candidate}
              /\ state' = [state EXCEPT ![i] = Candidate]
              /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
              \* Most implementations would probably just set the local vote
              \* atomically, but messaging localhost for it is weaker.
              \*   CCF change: We do this atomically to reduce state space
              /\ votedFor' = [votedFor EXCEPT ![i] = i]
              /\ votesRequested' = [votesRequested EXCEPT ![i] = [j \in Server |-> 0]]
              /\ votesSent' = [votesSent EXCEPT ![i] = TRUE ]
              /\ votesGranted'   = [votesGranted EXCEPT ![i] = {i}]
              /\ UNCHANGED <<messages, messagesSent, leaderVars, logVars>>

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
    IN
    /\ state[i] = Candidate
    /\ votesRequested[i][j] < RequestVoteLimit
    /\ votesRequested' = [votesRequested EXCEPT ![i][j] = votesRequested[i][j] + 1]
    \* CCF change: Timeout votes for itself atomically. Thus we do not need to request our own vote.
    /\ i /= j
    /\ Send(msg)
    /\ UNCHANGED <<messagesSent, serverVars, votesGranted, leaderVars, logVars, votesSent>>

\* Leader i sends j an AppendEntries request containing up to 1 entry.
\* While implementations may want to send more than 1 at a time, this spec uses
\* just 1 because it minimizes atomic regions without loss of generality.
AppendEntries(i, j) ==
    /\ i /= j
    /\ state[i] = Leader
    /\ Len(log[i]) > 0
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
       \* Prevent sending unnecessary append entries messages
       /\ Len(log[i]) >= nextIndex[i][j]
       /\ IF Len(messagesSent[i][j]) >= index 
          THEN messagesSent[i][j][index] < MessagesLimit
          ELSE TRUE
       /\ messagesSent' =
            IF Len(messagesSent[i][j]) < index 
            THEN [messagesSent EXCEPT ![i][j] = Append(messagesSent[i][j], 1) ]
            ELSE [messagesSent EXCEPT ![i][j][index] = messagesSent[i][j][index] + 1 ]
       /\ Send(msg)
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
    /\ state[i] = Candidate
    /\ votesGranted[i] \in Quorum
    /\ state'      = [state EXCEPT ![i] = Leader]
    /\ nextIndex'  = [nextIndex EXCEPT ![i] =
                         [j \in Server |-> Len(log[i]) + 1]]
    /\ matchIndex' = [matchIndex EXCEPT ![i] =
                         [j \in Server |-> 0]]
    \* CCF: We reset our own log to its committable subsequence, throwing out
    \* all unsigned log entries of the previous leader.
    /\ log' = [log EXCEPT ![i] = SubSeq(log[i],1,MaxCommittableIndex(log[i]))]
    /\ UNCHANGED <<messages, messagesSent, currentTerm, votedFor, votesRequested, candidateVars, commitIndex, clientRequests, committedLog, committedLogDecrease>>

\* Leader i receives a client request to add v to the log.
ClientRequest(i) ==
    /\ state[i] = Leader
    /\ LET entry == [term  |-> currentTerm[i],
                     value |-> clientRequests,
              contentType  |-> TypeEntry]
           newLog == Append(log[i], entry)
       IN  /\ log' = [log EXCEPT ![i] = newLog]
           \* Make sure that each request is unique, reduce state space to be explored
           /\ clientRequests' = clientRequests + 1
    /\ UNCHANGED <<messages, messagesSent, serverVars, candidateVars,
                   leaderVars, commitIndex, committedLog, committedLogDecrease>>

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
        /\ UNCHANGED <<messages, messagesSent, serverVars, candidateVars, clientRequests,
                    leaderVars, commitIndex, committedLog, committedLogDecrease>>

\* Leader i advances its commitIndex.
\* This is done as a separate step from handling AppendEntries responses,
\* in part to minimize atomic regions, and in part so that leaders of
\* single-server clusters are able to mark entries committed.
AdvanceCommitIndex(i) ==
    /\ state[i] = Leader
    /\ LET \* The set of servers that agree up through index.
           Agree(index) == {i} \cup {k \in Server :
                                         matchIndex[i][k] >= index}
           \* The maximum indexes for which a quorum agrees
           agreeIndexes == {index \in 1..Len(log[i]) :
                \* CCF extension: Only count max indexes that are signatures.    
                Agree(index) \in Quorum /\ log[i][index].contentType = TypeSignature}
           \* New value for commitIndex'[i]
           newCommitIndex ==
              IF /\ agreeIndexes /= {}
                 /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
              THEN
                  Max(agreeIndexes)
              ELSE
                  commitIndex[i]
           newCommittedLog ==
              IF newCommitIndex > 1 THEN 
                  [ j \in 1..newCommitIndex |-> log[i][j] ] 
              ELSE 
                   << >>
       IN /\ commitIndex[i] < newCommitIndex \* only advance if necessary
          /\ commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
          /\ committedLogDecrease' = \/ ( newCommitIndex < Len(committedLog) )
                                     \/ \E j \in 1..Len(committedLog) : committedLog[j] /= newCommittedLog[j]
          /\ committedLog' = newCommittedLog
    /\ UNCHANGED <<messages, messagesSent, serverVars, candidateVars, leaderVars, log, clientRequests>>

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
       /\ UNCHANGED <<messagesSent, state, currentTerm, candidateVars, leaderVars, logVars>>

\* Server i receives a RequestVote response from server j with
\* m.mterm = currentTerm[i].
HandleRequestVoteResponse(i, j, m) ==
    \* This tallies votes even when the current state is not Candidate, but
    \* they won't be looked at, so it doesn't matter.
    /\ m.mterm = currentTerm[i]
    /\ \/ /\ m.mvoteGranted
          /\ votesGranted' = [votesGranted EXCEPT ![i] =
                                  votesGranted[i] \cup {j}]
          /\ UNCHANGED <<votesSent>>
       \/ /\ ~m.mvoteGranted
          /\ UNCHANGED <<votesSent, votesGranted>>
    /\ Discard(m)
    /\ UNCHANGED <<messagesSent, serverVars, votedFor, votesRequested, leaderVars, logVars>>

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
    /\ UNCHANGED <<messagesSent, serverVars, logVars>>

ReturnToFollowerState(i, m) ==
    /\ m.mterm = currentTerm[i]
    /\ state[i] = Candidate
    /\ state' = [state EXCEPT ![i] = Follower]
    /\ UNCHANGED <<messagesSent, currentTerm, votedFor, logVars, messages>>

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
    /\ UNCHANGED <<messagesSent, serverVars, log, clientRequests, committedLog, committedLogDecrease>>

ConflictAppendEntriesRequest(i, index, m) ==
    /\ m.mentries /= << >>
    /\ Len(log[i]) >= index
    /\ log[i][index].term /= m.mentries[1].term
    /\ LET new == [index2 \in 1..(Len(log[i]) - 1) |-> log[i][index2]]
       IN log' = [log EXCEPT ![i] = new]
    \* On conflicts, we shorten the log. This means we also want to reset the
    \*  sent messages that we track to limit the state space
    /\ LET newCounts == [j \in Server 
                |-> [n \in 1..Min({Len(messagesSent[i][j]) - 1, index - 1}) 
                |-> messagesSent[i][j][n]]]
       IN messagesSent' = [messagesSent EXCEPT ![i] = newCounts ]
    /\ UNCHANGED <<serverVars, commitIndex, messages, clientRequests, committedLog, committedLogDecrease>>

NoConflictAppendEntriesRequest(i, j, m) ==
    /\ m.mentries /= << >>
    /\ Len(log[i]) = m.mprevLogIndex
    /\ log' = [log EXCEPT ![i] = Append(log[i], m.mentries[1])]
    /\ Reply([mtype           |-> AppendEntriesResponse,
              mterm           |-> currentTerm[i],
              msuccess        |-> TRUE,
              mmatchIndex     |-> m.mprevLogIndex + Len(m.mentries),
              msource         |-> i,
              mdest           |-> j],
              m)
    /\ UNCHANGED <<messagesSent, serverVars, commitIndex, clientRequests, committedLog, committedLogDecrease>>

AcceptAppendEntriesRequest(i, j, logOk, m) ==
    \* accept request
    /\ m.mterm = currentTerm[i]
    /\ state[i] = Follower
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
    /\ UNCHANGED <<messagesSent, serverVars, candidateVars, logVars>>

\* Any RPC with a newer term causes the recipient to advance its term first.
UpdateTerm(i, j, m) ==
    /\ m.mterm > currentTerm[i]
    /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.mterm]
    /\ state'          = [state       EXCEPT ![i] = Follower]
    /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
       \* messages is unchanged so m can be processed further.
    /\ UNCHANGED <<messages, messagesSent, candidateVars, leaderVars, logVars>>

\* Responses with stale terms are ignored.
DropStaleResponse(i, j, m) ==
    /\ m.mterm < currentTerm[i]
    /\ Discard(m)
    /\ UNCHANGED <<serverVars, messagesSent, candidateVars, leaderVars, logVars>>

\* Receive a message.
Receive(m) ==
    LET i == m.mdest
        j == m.msource
    IN \* Any RPC with a newer term causes the recipient to advance
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
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars>>

----
\* Defines how the variables may transition.
Next == \/ \E i \in Server : Timeout(i)
        \/ \E i, j \in Server : RequestVote(i, j)
        \/ \E i \in Server : BecomeLeader(i)
        \/ \E i \in Server : ClientRequest(i)
        \/ \E i \in Server : SignCommittableMessages(i)
        \/ \E i \in Server : AdvanceCommitIndex(i)
        \/ \E i,j \in Server : AppendEntries(i, j)
        \/ \E m \in messages : Receive(m)
        \* \/ \E m \in messages : DropMessage(m)

\* The specification must start with the initial state and transition according
\* to Next.
Spec == Init /\ [][Next]_vars

\* The following are a set of verification by jinlmsft@hotmail.com
BothLeader( i, j ) == 
    /\ i /= j
    /\ currentTerm[i] = currentTerm[j]
    /\ state[i] = Leader
    /\ state[j] = Leader

MoreThanOneLeaderInv ==
    \lnot \E i, j \in Server :  BothLeader( i, j ) 
    
LogInv == \lnot committedLogDecrease

\* The following are a set of invariants by
\* https://github.com/dricketts/raft.tla/blob/master/raft.tla
(***************************************************************************)
(* The main safety proofs are below                                        *)
(***************************************************************************) 
----
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
\* Correctness invariants

\* The prefix of the log of server i that has been committed
Committed(i) == SubSeq(log[i],1,commitIndex[i])

\* The prefix of the log of server i up to term x
CommittedTermPrefix(i, x) == 
    \* Only if log of i is non-empty, and if there exists an entry up to the term x
    IF Len(log[i]) /= 0 /\ \E y \in DOMAIN log[i] : log[i][y].term <= x 
    THEN 
      \* then, we use the subsequence up to the maximum committed term of the leader
      LET maxTerm == (CHOOSE y \in DOMAIN log[i] : \A z \in DOMAIN log[i] : log[i][y].term >= log[i][z].term /\ y >= z)
      IN SubSeq(log[i], 1, Min({maxTerm, commitIndex[i]}))
    \* Otherwise the prefix is the empty tuple
    ELSE << >>
----
\* I believe that the election safety property in the Raft
\* paper is stronger than it needs to be and requires history
\* variables. The definition ElectionSafety is an invariant that
\* is strong enough without requiring history variables. First,
\* we state two properties which will allow us to conclude election
\* safety

\* All leaders have a quorum of servers who either voted
\* for the leader or have a higher term
LeaderVotesQuorumInv ==
    \A i \in Server :
        state[i] = Leader =>
        {j \in Server : currentTerm[j] > currentTerm[i] \/
                        (currentTerm[j] = currentTerm[i] /\ votedFor[j] = i)} \in Quorum

\* If a candidate has a chance of being elected, there
\* are no log entries with that candidate's term
CandidateTermNotInLogInv ==
    \A i \in Server :
        (/\ state[i] = Candidate
         /\ {j \in Server : currentTerm[j] = currentTerm[i] /\ votedFor[j] \in {i, Nil}} \in Quorum) =>
        \A j \in Server :
        \A n \in DOMAIN log[j] :
             log[j][n].term /= currentTerm[i]

\* A leader always has the greatest index for its current term (this does not 
\* mean all of its log will survive if it is not committed + signed yet)
ElectionSafetyInv ==
    \A i \in Server :
        state[i] = Leader =>
        \A j \in Server :
            MaxWithZero({n \in DOMAIN log[i] : log[i][n].term = currentTerm[i]}) >=
            MaxWithZero({n \in DOMAIN log[j] : log[j][n].term = currentTerm[i]})
----
\* Every (index, term) pair determines a log prefix
LogMatchingInv ==
    \A i, j \in Server :
        \A n \in (1..Len(log[i])) \cap (1..Len(log[j])) :
            log[i][n].term = log[j][n].term =>
            SubSeq(log[i],1,n) = SubSeq(log[j],1,n)
----
\* A leader has all committed entries in its log. This is expressed
\* by LeaderCompleteness below. The inductive invariant for
\* that property is the conjunction of LeaderCompleteness with the
\* other three properties below.

\* Votes are only granted to servers with logs
\* that are at least as up to date
\* However we limit this check to only apply while there is no leader selected
\* for the current term yet.
\* Otherwise, we run into issues with working leaders extending their log 
\* and throwing an error because they had voted for someone else earlier.
VotesGrantedInv ==
    \A i \in Server :
    \A j \in votesGranted[i] :
        /\ currentTerm[i] = currentTerm[j] 
        /\ \lnot \E l \in Server : (state[l] = Leader /\ currentTerm[l] = currentTerm[i])
        =>
        \* The following is a subtlety:
        \* Only the committed entries of j are
        \* a prefix of i's log, not the entire 
        \* log of j
        IsPrefix(Committed(j),log[i])

\* All committed entries are contained in the log
\* of at least one server in every quorum
QuorumLogInv ==
    \A i \in Server :
    \A S \in Quorum :
        \E j \in S :
            IsPrefix(Committed(i), log[j])
        
\* The "up-to-date" check performed by servers
\* before issuing a vote implies that i receives
\* a vote from j only if i has all of j's committed
\* entries
MoreUpToDateCorrectInv ==
    \A i, j \in Server :
       (\/ LastTerm(log[i]) > LastTerm(log[j])
        \/ /\ LastTerm(log[i]) = LastTerm(log[j])
           /\ Len(log[i]) >= Len(log[j])) =>
       IsPrefix(Committed(j), log[i])

\* The committed entries in every log are a prefix of the
\* leader's log up to the leader's term (since a next Leader may already be 
\* elected without the old leader stepping down yet)
LeaderCompletenessInv ==
    \A i \in Server :
        state[i] = Leader =>
        \A j \in Server :
            IsPrefix(CommittedTermPrefix(j, currentTerm[i]),log[i])


\* In CCF, only signature messages should ever be committed 
SignatureInv == 
    \A i \in Server :
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
\* - Added the following features to the model:
\*   - SignCommittableMessages: In CCF the leader signs the last messages which
\*     only makes them committed after this signature has been committed.
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