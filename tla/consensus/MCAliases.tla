----- MODULE MCAliases -----
EXTENDS ccfraft

LOCAL INSTANCE TLCExt

srv == CHOOSE s \in Servers : [NextInt(s)]_vars
L == TypeReconfiguration :> "r" @@ TypeSignature :> "s" @@ TypeEntry :> "e"
S == CHOOSE f \in [ LeadershipStates -> {"▵", "▿", "▴", "○"} ] : IsInjective(f)
C == CHOOSE f \in [ Servers -> {"[0;30m", "[0;31m", "[0;32m", "[0;33m", "[0;34m"}]: IsInjective(f)
B == CHOOSE f \in [ Servers -> {"[47m", "[41m", "[42m", "[43m", "[44m"}]: IsInjective(f)
Colorize(server, str) == C[server] \o str \o "[0m"
ColorizeServer(server, prefix) == Colorize(server, prefix \o ToString(server))
ColorizeTerm(term) == "[0;3" \o ToString(term-2) \o "m"
StringifyLog(s) == FoldSeq(LAMBDA e, acc: acc \o ColorizeTerm(e.term) \o L[e.contentType] \o "[0m", "", log[s])

DebugAliasGlobals ==
    [
        \* Total number of leader elections, i.e.,  BecomeLeader actions.
        le  |-> TLCGetAndSet(8, +, IF \E s \in Servers: <<BecomeLeader(s)>>_vars THEN 1 ELSE 0, 1),
        \* Set of nodes that are blocked right now.
        blocked  |-> { s \in Servers : ~[NextInt(s)]_vars},
        \* Set of nodes that are active right now.
        cluster |-> { Colorize(s, ToString(s)) : s \in { s \in Servers : leadershipState[s] \in {Leader, Follower} } },
        \* Sequence showing which node is active when.
        tl  |-> TLCGetAndSet(9, LAMBDA o, v: o \o C[v] \o "▧" \o "[0m", CHOOSE i \in Servers: [NextInt(i)]_vars, "")
    ]

DebugAliasAggregates ==
    LET Cup(f, g) == Pointwise(f, g, \cup)
        Plus(f, g) == Pointwise(f, g, +) IN
    [
        \* Per Node (node-local):
            \* The set of nodes granting a vote to this node, ever.
            vg   |-> TLCGetAndSet(0, Cup, votesGranted, [s \in Servers |-> {}]),
            \* \* Set of messages received by or pending at a node.
            \*mr   |-> TLCGetAndSet(2,
            \*            LAMBDA o, v: [s \in Servers |-> o[s] \cup { m \in v : m.dest = s }],
            \*            Network!Messages, [s \in Servers |-> {}]),
            \* \* Total number of delivered/received messages per node (message is considered delivered if it is no longer in a node's inbox)
            rms  |-> TLCGetAndSet(3,
                        LAMBDA o, v: 
                            [ s \in Servers |-> o[s] + IF Len(v[s]) > Len(v'[s]) THEN Len(v[s]) - Len(v'[s]) ELSE 0 ], 
                        messages, [s \in Servers |-> 0]),
            \* \* Set of nodes, a node has ever voted for.
            vf   |-> TLCGetAndSet(4, 
                        LAMBDA o, v: 
                            [ s \in Servers |-> o[s] \cup IF v[s] = Nil THEN {} ELSE {v[s]} ],
                        votedFor, [s \in Servers |-> {}]),
            \* Sequence of state transitions of this node.
            st   |-> TLCGetAndSet(5, 
                        LAMBDA o, v: 
                            [ s \in Servers |-> IF IsSuffix(<<v[s]>>, o[s]) 
                                                THEN o[s] 
                                                ELSE o[s] \o <<TLCGet("level")', v[s]>>],
                        leadershipState, [s \in Servers |-> <<>>]),
            ss   |-> TLCGetAndSet(6, 
                        LAMBDA o, v: [s \in Servers |-> o[s] \o C[s] \o S[v[s]] \o "[0m"],
                        leadershipState, [s \in Servers |-> ""])
            \* Times at which this node is active (this becomes unwidely for longer traces).
            \*ta   |-> TLCGetAndSet(7, 
            \*            LAMBDA o, v: [ o EXCEPT ![v] = @ \cup {TLCGet("level")} ],
            \*            CHOOSE i \in Servers: NextOfI(i), [s \in Servers |-> {}]),
    ]

DebugAliasVars ==
    [
        preVoteStatus |-> preVoteStatus,
        configurations |-> configurations,
        messages |-> messages,
        currentTerm |-> currentTerm,
        leadershipState |-> leadershipState,
        membershipState |-> membershipState,
        votedFor |-> votedFor,
        hasJoined |-> hasJoined,
        \* More compact visualization of the log.  
        lg |-> [ s \in Servers |-> StringifyLog(s) ],
        \*log |-> log,
        commitIndex |-> commitIndex,
        votesGranted |-> votesGranted,
        sentIndex |-> sentIndex,
        matchIndex |-> matchIndex,
        retirementCompleted |-> retirementCompleted,
        _MessagesTo |-> [ s, t \in Servers |-> Network!MessagesTo(s, t) ]
    ]

DebugAlias ==
    \*[ _format |-> B[srv] \o "/\\[0m %1$s = %2$s\n" ]
    \*  @@
    \*DebugAliasAggregates
    \*  @@
    DebugAliasGlobals
      @@
    DebugAliasVars

\* Print only the state of the acting server in that state.
DebugActingServerAlias ==
    [
        \* Comment this format in VSCode because it breaks its parser. :-()
        _format |-> B[srv] \o "/\\[0m %1$s = %2$s\n",
        srv |-> srv,
        configurations |-> configurations[srv],
        currentTerm |-> currentTerm[srv],
        votedFor |-> votedFor[srv],
        leadershipState |-> leadershipState[srv],
        log |-> StringifyLog(srv),
        commitIndex |-> commitIndex[srv],
        votesGranted |-> votesGranted[srv],
        sentIndex |-> sentIndex[srv],
        matchIndex |-> matchIndex[srv]
    ]

\* $ tput rmam ; tlc -note -simulate SIMccfraft.tla; tput smam  ## tput rmam/smam disables/enables line breaks.
\* $ tput rmam ; tlc -note -simulate SIMccfraft.tla -continue; tput smam  ## Run forever while eye-balling the output.
AnimateLogAndStateAlias ==
    \* ...overwrite tells TLC to overwrite the previous state instead of printing a new one.
    IF TLCSet("-Dtlc2.output.StatePrinter.overwrite", 150 (*in milliseconds*))
    THEN
        DebugAliasGlobals
        @@
        FoldSet(LAMBDA s, rcd: rcd @@ ColorizeServer(s, "log_") :> StringifyLog(s), <<>>, Servers)
        @@
        FoldSet(LAMBDA s, rcd: rcd @@ ColorizeServer(s, "ste_") :>
            ToString(leadershipState[s]) \o " " \o ToString(currentTerm[s]), <<>>, Servers)
    ELSE <<>>

=============================================================================