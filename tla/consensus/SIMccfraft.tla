---------- MODULE SIMccfraft ----------
EXTENDS ccfraft, TLC, Integers, IOUtils, MCAliases

CONSTANTS
    NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive

Servers_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}

----

CCF == INSTANCE ccfraft

SIMInitReconfigurationVars ==
    \* Start with all servers in the active configuration.
    \/ CCF!InitLogConfigServerVars(Servers, JoinedLog)
    \* Start with any subset of servers in the active configuration.
    \/ CCF!InitReconfigurationVars

SIMCheckQuorum(i) ==
    /\ 1 = RandomElement(1..10)
    /\ CCF!CheckQuorum(i)

SIMChangeConfigurationInt(i, newConfiguration) ==
    /\ 1 = RandomElement(1..100)
    /\ CCF!ChangeConfigurationInt(i, newConfiguration)

SIMTimeout(i) ==
    /\ \/ 1 = RandomElement(1..100)
       \* Always allow Timeout if no messages are in the network
       \* and no node is a candidate or leader.  Otherwise, the system
       \* will deadlock if 1 # RandomElement(...).
       \/ /\ \A s \in Servers: leadershipState[s] \notin {Leader, Candidate}
          /\ Network!Messages = {}
    /\ CCF!Timeout(i)

\* See https://github.com/tlaplus/tlaplus/issues/1039#issue-2574569206
\* for why we need to redefine the fairness constraint.
SIMFairness ==
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
    /\ \A s \in Servers : WF_vars(AppendRetiredCommitted(s))
    /\ \A s \in Servers : WF_vars(BecomeLeader(s))
    \* The following fairness conditions reference the original CCF actions
    \* and, thus, do not include the RandomElement conjunct.
    /\ \A s \in Servers : WF_vars(CCF!Timeout(s))
    /\ \A s \in Servers : 
        \E newConfiguration \in SUBSET(Servers) \ {{}}:
            WF_vars(CCF!ChangeConfigurationInt(s, newConfiguration))

\* The state constraint  StopAfter  stops TLC after the alloted
\* time budget is up, unless TLC encounters an error first.
StopAfter ==
    LET timeout == IF ("SIM_TIMEOUT" \in DOMAIN IOEnv) /\ IOEnv.SIM_TIMEOUT # "" THEN atoi(IOEnv.SIM_TIMEOUT) ELSE 1200
    (* The smoke test has a time budget of 20 minutes. *)
    IN TLCSet("exit", TLCGet("duration") > timeout)

DebugInvUpToDepth ==
    \* The following invariant causes TLC to terminate with a counterexample of length
    \* -depth after generating the first trace.
    TLCGet("level") < TLCGet("config").depth

----
\* Refinement

ABSExtend(i) == MappingToAbs!ExtendAxiom(i)
ABSCopyMaxAndExtend(i) == MappingToAbs!CopyMaxAndExtendAxiom(i)

=============================================================================

------------------------------- MODULE SIMPostCondition -------------------------------
LOCAL INSTANCE TLC
LOCAL INSTANCE TLCExt
LOCAL INSTANCE FiniteSets
LOCAL INSTANCE Sequences
LOCAL INSTANCE IOUtils
LOCAL INSTANCE Integers

SIMPostCondition ==
    IF CounterExample.state = {} THEN TRUE ELSE
        /\ PrintT("Length of counterexample: " \o ToString(Cardinality(CounterExample.state)))
        /\ Serialize(ToString(Cardinality(CounterExample.state) - 1), 
                "depth.txt",
                [format |-> "TXT", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "TRUNCATE_EXISTING">>]
            ).exitValue = 0

=============================================================================

## Repeatedly run TLC in simulation mode to shorten a counterexample (the depth parameter will successively be reduced based on the length of the previous counterexample).
$ echo 500 > depth.txt
## Loop while the depth.txt file exists and is not empty.
$ while [ -s depth.txt ];
    do 
        TS=$(date +%s) && tlc SIMccfraft -simulate -workers auto -depth $(cat depth.txt) -postcondition 'SIMPostCondition!SIMPostCondition' 2>&1 | tee SIMccfraft_TTrace_$TS.out && sleep 5; 
    done
