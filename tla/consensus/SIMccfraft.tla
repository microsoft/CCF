---------- MODULE SIMccfraft ----------
EXTENDS ccfraft, TLC, Integers, StatsFile, IOUtils, MCAliases

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
       \* and no node is a candidate or leader.  Otherise, the system
       \* will deadlock if 1 # RandomElement(...).
       \/ /\ \A s \in Servers: leadershipState[s] \notin {Leader, Candidate}
          /\ Network!Messages = {}
    /\ CCF!Timeout(i)

\* The state constraint  StopAfter  stops TLC after the alloted
\* time budget is up, unless TLC encounteres an error first.
StopAfter ==
    LET timeout == IF ("SIM_TIMEOUT" \in DOMAIN IOEnv) /\ IOEnv.SIM_TIMEOUT # "" THEN atoi(IOEnv.SIM_TIMEOUT) ELSE 1200
    (* The smoke test has a time budget of 20 minutes. *)
    IN TLCSet("exit", TLCGet("duration") > timeout)

DebugInvUpToDepth ==
    \* The following invariant causes TLC to terminate with a counterexample of length
    \* -depth after generating the first trace.
    TLCGet("level") < TLCGet("config").depth
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

## Repeatedly run TLC in simulation mode to shorten a counterexample (the depth parameter will consequtively be reduced based on the length of the previous counterexample).
$ echo 500 > depth.txt
## Loop while the depth.txt file exists and is not empty.
$ while [ -s depth.txt ];
    do 
        TS=$(date +%s) && tlc SIMccfraft -simulate -workers auto -depth $(cat depth.txt) -postcondition 'SIMPostCondition!SIMPostCondition' 2>&1 | tee SIMccfraft_TTrace_$TS.out && sleep 5; 
    done
