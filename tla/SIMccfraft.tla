---------- MODULE SIMccfraft ----------
EXTENDS ccfraft, TLC, Integers

Servers_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}

----
Fail ==
    \/ \E i \in Servers : Timeout(i)
    \/ \E i \in Servers : \E c \in SUBSET(Servers) : ChangeConfiguration(i, c)
    \/ \E i \in Servers : CheckQuorum(i)

Forward ==
    \/ \E i, j \in Servers : RequestVote(i, j)
    \/ \E i \in Servers : BecomeLeader(i)
    \/ \E i \in Servers : ClientRequest(i)
    \/ \E i \in Servers : SignCommittableMessages(i)
    \/ \E i, j \in Servers : NotifyCommit(i,j)
    \/ \E i \in Servers : AdvanceCommitIndex(i)
    \/ \E i, j \in Servers : AppendEntries(i, j)
    \/ Receive

SIMNext ==
    \* To increase coverage, favor sub-actions during simulation that move the 
    \* system state forward.
    LET rnd == RandomElement(1..100)
    IN  IF rnd = 1 THEN Fail
        \* TODO Evaluating ENABLED Forward is a performance bottleneck. An upcoming
        \* TODO change in TLC should remove the need for ENABLED Forward.
        ELSE IF ENABLED Forward THEN Forward ELSE Fail

SIMSpec ==
    Init /\ [][SIMNext]_vars

\* The state constraint  StopAfter  stops TLC after the alloted
\* time budget is up, unless TLC encounteres an error first.
StopAfter ==
    (* The smoke test has a time budget of 5 minutes. *)
    TLCSet("exit", TLCGet("duration") > 300)

=============================================================================

------------------------------- MODULE SIMPostCondition -------------------------------
LOCAL INSTANCE TLC
LOCAL INSTANCE TLCExt
LOCAL INSTANCE FiniteSets
LOCAL INSTANCE Sequences
LOCAL INSTANCE IOUtils

SIMPostCondition ==
    IF CounterExample.state = {} THEN TRUE ELSE
        /\ PrintT("Length of counterexample: " \o ToString(Cardinality(CounterExample.state)))
        /\ Serialize(ToString(Cardinality(CounterExample.state)), 
                "depth.txt",
                [format |-> "TXT", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "TRUNCATE_EXISTING">>]
            ).exitValue = 0

=============================================================================

## Repeatedly run TLC in simulation mode to shorten a counterexample (the depth parameter will consequtively be reduced based on the length of the previous counterexample).
$ echo 500 > depth.txt
$ while true;
    do 
        TS=$(date +%s) DEPTH=$(cat depth.txt) && tlc SIMccfraft -simulate -workers auto -depth $DEPTH -postcondition 'SIMPostCondition!SIMPostCondition' -dumptrace tlc SIMccfraft-$TS.bin > SIMccfraft-$TS.out && sleep 5; 
    done