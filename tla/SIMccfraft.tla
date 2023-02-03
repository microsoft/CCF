---------- MODULE SIMccfraft ----------
EXTENDS ccfraft, TLC, Integers

Servers_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}

----

CC ==
    \E i \in Servers :
        \E c \in SUBSET(Servers \ removedFromConfiguration) :
            ChangeConfiguration(i, c)

CQ ==
    \E i \in Servers : CheckQuorum(i)

TO ==
    \E i \in Servers : Timeout(i)

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
    LET rnd == RandomElement(1..1000)
    IN  \* TODO Evaluating ENABLED A is a performance bottleneck. An upcoming
        \* TODO change in TLC should remove the need for ENABLED A.
        CASE rnd = 1        /\ ENABLED TO -> TO
          [] rnd = 2        /\ ENABLED CQ -> CQ
          [] rnd \in 10..20 /\ ENABLED CC -> CC
          [] OTHER -> IF ENABLED Forward THEN Forward ELSE Next

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
## Loop while the depth.txt file exists and is not empty.
$ while [ -s depth.txt ];
    do 
        TS=$(date +%s) && tlc SIMccfraft -simulate -workers auto -depth $(cat depth.txt) -postcondition 'SIMPostCondition!SIMPostCondition' 2>&1 | tee SIMccfraft_TTrace_$TS.out && sleep 5; 
    done
