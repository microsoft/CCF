---------- MODULE SIMCoverageccfraft ----------
EXTENDS ccfraft, TLC, Integers, CSV, TLCExt

CONSTANTS
    NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive

Servers_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}

Baseline ==
    {<<"Next", 0..0, 0..0, 0..0>>}

Confs == 
    Baseline \cup
        ({"SIMNext"} \X {1..1, 1..10, 1..100} \X {201..201, 201..210, 201..300} \X {401..401, 401..410, 401..500})

VARIABLE conf

CCF == INSTANCE ccfraft

SIMCheckQuorum(i) ==
    /\ conf[1] # "Next" => RandomElement(1..1000) \in conf[3]
    /\ CCF!CheckQuorum(i)

SIMChangeConfigurationInt(i, newConfiguration) ==
    /\ conf[1] # "Next" => RandomElement(1..1000) \in conf[4]
    /\ CCF!ChangeConfigurationInt(i, newConfiguration)

SIMTimeout(i) ==
    /\ \/ RandomElement(1..1000) \in conf[2]
       \/ conf[1] # "Next"
       \* Always allow Timeout if no messages are in the network
       \* and no node is a candidate or leader.  Otherise, the system
       \* will deadlock if 1 # RandomElement(...).
       \/ /\ \A s \in Servers: state[s] \notin {Leader, Candidate}
          /\ Network!Messages = {}
    /\ CCF!Timeout(i)

SIMCoverageSpec ==
    /\ Init
    /\ conf \in Confs
    /\ [][UNCHANGED conf /\ Next]_<<vars, conf>>

------------------------------------------------------------------------------

CSVFile == "SIMCoverageccfraft_S" \o ToString(Cardinality(Servers)) \o ".csv"

CSVColumnHeaders ==
    "Spec#P#Q#R#reconfigurationCount#currentTerm#state#node"

ASSUME
    CSVRecords(CSVFile) = 0 => 
        CSVWrite(CSVColumnHeaders, <<>>, CSVFile)

StatisticsStateConstraint ==
    (TLCGet("level") > TLCGet("config").depth) =>
        TLCDefer(\A s \in Servers : CSVWrite("%1$s#%2$s#%3$s#%4$s#%5$s#%6$s#%7$s#%8$s",
                << conf[1], Cardinality(conf[2]), Cardinality(conf[3]), Cardinality(conf[4]), 
                   reconfigurationCount, currentTerm[s], state[s], s>>,
                CSVFile))
=============================================================================
