---------- MODULE SIMCoverageccfraft ----------
EXTENDS SIMccfraft, TLC, Integers, CSV, TLCExt

Baseline ==
    {<<"Next", 0..0, 0..0, 0..0>>}

Confs == 
    Baseline \cup
        ({"SIMNext"} \X {1..1, 1..10, 1..100} \X {201..201, 201..210, 201..300} \X {401..401, 401..410, 401..500})

VARIABLE conf

SIMCoverageNext ==
    \* To increase coverage, favor sub-actions during simulation that move the 
    \* system state forward.
    LET rnd == RandomElement(1..1000)
        \* TODO Evaluating ENABLED is a performance bottleneck. An upcoming
        \* TODO change in TLC should remove the need for ENABLED to prevent
        \* TODO deadlocks.
        \* An orthogonal problem is that TLC does not split the next-state
        \* relation into multiple Action instances, which would allow us to
        \* collect sub-action level statistics to assess coverage. With SIMNext,
        \* TLC's statistics reports only the number of SIMNext steps in behaviors.
    IN
        CASE rnd \in conf[2] /\ ENABLED TO -> TO
          [] rnd \in conf[3] /\ ENABLED CQ -> CQ
          [] rnd \in conf[4] /\ ENABLED CC -> CC
          [] OTHER -> IF ENABLED Forward THEN Forward ELSE Next

SIMCoverageSpec ==
    /\ Init
    /\ conf \in Confs
    /\ [][UNCHANGED conf /\ IF conf[1] = "SIMNext" THEN SIMCoverageNext ELSE Next]_<<vars, conf>>

------------------------------------------------------------------------------

CSVFile == "SIMCoverageccfraft_S" \o ToString(Cardinality(Servers)) \o ".csv"

CSVColumnHeaders ==
    "Spec#P#Q#R#reconfigurationCount#committedLog#clientRequests#commitsNotified11#commitsNotified12#currentTerm#state#node"

ASSUME
    CSVRecords(CSVFile) = 0 => 
        CSVWrite(CSVColumnHeaders, <<>>, CSVFile)

StatisticsStateConstraint ==
    (TLCGet("level") > TLCGet("config").depth) =>
        TLCDefer(\A srv \in Servers : CSVWrite("%1$s#%2$s#%3$s#%4$s#%5$s#%6$s#%7$s#%8$s#%9$s#%10$s#%11$s#%12$s",
                << conf[1], Cardinality(conf[2]), Cardinality(conf[3]), Cardinality(conf[4]), 
                   reconfigurationCount, committedLog.index, clientRequests, 
                   commitsNotified[srv][1], commitsNotified[srv][2], 
                   currentTerm[srv], state[srv], srv>>,
                CSVFile))
=============================================================================
