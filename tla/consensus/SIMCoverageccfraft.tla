
  $ wget https://nightly.tlapl.us/dist/tla2tools.jar
  $ wget https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar
  ## Run wiht as many workers as you like to parallelize the nested simulation runs (auto uses all your cores).
  $ java -jar tla2tools.jar -config SIMCoverageccfraft.tla SIMCoverageccfraft.tla -workers auto

----------------------------- MODULE SIMCoverageccfraft -----------------------------
EXTENDS TLC, Naturals, Sequences, IOUtils

CmdLine ==
    <<"sh", "-c",
    "java " \o
    "-XX:+UseParallelGC " \o
    "-Dtlc2.tool.impl.Tool.cdot=true " \o
    "-Dtlc2.tool.Simulator.extendedStatistics=true " \o
    "-jar tla2tools.jar " \o
    "-depth 1000 " \o
    "-simulate SIMccfraft.tla >> SIMCoverageccfraft.txt 2>&1">>

-----------------------------------------------------------------------------

VARIABLE c, d

Init ==
    /\ c \in [ R: {10, 1000}, C: {10, 1000}, Q: {10, 1000}, T: {10, 1000} ]
    /\ d = FALSE

Next ==
    /\ ~d
    /\ d' = TRUE
    /\ PrintT(<<"conf", c>>)
    /\ IOEnvExec(c, CmdLine).exitValue = 0
    /\ UNCHANGED c

=============================================================================
---- CONFIG SIMCoverageccfraft ----
INIT Init
NEXT Next
CHECK_DEADLOCK FALSE
====