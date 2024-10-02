---- MODULE StatsFile----
EXTENDS TLC, Json, Sequences, Naturals, IOUtils

\* Filename to write TLC stats to
StatsFilename ==
    IF "StatsFileName" \in DOMAIN IOEnv
    THEN IOEnv.StatsFileName 
    ELSE Print("Found no env var StatsFileName.  Falling back to MCccfraft_stats.json.", "MCccfraft_stats.json")
ASSUME StatsFilename \in STRING

\* Filename to write TLC coverage to
CoverageFilename ==
    IF "CoverageFilename" \in DOMAIN IOEnv
    THEN IOEnv.CoverageFilename 
    ELSE Print("Found no env var CoverageFilename.  Falling back to MCccfraft_coverage.json.", "MCccfraft_coverage.json")
ASSUME CoverageFilename \in STRING

\* Writes TLC stats (such as number of states and duration) to StatsFilename in ndJson format
\* Specify WriteStatsFile as a postcondition to write the stats file at the end of model checking
WriteStatsFile == 
    /\ PrintT("Writing stats to file: " \o StatsFilename)
    /\ Serialize(<<TLCGet("stats")>>, StatsFilename, [format |-> "NDJSON", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "APPEND">>])

\* Append TLC coverage in ndJson format to file identified by CoverageFilename.  Create CoverageFilename if it does not exist.
SerializeCoverage ==
    Serialize(<<TLCGet("spec")>>, CoverageFilename, [format |-> "NDJSON", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "APPEND">>])

====
