---- MODULE StatsFile----
EXTENDS TLC, Json, Sequences, Naturals, IOUtils

\* Filename to write TLC stats to
CONSTANT StatsFilename
ASSUME StatsFilename \in STRING

\* Filename to write TLC coverage to
CONSTANT CoverageFilename
ASSUME CoverageFilename \in STRING


\* Writes TLC stats (such as number of states and duration) to StatsFilename in ndJson format
\* Specify WriteStatsFile as a postcondition to write the stats file at the end of model checking
WriteStatsFile == 
    /\ PrintT("Writing stats to file: " \o StatsFilename)
    /\ ndJsonSerialize(StatsFilename, <<TLCGet("stats")>>)

\* Append TLC coverage in ndJson format to file identified by CoverageFilename.  Create CoverageFilename if it does not exist.
SerialiseCoverage ==
    /\ PrintT("Writing coverage to file: " \o CoverageFilename)
    /\ Serialize(<<TLCGet("spec")>>, CoverageFilename, [format |-> "NDJSON", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "APPEND">>])

====
