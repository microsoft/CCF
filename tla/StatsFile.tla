---- MODULE StatsFile----
EXTENDS TLC, Json, Sequences, Naturals

\* Filename to write TLC stats to
CONSTANT StatsFilename
ASSUME StatsFilename \in STRING

\* Filename to write TLC coverage to
CONSTANT CoverageFilenamePrefix
ASSUME CoverageFilenamePrefix \in STRING


\* Writes TLC stats (such as number of states and duration) to StatsFilename in ndJson format
\* Specify WriteStatsFile as a postcondition to write the stats file at the end of model checking
WriteStatsFile == 
    /\ PrintT("Writing stats to file: " \o StatsFilename)
    /\ ndJsonSerialize(StatsFilename, <<TLCGet("stats")>>)

\* Writes TLC coverage to CoverageFilenamePrefix_coverage_*.json in ndJson format
SerialiseCoverageConstraint ==
    LET interval == 500000
    IN IF TLCGet("distinct") % interval = 0 THEN ndJsonSerialize(CoverageFilenamePrefix \o "_coverage_" \o ToString(TLCGet("distinct") \div interval) \o ".json", <<TLCGet("spec")>>) ELSE TRUE

====