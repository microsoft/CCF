---- MODULE StatsFile----
EXTENDS TLC, Json, Sequences

\* Filename to write TLC stats to
CONSTANT StatsFilename
ASSUME StatsFilename \in STRING

\* Writes TLC stats (such as number of states and duration) to StatsFilename in ndJson format
\* Specify WriteStatsFile as a postcondition to write the stats file at the end of model checking
WriteStatsFile == 
    /\ PrintT("Writing stats to file: " \o StatsFilename)
    /\ ndJsonSerialize(StatsFilename, <<TLCGet("stats")>>)

====