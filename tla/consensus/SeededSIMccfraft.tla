---------- MODULE SeededSIMccfraft ----------
EXTENDS SIMccfraft, RaftSeeds

SeededVars == <<seedId, vars>>

SeededInit == SeedInit

SeededNext ==
    /\ Next
    /\ UNCHANGED seedId

SeededSpec == SeededInit /\ [][SeededNext]_SeededVars

SeededView == SeededVars

=============================================================================
