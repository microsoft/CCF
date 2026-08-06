---------- MODULE SeededSIMccfraft_3N ----------
EXTENDS SIMccfraft, RaftSeeds_3N

SeededVars == <<seedId, vars>>

SeededInit == SeedInit

SeededNext ==
    /\ Next
    /\ UNCHANGED seedId

SeededSpec == SeededInit /\ [][SeededNext]_SeededVars

SeededView == SeededVars

=============================================================================
