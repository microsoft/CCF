---- MODULE DRConsistency ----

EXTENDS MulitNodeConsistency

\* This action allows committed transaction to be rolled back
DecreaseCommitSeqnumUnsafe ==
    /\ commit_seqnum' \in 0..commit_seqnum
    /\ UNCHANGED <<ledgers, history>>

NextDR == 
    \/ NextMultiNode
    \/ DecreaseCommitSeqnumUnsafe

SpecDR == Init /\ [][NextDR]_vars

====