---- MODULE RaftSeeds ----
EXTENDS ccfraft

CONSTANTS
    PV_PreVoteDisabled, PV_PreVoteCapable, PV_PreVoteEnabled,
    L_Follower, L_PreVoteCandidate, L_Candidate, L_Leader, L_None,
    R_Active, R_RetirementOrdered, R_RetirementSigned, R_RetirementCompleted, R_RetiredCommitted,
    M_RequestVoteRequest, M_RequestVoteResponse, M_AppendEntriesRequest, M_AppendEntriesResponse, M_ProposeVoteRequest,
    N_OrderedNoDup, N_Ordered, N_ReorderedNoDup, N_Reordered,
    T_Entry, T_Signature, T_Reconfiguration, T_Retired

VARIABLE seedId

SeedServers == {"0"}

SeedInit ==
    /\ seedId = "marked_startup_after_signature"
    /\ preVoteStatus = ("0" :> {PV_PreVoteCapable, PV_PreVoteEnabled})
    /\ configurations = ("0" :> <<{"0"}>>)
    /\ hasJoined = ("0" :> TRUE)
    /\ retirementCompleted = ("0" :> {})
    /\ messages = ("0" :> <<>>)
    /\ currentTerm = ("0" :> 2)
    /\ leadershipState = ("0" :> L_Leader)
    /\ membershipState = ("0" :> R_Active)
    /\ votedFor = ("0" :> Nil)
    /\ isNewFollower = ("0" :> TRUE)
    /\ votesGranted = ("0" :> {})
    /\ sentIndex = ("0" :> ("0" :> 2))
    /\ matchIndex = ("0" :> ("0" :> 0))
    /\ log = ("0" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature]>>)
    /\ commitIndex = ("0" :> 2)
====
