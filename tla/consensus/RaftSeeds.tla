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

SeedServers == {"0", "1", "2"}

SeedInit ==
    \/ /\ seedId = "reconfig_01_el0_12_prevote_multiple_candidates"
       /\ preVoteStatus = ("0" :> {PV_PreVoteCapable, PV_PreVoteEnabled} @@ "1" :> {PV_PreVoteCapable, PV_PreVoteEnabled} @@ "2" :> {PV_PreVoteCapable, PV_PreVoteEnabled})
       /\ configurations = ("0" :> (5 :> {"1", "2"}) @@ "1" :> (3 :> {"0", "1"} @@ 5 :> {"1", "2"}) @@ "2" :> (3 :> {"0", "1"} @@ 5 :> {"1", "2"}))
       /\ hasJoined = ("0" :> TRUE @@ "1" :> TRUE @@ "2" :> TRUE)
       /\ retirementCompleted = ("0" :> {"0"} @@ "1" :> {} @@ "2" :> {})
       /\ messages = ("0" :> <<>> @@ "1" :> <<[type |-> M_AppendEntriesRequest, dest |-> "1", source |-> "0", term |-> 2, commitIndex |-> 6, prevLogTerm |-> 2, entries |-> <<[term |-> 2, contentType |-> T_Entry], [term |-> 2, contentType |-> T_Signature]>>, prevLogIndex |-> 6], [type |-> M_RequestVoteRequest, dest |-> "1", source |-> "0", term |-> 2, lastCommittableIndex |-> 8, lastCommittableTerm |-> 2, isPreVote |-> TRUE]>> @@ "2" :> <<[type |-> M_AppendEntriesRequest, dest |-> "2", source |-> "0", term |-> 2, commitIndex |-> 6, prevLogTerm |-> 2, entries |-> <<[term |-> 2, contentType |-> T_Entry], [term |-> 2, contentType |-> T_Signature]>>, prevLogIndex |-> 6], [type |-> M_RequestVoteRequest, dest |-> "2", source |-> "0", term |-> 2, lastCommittableIndex |-> 8, lastCommittableTerm |-> 2, isPreVote |-> TRUE]>>)
       /\ currentTerm = ("0" :> 2 @@ "1" :> 2 @@ "2" :> 2)
       /\ leadershipState = ("0" :> L_PreVoteCandidate @@ "1" :> L_Follower @@ "2" :> L_PreVoteCandidate)
       /\ membershipState = ("0" :> R_RetirementCompleted @@ "1" :> R_Active @@ "2" :> R_Active)
       /\ votedFor = ("0" :> Nil @@ "1" :> Nil @@ "2" :> Nil)
       /\ isNewFollower = ("0" :> TRUE @@ "1" :> TRUE @@ "2" :> TRUE)
       /\ votesGranted = ("0" :> {"0"} @@ "1" :> {} @@ "2" :> {"1", "2"})
       /\ sentIndex = ("0" :> ("0" :> 2 @@ "1" :> 8 @@ "2" :> 8) @@ "1" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0) @@ "2" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0))
       /\ matchIndex = ("0" :> ("0" :> 0 @@ "1" :> 6 @@ "2" :> 6) @@ "1" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0) @@ "2" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0))
       /\ log = ("0" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, contentType |-> T_Entry], [term |-> 2, contentType |-> T_Signature]>> @@ "1" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature]>> @@ "2" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature]>>)
       /\ commitIndex = ("0" :> 6 @@ "1" :> 4 @@ "2" :> 4)
    \/ /\ seedId = "pre_vote_denied_stale_log_prevote"
       /\ preVoteStatus = ("0" :> {PV_PreVoteCapable, PV_PreVoteEnabled} @@ "1" :> {PV_PreVoteCapable, PV_PreVoteEnabled} @@ "2" :> {PV_PreVoteCapable, PV_PreVoteEnabled})
       /\ configurations = ("0" :> (3 :> {"0", "1", "2"}) @@ "1" :> (3 :> {"0", "1", "2"}) @@ "2" :> (3 :> {"0", "1", "2"}))
       /\ hasJoined = ("0" :> TRUE @@ "1" :> TRUE @@ "2" :> TRUE)
       /\ retirementCompleted = ("0" :> {} @@ "1" :> {} @@ "2" :> {})
       /\ messages = ("0" :> <<[type |-> M_AppendEntriesRequest, dest |-> "0", source |-> "1", term |-> 3, commitIndex |-> 4, prevLogTerm |-> 2, entries |-> <<[term |-> 3, contentType |-> T_Signature]>>, prevLogIndex |-> 4]>> @@ "1" :> <<[type |-> M_AppendEntriesResponse, dest |-> "1", source |-> "2", term |-> 3, success |-> TRUE, lastLogIndex |-> 5], [type |-> M_RequestVoteRequest, dest |-> "1", source |-> "0", term |-> 3, lastCommittableIndex |-> 4, lastCommittableTerm |-> 2, isPreVote |-> TRUE]>> @@ "2" :> <<>>)
       /\ currentTerm = ("0" :> 3 @@ "1" :> 3 @@ "2" :> 3)
       /\ leadershipState = ("0" :> L_PreVoteCandidate @@ "1" :> L_Leader @@ "2" :> L_Follower)
       /\ membershipState = ("0" :> R_Active @@ "1" :> R_Active @@ "2" :> R_Active)
       /\ votedFor = ("0" :> "1" @@ "1" :> "1" @@ "2" :> "1")
       /\ isNewFollower = ("0" :> TRUE @@ "1" :> TRUE @@ "2" :> TRUE)
       /\ votesGranted = ("0" :> {"0"} @@ "1" :> {"1", "2"} @@ "2" :> {})
       /\ sentIndex = ("0" :> ("0" :> 2 @@ "1" :> 4 @@ "2" :> 4) @@ "1" :> ("0" :> 5 @@ "1" :> 4 @@ "2" :> 5) @@ "2" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0))
       /\ matchIndex = ("0" :> ("0" :> 0 @@ "1" :> 4 @@ "2" :> 4) @@ "1" :> ("0" :> 4 @@ "1" :> 0 @@ "2" :> 4) @@ "2" :> ("0" :> 0 @@ "1" :> 0 @@ "2" :> 0))
       /\ log = ("0" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature]>> @@ "1" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 3, contentType |-> T_Signature]>> @@ "2" :> <<[term |-> 2, configuration |-> {"0"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 2, configuration |-> {"0", "1", "2"}, contentType |-> T_Reconfiguration], [term |-> 2, contentType |-> T_Signature], [term |-> 3, contentType |-> T_Signature]>>)
       /\ commitIndex = ("0" :> 4 @@ "1" :> 4 @@ "2" :> 4)
====
