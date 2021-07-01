
---------- MODULE MCraft ----------
EXTENDS ccfraft, TLC

Server_mc == {NodeOne, NodeTwo, NodeThree}

\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
TermLimit == 3

\* Limit number of requests (new entires) that can be made
RequestLimit == 1

\* Limit on number of request votes that can be sent to each other node
RequestVoteLimit_mc == 1

MessagesLimit_mc == 2

mc_spec == Spec

constraint_term == \A i \in Server : currentTerm[i] <= TermLimit
\* Constraint for the request limit. clientRequests starts at 1
\*  and increments with each request, so we add 1 to the user
\*  defined request limit.
constraint_requests == clientRequests <= (RequestLimit + 1)

Symmetry == Permutations(Server_mc)

\* We made several restrictions to the state space of Raft. However since we
\* made these restrictions, Deadlocks can occur at places that Raft would in
\* real-world deployments handle graciously. 
\* One example of this is if a Quorum of nodes becomes Candidate but can not
\* timeout anymore since we constrained the terms. Then, an artificial Deadlock
\* is reached. We solve this below. If TerLimit is set to any number >2, this is
\* not an issue since breadth-first search will make sure that a similar
\* situation is simulated at term==1 which results in a term increase to 2.
constraint_candidate_quorum == 
    Cardinality({ i \in Server : state[i] = Candidate}) <= 1

===================================
