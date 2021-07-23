
---------- MODULE MCraft ----------
EXTENDS ccfraft, TLC

PossibleServer_mc == {NodeOne, NodeTwo, NodeThree, NodeFour, NodeFive}
InitialServer_mc == {NodeOne, NodeTwo, NodeThree}
tmp == [s \in PossibleServer_mc |-> Follower]
InitialConfig_mc == [tmp EXCEPT ![NodeFour] = Pending,
                                ![NodeFive] = Pending]

\*  SNIPPET_START: mc_config
\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
TermLimit_mc == 4

\* Limit number of requests (new entries) that can be made
RequestLimit_mc == 2

\* Limit on number of request votes that can be sent to each other node
RequestVoteLimit_mc == 1

\* Limit number of reconfigurations
ReconfigurationLimit_mc == 1

\* Limit number of duplicate messages sent to the same server
MessagesLimit_mc == 1

\* Limit number of times a RetiredLeader server sends commit notifications
CommitNotificationLimit_mc == 1

\* We made several restrictions to the state space of Raft. However since we
\* made these restrictions, Deadlocks can occur at places that Raft would in
\* real-world deployments handle graciously. 
\* One example of this is if a Quorum of nodes becomes Candidate but can not
\* timeout anymore since we constrained the terms. Then, an artificial Deadlock
\* is reached. We solve this below. If TermLimit is set to any number >2, this is
\* not an issue since breadth-first search will make sure that a similar
\* situation is simulated at term==1 which results in a term increase to 2.
MaxSimultaneousCandidates_mc == 1
\* SNIPPET_END: mc_config

mc_spec == Spec

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file. 
Symmetry == Permutations(PossibleServer_mc)

===================================
