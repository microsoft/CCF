---------- MODULE MCccfraftWithReconfig ----------
EXTENDS ccfraft, TLC

Servers_mc == {NodeOne, NodeTwo}
Configurations_mc == <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>

\*  SNIPPET_START: mc_config
\* Limit the terms that can be reached. Needs to be set to at least 3 to
\* evaluate all relevant states. If set to only 2, the candidate_quorum
\* constraint below is too restrictive.
TermLimit_mc == 3

\* Limit number of requests (new entries) that can be made
RequestLimit_mc == 2

\* Limit on number of request votes that can be sent to each other node
RequestVoteLimit_mc == 1

\* Limit number of duplicate messages sent to the same server
MessagesLimit_mc == 1

\* Limit number of times a RetiredLeader server sends commit notifications
CommitNotificationLimit_mc == 2

\* Limit max number of simultaneous candidates
MaxSimultaneousCandidates_mc == 1
\* SNIPPET_END: mc_config

mc_spec == Spec

\* Symmetry set over possible servers. May dangerous and is only enabled
\* via the Symmetry option in cfg file.
Symmetry == Permutations(Servers_mc)

===================================