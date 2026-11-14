-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Verify candidate selection with divergent signed suffixes and pre-vote.

-- Node 0 is the start node
initialize scenario "candidate_viability" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  -- Single reconfiguration adds nodes 1, 2, 3, and 4
  trustNodes 2 [1, 2, 3, 4]
  replicate 2 [signature]

  -- Few roundtrips advance the commit on node 0
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  assertCommitIdx 0 4

  -- And then a further roundtrip makes this commit known everywhere
  -- NB: Important that they all agree the initial config is committed!
  periodicAll 10
  dispatchAll
  assertStateSync

  -- Node 0 advances to term 3, becomes primary again
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"

  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 0 "leadership_state" "Leader"

  -- Node 0 produces a slightly longer suffix in term 3
  replicate 3 [signature]
  replicate 3 [signature]

  -- Roundtrip advances the commit on node 0
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 6

  -- Node 0 produces a further uncommitted suffix
  replicate 3 [signature]
  replicate 3 [signature]

  -- But they're partitioned, so no-one hears this final suffix or the latest commit point
  disconnectNode 0

  -- Meanwhile, node 4 is fully partitioned
  disconnectNode 4

  -- Node 1 calls an wins an election, and wins with 2 and 3
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 produces an alternative branch
  replicate 4 [signature]
  replicate 4 [signature]

  -- But before _that_ is shared, the partition flips:
  -- - Node 0 reconnects
  reconnectNode 0
  -- - Node 1 is isolated
  disconnectNode 1
  -- - Node 4 is still isolated
  disconnectNode 4

  -- Node 0 catches up on term
  periodicOne 0 10
  dispatchAll

  -- Node 0 calls a fresh election
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 0 "leadership_state" "Leader"

  -- Node 0 further extends their branch, in term 5
  replicate 5 [signature]
  replicate 5 [signature]
  replicate 5 [signature]

  -- But before _that_ is shared, the partition flips again:
  -- - Node 1 reconnects
  reconnectNode 1
  -- - Node 0 is isolated
  disconnectNode 0
  -- - Node 4 is still isolated
  disconnectNode 4

  -- Repeated isolated pre-votes cannot inflate node 0's term.
  periodicOne 0 100
  periodicOne 0 100
  periodicOne 0 100
  periodicOne 0 100
  periodicOne 0 100
  assertDetail 0 "current_view" 5

  -- Node 1 catches up on term
  periodicOne 1 10
  dispatchAll

  -- Node 1 calls a fresh election
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 1 "leadership_state" "Leader"

  -- Node 1 further extends their branch, in term 6
  replicate 6 [signature]

  -- Now we only connect nodes 1 with 3 and 4, to minimise unnecessary traffic
  assertCommitIdx 3 4 -- 3 hasn't heard anything for a long time
  assertCommitIdx 4 4 -- 4 hasn't heard anything for a long time
  reconnectNode 3
  reconnectNode 4
  disconnectNode 0
  disconnectNode 2

  -- Node 1 brings 3 and 4 up-to-date slowly, with many missed messages
  periodicOne 1 10
  dispatchSingle 1 3
  dispatchSingle 1 4
  dispatchOne 3
  dispatchOne 4

  dropPendingTo 1 3
  dropPendingTo 1 4

  periodicOne 1 10
  dispatchSingle 1 3
  dispatchSingle 1 4
  dispatchOne 3
  dispatchOne 4

  -- NB: At this point we have an entry (4.8) that is present on a majority of nodes,
  -- but cannot be committed. This is sound - node 0 could still win an election and
  -- commit their own branch. Node 1 must wait for an entry in current term (6.9) to
  -- advance commit
  stateAll
  summariseLogsAll
  assertCommitIdx 1 4

  -- But if we keep delivering messages, then we _do_ safely advance commit
  periodicOne 1 10
  dispatchAll
  stateAll
  summariseLogsAll
  assertCommitIdx 1 9

  -- And just as a sanity check, we can bring all nodes in-sync on this
  reconnectNode 0
  reconnectNode 2

  periodicAll 10
  dispatchAll

  -- Choose node 4, one of the up-to-date nodes, for the next election.
  periodicOne 4 100
  assertDetail 4 "leadership_state" "PreVoteCandidate"
  dispatchAll
  assertDetail 4 "leadership_state" "Leader"
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  -- Node 0's two divergent term ranges require another prefix-repair round.
  periodicOne 4 10
  dispatchAll

  stateAll
  assertDetail 4 "leadership_state" "Leader"
  assertCommitIdx 4 9
  assertStateSync

  summariseLogsAll
