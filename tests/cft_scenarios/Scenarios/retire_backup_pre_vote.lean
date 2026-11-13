-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "retire_backup_pre_vote" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  trustNode 2 2
  trustNode 2 3
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 6
  assertCommitIdx 1 6
  assertCommitIdx 2 6

  -- # the leader 0 reconfigures to remove 3
  swapNodes 2 (retire := [3])
  replicate 2 [signature]

  -- # node 3 learns it is out of the network but not that this entry is committed
  dispatchSingle 0 3

  -- # Disconnect it to prevent it from learning that the entry is committed
  disconnectNode 3

  -- # node 0 commits removing Node 3
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 8
  assertCommitIdx 1 8
  assertCommitIdx 2 8
  assertCommitIdx 3 6 -- Node 3 hasn't heard anything for a long time

  -- # When Node 3 reconnects it becomes a PreVoteCandidate
  reconnectNode 3
  periodicOne 3 100
  assertDetail 3 "leadership_state" "PreVoteCandidate"

  dispatchAll

  -- # Node 3's candidacy does not cause Node 0 to step down
  dispatchSingle 3 0
  assertDetail 0 "leadership_state" "Leader"
