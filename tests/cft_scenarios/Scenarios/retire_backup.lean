-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "retire_backup" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  trustNode 2 2
  trustNode 2 3
  emitSignature 2

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
  emitSignature 2

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

  -- # When Node 3 reconnects it can only start a speculative pre-vote in term 2.
  reconnectNode 3
  periodicOne 3 100
  assertDetail 3 "leadership_state" "PreVoteCandidate"
  assertDetail 3 "current_view" 2

  -- # The removed node cannot disrupt the current leader or obtain a quorum.
  dispatchSingle 3 0
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 2

  dispatchAll
  assertDetail 3 "leadership_state" "PreVoteCandidate"
  assertDetail 3 "current_view" 2
  assertDetail 0 "leadership_state" "Leader"

  -- # Node 3 can learn from Node 0 that it has been retired
  periodicOne 0 10
  dispatchSingle 0 3
  assertDetail 3 "leadership_state" "Follower"
  -- Pre-vote discarded the unsigned removal, so first repair the missing prefix.
  dispatchSingle 3 0
  periodicOne 0 10
  dispatchSingle 0 3
  assertCommitIdx 3 8
  assertDetail 3 "retirement_phase" "Completed"

  summariseLogsAll
