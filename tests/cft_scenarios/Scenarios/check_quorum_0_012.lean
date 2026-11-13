-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "check_quorum_0_012" do
  startNode 0
  emitSignature 2
  swapNodes 2 (trust := [1, 2])
  emitSignature 2

  periodicOne 0 10
  dispatchAll
  dispatchAll
  periodicOne 0 10
  dispatchAll

  -- All nodes have both configs: {0} and {0,1,2}
  assertCommitIdx 0 4
  assertAbsentConfig 0 1
  assertConfig 0 3 [0, 1, 2]

  assertCommitIdx 1 2
  assertConfig 1 1 [0]
  assertConfig 1 3 [0, 1, 2]

  assertCommitIdx 2 2
  assertConfig 2 1 [0]
  assertConfig 2 3 [0, 1, 2]

  -- Node 0 should step down via CheckQuorum
  disconnectNode 0
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"

  -- Node 1 should try to start an election but fails without a quorum in {0}
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertDetail 1 "leadership_state" "PreVoteCandidate"

  -- Fixup the network to allow a leader to be elected and the test to pass
  reconnectNode 0
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchAll
