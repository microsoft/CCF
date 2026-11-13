-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "nominate_successor" do
  startNode 0
  emitSignature 2

  swapNodes 2 (trust := [1, 2])
  emitSignature 2

  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll

  assertCommitIdx 0 4
  assertConfig 0 3 [0, 1, 2]

  assertCommitIdx 1 4
  assertConfig 1 3 [0, 1, 2]

  assertCommitIdx 2 4
  assertConfig 2 3 [0, 1, 2]

  -- Node 0 nominates node 2 via the highest-node-ID tie-break
  assertDetail 0 "leadership_state" "Leader"
  nominateSuccessor 0
  assertDetail 0 "leadership_state" "Leader"
  dispatchSingle 0 2
  assertDetail 2 "leadership_state" "Candidate"

  -- Node 1 now is updated to have a better matchIdx than node 2
  emitSignature 2
  periodicOne 0 10
  dispatchSingle 0 1
  dispatchSingle 1 0
  assertCommitIdx 0 5

  -- Node 0 nominates node 1 as a successor now
  nominateSuccessor 0
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Candidate"

  loopUntilSync
