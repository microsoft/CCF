-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A retiring leader nominates the successor with the highest match index,
-- even when a node with a higher ID is in the same latest configuration.
initialize scenario "retirement_nominates_most_replicated" do
  startNode 0
  emitSignature 2

  swapNodes 2 (trust := [1, 2, 3])
  emitSignature 2

  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertConfig 0 3 [0, 1, 2, 3]

  -- Node 3 stops receiving replication, so it lags behind nodes 1 and 2.
  disconnectNode 3

  -- Reconfig [0, 1, 2, 3] -> [1, 2, 3]
  swapNodes 2 (retire := [0])
  emitSignature 2
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertDetail 0 "retirement_phase" "Completed"
  assertDetail 0 "leadership_state" "Leader"

  cleanupNodes 2 [0]
  -- Deliver the retirement write as the last entry in its AppendEntries batch.
  periodicAll 10
  dispatchAll
  assertLastTxid 1 "2.7"
  assertLastTxid 2 "2.7"
  emitSignature 2
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 8
  assertDetail 0 "leadership_state" "None"
  assertDetail 0 "retirement_phase" "RetiredCommitted"

  -- Nodes 1 and 2 are tied on progress and membership, so the higher ID, node 2,
  -- is nominated. Node 3 has the highest ID, but its lower match index excludes it.
  assertDetail 2 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 3 "leadership_state" "Follower"

  reconnectNode 3
  emitSignature 3
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 2 9
  assertCommitIdx 3 9
