-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Committing a signature after a pending configuration retires the configuration
-- before it, so the same commit can reach later signatures without it
initialize scenario "commit_stepwise_through_reconfiguration" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  -- Initial configuration [0, 1, 2], all nodes in sync
  trustNodes 2 [1, 2]
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync

  -- 2 becomes unavailable
  disconnectNode 2

  -- 5: [0, 1, 2] -> [0, 1, 2, 3, 4], 6: signature
  trustNodes 2 [3, 4]
  replicate 2 [signature]

  -- 1 receives up to 6, but its acknowledgement is held back
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "2.6"

  -- 7: transaction, 8: signature
  replicate 2 ["hello"]
  replicate 2 [signature]

  -- 3 and 4 catch up to 8, while 1 receives nothing more
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchOne 0
  dispatchOne 3
  dispatchOne 4
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchOne 0
  dispatchOne 3
  dispatchOne 4
  periodicOne 0 10
  dropPendingTo 0 1
  dispatchOne 0
  dispatchOne 3
  dispatchOne 4
  assertLastTxid 3 "2.8"
  assertLastTxid 4 "2.8"

  -- 0, 3 and 4 are a majority of [0, 1, 2, 3, 4] at 8, but only 0 of [0, 1, 2]
  -- has 6, so nothing after 4 commits
  assertCommitIdx 0 4

  -- 1's acknowledgement of 6 gives [0, 1, 2] a majority at 6, so 6 can commit.
  -- That would commit [0, 1, 2, 3, 4] and retire [0, 1, 2], so 0 commits 8 at once.
  dispatchOne 1
  assertCommitIdx 0 8
