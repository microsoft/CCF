-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Entries passed to replicate() together are appended as one batch
initialize scenario "batched_append" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  -- 3: signature, 4: transaction, replicated in one batch by the only node.
  -- 0 commits 3 once, at the end of the batch.
  replicate 2 [signature, "hello"]
  assertLastTxid 0 "2.4"
  assertCommitIdx 0 3

  -- With a peer, a batch commits once the peer acknowledges it
  trustNode 2 1
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6

  -- 7: transaction, 8: signature, 9: transaction
  replicate 2 ["a", signature, "b"]
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  assertCommitIdx 0 8
  assertCommitIdx 1 8
