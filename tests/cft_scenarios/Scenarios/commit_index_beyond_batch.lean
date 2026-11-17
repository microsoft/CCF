-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node which joins is told of a commit index beyond the entries which it has
-- received. The primary sends its log in two batches, and the first ends in a
-- transaction which follows a signature. Node 1 commits that signature as it
-- applies it, and has nothing further to commit at the end of the batch.
-- Found by `cft_model_driver --explore`, from `batched_append`, then written
-- to deliver one batch at a time.
initialize scenario "commit_index_beyond_batch" do
  startNode 0
  replicate 2 [signature, "hello"]
  replicate 2 [signature]
  assertCommitIdx 0 4

  -- 1 joins, holds nothing, and rejects the first message of the primary
  trustNode 2 1
  dispatchAll
  periodicOne 0 10

  -- The first batch ends at 2.3, and the primary has committed 2.4
  dispatchSingle 0 1
  assertLastTxid 1 "2.3"
  assertCommitIdx 1 2

  -- The second batch ends at 2.5
  dispatchSingle 0 1
  assertLastTxid 1 "2.5"

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 4
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 4
