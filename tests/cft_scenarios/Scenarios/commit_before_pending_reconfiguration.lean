-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A signature appended before a pending reconfiguration needs a majority of each
-- configuration at or before that signature, not of the configuration after it
initialize scenario "commit_before_pending_reconfiguration" do
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

  -- 5: transaction, 6: signature, 7: [0, 1, 2] -> [0, 1, 2, 3], 8: signature
  replicate 2 ["hello"]
  replicate 2 [signature]
  trustNode 2 3
  replicate 2 [signature]
  assertConfig 0 7 [0, 1, 2, 3]

  -- 3 is unavailable as well, so only 0 and 1 can acknowledge
  disconnectNode 3

  periodicOne 0 10
  dispatchOne 0
  dispatchOne 1
  assertLastTxid 1 "2.8"

  -- 0 and 1 are a majority of [0, 1, 2], the only configuration at or before 6,
  -- so 0 commits 6. 8 also needs a majority of [0, 1, 2, 3], so it does not.
  assertCommitIdx 0 6

  periodicOne 0 10
  dispatchOne 0
  assertCommitIdx 1 6
