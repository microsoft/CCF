-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A batch of no entries appends nothing, alone or with a backup
initialize scenario "replicate_empty" do
  startNode 0
  replicate 2 []
  assertLastTxid 0 "2.1"
  replicate 2 [signature]
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  replicate 2 []
  assertLastTxid 0 "2.4"
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 1 4
  assertStateSync
