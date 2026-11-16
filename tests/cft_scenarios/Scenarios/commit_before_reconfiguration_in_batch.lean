-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A signature commits without the node added by a later configuration of the same batch
initialize scenario "commit_before_reconfiguration_in_batch" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  -- 3: transaction, 4: signature, 5: [0] -> [0, 1]
  replicateAndTrustNode 2 ["hello", signature] 1
  assertConfig 0 5 [0, 1]
  assertCommitIdx 0 4

  -- 6 also needs 1
  replicate 2 [signature]
  assertCommitIdx 0 4
