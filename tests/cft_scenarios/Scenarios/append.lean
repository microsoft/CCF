-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Create a Start Node, commit initial transaction and signature
-- Append transaction to the node's log, observe that they are committed
initialize scenario "append" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  replicate 2 ["first transaction"]
  -- Commit hasn't moved, the transaction is not part of a signed
  -- suffix, and so is not committable
  assertCommitIdx 0 2
  replicate 2 [signature]
  -- The signature has been emitted, commit is immediate since
  -- no other nodes need to be notified
  assertCommitIdx 0 4

  -- Append more than one transaction in a signed batch
  replicate 2 ["second transaction"]
  replicate 2 ["third transaction"]
  replicate 2 ["fourth transaction"]
  assertCommitIdx 0 4
  replicate 2 [signature]
  assertCommitIdx 0 8
