-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Create a Start Node, commit initial transaction and signature
-- https://microsoft.github.io/CCF/main/operations/start_network.html#starting-the-first-node
initialize scenario "startup" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2
