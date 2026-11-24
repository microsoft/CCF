-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A primary sends before its next tick once it has replicated 20,000 bytes. They include
-- the name of a node in a configuration, in which a quote is escaped: here, the last
-- entry takes them to exactly as many, only if the escape is counted.
initialize scenario "escaped_node_name" do
  startNode "\""
  replicate 2 [signature]
  trustNode 2 1
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx "\"" 4

  replicate 2 ["".pushn 'x' 14808]
  dispatchAll
  assertLastTxid 1 "2.5"

  replicate 2 [signature]
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 1 6
  assertStateSync
