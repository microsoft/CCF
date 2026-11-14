-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Queue the messages produced by replication, elections, and nomination, then
-- render their compact labels for scenario diagnostics.
initialize scenario "message_type_summaries" do
  startNode 0
  replicate 2 [signature]
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  -- Heartbeat and successful append response.
  periodicOne 0 10
  summariseMessages 0 1
  dispatchSingle 0 1
  summariseMessages 1 0
  dispatchSingle 1 0

  -- Pre-vote request/response, then regular vote request/response.
  dropPending 0
  dropPending 1
  dropPending 2
  periodicOne 1 100
  summariseMessages 1 2
  dispatchSingle 1 2
  summariseMessages 2 1
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Candidate"
  summariseMessages 1 2
  dispatchSingle 1 2
  summariseMessages 2 1
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Leader"

  -- Leadership nomination proposal.
  dropPending 1
  nominateSuccessor 1
  summariseMessages 1 0
  summariseMessages 1 2
  dropPending 1
  loopUntilSync
