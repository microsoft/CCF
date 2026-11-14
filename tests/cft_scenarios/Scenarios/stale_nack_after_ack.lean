-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A rejection which arrives after the acknowledgement of later entries does
-- not send the primary back. Node 2 rejects the first message which the
-- primary sends to it, and that rejection is delayed until node 2 has
-- acknowledged the whole log. The primary then sends node 2 only the entries
-- which follow.
-- Found by `cft_model_driver --explore`, from `reconfiguration`, then written
-- to end with a commit.
initialize scenario "stale_nack_after_ack" do
  startNode 0
  trustNodes 2 [1, 2]

  -- 1 and 2 hold nothing, and reject the first message of the primary. The
  -- rejection from 2 is held back
  dispatchOne 0
  holdNth 2 0 0

  -- 1 and 2 receive the log up to 2.2, and acknowledge it
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll
  assertLastTxid 2 "2.2"

  -- The rejection from 2 arrives, and names an index below the one which 2 has
  -- acknowledged
  dispatchHeld 0

  -- The primary signs at 2.3, which commits on every node
  replicate 2 [signature]
  periodicOne 0 10
  dispatchAll
  periodicOne 0 10
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 3
  assertDetail 2 "leadership_state" "Follower"
  assertCommitIdx 2 3
