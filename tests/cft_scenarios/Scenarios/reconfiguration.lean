-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "reconfiguration" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync

  stateAll

  -- Reconfiguration: add two nodes at once that are necessary to
  -- commit reconfiguration entry itself
  -- New configuration: [0, 1, 2, 3] in term 2
  trustNodes 2 [2, 3]
  emitSignature 2
  periodicAll 10
  dispatchOne 0

  stateAll

  dispatchOne 1 -- ACK 2.6 from 1

  stateAll -- 5 isn't committed until one of the new nodes (either 2 or 3) acks
  assertCommitIdx 0 4

  dispatchOne 2 -- NACK 2.6 from 2
  periodicOne 0 10
  dispatchOne 0 -- AE catchup from 0
  dispatchOne 2 -- ACK 2.6 from 2

  stateAll -- 6 is now committed as new node 2 has acked
  assertCommitIdx 0 6

  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
