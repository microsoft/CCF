-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Atomically replace one backup and converge the replacement on the committed
-- ledger while the removed backup remains retired.
initialize scenario "swap_single_node" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  swapNode 2 1 3
  emitSignature 2
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertConfig 0 5 [0, 2, 3]
  assertConfig 2 5 [0, 2, 3]
  assertConfig 3 5 [0, 2, 3]
  assertDetail 1 "membership_state" "Retired"
  loopUntilSync
