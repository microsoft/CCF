-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "replicate" do
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
  assertCommitIdx 0 4

  replicate 2 "helloworld"
  emitSignature 2
  periodicAll 10
  dispatchAll
  periodicAll 1
  stateAll

  assertCommitIdx 0 6

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
