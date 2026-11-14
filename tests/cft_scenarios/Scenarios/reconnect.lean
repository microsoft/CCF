-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "reconnect" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  replicate 2 ["helloworld"]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 6
  assertStateSync

  disconnect 0 1
  replicate 2 ["salutonmondo"]
  replicate 2 [signature]

  assertCommitIdx 1 6
  dispatchAll
  assertCommitIdx 1 6

  reconnect 0 1
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 0 8
  assertStateSync
