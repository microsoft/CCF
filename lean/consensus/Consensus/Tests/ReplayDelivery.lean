module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Interpreter

public import Consensus.Replay.Interpreter

public section

namespace Consensus.Tests.ReplayDelivery

open Consensus Consensus.Replay Consensus.Model.Node

private def header : Header := { bootstrap := {0}, declared := ["0", "1"] }

/-- An AppendEntries from 0 to 1; its rendered packet omits the entry request ID. -/
private def appendEntries (request : ReqID) : Envelope :=
  {
    source := 0
    target := 1
    payload :=
      .appendEntriesRequest
        {
          term := 2
          prevLogIndex := 0
          prevLogTerm := 0
          entries := [{ term := 2, content := .transaction request {} }]
          primaryCommit := 0
        }
  }

private def receive (network : List Envelope) : Except String ReplayState :=
  runInstruction header { state := { header.initial with network } }
    (.action (.receive "0" "1" (messageJson (appendEntries 1).payload)) default)

/-- Checks delivery selection among queued envelopes whose rendered packets are equal. -/
def run : IO Unit := do
  match receive [appendEntries 1, appendEntries 1] with
  | .ok replay =>
      unless replay.state.network.count (appendEntries 1) == 1 do
        throw
          (IO.userError "identical candidates: exactly one occurrence must be delivered")
  | .error error => throw (IO.userError s!"identical candidates: {error}")
  match receive [appendEntries 1, appendEntries 2] with
  | .error error =>
      unless error.startsWith "ambiguous delivery" do
        throw (IO.userError s!"different entries: unexpected error {error}")
  | .ok _ => throw (IO.userError "different entries: delivery must be ambiguous")
  IO.println "Replay delivery checks passed."

#eval run

end Consensus.Tests.ReplayDelivery
