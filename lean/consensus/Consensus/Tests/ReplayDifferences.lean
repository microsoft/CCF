module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Interpreter

public import Consensus.Replay.Interpreter

public section

namespace Consensus.Tests.ReplayDifferences

open Consensus Consensus.Replay Consensus.Model.Node
open CCF (Finset)

private def header : Header := { bootstrap := {0}, declared := ["0", "1", "2"] }

private def configuration (request : ReqID) (nodes : Finset NodeID) : Entry :=
  { term := 2, content := .transaction request { configuration := some nodes } }

private def signature : Entry := { term := 2, content := .signature }

/-- Node 1 as a follower in term 2 which holds `log`. -/
private def follower (log : List Entry) : Model.State :=
  let initial := header.initial
  let node : NodeState :=
    {
      Model.initialNodeState header.bootstrap 1 with
        role := .follower, currentTerm := 2, log
    }
  {
    initial with
      nodes := initial.nodes.map fun (id, state) => (id, if id = 1 then node else state)
  }

/-- Node 2 retires before the signature at 3, and node 1 joins after it. -/
private def retiredBeforeSnapshot : List Entry :=
  [
    configuration 0 {0, 2},
    configuration 1 {0},
    signature,
    configuration 2 {0, 1},
    signature
  ]

private def heartbeat (target : NodeID) : Envelope :=
  {
    source := 1
    target
    payload :=
      .appendEntriesRequest
        {
          term := 2,
          prevLogIndex := 5,
          prevLogTerm := 2,
          entries := [],
          primaryCommit := 3
        }
  }

/-- Whether the model sent `queued` and CCF nothing, for node 1 which started at `snapshot`. -/
private def unsent (snapshot : Nat) (queued : List Envelope)
    : Except String ReplayState :=
  runInstruction header
    { state := follower retiredBeforeSnapshot, queued, snapshots := [(1, snapshot)] }
    (.observeSends [] default)

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do
    throw (IO.userError message)

private def rejected (result : Except String ReplayState) : Bool :=
  match result with
  | .error error => (error.splitOn "with no native send").length == 2
  | .ok _ => false

/-- Checks what replay accepts where CCF and the model differ, and that it accepts no more. -/
def run : IO Unit := do
  -- A node which started from a snapshot does not know a node which retired before it
  check (unsent 3 [heartbeat 2]).isOk
    "snapshot: entries for a node which retired before it must be lost"
  check (rejected (unsent 3 [heartbeat 0])) "snapshot: entries for a peer must be sent"
  check (rejected (unsent 0 [heartbeat 2]))
    "no snapshot: entries for a node whose retirement is not confirmed must be sent"
  let response : Envelope :=
    {
      heartbeat 2 with
        payload := .requestVoteResponse { term := 2, voteGranted := true }
    }
  check (rejected (unsent 3 [response])) "snapshot: a response must be sent to any node"
  IO.println "Replay difference checks passed."

#eval run

end Consensus.Tests.ReplayDifferences
