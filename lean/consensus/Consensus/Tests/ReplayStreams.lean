module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Input

public import Consensus.Replay.Input

public section

namespace Consensus.Tests.ReplayStreams

open Lean Consensus Consensus.Replay Consensus.Model.Node

private def tick (line : Nat) (process : String) (time : Nat) (node : String) : Record :=
  {
    file := "trace"
    line
    value :=
      Json.mkObj
        [
          ("process_id", toJson process),
          ("h_ts", toJson time),
          (
            "msg",
            Json.mkObj [("function", "tick"), ("state", Json.mkObj [("node_id", node)])]
          )
        ]
  }

private def expectError (name : String) (records : Array Record) (expected : String)
    : IO Unit := do
  let .error error := prepareEvents records
  | throw (IO.userError s!"{name}: must be rejected")
  unless error == expected do
    throw (IO.userError s!"{name}: unexpected error {error}")

private def header : Header := { bootstrap := {0, 1}, declared := ["0", "1"] }

private def action (step : Step) : Instruction := .action step default

private def sends (sends : List (String × Json)) : Instruction :=
  .observeSends (sends.map fun (target, packet) => { target, packet, origin := default })
    default

private def group (node : String) (time : Nat) (instructions : Array Instruction)
    : Group :=
  { node, time, instructions }

/-- The primary's first AppendEntries to the follower, carrying the genesis entry. -/
private def appendEntries : Json :=
  messageJson
    (.appendEntriesRequest
      {
        term := Model.BOOTSTRAP_TERM
        prevLogIndex := 0
        prevLogTerm := 0
        entries := (Model.initialNodeState header.bootstrap 0).log
        primaryCommit := 0
      })

private def response : Json :=
  messageJson
    (.appendEntriesResponse
      { term := Model.BOOTSTRAP_TERM, success := true, lastLogIndex := 1 })

private def send : Array Instruction :=
  #[action (.local "0" (.sendEntries 1 1)), sends [("1", appendEntries)]]

private def signature : Instruction :=
  action (.local "0" (.append [{ content := .signature }]))

private def acknowledge : Instruction := action (.receive "1" "0" response)

private def follower : Array Group :=
  #[group "1" 3 #[action (.receive "0" "1" appendEntries), sends [("0", response)]]]

/-- Checks per-process ordering keys and the scheduling of groups. -/
def run : IO Unit := do
  expectError "repeated h_ts" #[tick 1 "a" 5 "0", tick 2 "a" 5 "0"]
    "trace:2: h_ts 5 of process 'a' repeats trace:1"
  expectError "node in two processes" #[tick 1 "a" 0 "0", tick 2 "b" 0 "0"]
    "trace:2: node '0' is traced by processes 'a' and 'b'"
  -- The primary's receive heads a group with an earlier `h_ts`, so it waits for the follower.
  let primary := #[group "0" 0 send, group "0" 1 #[signature], group "0" 2 #[acknowledge]]
  if let .error error := replay header #[primary, follower] then
    throw (IO.userError s!"waiting receive: {error}")
  -- Once the signature's group starts, its receive runs before the follower can respond.
  let primary := #[group "0" 0 send, group "0" 1 #[signature, acknowledge]]
  match replay header #[primary, follower] with
  | .error error =>
      unless error.endsWith "no pending packet from '1' to '0'" do
        throw (IO.userError s!"atomic group: unexpected error {error}")
  | .ok _ => throw (IO.userError "atomic group: another group ran inside a started group")
  IO.println "Replay stream checks passed."

#eval run

end Consensus.Tests.ReplayStreams
