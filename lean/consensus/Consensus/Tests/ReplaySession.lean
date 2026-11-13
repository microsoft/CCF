module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Session

public import Consensus.Replay.Session

public section

namespace Consensus.Tests.ReplaySession

open Consensus Consensus.Replay
open CCF.MultiNodeTransitionSystem (nodeState)

/-- The first node starts, then signs: two driver commands. -/
private def trace : List String :=
  [
    r#"{"msg":{"cmd":"start_node,0"}}"#,
    r#"{"msg":{"function":"become_leader","state":{"node_id":"0"}}}"#,
    r#"{"msg":{"function":"replicate","state":{"node_id":"0"}}}"#,
    r#"{"msg":{"function":"replicate_entry","state":{"node_id":"0"},"globally_committable":false}}"#,
    r#"{"msg":{"function":"add_configuration","state":{"node_id":"0"},"nodes":{"0":{}}}}"#,
    r#"{"msg":{"cmd":"replicate,2,$"}}"#,
    r#"{"msg":{"function":"replicate","state":{"node_id":"0","last_idx":1,"commit_idx":0}}}"#,
    r#"{"msg":{"function":"replicate_entry","state":{"node_id":"0"},"seqno":2,"globally_committable":true}}"#,
    r#"{"msg":{"function":"commit","state":{"node_id":"0"},"idx":2}}"#
  ]

private def check (condition : Bool) (message : String) : IO Unit := do
  unless condition do
    throw (IO.userError message)

/-- The ledger length and commit index of node 0 in the model. -/
private def ledger (session : Session) : Option (Nat × Nat) :=
  (nodeState session.state 0).map fun node => (node.log.length, node.commitIndex)

/-- Checks replay by command against replay of the whole trace, and the state between commands. -/
def run : IO Unit := do
  let records ← IO.ofExcept (parseLog "trace" ("\n".intercalate trace))
  let commands := splitCommands records
  check (commands.map (·.size) == #[5, 4]) "split: each command has its own records"
  match replayTrace records, replayByCommand records with
  | .ok whole, .ok byCommand =>
      check (whole == byCommand && whole.actions == 1)
        "by command: the result differs from that of the whole trace"
  | whole, byCommand =>
      let describe (result : Except String Result) :=
        match result with
        | .ok _ => "accepted"
        | .error error => error
      throw
        (IO.userError s!"whole trace: {describe whole}; by command: {describe byCommand}")
  let started ← IO.ofExcept (Session.start ["0"] commands[0]!)
  check (ledger started == some (1, 0)) "start: the model has the first command only"
  let signed ← IO.ofExcept (started.feed commands[1]!)
  check (ledger signed == some (2, 2)) "feed: the model has the second command"
  -- A command holds whole groups: an entry cannot follow its `replicate` in a later one.
  match started.feed (commands[1]!.extract 0 2) >>= (·.feed (commands[1]!.extract 2)) with
  | .error error =>
      check ((error.splitOn "ungrouped event replicate_entry").length == 2)
        s!"split group: unexpected error {error}"
  | .ok _ => throw (IO.userError "split group: a group was continued in the next command")
  match Session.start ["1"] commands[0]! with
  | .error error =>
      check ((error.splitOn "undeclared node '0'").length == 2)
        s!"undeclared node: unexpected error {error}"
  | .ok _ =>
      throw (IO.userError "undeclared node: a node outside the declared ones started")
  IO.println "Replay session checks passed."

#eval run

end Consensus.Tests.ReplaySession
