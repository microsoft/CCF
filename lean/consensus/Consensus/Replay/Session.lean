module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Reduction

public section

/-!
# Replay by command

A driver runs one command at a time, and the events of each command are whole native groups.
A session replays the records of each command as they arrive, and keeps the model state
between commands, so that a program which issues commands can follow the model as it goes.
Replaying a trace by command gives the result of replaying it whole.
-/

namespace Consensus.Replay

open Model.Node (ReqID)

/-- A replay which has run the records of some commands, and awaits those of the next. -/
structure Session where
  header : Header
  replay : ReplayState
  /-- The request ID of the next transaction. -/
  nextRequestId : ReqID
  /-- Instructions and actions run so far. -/
  instructions : Nat := 0
  actions : Nat := 0

namespace Session

private def run (session : Session) (instructions : Array Instruction)
    : Except String Session := do
  let replay ←
    runInstructions session.header session.replay instructions (session.instructions + 1)
  return {
    session with
      replay
      instructions := session.instructions + instructions.size
      actions := session.actions + countActions instructions
  }

/--
Start a replay among the `declared` nodes, with the records of the first command, which
bootstraps the network.
-/
def start (declared : List String) (records : Array Record) : Except String Session := do
  let (events, _) ← prepareEvents records
  let header : Header := { bootstrap := ∅, declared }
  let (leader, instructions, nextRequestId) ← Reducer.reduceFirstCommand events header
  let header := { header with bootstrap := {← header.nodeId leader} }
  header.validate
  run { header, replay := { state := header.initial }, nextRequestId } instructions

/-- Replay the records of the next command. -/
def feed (session : Session) (records : Array Record) : Except String Session := do
  let (events, _) ← prepareEvents records
  let (instructions, nextRequestId) ←
    Reducer.reduceCommand events session.header session.nextRequestId
  run { session with nextRequestId } instructions

/-- The model state after the commands replayed so far. -/
def state (session : Session) : Model.State :=
  session.replay.state

def result (session : Session) : Result where
  instructions := session.instructions
  actions := session.actions
  observations := session.instructions - session.actions
  outcomes := session.replay.shown

end Session

private def startsCommand (record : Record) : Bool :=
  ((optional record.value "msg").bind (optional · "cmd")).isSome

/--
The records of each driver command, in order, each starting with its `cmd` record.
Records before the first `cmd` record form a command of their own.
-/
def splitCommands (records : Array Record) : Array (Array Record) :=
  records.foldl
    (fun commands record =>
      if startsCommand record || commands.isEmpty then
        commands.push #[record]
      else
        commands.modify (commands.size - 1) (·.push record))
    #[]

/-- Replay a whole trace. -/
def replayTrace (records : Array Record) : Except String Result := do
  let (events, declared) ← prepareEvents records
  let reduced ← reduce events declared
  replay reduced.header reduced.instructions

/-- Replay a trace one driver command at a time, among the nodes which it names. -/
def replayByCommand (records : Array Record) : Except String Result := do
  let (_, declared) ← prepareEvents records
  let commands := splitCommands records
  let some first := commands[0]? | throw "trace has no records"
  let session ← Session.start declared first
  let session ← (commands.extract 1).foldlM Session.feed session
  if session.instructions == 0 then throw "replay instructions must not be empty"
  return session.result

end Consensus.Replay
