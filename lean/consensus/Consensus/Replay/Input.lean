module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter

import Std.Data.HashMap

public section

namespace Consensus.Replay

def require (condition : Bool) (message : String) : Except String Unit :=
  unless condition do throw message

structure Record where
  file : String
  /-- The number of the record among those of the trace, from 1. -/
  line : Nat
  ts : Option Nat
  value : Emitted
deriving Inhabited

def Record.location (record : Record) : String := s!"{record.file}:{record.line}"

/-- Read the `ccf.cft` records of a trace, skipping those of other tags. -/
def parseLog (file : String) (input : ByteArray) : Except String (Array Record) := do
  let mut records := #[]
  let mut position : USize := 0
  let mut line := 0
  while position < input.usize do
    line := line + 1
    let (message, next) ←
      (CCF.Msgpack.run readMessage input position).mapError (s!"{file}:{line}: " ++ ·)
    position := next
    if let some (ts, value) := message then
      records := records.push { file, line, ts, value }
  return records

def readLog (path : System.FilePath) : IO (Except String (Array Record)) := do
  let path ← IO.FS.realPath path
  return parseLog path.toString (← IO.FS.readBinFile path)

structure Event where
  /-- The trace record the event was read from. -/
  record : Record
  /--
  `m_ts`: a counter the emitting process (`pid`) increments for each record it emits, so its
  order within a `pid` is the order of emission. Other tags share the counter, so it may
  have gaps.
  -/
  m_ts : Nat
  /--
  `ts`: the wall-clock emission time in nanoseconds, when the trace records it. Clocks of
  different processes may disagree, and one may step backwards.
  -/
  ts : Option Nat
  /-- `msg.function`: the name of the event. -/
  function : String
  /-- `msg.state.node_id`: the node the event is about. -/
  node : String
  /-- `msg`: the event's own fields. -/
  body : Body
  /-- `msg.state`: the node's consensus state when the event was emitted. -/
  state : StateSnapshot
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/--
Order each process's records by `m_ts`, skip driver command records, split events into
per-node streams sorted by node, and collect node identities.
-/
def prepareEvents (records : Array Record)
    : Except String (Array (Array Event) × List String) := do
  let records :=
    records.toList.mergeSort
      fun a b =>
        a.value.pid < b.value.pid
        || (a.value.pid == b.value.pid && a.value.m_ts <= b.value.m_ts)
  let mut events : Array Event := #[]
  let mut previous : Option Record := none
  let mut pids : Std.HashMap String String := {}
  let mut declared : List String := []
  for record in records do
    let { pid, m_ts, msg } := record.value
    if let some earlier := previous then
      if earlier.value.pid == pid && earlier.value.m_ts == m_ts then
        throw s!"{record.location}: m_ts {m_ts} of pid '{pid}' repeats {earlier.location}"
    previous := some record
    if let .event function body := msg then
      let state := body.state
      let node := state.node_id
      if let some other := pids[node]? then
        unless other == pid do
          throw
            s!"{record.location}: node '{node}' is traced by pids '{other}' and '{pid}'"
      pids := pids.insert node pid
      events := events.push { record, m_ts, ts := record.ts, function, node, body, state }
      declared := node :: declared
      match body with
      | .retiredCommittedTx event => declared := event.retired_node_id :: declared
      | .addConfiguration event => declared := event.nodes ++ declared
      | _ => pure ()
  let streams :=
    pids.keys.mergeSort.toArray.map fun node => events.filter (·.node == node)
  return (streams, declared.mergeSort.eraseDups)

end Consensus.Replay
