module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter

import Std.Data.HashMap

public section

namespace Consensus.Replay

open Lean

def require (condition : Bool) (message : String) : Except String Unit :=
  unless condition do throw message

def object (value : Json) : Except String (List (String × Json)) :=
  (·.toList) <$> value.getObj?

def field (value : Json) (key : String) : Except String Json :=
  (value.getObjVal? key).mapError (fun error => s!"{key}: {error}")

def optional (value : Json) (key : String) : Option Json :=
  (value.getObjVal? key).toOption

def text (value : Json) : Except String String :=
  value.getStr?

def natural : Json → Except String Nat
  | .num { mantissa := .ofNat value, exponent := 0 } => pure value
  | _ => throw "expected natural number"

def string (value : Json) (key : String) : Except String String :=
  field value key >>= text

def nat (value : Json) (key : String) : Except String Nat :=
  field value key >>= natural

def boolean (value : Json) (key : String) : Except String Bool :=
  field value key >>= Json.getBool?

def configuration (value : Json) : Except String (List String) := do
  let nodes ← object (← field value "nodes")
  return nodes.map Prod.fst

structure Record where
  file : String
  line : Nat
  value : Json
deriving Inhabited

def Record.location (record : Record) : String := s!"{record.file}:{record.line}"

/-- Read one JSON record per line without a schema pass. -/
def parseLog (file input : String) : Except String (Array Record) := do
  let mut records := #[]
  let lines := if input.isEmpty then [] else input.splitOn "\n"
  let lines := if input.endsWith "\n" then lines.dropLast else lines
  for raw in lines, line in [1:lines.length + 1] do
    let raw := if raw.endsWith "\r" then raw.dropEnd 1 |>.toString else raw
    let value ← (Json.parse raw).mapError (fun error => s!"{file}:{line}: {error}")
    records := records.push { file, line, value }
  return records

def readLog (path : System.FilePath) : IO (Except String (Array Record)) := do
  let path ← IO.FS.realPath path
  let bytes ← IO.FS.readBinFile path
  let some input := String.fromUTF8? bytes
  | return .error s!"{path}: invalid UTF-8"
  return parseLog path.toString input

structure Event where
  /-- The trace line the event was read from. -/
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
  message : Json
  /-- `msg.state`: the node's consensus state when the event was emitted. -/
  state : Json
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/--
Order each process's records by `m_ts`, skip driver command records and records with a
`tag` other than `ccf.cft`, split events into per-node streams sorted by node, and collect
node identities.
-/
def prepareEvents (records : Array Record)
    : Except String (Array (Array Event) × List String) := do
  let records :=
    records.filter
      fun record => (optional record.value "tag").all (· == Json.str "ccf.cft")
  let keyed ←
    records.mapM
      fun record =>
        (do
          return (← string record.value "pid", ← nat record.value "m_ts", record))
        |>.mapError (s!"{record.location}: " ++ ·)
  let keyed :=
    keyed.toList.mergeSort fun (p, t, _) (q, u, _) => p < q || (p == q && t <= u)
  let mut events : Array Event := #[]
  let mut previous : Option (String × Nat × Record) := none
  let mut pids : Std.HashMap String String := {}
  let mut declared : List String := []
  for (pid, m_ts, record) in keyed do
    if let some (last, lastMts, earlier) := previous then
      if last == pid && lastMts == m_ts then
        throw s!"{record.location}: m_ts {m_ts} of pid '{pid}' repeats {earlier.location}"
    previous := some (pid, m_ts, record)
    try
      let message ← field record.value "msg"
      unless (optional message "cmd").isSome do
        let function ← string message "function"
        let state ←
          if function == "retired_committed_tx" then
            pure Json.null
          else
            field message "state"
        let node ←
          string (if function == "retired_committed_tx" then message else state) "node_id"
        if let some other := pids[node]? then
          require (other == pid) s!"node '{node}' is traced by pids '{other}' and '{pid}'"
        pids := pids.insert node pid
        let ts ← (optional record.value "ts").mapM natural
        events := events.push { record, m_ts, ts, function, node, message, state }
        declared := node :: declared
        if function == "retired_committed_tx" then
          declared := (← string message "retired_node_id") :: declared
        if function == "add_configuration" then
          declared := (← configuration message) ++ declared
    catch error =>
      throw s!"{record.location}: {error}"
  let streams :=
    pids.keys.mergeSort.toArray.map fun node => events.filter (·.node == node)
  return (streams, declared.mergeSort.eraseDups)

end Consensus.Replay
