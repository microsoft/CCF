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
  record : Record
  command : Option Record
  /-- `h_ts`, the emission order within the record's process; other tags share the counter. -/
  time : Nat
  function : String
  node : String
  message : Json
  state : Json
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/--
Order each process's records by `h_ts`, carry command provenance within a process,
split events into per-node streams sorted by node, and collect node identities.
-/
def prepareEvents (records : Array Record)
    : Except String (Array (Array Event) × List String) := do
  let keyed ←
    records.mapM
      fun record =>
        (do
          return (← string record.value "process_id", ← nat record.value "h_ts", record))
        |>.mapError (s!"{record.location}: " ++ ·)
  let keyed :=
    keyed.toList.mergeSort fun (p, t, _) (q, u, _) => p < q || (p == q && t <= u)
  let mut events := #[]
  let mut previous : Option (String × Nat × Record) := none
  let mut command : Option Record := none
  let mut processes : Std.HashMap String String := {}
  let mut declared : List String := []
  for (process, time, record) in keyed do
    if let some (last, lastTime, earlier) := previous then
      if last == process && lastTime == time then
        throw
          s!"{record.location}: h_ts {time} of process '{process}' repeats {earlier.location}"
      if last != process then
        command := none
    previous := some (process, time, record)
    try
      let message ← field record.value "msg"
      if (optional message "cmd").isSome then
        command := some record
      else
        let function ← string message "function"
        let state ←
          if function == "retired_committed_tx" then
            pure Json.null
          else
            field message "state"
        let node ←
          string (if function == "retired_committed_tx" then message else state) "node_id"
        if let some other := processes[node]? then
          require (other == process)
            s!"node '{node}' is traced by processes '{other}' and '{process}'"
        processes := processes.insert node process
        events := events.push { record, command, time, function, node, message, state }
        declared := node :: declared
        if function == "retired_committed_tx" then
          declared := (← string message "retired_node_id") :: declared
        if function == "add_configuration" then
          declared := (← configuration message) ++ declared
    catch error =>
      throw s!"{record.location}: {error}"
  let streams :=
    processes.keys.mergeSort.toArray.map fun node => events.filter (·.node == node)
  return (streams, declared.mergeSort.eraseDups)

end Consensus.Replay
