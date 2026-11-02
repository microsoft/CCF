module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Interpreter

public section

namespace CCFRaft.Replay

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
  function : String
  node : String
  message : Json
  state : Json
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/-- Project events, carry command provenance, and collect node identities. -/
def prepareEvents (records : Array Record)
    : Except String (Array Event × List String) := do
  let mut events := #[]
  let mut command : Option Record := none
  let mut declared : List String := []
  for record in records do
    try
      let message ← field record.value "msg"
      if (optional message "cmd").isSome then
        command := some record
      else
        let function ← string message "function"
        let state ← field message "state"
        let node ← string state "node_id"
        events := events.push { record, command, function, node, message, state }
        declared := node :: declared
        if function == "add_configuration" then
          declared := (← configuration message) ++ declared
    catch error =>
      throw s!"{record.location}: {error}"
  return (events, declared.mergeSort.eraseDups)

end CCFRaft.Replay
