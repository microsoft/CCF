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

def text (value : Json) : Except String String := do
  let name ← value.getStr?
  require (!name.isEmpty) "expected nonempty string"
  return name

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
  return (nodes.map Prod.fst).mergeSort

structure Record where
  file : String
  line : Nat
  value : Json
deriving Inhabited

def Record.location (record : Record) : String := s!"{record.file}:{record.line}"

/-- Read one JSON record per line without a schema pass. -/
def parseLog (file input : String) : Except String (Array Record) := do
  let mut records := #[]
  let lines := input.splitOn "\n"
  let lines := if input.endsWith "\n" then lines.dropLast else lines
  for raw in lines, line in [1:lines.length + 1] do
    let raw := if raw.endsWith "\r" then raw.dropEnd 1 |>.toString else raw
    let value ← (Json.parse raw).mapError (fun error => s!"{file}:{line}: {error}")
    records := records.push { file, line, value }
  require (!records.isEmpty)
    s!"{file}: empty trace; no Raft events (configure the driver's trace collector)"
  return records

def readLog (path : System.FilePath) : IO (Except String (Array Record)) := do
  let path ← IO.FS.realPath path
  let bytes ← IO.FS.readBinFile path
  let some input := String.fromUTF8? bytes
  | return .error s!"{path}: invalid UTF-8"
  return parseLog path.toString input

structure Event where
  record : Record
  command : Record
  function : String
  node : String
  message : Json
  state : Json
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/-- Validate input, preserve capture order, attach commands, and discover node identities. -/
def prepareEvents (records : Array Record)
    : Except String (Array Event × List String) := do
  let mut events := #[]
  let mut command : Option Record := none
  let mut nodes : List String := []
  let mut process : Option String := none
  let mut sequence := 0
  for record in records do
    try
      let row := record.value
      require ((← string row "tag") == "ccf.raft_trace")
        "expected ccf.raft_trace envelope"
      let identity ← string row "process_id"
      require (process.all (· == identity)) "mixed trace processes"
      require ((← nat row "h_ts") == sequence)
        "missing, duplicate or reordered trace sequence"
      process := some identity
      sequence := sequence + 1
      let message ← field row "msg"
      if let some cmd := optional message "cmd" then
        let parts := (← text cmd).splitOn ","
        let name := parts.head!
        let mut created := []
        if ["start_node", "create_new_node", "nodes"].contains name then
          created := parts.drop 1
        else if ["trust_node", "trust_nodes"].contains name then
          created := parts.drop 2
        else if name == "swap_node" then
          created := parts.drop 3
        else if name == "swap_nodes" then
          let mut incoming := false
          for part in parts.drop 2 do
            if part == "in" then
              incoming := true
            else if part == "out" then
              incoming := false
            else if incoming then
              created := created ++ [part]
        for node in created do
          let _ ← text (.str node)
          require (!nodes.contains node) s!"duplicate node creation '{node}'"
          nodes := nodes ++ [node]
        command := some record
      else
        let some cmd := command | throw "event before command"
        let function ← string message "function"
        let state ← field message "state"
        require
          (["None", "Follower", "PreVoteCandidate", "Candidate", "Leader"].contains
            (← string state "leadership_state"))
          "invalid role"
        require
          (match ← string state "membership_state", optional state "retirement_phase" with
            | "Active", none | "Active", some .null => true
            | "Retired", some (.str phase) =>
                ["Ordered", "Signed", "Completed", "RetiredCommitted"].contains phase
            | _, _ => false)
          "unsupported membership/retirement phase"
        for key in ["current_view", "last_idx", "commit_idx"] do
          let _ ← nat state key
        for key
            in [
              "retirement_idx",
              "retirement_committable_idx",
              "retired_committed_idx"
            ] do
          if let some value := optional state key then
            unless value == .null do
              let _ ← natural value
        if let some markers := optional state "committable_indices" then
          let _ ← (← markers.getArr?).toList.mapM natural
        if let some configurations := optional message "configurations" then
          for value in ← configurations.getArr? do
            let _ ← configuration value
            let _ ← nat value "idx"
        let node ← string state "node_id"
        unless nodes.contains node do
          nodes := nodes ++ [node]
        events := events.push { record, command := cmd, function, node, message, state }
    catch error =>
      throw s!"{record.location}: {error}"
  require (!events.isEmpty) "trace contains commands but no Raft events"
  return (events, nodes.mergeSort)

end CCFRaft.Replay
