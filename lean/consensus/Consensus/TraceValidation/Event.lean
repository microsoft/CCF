module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Lean.Data.Json

@[expose] public section

/-!
# Trace events for messy-model trace validation

Decoding only: one record per line, `{process_id, h_ts, msg}`. Command records
(`msg.cmd`) are driver provenance and are kept apart. Every other record is one
trace event of the node named by `msg.state.node_id` (or `msg.node_id` for
`retired_committed_tx`, which carries no snapshot).

Events are split into one stream per node, ordered by `h_ts` within the node's
process. The global order across processes is never used.
-/

namespace Consensus.TraceValidation.Exec

open Lean

structure Ev where
  file : String
  line : Nat
  process : String
  hts : Nat
  node : String
  function : String
  /-- The `msg` object, including `function` and `state`. -/
  msg : Json
deriving Inhabited

def Ev.loc (e : Ev) : String := s!"{e.file}:{e.line} [{e.function}]"

def Ev.keys (e : Ev) : List String :=
  match e.msg.getObj? with
  | .ok o => o.toList.map Prod.fst |>.filter (· != "function")
  | .error _ => []

def natural : Json -> Except String Nat
  | .num { mantissa := .ofNat value, exponent := 0 } => pure value
  | j => throw s!"expected natural number, got {j.compress}"

def getNat (j : Json) (k : String) : Except String Nat := do
  natural (← (j.getObjVal? k).mapError (fun e => s!"{k}: {e}"))

def getStr (j : Json) (k : String) : Except String String := do
  (← (j.getObjVal? k).mapError (fun e => s!"{k}: {e}")).getStr?

structure Trace where
  events : Array Ev
  commands : Nat
  records : Nat

/-- Decode one ndjson capture. -/
def decode (file input : String) : Except String Trace := do
  let mut events := #[]
  let mut commands := 0
  let mut records := 0
  let lines := input.splitOn "\n"
  for raw in lines, line in [1:lines.length + 1] do
    if raw.trimAscii.isEmpty then continue
    let loc := s!"{file}:{line}"
    let value ← (Json.parse raw).mapError (fun e => s!"{loc}: {e}")
    records := records + 1
    let msg ← (value.getObjVal? "msg").mapError (fun e => s!"{loc}: {e}")
    if (msg.getObjVal? "cmd").isOk then
      commands := commands + 1
      continue
    let process ← (getStr value "process_id").mapError (fun e => s!"{loc}: {e}")
    let hts ← (getNat value "h_ts").mapError (fun e => s!"{loc}: {e}")
    let function ← (getStr msg "function").mapError (fun e => s!"{loc}: {e}")
    let node ←
      (if function == "retired_committed_tx" then
          getStr msg "node_id"
        else do
          getStr (← msg.getObjVal? "state") "node_id").mapError
        (fun e => s!"{loc}: {e}")
    events := events.push { file, line, process, hts, node, function, msg }
  return { events, commands, records }

def readTrace (path : System.FilePath) : IO (Except String Trace) := do
  let input ← IO.FS.readFile path
  return decode path.toString input

/-- One stream per node, ordered by `h_ts`; a node must live in one process. -/
def streams (trace : Trace) : Except String (List (String × Array Ev)) := do
  let nodes := (trace.events.toList.map (·.node)).mergeSort.eraseDups
  nodes.mapM
    fun node => do
      let evs := trace.events.filter (·.node == node)
      let procs := (evs.toList.map (·.process)).eraseDups
      unless procs.length == 1 do
        throw s!"node {node} spans processes {procs}"
      let sorted := evs.qsort (fun a b => a.hts < b.hts)
      for i in [1:sorted.size] do
        if sorted[i - 1]!.hts == sorted[i]!.hts then
          throw s!"{sorted[i]!.loc}: duplicate h_ts {sorted[i]!.hts} in process {procs}"
      return (node, sorted)

end Consensus.TraceValidation.Exec
