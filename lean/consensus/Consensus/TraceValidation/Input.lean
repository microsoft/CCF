module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Abs
public import Consensus.TraceValidation.Event

@[expose] public section

/-!
# Validator input (reviewed)

The trusted path from a trace file to the arguments of `validate`: `load` decodes the file
(`Exec.decode`), splits it into one stream per node (`Exec.streams`) and computes the
trace-wide parameters (`environment`). A reviewer checks it against the capture format in
`cft_trace_msgpack.h` and `consensus/replay/README.md`.
-/

namespace Consensus.TraceValidation

open Lean
open CCF (Finset)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Ev)

/-- Trace-wide parameters, computed by the decoder. -/
structure Env where
  /-- The trace's node ids, sorted. -/
  names : Names
  /-- Every node's address, as in configuration hooks. -/
  addrs : List (Exec.NodeId × String)
  /-- The genesis configuration: the node whose first event is `become_leader`. -/
  genesis : Finset NodeID

/-- The `(node id, address)` pairs anywhere in an event. -/
partial def collectAddrs (j : Json) (acc : List (Exec.NodeId × String))
    : List (Exec.NodeId × String) :=
  match j with
  | .obj kvs =>
      kvs.toArray.foldl (init := acc)
        fun acc (k, v) =>
          match v.getObjValAs? String "address" with
          | .ok a => if acc.contains (k, a) then acc else (k, a) :: acc
          | .error _ => collectAddrs v acc
  | .arr vs => vs.foldl (init := acc) fun acc v => collectAddrs v acc
  | _ => acc

/--
The environment and the per-node streams, keyed by clean id: the node ids are those with a
stream or an address, the genesis configuration is the one node whose stream starts with
`become_leader`.
-/
def environment (ss : List (Exec.NodeId × Array Ev))
    : Except String (Env × List (NodeID × List Ev)) := do
  let addrs :=
    ss.foldl (init := [])
      fun acc (_, evs) =>
        evs.foldl (init := acc) fun acc e => collectAddrs e.msg acc
  for (n, a) in addrs do
    if addrs.any fun (m, b) => m == n && b != a then throw s!"node {n} has two addresses"
  let ids := ((ss.map Prod.fst) ++ addrs.map Prod.fst).mergeSort (· <= ·) |>.eraseDups
  let names : Names := { known := ids.toArray }
  let firsts :=
    ss.filterMap
      fun (n, evs) =>
        if (evs[0]?.map (·.function)) == some "become_leader" then
          some (names.id n)
        else
          none
  unless firsts.length == 1 do
    throw
      s!"expected one genesis node (stream starting with become_leader), found {firsts.length}"
  let env : Env := { names, addrs, genesis := CCF.Finset.ofList firsts }
  return (env, ss.map fun (n, evs) => (names.id n, evs.toList))

/-- A trace file, as `validate`'s arguments. -/
def load (path : System.FilePath)
    : IO (Except String (Env × List (NodeID × List Ev))) := do
  let input ← IO.FS.readFile path
  return do
    environment (← Exec.streams (← Exec.decode path.toString input))

end Consensus.TraceValidation
