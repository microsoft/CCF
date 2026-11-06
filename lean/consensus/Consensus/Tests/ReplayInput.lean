module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Consensus.Replay.Input
import Consensus.Replay.Input

open Lean Consensus.Replay

private def retirement (node : String := "0") (seqno : Nat := 2) : Json :=
  Json.mkObj
    [
      ("function", toJson "retired_committed_tx"),
      ("node_id", toJson node),
      ("seqno", toJson seqno),
      ("retired_node_id", toJson "1")
    ]

private def append (node : String := "0") (seqno : Nat := 2) (signature : Bool := false)
    : Json :=
  Json.mkObj
    [
      ("function", toJson "replicate"),
      ("state", Json.mkObj [("node_id", toJson node)]),
      ("seqno", toJson seqno),
      ("globally_committable", toJson signature)
    ]

private def confirmations (messages : List Json)
    : Except String (List (List String)) := do
  let records :=
    messages.toArray.map
      fun message =>
        { file := "test", line := 1, value := Json.mkObj [("msg", message)] : Record }
  let (events, _) ← prepareEvents records
  return events.toList.map (·.retirementConfirmations)

#guard confirmations [retirement, append] == .ok [["1"]]
#guard confirmations [retirement "other", append] == .ok [[]]
#guard confirmations [retirement "0" 1, append] == .ok [[]]
#guard confirmations [retirement, append "0" 1, append] == .ok [[], ["1"]]
#guard confirmations [retirement] == .ok []
#guard confirmations [append, retirement] == .ok [[]]
#guard (confirmations [retirement, append "0" 2 true]).toOption.isNone
