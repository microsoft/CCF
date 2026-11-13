-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import consistency.Model
public import Lean.Data.Json

public section

namespace consistency.TraceValidation

open Lean Model

private def string (record : Json) (field : String) : Except String String :=
  (record.getObjVal? field).bind Json.getStr?

private def nat (record : Json) (field : String) : Except String Nat :=
  (record.getObjVal? field).bind Json.getNat?

private def apply (state : State) (action : Action) : Except String State := do
  let some next := Model.step state action
  | throw s!"disabled model action: {repr action}"
  return next

private def responseIndex (state : State) (id : TxID) : Except String Nat := do
  let some index :=
    state.history.findIdx?
      fun event =>
        match event with
        | .response .rw _ _ observed => observed == id
        | _ => false
  | throw s!"no write response for {repr id}"
  return index + 1

/-- State for replaying a trace: the model state, and each node's latest vote request as
(node, view, last committable sequence number, view of that entry). -/
private structure Replay where
  model : State := initialState
  votes : List (String × Nat × Nat × Nat) := []

/-- Replay one `ccf.cft` consensus trace event exported by a node, or a transaction status
given to a client, using the guarded consistency model. Nothing is reconstructed: a new
leader keeps the prefix that it reported when requesting votes, and every ledger entry is
replayed as a write, so that it can be reported committed or invalid. A trace missing an
election or an entry is rejected. Consensus events the model does not use are skipped. -/
private def replayEvent (replay : Replay) (event : Json) : Except String Replay := do
  let model := replay.model
  let node := event.getObjVal? "state"
  match ← string event "function" with
  | "send_request_vote" =>
      let id ← string (← node) "node_id"
      let packet ← event.getObjVal? "packet"
      let term ← nat packet "term"
      let kept ← nat packet "last_committable_idx"
      let source ← nat packet "term_of_last_committable_idx"
      let votes := replay.votes.filter (·.1 != id)
      return { replay with votes := (id, term, kept, source) :: votes }
  | "become_leader" =>
      let id ← string (← node) "node_id"
      let view ← nat (← node) "current_view"
      let length ← nat (← node) "last_idx"
      let latest := model.branches.length
      unless view > latest || model == initialState do
        throw s!"view {view} already has a leader"
      -- The new leader's ledger is a prefix of the branch of its last entry's view.
      let vote :=
        replay.votes.find?
          fun (voter, term, kept, _) => voter == id && term == view && kept == length
      let source := (vote.map (·.2.2.2)).getD latest
      let mut model := model
      for _ in [:view - latest] do
        model ← apply model (.elect source length)
      return { replay with model }
  | "replicate" =>
      let view ← nat event "view"
      let model ← apply model (.request .rw)
      let request := model.history.length
      let model ← apply model (.execute request view)
      let model ← apply model (.respond request view (← nat event "seqno"))
      return { replay with model }
  | "commit" =>
      -- A node's ledger up to its commit point is a prefix of its current view's branch.
      let view ← nat (← node) "current_view"
      let seqno ← nat event "idx"
      let some entry := (at? model.branches view).bind (at? · seqno)
      | throw s!"commit of unknown entry {seqno} in view {view}"
      let model ← apply model (.commit (← responseIndex model ⟨entry.view, seqno⟩))
      return { replay with model }
  | "tx_status" =>
      let index ← responseIndex model ⟨← nat event "view", ← nat event "seqno"⟩
      let action ←
        match ← string event "status" with
        | "Committed" => pure (Action.commit index)
        | "Invalid" => pure (Action.invalidate index)
        | status => throw s!"status {status} is not final"
      return { replay with model := ← apply model action }
  | _ => return replay

/-- Replay a nonempty NDJSON capture, reporting the exact failing line.
Each record holds one event in its `msg` field. -/
def checkFile (path : System.FilePath) : IO Nat := do
  let input ← IO.FS.Handle.mk path .read
  let mut state : Replay := {}
  let mut lineNumber := 0
  let mut events := 0
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    lineNumber := lineNumber + 1
    if line.trimAscii.toString.isEmpty then continue
    match (Json.parse line).bind (·.getObjVal? "msg") |>.bind (replayEvent state) with
    | .error message => throw (IO.userError s!"{path}:{lineNumber}: {message}")
    | .ok next => state := next
    events := events + 1
  if events == 0 then throw (IO.userError s!"{path}: empty trace")
  return events

end consistency.TraceValidation
