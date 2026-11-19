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

private def tx (record : Json) : Except String Nat :=
  (record.getObjVal? "tx").bind Json.getNat?

private def txid (record : Json) : Except String TxID := do
  let values ← (record.getObjVal? "tx_id").bind Json.getArr?
  let [view, seqno] := values.toList | throw "tx_id must contain [view, seqno]"
  let view ← view.getNat?
  let seqno ← seqno.getNat?
  unless view ≥ 2 && seqno > 0 do
    throw "tx_id requires view >= 2 and seqno > 0"
  return ⟨view, seqno⟩

private def apply (state : State) (action : Action) : Except String State := do
  let some next := Model.step state action
  | throw s!"disabled model action: {repr action}"
  return next

/-- Fill unobserved elections and non-application entries as in TraceMultiNodeReads.
Every inserted action goes through the model's guards, including committed-prefix checks. -/
private def prepare (state : State) (id : TxID) (length : Nat) : Except String State := do
  let mut state := state
  for _ in [:id.view - state.branches.length] do
    let source := state.branches.length
    let some ledger := at? state.branches source | throw "missing election source"
    let retained :=
      (ledger.zipIdx.takeWhile
        fun (entry, index) =>
          !((statusIDs state.history .invalid).contains ⟨entry.view, index + 1⟩)).length
    state ← apply state (.elect source (min (id.seqno - 1) retained))
  let some ledger := at? state.branches id.view | throw "missing branch"
  unless ledger.length ≤ length do
    throw "observed position precedes the reconstructed branch tip"
  for _ in [:length - ledger.length] do
    state ← apply state (.appendOther id.view)
  return state

private def requestIndex (state : State) (kind : TxType) (id : Nat)
    : Except String Nat := do
  let some index := state.history.findIdx? (· == .request kind id)
  | throw s!"no {repr kind} request for tx {id}"
  return index + 1

private def responseIndex (state : State) (id : TxID) : Except String Nat := do
  let some index :=
    state.history.findIdx?
      fun event =>
        match event with
        | .response .rw _ _ observed => observed == id
        | _ => false
  | throw s!"no write response for {repr id}"
  return index + 1

private def checkResponse (state : State) (id : TxID) : Except String State := do
  let some (.response _ _ _ observed) := state.history.getLast?
  | throw "model did not produce a response"
  unless observed == id do
    throw s!"response ID mismatch: expected {repr id}, got {repr observed}"
  return state

/-- Replay one existing `tests/tvc.py` record using the guarded consistency model.
Application values are absent from this format and are not compared. -/
def replayRecord (state : State) (record : Json) : Except String State := do
  match ← string record "action", ← string record "type" with
  | "RwTxRequestAction", "RwTxRequest"
  | "RoTxRequestAction", "RoTxRequest" =>
      unless (← tx record) == nextRequestId state.history do
        throw "request IDs must start at zero and increase by one"
      apply state
        (.request (if (← string record "type") == "RwTxRequest" then .rw else .ro))
  | "RwTxExecuteAction", "RwTxExecute" =>
      let id ← txid record
      let index ← requestIndex state .rw (← tx record)
      let state ← prepare state id (id.seqno - 1)
      apply state (.execute index id.view)
  | "RwTxResponseAction", "RwTxResponse" =>
      let id ← txid record
      let index ← requestIndex state .rw (← tx record)
      checkResponse (← apply state (.respond index id.view id.seqno)) id
  | "RoTxResponseAction", "RoTxResponse" =>
      let id ← txid record
      let index ← requestIndex state .ro (← tx record)
      let state ← prepare state id id.seqno
      checkResponse (← apply state (.read index id.view)) id
  | "StatusCommittedResponseAction", "TxStatusReceived" =>
      unless (← string record "status") == "CommittedStatus" do
        throw "committed action requires CommittedStatus"
      apply state (.commit (← responseIndex state (← txid record)))
  | "StatusInvalidResponseAction", "TxStatusReceived" =>
      unless (← string record "status") == "InvalidStatus" do
        throw "invalid action requires InvalidStatus"
      apply state (.invalidate (← responseIndex state (← txid record)))
  | action, kind => throw s!"unknown action/type pair: {action}/{kind}"

/-- Replay a nonempty NDJSON capture, reporting the exact failing line. -/
def checkFile (path : System.FilePath) : IO Nat := do
  let input ← IO.FS.Handle.mk path .read
  let mut state := initialState
  let mut lineNumber := 0
  let mut events := 0
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    lineNumber := lineNumber + 1
    if line.trimAscii.toString.isEmpty then continue
    match (Json.parse line).bind (replayRecord state) with
    | .error message => throw (IO.userError s!"{path}:{lineNumber}: {message}")
    | .ok next => state := next
    events := events + 1
  if events == 0 then throw (IO.userError s!"{path}: empty trace")
  return events

end consistency.TraceValidation
