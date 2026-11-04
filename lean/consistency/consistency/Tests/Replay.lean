-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

meta import consistency.TraceValidation
import consistency.TraceValidation

open Lean consistency.Model consistency.TraceValidation

private def record (action kind : String) (fields : List (String × Json) := []) : Json :=
  Json.mkObj ([("action", toJson action), ("type", toJson kind)] ++ fields)

private def request (kind : String) (tx : Nat) : Json :=
  record s!"{kind}TxRequestAction" s!"{kind}TxRequest" [("tx", toJson tx)]

private def write (action : String) (tx view seqno : Nat) : Json :=
  record s!"RwTx{action}Action" s!"RwTx{action}"
    [("tx", toJson tx), ("tx_id", toJson [view, seqno])]

private def status (value : String) (view seqno : Nat) : Json :=
  record s!"Status{value}ResponseAction" "TxStatusReceived"
    [("tx_id", toJson [view, seqno]), ("status", toJson s!"{value}Status")]

private def writeTrace : List Json :=
  [request "Rw" 0, write "Execute" 0 2 10, write "Response" 0 2 10]

private def check (name : String) (records : List Json) (accepted : Bool) : IO Unit := do
  let result := records.foldlM replayRecord initialState
  unless result.isOk == accepted do
    throw (IO.userError s!"{name}: unexpected replay result: {repr result}")

private def run : IO Unit := do
  let committed := writeTrace ++ [status "Committed" 2 10]
  check "write and commit" committed true
  check "election drops known invalid suffix before filling a gap"
    (writeTrace
      ++ [
        status "Invalid" 2 10,
        request "Rw" 1,
        write "Execute" 1 3 12,
        write "Response" 1 3 12,
        status "Committed" 3 12
      ]) true
  check "forwarded read"
    (committed
      ++ [
        request "Ro" 1,
        record "RoTxResponseAction" "RoTxResponse"
          [("tx", toJson (1 : Nat)), ("tx_id", toJson ([2, 10] : List Nat))]
      ])
    true
  check "read backfill"
    [
      request "Ro" 0,
      record "RoTxResponseAction" "RoTxResponse"
        [("tx", toJson (0 : Nat)), ("tx_id", toJson ([4, 12] : List Nat))]
    ]
    true
  check "unknown action" [record "Other" "Other"] false
  check "action/type mismatch" [record "RwTxRequestAction" "RoTxRequest"] false
  check "missing field" [record "RwTxRequestAction" "RwTxRequest"] false
  check "request ID" [request "Rw" 1] false
  check "missing request" [write "Execute" 0 2 10] false
  check "missing execution" [request "Rw" 0, write "Response" 0 2 10] false
  check "reserved view" [request "Rw" 0, write "Execute" 0 1 10] false
  check "zero sequence number" [request "Rw" 0, write "Execute" 0 2 0] false
  check "wrong response ID" (writeTrace.take 2 ++ [write "Response" 0 2 11]) false
  check "duplicate response" (writeTrace ++ [write "Response" 0 2 10]) false
  check "invalid after commit" (committed ++ [status "Invalid" 2 10]) false
  check "commit after invalid"
    (writeTrace ++ [status "Invalid" 2 10, status "Committed" 2 10]) false
  check "rollback below commitment"
    (committed ++ [request "Rw" 1, write "Execute" 1 3 10]) false
  check "status without response" [status "Committed" 2 10] false
  check "status mismatch"
    (writeTrace
      ++ [record "StatusCommittedResponseAction" "TxStatusReceived"
            [("tx_id", toJson ([2, 10] : List Nat)), ("status", toJson "InvalidStatus")]])
    false

#eval run
