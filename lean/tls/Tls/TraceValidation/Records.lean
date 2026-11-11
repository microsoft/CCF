-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Lean.Data.Json

public section

/-!
Human-reviewed strict decoding of schema 1 NDJSON trace records, as written by the hooks in
`src/tls/openssl_connection_engine.h` and `src/tls/traffic_keys.h` in a `CCF_TLS_TRACING` build.
-/

namespace Tls.TraceValidation

open Lean

/-- One thing OpenSSL or the engine did during a pass, in the order in which it happened. -/
inductive Operation where
  /-- `r<type>`: OpenSSL decrypted a record with this inner content type. -/
  | recordIn (contentType : Nat)
  /-- `rk<0|1>`: OpenSSL processed a peer's KeyUpdate message. -/
  | keyUpdateIn (requested : Bool)
  /-- `w<type>`: OpenSSL encrypted a record with this inner content type. -/
  | recordOut (contentType : Nat)
  /-- `wk<0|1>`: OpenSSL constructed a KeyUpdate message. -/
  | keyUpdateOut (requested : Bool)
  /-- `d<bytes>`: `SSL_read` returned plaintext, which the engine handed to its owner. -/
  | delivered (bytes : Nat)
  /-- `s<bytes>`: `SSL_write` returned having written this much plaintext. -/
  | wrote (bytes : Nat)
  /-- `e<error>`: `SSL_read` failed with this `SSL_get_error` result. -/
  | readFailed (error : Nat)
  /-- `f<error>`: `SSL_write` failed with this `SSL_get_error` result. -/
  | writeFailed (error : Nat)
  /-- `x<reason>`: the reason OpenSSL queued for the protocol error just reported. -/
  | errorReason (reason : Nat)
  /-- `u0`: `SSL_key_update` failed. -/
  | updateFailed
  /-- `p0`: the input ended while the engine was filling its input buffer. -/
  | prefetchFailed
deriving DecidableEq, Repr

/-- The connection state and the operations which the hooks record for one worker pass. -/
structure Pass where
  /-- The engine, numbered within the traced process. -/
  engine : Nat
  /-- The connection id, unique within its engine. -/
  conn : Nat
  /-- This is the pass which completed the handshake. -/
  first : Bool
  /-- `TrafficKeyPolicy::record_budget`. -/
  budget : Nat
  /-- The loop dispatched the pass with a readable event. -/
  readable : Bool
  /-- `has_pending_input` when the pass began. -/
  pendingBefore : Bool
  /-- Bytes of output queued when the pass began, after this pass's sends were appended. -/
  queuedBefore : Nat
  /-- What happened, in order. -/
  operations : List Operation
  /-- What `drive_ready` returned: the connection survived the pass. -/
  alive : Bool
  /-- The connection was closed when the pass ended, whether or not it survived the pass. -/
  closed : Bool
  /-- `TrafficKeys::sent`. -/
  sent : Nat
  /-- `TrafficKeys::received`. -/
  received : Nat
  /-- `TrafficKeys::failed`. -/
  exceeded : Bool
  /-- `SSL_in_init`. -/
  inInit : Bool
  /-- `SSL_get_key_update_type() != SSL_KEY_UPDATE_NONE`. -/
  updateQueued : Bool
  /-- `write_retry_length`. -/
  retry : Nat
  /-- `want_write`. -/
  wantWrite : Bool
  /-- `read_wants_write`. -/
  readWantsWrite : Bool
  /-- Bytes of output queued when the pass ended. -/
  queued : Nat
  /-- `has_pending_input` when the pass ended. -/
  pending : Bool
deriving Repr

/-- A trace record. -/
inductive Event where
  /-- The first record. -/
  | traceStart (schema : Nat)
  /-- The test case or subcase which the following records come from. -/
  | label (kind name : String)
  /-- A worker pass over an established connection with a traffic-key policy. -/
  | pass (pass : Pass)
  /-- A traced connection was closed without a pass: shutdown, idle expiry or its output bound. -/
  | abort (engine conn : Nat)
  /-- The last record, with the number of records before it. -/
  | traceEnd (events : Nat)
deriving Repr

/-- The largest number a trace field may carry. -/
def uint64Max : Nat := UInt64.size - 1

private def nat64 (j : Json) : Except String Nat := do
  let value ← j.getNat?.mapError fun _ => "expected a nonnegative JSON integer"
  if value > uint64Max then throw "integer exceeds uint64"
  return value

private def field (j : Json) (name : String) : Except String Json :=
  (j.getObjVal? name).mapError fun _ => s!"missing field '{name}'"

/-- A required uint64 field. -/
def num (j : Json) (name : String) : Except String Nat :=
  (field j name).bind fun value => (nat64 value).mapError fun e => s!"field '{name}': {e}"

/-- A required string field. -/
def str (j : Json) (name : String) : Except String String :=
  (field j name).bind
    fun value =>
      value.getStr?.mapError fun _ => s!"field '{name}': expected a string"

private def boolean (j : Json) (name : String) : Except String Bool :=
  (field j name).bind
    fun value =>
      value.getBool?.mapError fun _ => s!"field '{name}': expected a boolean"

private def fields (j : Json) (allowed : List String) : Except String Unit := do
  let object ← j.getObj?.mapError fun _ => "expected a JSON object"
  match object.keys.find? (!allowed.contains ·) with
  | some key => throw s!"unknown field '{key}'"
  | none => return ()

private def digits (text : List Char) : Option Nat :=
  if text.isEmpty || text.length > 20 then
    none
  else
    text.foldl
      (fun value c =>
        value.bind fun n => if c.isDigit then some (n * 10 + (c.toNat - 48)) else none)
      (some 0)

/-- Decodes one operation token. -/
def decodeOperation (token : String) : Except String Operation :=
  let invalid : Except String Operation := .error s!"unknown operation '{token}'"
  match token.toList with
  | ['r', 'k', '0'] => .ok (.keyUpdateIn false)
  | ['r', 'k', '1'] => .ok (.keyUpdateIn true)
  | ['w', 'k', '0'] => .ok (.keyUpdateOut false)
  | ['w', 'k', '1'] => .ok (.keyUpdateOut true)
  | ['u', '0'] => .ok .updateFailed
  | ['p', '0'] => .ok .prefetchFailed
  | kind :: rest =>
      match digits rest with
      | none => invalid
      | some value =>
          match kind with
          | 'r' => .ok (.recordIn value)
          | 'w' => .ok (.recordOut value)
          | 'd' => .ok (.delivered value)
          | 's' => .ok (.wrote value)
          | 'e' => .ok (.readFailed value)
          | 'f' => .ok (.writeFailed value)
          | 'x' => .ok (.errorReason value)
          | _ => invalid
  | [] => invalid

private def decodePass (j : Json) : Except String Pass := do
  fields
    j
    [
      "seq",
      "type",
      "engine",
      "conn",
      "first",
      "budget",
      "readable",
      "pending_before",
      "queued_before",
      "ops",
      "alive",
      "closed",
      "sent",
      "received",
      "exceeded",
      "in_init",
      "update_queued",
      "retry",
      "want_write",
      "read_wants_write",
      "queued",
      "pending"
    ]
  let tokens ←
    (field j "ops").bind
      fun value =>
        value.getArr?.mapError fun _ => "field 'ops': expected an array"
  let operations ←
    tokens.toList.mapM
      fun token => do
        let text ← token.getStr?.mapError fun _ => "field 'ops': expected strings"
        decodeOperation text
  return {
    engine := ← num j "engine"
    conn := ← num j "conn"
    first := ← boolean j "first"
    budget := ← num j "budget"
    readable := ← boolean j "readable"
    pendingBefore := ← boolean j "pending_before"
    queuedBefore := ← num j "queued_before"
    operations
    alive := ← boolean j "alive"
    closed := ← boolean j "closed"
    sent := ← num j "sent"
    received := ← num j "received"
    exceeded := ← boolean j "exceeded"
    inInit := ← boolean j "in_init"
    updateQueued := ← boolean j "update_queued"
    retry := ← num j "retry"
    wantWrite := ← boolean j "want_write"
    readWantsWrite := ← boolean j "read_wants_write"
    queued := ← num j "queued"
    pending := ← boolean j "pending"
  }

/-- Decodes one record into its sequence number and event. -/
def decode (j : Json) : Except String (Nat × Event) := do
  let seq ← num j "seq"
  let event ←
    match ← str j "type" with
    | "trace_start" => do
        fields j ["seq", "type", "schema"]
        pure (Event.traceStart (← num j "schema"))
    | "case" => do
        fields j ["seq", "type", "name"]
        pure (Event.label "case" (← str j "name"))
    | "subcase" => do
        fields j ["seq", "type", "name"]
        pure (Event.label "subcase" (← str j "name"))
    | "pass" => Event.pass <$> decodePass j
    | "abort" => do
        fields j ["seq", "type", "engine", "conn"]
        pure (Event.abort (← num j "engine") (← num j "conn"))
    | "trace_end" => do
        fields j ["seq", "type", "events"]
        pure (Event.traceEnd (← num j "events"))
    | other => throw s!"unknown record type '{other}'"
  return (seq, event)

/-- Parses one line as a JSON object. -/
def parseLine (line : String) : Except String Json := do
  let json ← (Json.parse line).mapError fun e => s!"invalid JSON: {e}"
  match json with
  | .obj _ => return json
  | _ => throw "expected a JSON object"

end Tls.TraceValidation
