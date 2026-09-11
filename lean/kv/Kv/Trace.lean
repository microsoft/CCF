-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Protocol.Model
import Lean.Data.Json

namespace Kv.Trace
open Lean

def uint64Max : Nat := UInt64.size - 1

def nat64 (j : Json) : Except String Nat := do
  let v ← j.getNat?.mapError fun _ =>
    if j matches .num _ then "expected a nonnegative JSON integer, not a floating-point number"
    else "expected a JSON integer"
  if v > uint64Max then throw "integer exceeds uint64"
  return v

def field (j : Json) (name : String) : Except String Json := j.getObjVal? name
def str (j : Json) (name : String) : Except String String := (field j name).bind Json.getStr?
def num (j : Json) (name : String) : Except String Nat := (field j name).bind nat64
def boolean (j : Json) (name : String) : Except String Bool := (field j name).bind Json.getBool?

def hex (j : Json) : Except String String := do
  let s ← j.getStr?
  if s.length % 2 != 0 || !s.all (fun c => c.isDigit || ('a' ≤ c && c ≤ 'f')) then
    throw "bytes must be even-length lowercase hexadecimal (empty bytes are allowed)"
  return s

def bytes (j : Json) (name : String) : Except String String := (field j name).bind hex

def nullable (f : Json → Except String α) (j : Json) : Except String (Option α) :=
  match j with
  | .null => .ok none
  | _ => some <$> f j

def optionalBytes (j : Json) (name : String) : Except String (Option String) :=
  (field j name).bind (nullable hex)

def optionalNum (j : Json) (name : String) : Except String (Option Nat) :=
  (field j name).bind (nullable nat64)

def fields (j : Json) (allowed : List String) : Except String Unit := do
  match (← j.getObj?).keys.find? (!allowed.contains ·) with
  | some k => throw s!"unknown field '{k}'"
  | none => return ()

def numberChar (c : Char) : Bool :=
  c.isDigit || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'

open Std.Internal.Parsec Std.Internal.Parsec.String in
/-- The bundled parser normalizes numbers and object keys. Check the lexical
information it would otherwise discard before giving it any numeric input. -/
partial def lexicalScan (objects : List (List String)) : Parser Unit := do
  match ← peek? with
  | none => return ()
  | some '"' =>
    skip
    let key ← Json.Parser.str
    ws
    if (← peek?) != some ':' then lexicalScan objects
    else match objects with
      | [] => fail "object key outside object"
      | keys :: parents =>
        if keys.contains key then fail s!"duplicate object key '{key}'"
        lexicalScan ((key :: keys) :: parents)
  | some '{' => skip; lexicalScan ([] :: objects)
  | some '}' => skip; lexicalScan (objects.drop 1)
  | some c =>
    skip
    if !(c.isDigit || c == '-') then lexicalScan objects
    else
      let token := c.toString ++ (← manyChars (satisfy numberChar))
      if !token.all Char.isDigit || token.length > 20 then
        fail "number must be an exact nonnegative uint64 JSON integer (no sign, fraction, or exponent)"
      lexicalScan objects

open Std.Internal.Parsec in
def lexicalCheck (line : String) : Except String Unit :=
  match lexicalScan [] ⟨line, line.startPos⟩ with
  | .success .. => .ok ()
  | .error _ .eof => .error "unterminated JSON string"
  | .error _ (.other message) => .error message

def decodeWrites (j : Json) : Except String Pending := do
  let array ← j.getArr?
  array.toList.mapM fun item => do
    fields item ["map", "key", "value"]
    return ((← str item "map", ← bytes item "key"), ← optionalBytes item "value")

def eventFields (kind : String) : Except String (List String) :=
  let st := ["store", "tx"]
  let mp := st ++ ["map"]
  match kind with
  | "trace_start" => .ok ["schema"]
  | "case_begin" | "subcase_begin" | "subcase_end" => .ok ["name"]
  | "case_end" => .ok ["name", "failed"]
  | "store_create" | "store_end" => .ok ["store"]
  | "tx_create" | "tx_end" | "commit_begin" => .ok st
  | "snapshot" => .ok (st ++ ["version", "global", "term"])
  | "map_acquire" => .ok (mp ++ ["version", "global"])
  | "map_unavailable" | "clear" => .ok mp
  | "get" | "get_global" | "has" | "has_global" | "previous_write" | "put" =>
    .ok (mp ++ ["key", "value"])
  | "remove" => .ok (mp ++ ["key"])
  | "size" => .ok (mp ++ ["value"])
  | "foreach_begin" | "foreach_end" => .ok (mp ++ ["iteration"])
  | "foreach_entry" => .ok (mp ++ ["iteration", "key", "value"])
  | "foreach_continue" => .ok (mp ++ ["iteration", "value"])
  | "apply" => .ok (st ++ ["version", "term", "writes"])
  | "commit_result" => .ok (st ++ ["result", "version"])
  | "compact" => .ok ["store", "version", "requested"]
  | "rollback" => .ok ["store", "version", "requested", "term"]
  | "rollback_rejected" => .ok ["store", "requested", "term"]
  | "unsupported" => .ok ["store", "operation"]
  | "trace_end" => .ok ["events"]
  | _ => .error s!"unknown event type '{kind}'"

def decodeEvent (j : Json) (kind : String) : Except String Event := do
  fields j (["type", "seq"] ++ (← eventFields kind))
  match kind with
  | "trace_start" => return .traceStart (← num j "schema")
  | "case_begin" => return .caseBegin (← str j "name")
  | "case_end" => return .caseEnd (← str j "name") (← boolean j "failed")
  | "subcase_begin" => return .subcaseBegin (← str j "name")
  | "subcase_end" => return .subcaseEnd (← str j "name")
  | "store_create" => return .storeCreate (← num j "store")
  | "store_end" => return .storeEnd (← num j "store")
  | "tx_create" => return .txCreate (← num j "store") (← num j "tx")
  | "tx_end" => return .txEnd (← num j "store") (← num j "tx")
  | "snapshot" =>
    return .snapshot (← num j "store") (← num j "tx") (← num j "version")
      (← num j "global") (← num j "term")
  | "map_acquire" =>
    return .acquire (← num j "store") (← num j "tx") (← str j "map")
      (← num j "version") (← num j "global")
  | "map_unavailable" =>
    return .unavailable (← num j "store") (← num j "tx") (← str j "map")
  | "get" | "get_global" =>
    return .get (← num j "store") (← num j "tx") (← str j "map") (← bytes j "key")
      (← optionalBytes j "value") (kind == "get_global")
  | "has" | "has_global" =>
    return .has (← num j "store") (← num j "tx") (← str j "map") (← bytes j "key")
      (← boolean j "value") (kind == "has_global")
  | "previous_write" =>
    return .previous (← num j "store") (← num j "tx") (← str j "map") (← bytes j "key")
      (← optionalNum j "value")
  | "put" =>
    return .put (← num j "store") (← num j "tx") (← str j "map") (← bytes j "key")
      (← bytes j "value")
  | "remove" =>
    return .remove (← num j "store") (← num j "tx") (← str j "map") (← bytes j "key")
  | "clear" => return .clear (← num j "store") (← num j "tx") (← str j "map")
  | "size" => return .size (← num j "store") (← num j "tx") (← str j "map") (← num j "value")
  | "foreach_begin" =>
    return .foreachBegin (← num j "store") (← num j "tx") (← str j "map") (← num j "iteration")
  | "foreach_entry" =>
    return .foreachEntry (← num j "store") (← num j "tx") (← str j "map")
      (← num j "iteration") (← bytes j "key") (← bytes j "value")
  | "foreach_continue" =>
    return .foreachContinue (← num j "store") (← num j "tx") (← str j "map")
      (← num j "iteration") (← boolean j "value")
  | "foreach_end" =>
    return .foreachEnd (← num j "store") (← num j "tx") (← str j "map") (← num j "iteration")
  | "commit_begin" => return .commitBegin (← num j "store") (← num j "tx")
  | "apply" =>
    return .apply (← num j "store") (← num j "tx") (← num j "version")
      (← num j "term") (← decodeWrites (← field j "writes"))
  | "commit_result" =>
    let result ← match ← str j "result" with
      | "success" => pure Outcome.success
      | "conflict" => pure Outcome.conflict
      | "no_replicate" => pure Outcome.noReplicate
      | other => throw s!"unknown commit result '{other}'"
    return .commitResult (← num j "store") (← num j "tx") result (← num j "version")
  | "compact" => return .compact (← num j "store") (← num j "version") (← num j "requested")
  | "rollback" =>
    return .rollback (← num j "store") (← num j "version") (← num j "requested") (← num j "term")
  | "rollback_rejected" =>
    return .rollbackRejected (← num j "store") (← num j "requested") (← num j "term")
  | "unsupported" =>
    let sid ← match field j "store" with
      | .error _ => pure none
      | .ok value => some <$> nat64 value
    return .unsupported sid (← str j "operation")
  | "trace_end" => return .traceEnd (← num j "events")
  | _ => throw s!"unknown event type '{kind}'"

def decode (j : Json) : Except String Record := do
  return { seq := ← num j "seq", event := ← decodeEvent j (← str j "type") }

def parseLine (line : String) : Except String Json := do
  lexicalCheck line
  Json.parse line

structure Report where
  status : String
  events : Nat
  message : String
  seq? : Option Nat := none
  store? : Option Nat := none
  tx? : Option Nat := none
  deriving Repr, BEq, ToJson

def statusName : FailureKind → String
  | .rejected => "rejected"
  | .invalidTrace => "invalid_trace"
  | .unsupported => "unsupported"

def failureReport (w : World) (j : Json) (failure : Failure) : Report :=
  let kind := (str j "type").toOption.getD "<undecoded>"
  let seq := (num j "seq").toOption
  let sid := (num j "store").toOption
  let tid := (num j "tx").toOption
  { status := statusName failure.kind
    events := w.count
    message := s!"event {w.count + 1} type={kind} case={w.currentCase.getD "<none>"} store={repr sid} tx={repr tid}: {failure.message}"
    seq? := seq, store? := sid, tx? := tid }

def checkLine (w : World) (line : String) : Except Report World := do
  let j ← match parseLine line with
    | .ok j => pure j
    | .error message => throw (failureReport w .null ⟨.invalidTrace, message⟩)
  let r ← match decode j with
    | .ok r => pure r
    | .error message => throw (failureReport w j ⟨.invalidTrace, message⟩)
  match step w r with
  | .ok next => return next
  | .error failure => throw (failureReport w j failure)

def finishReport (w : World) : Report :=
  if !w.ended then
    failureReport w .null ⟨.invalidTrace, "truncated stream: missing trace_end"⟩
  else
    { status := "accepted", events := w.count, message := s!"accepted {w.count} events in {w.cases} cases" }

def checkLines (lines : List String) : Report := Id.run do
  let mut w : World := {}
  for line in lines do
    match checkLine w line with
    | .ok next => w := next
    | .error report => return report
  return finishReport w

def checkText (text : String) : Report :=
  let lines := text.splitOn "\n"
  let lines := if lines.getLast? == some "" then lines.dropLast else lines
  checkLines lines

def checkHandle (handle : IO.FS.Handle) : IO Report := do
  let mut w : World := {}
  let mut eof := false
  while !eof do
    match ← handle.getLine.toBaseIO with
    | .error e => return failureReport w .null ⟨.invalidTrace, s!"cannot read trace: {e}"⟩
    | .ok line =>
      if line.isEmpty then
        eof := true
      else
        match checkLine w line with
        | .ok next => w := next
        | .error report => return report
  return finishReport w

def checkFile (path : System.FilePath) : IO Report :=
  IO.FS.withFile path .read checkHandle

def Report.exitCode (r : Report) : UInt32 :=
  match r.status with
  | "accepted" => 0
  | "rejected" => 1
  | "unsupported" => 3
  | _ => 2

end Kv.Trace
