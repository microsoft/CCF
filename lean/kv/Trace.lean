-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Lean.Data.Json

namespace Kv.Trace
open Lean

def uint64Max : Nat := 18446744073709551615

def nat64 (j : Json) : Except String Nat := do
  match j with
  | .num n =>
    if n.exponent != 0 || n.mantissa < 0 then
      throw "expected a nonnegative JSON integer, not a floating-point number"
    let v := n.mantissa.toNat
    if v > uint64Max then throw "integer exceeds uint64"
    return v
  | _ => throw "expected a JSON integer"

def field (j : Json) (name : String) : Except String Json := j.getObjVal? name
def str (j : Json) (name : String) : Except String String := (field j name).bind Json.getStr?
def num (j : Json) (name : String) : Except String Nat := (field j name).bind nat64
def boolean (j : Json) (name : String) : Except String Bool := (field j name).bind Json.getBool?

def hex (j : Json) : Except String String := do
  let s ← j.getStr?
  if s.length % 2 != 0 ||
      !s.toList.all (fun c => c.isDigit || ('a' ≤ c && c ≤ 'f')) then
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
  let obj ← j.getObj?
  for (k, _) in obj.toList do
    if !allowed.contains k then throw s!"unknown field '{k}'"

/-- The bundled parser normalizes numbers and object keys. Check the lexical
information it would otherwise discard before giving it any numeric input. -/
partial def quoted (cs : List Char) (acc : List Char := ['"']) (escaped := false) :
    Except String (String × List Char) := do
  match cs with
  | [] => throw "unterminated JSON string"
  | c :: rest =>
    if c == '"' && !escaped then
      let raw := String.ofList ((c :: acc).reverse)
      let j ← Json.parse raw
      return (← j.getStr?, rest)
    else
      quoted rest (c :: acc) (c == '\\' && !escaped)

def numberChar (c : Char) : Bool :=
  c.isDigit || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'

partial def lexicalCheck (cs : List Char) (objects : List (List String) := []) :
    Except String Unit := do
  match cs with
  | [] => return ()
  | '"' :: rest =>
    let (value, rest) ← quoted rest
    if (rest.dropWhile Char.isWhitespace).head? == some ':' then
      match objects with
      | [] => throw "object key outside object"
      | keys :: parents =>
        if keys.contains value then throw s!"duplicate object key '{value}'"
        lexicalCheck rest ((value :: keys) :: parents)
    else lexicalCheck rest objects
  | '{' :: rest => lexicalCheck rest ([] :: objects)
  | '}' :: rest => lexicalCheck rest (objects.drop 1)
  | c :: rest =>
    if c.isDigit || c == '-' then
      let (tail, remaining) := rest.span numberChar
      let token := c :: tail
      if !token.all Char.isDigit || token.length > 20 then
        throw "number must be an exact nonnegative uint64 JSON integer (no sign, fraction, or exponent)"
      lexicalCheck remaining objects
    else lexicalCheck rest objects

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
  lexicalCheck line.toList
  Json.parse line

structure Report where
  status : String
  events : Nat
  message : String
  seq : Option Nat := none
  store : Option Nat := none
  tx : Option Nat := none
  deriving Repr, BEq

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
    seq, store := sid, tx := tid }

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
    let lineResult : Except IO.Error String ← try
      pure (Except.ok (← handle.getLine) : Except IO.Error String)
    catch e => pure (Except.error e)
    match lineResult with
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

def Report.json (r : Report) : Json :=
  Json.mkObj <| [
    ("status", toJson r.status), ("events", toJson r.events), ("message", toJson r.message)] ++
    (r.seq.toList.map fun n => ("seq", toJson n)) ++
    (r.store.toList.map fun n => ("store", toJson n)) ++
    (r.tx.toList.map fun n => ("tx", toJson n))

def Report.exitCode (r : Report) : UInt32 :=
  match r.status with
  | "accepted" => 0
  | "rejected" => 1
  | "unsupported" => 3
  | _ => 2

end Kv.Trace
