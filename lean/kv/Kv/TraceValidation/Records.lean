-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model
public import Lean.Data.Json

public section

/-! Human-reviewed strict decoding of schema 1 NDJSON trace records. -/

namespace Kv.TraceValidation

open Lean Kv.Model

/-- The largest number a trace field may carry. -/
def uint64Max : Nat := UInt64.size - 1

/-- A JSON number that is an exact nonnegative integer no larger than `uint64Max`. -/
def nat64 (j : Json) : Except String Nat := do
  let v ←
    j.getNat?.mapError
      fun _ =>
        if j matches .num _ then
          "expected a nonnegative JSON integer, not a floating-point number"
        else
          "expected a JSON integer"
  if v > uint64Max then throw "integer exceeds uint64"
  return v

/-- The value of a required field. -/
def field (j : Json) (name : String) : Except String Json := j.getObjVal? name

/-- A required string field. -/
def str (j : Json) (name : String) : Except String String :=
  (field j name).bind Json.getStr?

/-- A required uint64 field. -/
def num (j : Json) (name : String) : Except String Nat := (field j name).bind nat64

private def boolean (j : Json) (name : String) : Except String Bool :=
  (field j name).bind Json.getBool?

private def hex (j : Json) : Except String String := do
  let s ← j.getStr?
  if s.length % 2 != 0 || !s.all (fun c => c.isDigit || ('a' ≤ c && c ≤ 'f')) then
    throw "bytes must be even-length lowercase hexadecimal (empty bytes are allowed)"
  return s

private def bytes (j : Json) (name : String) : Except String String :=
  (field j name).bind hex

private def nullable {α : Type} (f : Json → Except String α) (j : Json)
    : Except String (Option α) :=
  match j with
  | .null => .ok none
  | _ => some <$> f j

private def optionalBytes (j : Json) (name : String) : Except String (Option String) :=
  (field j name).bind (nullable hex)

private def optionalNum (j : Json) (name : String) : Except String (Option Nat) :=
  (field j name).bind (nullable nat64)

private def fields (j : Json) (allowed : List String) : Except String Unit := do
  match (← j.getObj?).keys.find? (!allowed.contains ·) with
  | some k => throw s!"unknown field '{k}'"
  | none => return ()

private def numberChar (c : Char) : Bool :=
  c.isDigit || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'

open Std.Internal.Parsec Std.Internal.Parsec.String in
/-- The bundled parser normalizes numbers and object keys. Check the lexical
information it would otherwise discard before giving it any numeric input. -/
private partial def lexicalScan (objects : List (List String)) : Parser Unit := do
  match ← peek? with
  | none => return ()
  | some '"' =>
      skip
      let key ← Json.Parser.str
      ws
      if (← peek?) != some ':' then
        lexicalScan objects
      else
        match objects with
        | [] => fail "object key outside object"
        | keys :: parents =>
            if keys.contains key then fail s!"duplicate object key '{key}'"
            lexicalScan ((key :: keys) :: parents)
  | some '{' => skip; lexicalScan ([] :: objects)
  | some '}' => skip; lexicalScan (objects.drop 1)
  | some c =>
      skip
      if !(c.isDigit || c == '-') then
        lexicalScan objects
      else
        let token := c.toString ++ (← manyChars (satisfy numberChar))
        if !token.all Char.isDigit || token.length > 20 then
          fail
            "number must be an exact nonnegative uint64 JSON integer (no sign, fraction, or exponent)"
        lexicalScan objects

open Std.Internal.Parsec in
/-- Checks the raw line's lexical form, which `Json.parse` would otherwise normalize. -/
def lexicalCheck (line : String) : Except String Unit :=
  match lexicalScan [] ⟨line, line.startPos⟩ with
  | .success .. => .ok ()
  | .error _ .eof => .error "unterminated JSON string"
  | .error _ (.other message) => .error message

/-- Decodes an `apply` record's write set. -/
def decodeWrites (j : Json) : Except String Pending := do
  let array ← j.getArr?
  array.toList.mapM
    fun item => do
      fields item ["map", "key", "value"]
      return ((← str item "map", ← bytes item "key"), ← optionalBytes item "value")

/-- The fields each record type allows, excluding `type` and `seq`. -/
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

/-- Decodes the event of a record of type `kind`, rejecting unknown or missing fields. -/
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
  | "size" =>
      return .size (← num j "store") (← num j "tx") (← str j "map") (← num j "value")
  | "foreach_begin" =>
      return .foreachBegin (← num j "store") (← num j "tx") (← str j "map")
        (← num j "iteration")
  | "foreach_entry" =>
      return .foreachEntry (← num j "store") (← num j "tx") (← str j "map")
        (← num j "iteration") (← bytes j "key") (← bytes j "value")
  | "foreach_continue" =>
      return .foreachContinue (← num j "store") (← num j "tx") (← str j "map")
        (← num j "iteration") (← boolean j "value")
  | "foreach_end" =>
      return .foreachEnd (← num j "store") (← num j "tx") (← str j "map")
        (← num j "iteration")
  | "commit_begin" => return .commitBegin (← num j "store") (← num j "tx")
  | "apply" =>
      return .apply (← num j "store") (← num j "tx") (← num j "version")
        (← num j "term") (← decodeWrites (← field j "writes"))
  | "commit_result" =>
      let result ←
        match ← str j "result" with
        | "success" => pure Outcome.success
        | "conflict" => pure Outcome.conflict
        | "no_replicate" => pure Outcome.noReplicate
        | other => throw s!"unknown commit result '{other}'"
      return .commitResult (← num j "store") (← num j "tx") result (← num j "version")
  | "compact" =>
      return .compact (← num j "store") (← num j "version") (← num j "requested")
  | "rollback" =>
      return .rollback (← num j "store") (← num j "version") (← num j "requested")
        (← num j "term")
  | "rollback_rejected" =>
      return .rollbackRejected (← num j "store") (← num j "requested") (← num j "term")
  | "unsupported" =>
      let sid ←
        match field j "store" with
        | .error _ => pure none
        | .ok value => some <$> nat64 value
      return .unsupported sid (← str j "operation")
  | "trace_end" => return .traceEnd (← num j "events")
  | _ => throw s!"unknown event type '{kind}'"

/-- Decodes one record. -/
def decode (j : Json) : Except String Record := do
  return { seq := ← num j "seq", event := ← decodeEvent j (← str j "type") }

/-- Parses one NDJSON line after checking its lexical form. -/
def parseLine (line : String) : Except String Json := do
  lexicalCheck line
  Json.parse line

end Kv.TraceValidation
