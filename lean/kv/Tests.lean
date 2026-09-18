-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv

namespace Kv.Tests
open Lean Trace

def eventJson (e : Event) : String × List (String × Json) :=
  let st (s t : Nat) := [("store", toJson s), ("tx", toJson t)]
  let mp (s t : Nat) (m : String) := st s t ++ [("map", toJson m)]
  let pt (s t : Nat) (m k : String) := mp s t m ++ [("key", toJson k)]
  let it (s t : Nat) (m : String) (i : Nat) := mp s t m ++ [("iteration", toJson i)]
  match e with
  | .traceStart schema => ("trace_start", [("schema", toJson schema)])
  | .traceEnd n => ("trace_end", [("events", toJson n)])
  | .caseBegin n => ("case_begin", [("name", toJson n)])
  | .caseEnd n failed => ("case_end", [("name", toJson n), ("failed", toJson failed)])
  | .subcaseBegin n => ("subcase_begin", [("name", toJson n)])
  | .subcaseEnd n => ("subcase_end", [("name", toJson n)])
  | .storeCreate s => ("store_create", [("store", toJson s)])
  | .storeEnd s => ("store_end", [("store", toJson s)])
  | .txCreate s t => ("tx_create", st s t)
  | .txEnd s t => ("tx_end", st s t)
  | .snapshot s t v g term =>
    ("snapshot", st s t ++ [("version", toJson v), ("global", toJson g), ("term", toJson term)])
  | .acquire s t m v g =>
    ("map_acquire", mp s t m ++ [("version", toJson v), ("global", toJson g)])
  | .unavailable s t m => ("map_unavailable", mp s t m)
  | .get s t m k v g => (if g then "get_global" else "get", pt s t m k ++ [("value", toJson v)])
  | .has s t m k v g => (if g then "has_global" else "has", pt s t m k ++ [("value", toJson v)])
  | .previous s t m k v => ("previous_write", pt s t m k ++ [("value", toJson v)])
  | .put s t m k v => ("put", pt s t m k ++ [("value", toJson v)])
  | .remove s t m k => ("remove", pt s t m k)
  | .clear s t m => ("clear", mp s t m)
  | .size s t m v => ("size", mp s t m ++ [("value", toJson v)])
  | .foreachBegin s t m i => ("foreach_begin", it s t m i)
  | .foreachEntry s t m i k v =>
    ("foreach_entry", it s t m i ++ [("key", toJson k), ("value", toJson v)])
  | .foreachContinue s t m i v => ("foreach_continue", it s t m i ++ [("value", toJson v)])
  | .foreachEnd s t m i => ("foreach_end", it s t m i)
  | .commitBegin s t => ("commit_begin", st s t)
  | .apply s t v term ws =>
    let writes := ws.map fun ((m, k), value) =>
      Json.mkObj [("map", toJson m), ("key", toJson k), ("value", toJson value)]
    ("apply", st s t ++ [("version", toJson v), ("term", toJson term), ("writes", toJson writes)])
  | .commitResult s t result v =>
    let r := match result with
      | .success => "success" | .conflict => "conflict" | .noReplicate => "no_replicate"
    ("commit_result", st s t ++ [("result", toJson r), ("version", toJson v)])
  | .compact s v requested =>
    ("compact", [("store", toJson s), ("version", toJson v), ("requested", toJson requested)])
  | .rollback s v requested term =>
    ("rollback", [("store", toJson s), ("version", toJson v), ("requested", toJson requested),
      ("term", toJson term)])
  | .rollbackRejected s requested term =>
    ("rollback_rejected", [("store", toJson s), ("requested", toJson requested), ("term", toJson term)])
  | .unsupported sid op =>
    ("unsupported", [("operation", toJson op)] ++ sid.toList.map fun s => ("store", toJson s))

def encode (events : List Event) : String :=
  String.intercalate "\n" <| events.mapIdx fun index e =>
    let (kind, fields) := eventJson e
    (Json.mkObj (("type", toJson kind) :: ("seq", toJson (index + 1)) :: fields)).compress

def closed (body : List Event) : List Event :=
  let events := [.traceStart 1, .caseBegin "model regression", .storeCreate 1] ++ body ++
    [.storeEnd 1, .caseEnd "model regression" false]
  events ++ [.traceEnd events.length]

def start (t r g : Nat) (term := 0) : List Event :=
  [.txCreate 1 t, .snapshot 1 t r g term]

def commit (t v : Nat) (ws : Pending) (term := 0) (result := Outcome.success) : List Event :=
  [.commitBegin 1 t, .apply 1 t v term ws, .commitResult 1 t result v, .txEnd 1 t]

def seed (t r g : Nat) (value : String) : List Event :=
  start t r g ++ [.acquire 1 t "a" r g, .acquire 1 t "b" r g,
    .put 1 t "a" "00" value, .put 1 t "b" "00" value] ++
    commit t (r + 1) [(("a", "00"), some value), (("b", "00"), some value)]

def basic : List Event :=
  start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0,
    .get 1 1 "a" "" none false, .has 1 1 "a" "" false false,
    .put 1 1 "a" "" "", .get 1 1 "a" "" (some "") false,
    .has 1 1 "a" "" true false, .previous 1 1 "a" "" none,
    .get 1 1 "a" "" none true, .has 1 1 "a" "" false true,
    .remove 1 1 "a" "", .get 1 1 "a" "" none false,
    .put 1 1 "b" "00" "22", .size 1 1 "a" 0, .size 1 1 "b" 1
  ] ++ commit 1 1 [(("a", ""), none), (("b", "00"), some "22")] ++
  start 2 1 0 ++ [
    .acquire 1 2 "a" 0 0, .acquire 1 2 "b" 1 0,
    .previous 1 2 "b" "00" (some 1), .get 1 2 "b" "00" (some "22") false,
    .get 1 2 "b" "00" none true, .commitBegin 1 2,
    .commitResult 1 2 .success 0, .txEnd 1 2]

def absencePrefix : List Event :=
  start 1 0 0 ++ [.acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0,
    .get 1 1 "a" "00" none false] ++
  start 2 0 0 ++ [.acquire 1 2 "a" 0 0, .put 1 2 "a" "00" "11"] ++
  commit 2 1 [(("a", "00"), some "11")] ++
  [.put 1 1 "b" "00" "22", .commitBegin 1 1]

def globalPrefix : List Event :=
  seed 1 0 0 "11" ++ [.compact 1 1 1] ++ seed 2 1 1 "22" ++
    start 3 2 1 ++ [.acquire 1 3 "a" 2 1]

def seedKeys (t r g : Nat) (v0 v1 : String) : List Event :=
  start t r g ++ [.acquire 1 t "a" r g, .acquire 1 t "b" r g,
    .put 1 t "a" "00" v0, .put 1 t "a" "01" v1,
    .put 1 t "b" "00" v0, .put 1 t "b" "01" v1] ++
  commit t (r + 1) [(("a", "00"), some v0), (("a", "01"), some v1),
    (("b", "00"), some v0), (("b", "01"), some v1)]

def keyGlobalPrefix : List Event :=
  seedKeys 1 0 0 "11" "aa" ++ [.compact 1 1 1] ++
    seedKeys 2 1 1 "22" "bb" ++ start 3 2 1 ++ [.acquire 1 3 "a" 2 1]

def writeSkew : List Event :=
  start 1 0 0 ++ [.acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0,
    .get 1 1 "b" "00" none false, .put 1 1 "a" "00" "11"] ++
  start 2 0 0 ++ [.acquire 1 2 "a" 0 0, .acquire 1 2 "b" 0 0,
    .get 1 2 "a" "00" none false, .put 1 2 "b" "00" "22"] ++
  commit 1 1 [(("a", "00"), some "11")] ++
  [.commitBegin 1 2, .apply 1 2 2 0 [(("b", "00"), some "22")]]

def phantom : List Event :=
  start 1 0 0 ++ [.acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0, .size 1 1 "a" 0] ++
  start 2 0 0 ++ [.acquire 1 2 "a" 0 0, .put 1 2 "a" "01" "11"] ++
  commit 2 1 [(("a", "01"), some "11")] ++
  [.put 1 1 "b" "00" "22", .commitBegin 1 1, .apply 1 1 2 0 [(("b", "00"), some "22")]]

def sameValuePrevious : List Event :=
  seed 1 0 0 "11" ++
  start 2 1 0 ++ [.acquire 1 2 "a" 1 0, .put 1 2 "a" "00" "22",
    .previous 1 2 "a" "00" (some 1)] ++
  start 3 1 0 ++ [.acquire 1 3 "a" 1 0, .put 1 3 "a" "00" "11"] ++
  commit 3 2 [(("a", "00"), some "11")] ++
  [.commitBegin 1 2, .apply 1 2 3 0 [(("a", "00"), some "22")]]

def termConflict : List Event :=
  start 1 0 0 ++ [.acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11",
    .rollback 1 0 0 1, .commitBegin 1 1, .apply 1 1 1 1 [(("a", "00"), some "11")]]

def reusedVersion : List Event :=
  seed 1 0 0 "11" ++ start 2 1 0 ++ [.acquire 1 2 "a" 1 0,
    .rollback 1 0 0 0] ++ seed 3 0 0 "22" ++
  [.put 1 2 "a" "00" "33", .commitBegin 1 2, .apply 1 2 2 0 [(("a", "00"), some "33")]]

def interleavedSegment : List Event :=
  start 1 0 0 7 ++ [.acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11"] ++
  commit 1 1 [(("a", "00"), some "11")] 7 .noReplicate ++ [
    .compact 1 0 9,
    .storeCreate 2, .txCreate 2 3, .snapshot 2 3 0 0 2, .acquire 2 3 "q" 0 0,
    .put 2 3 "q" "00" "99", .commitBegin 2 3,
    .apply 2 3 1 2 [(("q", "00"), some "99")],
    .commitResult 2 3 .success 1, .txEnd 2 3, .rollback 2 0 0 3, .storeEnd 2
  ] ++ start 2 1 0 7 ++ [
    .acquire 1 2 "a" 1 0, .get 1 2 "a" "00" (some "11") false,
    .get 1 2 "a" "00" none true, .commitBegin 1 2,
    .commitResult 1 2 .success 0, .txEnd 1 2,
    .compact 1 1 1, .compact 1 1 20, .compact 1 1 0
  ]

def absentCreationPrefix : List Event :=
  start 1 0 0 ++ [.acquire 1 1 "a" 0 0] ++
  start 2 0 0 ++ [.acquire 1 2 "b" 0 0, .put 1 2 "b" "00" "11"] ++
  commit 2 1 [(("b", "00"), some "11")] ++ [.compact 1 1 1]

def persistEmpty (tid : Nat) : List Event :=
  start tid 0 0 ++ [.acquire 1 tid "b" 0 0, .remove 1 tid "b" "00"] ++
    commit tid 1 [(("b", "00"), none)]

def existingEmptyCompacted : List Event :=
  persistEmpty 1 ++ start 2 1 0 ++ [.acquire 1 2 "a" 0 0] ++
  start 3 1 0 ++ [.acquire 1 3 "b" 0 0, .put 1 3 "b" "00" "11"] ++
  commit 3 2 [(("b", "00"), some "11")] ++ [.compact 1 2 2]

def accepted : List (String × List Event) := [
  ("unrelated same-term rollback keeps attempt valid", seed 1 0 0 "11" ++
    start 2 1 0 ++ [.acquire 1 2 "a" 1 0] ++
    start 3 1 0 ++ [.acquire 1 3 "b" 1 0, .put 1 3 "b" "00" "22"] ++
    commit 3 2 [(("b", "00"), some "22")] ++ [.rollback 1 1 1 0, .put 1 2 "a" "00" "33"] ++
    commit 2 2 [(("a", "00"), some "33")]),
  ("global reads introduce no normal dependency", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0, .get 1 1 "a" "00" none true] ++
    start 2 0 0 ++ [.acquire 1 2 "a" 0 0, .put 1 2 "a" "00" "11"] ++
    commit 2 1 [(("a", "00"), some "11")] ++ [.put 1 1 "b" "00" "22"] ++
    commit 1 2 [(("b", "00"), some "22")])
]

def negative : List (String × String × List Event) := [
  ("initial frontier is validated without storing it", "rejected",
    seed 1 0 0 "11" ++ [.compact 1 1 1] ++ start 2 1 0),
  ("an acquired map cannot be reported unavailable", "invalid_trace",
    keyGlobalPrefix ++ [.compact 1 2 2, .unavailable 1 3 "a"]),
  ("existing map cannot refresh its global view", "rejected", keyGlobalPrefix ++ [
    .compact 1 2 2, .get 1 3 "a" "00" (some "22") true]),
  ("previously unread keys use the same captured map view", "rejected", keyGlobalPrefix ++ [
    .compact 1 2 2, .get 1 3 "a" "01" (some "bb") true]),
  ("global presence must use the captured map", "rejected", keyGlobalPrefix ++ [
    .has 1 3 "a" "01" false true]),
  ("map aliases cannot manufacture another capture", "invalid_trace", keyGlobalPrefix ++ [
    .compact 1 2 2, .acquire 1 3 "a" 2 2]),
  ("global read requires a map capture", "invalid_trace", start 1 0 0 ++ [
    .get 1 1 "a" "00" none true]),
  ("placeholder cannot capture subsequently created real map", "rejected",
    absentCreationPrefix ++ [.acquire 1 1 "b" 0 1]),
  ("compacted existing empty map cannot be treated as newly absent", "rejected",
    existingEmptyCompacted ++ [.acquire 1 2 "b" 0 0]),
  ("empty map rollback/recreation does not restore birth lineage", "rejected",
    persistEmpty 1 ++ start 2 1 0 ++ [.acquire 1 2 "b" 0 0, .rollback 1 0 0 0] ++
    persistEmpty 3 ++ [.put 1 2 "b" "00" "11", .commitBegin 1 2,
      .apply 1 2 2 0 [(("b", "00"), some "11")]]),
  ("above-head compaction cannot advance global", "rejected",
    seed 1 0 0 "11" ++ [.compact 1 2 2]),
  ("above-head compaction cannot replace established global", "rejected",
    seed 1 0 0 "11" ++ [.compact 1 1 1, .compact 1 2 9]),
  ("iteration IDs cannot be reused within one map", "invalid_trace", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .foreachBegin 1 1 "a" 1, .foreachEnd 1 1 "a" 1,
    .foreachBegin 1 1 "a" 1]),
  ("later snapshot cannot silently establish a different term", "rejected", start 1 0 0 1 ++ [
    .acquire 1 1 "a" 0 0, .txEnd 1 1] ++ start 2 0 0 2),
  ("empty bytes are not absence", "rejected", start 1 0 0 ++ [.acquire 1 1 "a" 0 0,
    .get 1 1 "a" "00" (some "") false]),
  ("wrong observed read", "rejected", start 1 0 0 ++ [.acquire 1 1 "a" 0 0,
    .get 1 1 "a" "00" (some "11") false]),
  ("partial multi-map application", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .acquire 1 1 "b" 0 0, .put 1 1 "a" "00" "11",
    .put 1 1 "b" "00" "22", .commitBegin 1 1, .apply 1 1 1 0 [(("a", "00"), some "11")]]),
  ("incorrectly successful absent dependency", "rejected",
    absencePrefix ++ [.apply 1 1 2 0 [(("b", "00"), some "22")]]),
  ("two-map write skew", "rejected", writeSkew),
  ("map-wide phantom dependency", "rejected", phantom),
  ("same-value write changes previous-write dependency", "rejected", sameValuePrevious),
  ("term-only stale attempt", "rejected", termConflict),
  ("reused version does not restore lineage", "rejected", reusedVersion),
  ("wrong map-global acquisition revision", "rejected",
    globalPrefix ++ [.compact 1 2 2, .acquire 1 3 "b" 2 0]),
  ("refreshed snapshot", "invalid_trace", start 1 0 0 ++ [.snapshot 1 1 0 0 0]),
  ("illegal rollback", "rejected", seed 1 0 0 "11" ++ [.compact 1 1 1, .rollback 1 0 0 1]),
  ("acquisition cannot choose an arbitrary older global revision", "rejected",
    globalPrefix ++ [.compact 1 2 2, .acquire 1 3 "b" 2 1]),
  ("global read cannot overlay pending write", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .get 1 1 "a" "00" (some "11") true]),
  ("previous-write cannot overlay pending write", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .previous 1 1 "a" "00" (some 1)]),
  ("successful writes without apply", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .commitBegin 1 1, .commitResult 1 1 .success 0]),
  ("duplicate apply keys", "invalid_trace", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .commitBegin 1 1,
    .apply 1 1 1 0 [(("a", "00"), some "11"), (("a", "00"), some "11")]]),
  ("missing iteration continuation", "invalid_trace", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .foreachBegin 1 1 "a" 1,
    .foreachEntry 1 1 "a" 1 "00" "11", .foreachEnd 1 1 "a" 1]),
  ("operation outside iteration callback", "invalid_trace", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .foreachBegin 1 1 "a" 1, .get 1 1 "a" "00" none false]),
  ("snapshot without acquisition outcome", "invalid_trace", start 1 0 0 ++ [.txEnd 1 1]),
  ("incomplete iteration", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .foreachBegin 1 1 "a" 1,
    .foreachEnd 1 1 "a" 1]),
  ("duplicate iteration entry", "rejected", start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11", .foreachBegin 1 1 "a" 1,
    .foreachEntry 1 1 "a" 1 "00" "11", .foreachContinue 1 1 "a" 1 true,
    .foreachEntry 1 1 "a" 1 "00" "11"]),
  ("unclosed attempt", "invalid_trace", [.txCreate 1 1]),
  ("reused attempt ID", "invalid_trace", [.txCreate 1 1, .txEnd 1 1, .txCreate 1 1]),
  ("unavailable without capture", "invalid_trace", [.txCreate 1 1, .unavailable 1 1 "a"]),
  ("explicit unsupported event", "unsupported", [.unsupported (some 1) "snapshot import"]),
  ("no coverage", "invalid_trace", [])
]

def assertStatus (name expected text : String) : IO Unit := do
  let result := checkText text
  if result.status != expected then
    throw (IO.userError s!"{name}: expected {expected}, got {result.status}: {result.message}")
  if result != checkText text then throw (IO.userError s!"nondeterministic replay: {name}")
  if expected != "accepted" && result.message.isEmpty then
    throw (IO.userError s!"missing diagnostic: {name}")

def assertProjection : IO Unit := do
  let records := (closed interleavedSegment).mapIdx fun index event =>
    { event, seq := index + 1 : Record }
  let initial ← match replay {} (records.take 3) with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"projection prefix: {e.message}")
  let segment := (records.drop 3).take interleavedSegment.length
  let final ← match replay initial segment with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"projection replay: {e.message}")
  let txs ← match projectApplications initial 1 segment with
    | .ok txs => pure txs
    | .error e => throw (IO.userError s!"projection computation: {e.message}")
  let before := (find initial.stores 1).get!
  let after := (find final.stores 1).get!
  if txs.length != 1 ||
      serialTransactions before.head.data before.head.version txs != some after.head.data ||
      after.head.version != before.head.version + txs.length then
    throw (IO.userError "selected-store serial projection disagrees with actual replay")

def assertStreaming : IO Unit :=
  IO.FS.withTempFile fun handle path => do
    let text := encode (closed basic)
    handle.putStr text
    handle.flush
    let streamed ← checkFile path
    let buffered := checkText text
    if streamed != buffered then
      throw (IO.userError "streaming and pure replay disagree")

def run : IO Unit := do
  assertProjection
  assertStreaming
  let good := encode (closed basic)
  assertStatus "basic accepted history" "accepted" good
  for (name, body) in accepted do
    assertStatus name "accepted" (encode (closed body))
  for (name, expected, body) in negative do
    assertStatus name expected (encode (closed body))
  let missingValue := (encode (closed (start 1 0 0 ++ [
    .acquire 1 1 "a" 0 0, .get 1 1 "a" "00" none false, .txEnd 1 1]))).replace
    ",\"value\":null" ""
  let malformed : List (String × String) := [
    ("missing point result is not absence", missingValue),
    ("empty", ""), ("blank record", "\n" ++ good),
    ("truncated", String.intercalate "\n" (good.splitOn "\n").dropLast),
    ("duplicate key", "{\"type\":\"trace_start\",\"seq\":1,\"seq\":2,\"schema\":1}"),
    ("escaped duplicate key", "{\"type\":\"trace_start\",\"seq\":1,\"\\u0073eq\":2,\"schema\":1}"),
    ("float", "{\"type\":\"trace_start\",\"seq\":1.0,\"schema\":1}"),
    ("exponent", "{\"type\":\"trace_start\",\"seq\":1e0,\"schema\":1}"),
    ("negative zero", "{\"type\":\"trace_start\",\"seq\":-0,\"schema\":1}"),
    ("uint64 overflow", "{\"type\":\"trace_start\",\"seq\":18446744073709551616,\"schema\":1}"),
    ("number as string", "{\"type\":\"trace_start\",\"seq\":\"1\",\"schema\":1}"),
    ("unknown event", "{\"type\":\"invented\",\"seq\":1}"),
    ("unknown field", "{\"type\":\"trace_start\",\"seq\":1,\"schema\":1,\"extra\":true}"),
    ("missing field", "{\"type\":\"trace_start\",\"seq\":1}"),
    ("trailing record", good ++ "\n{\"type\":\"trace_start\",\"seq\":999,\"schema\":1}"),
    ("uppercase bytes", good.replace "\"22\"" "\"AA\""),
    ("odd bytes", good.replace "\"22\"" "\"a\""),
    ("sequence regression", good.replace "\"seq\":2," "\"seq\":1,")]
  for (name, text) in malformed do assertStatus name "invalid_trace" text
  match parseLine "{\"seq\":18446744073709551615}" with
  | .error e => throw (IO.userError e)
  | .ok j =>
    if (num j "seq").toOption != some uint64Max then
      throw (IO.userError "uint64 precision was lost")
  let diagnostic := checkText (encode (closed (globalPrefix ++ [.compact 1 2 2, .acquire 1 3 "b" 2 1])))
  if diagnostic.store? != some 1 || diagnostic.tx? != some 3 || diagnostic.seq?.isNone then
    throw (IO.userError "missing rejection context")
  IO.println "checker self-tests passed"

end Kv.Tests

def main : IO Unit := Kv.Tests.run
