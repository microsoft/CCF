-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

meta import Kv.Properties.Invariants
meta import Kv.TraceValidation

public import Kv.Properties.Invariants
public import Kv.TraceValidation

public section

/-!
Checker self-tests that cannot be expressed as trace fixtures, run at build time: agreement
between the projected serial history and actual replay, and exact uint64 decoding. Accepted,
rejected, invalid and unsupported traces are fixtures under `replayer/fixtures/`, checked by
`replayer/check-fixtures.sh`.
-/

namespace Kv.Tests.Replay

open Lean Kv.Model Kv.Properties Kv.TraceValidation

private def closed (body : List Event) : List Event :=
  let events :=
    [.traceStart 1, .caseBegin "model regression", .storeCreate 1]
    ++ body
    ++ [.storeEnd 1, .caseEnd "model regression" false]
  events ++ [.traceEnd events.length]

private def start (t r g : Nat) (term := 0) : List Event :=
  [.txCreate 1 t, .snapshot 1 t r g term]

private def commit (t v : Nat) (ws : Pending) (term := 0) (result := Outcome.success)
    : List Event :=
  [.commitBegin 1 t, .apply 1 t v term ws, .commitResult 1 t result v, .txEnd 1 t]

private def interleavedSegment : List Event :=
  start 1 0 0 7
  ++ [.acquire 1 1 "a" 0 0, .put 1 1 "a" "00" "11"]
  ++ commit 1 1 [(("a", "00"), some "11")] 7 .noReplicate
  ++ [
    .compact 1 0 9,
    .storeCreate 2,
    .txCreate 2 3,
    .snapshot 2 3 0 0 2,
    .acquire 2 3 "q" 0 0,
    .put 2 3 "q" "00" "99",
    .commitBegin 2 3,
    .apply 2 3 1 2 [(("q", "00"), some "99")],
    .commitResult 2 3 .success 1,
    .txEnd 2 3,
    .rollback 2 0 0 3,
    .storeEnd 2
  ]
  ++ start 2 1 0 7
  ++ [
    .acquire 1 2 "a" 1 0,
    .get 1 2 "a" "00" (some "11") false,
    .get 1 2 "a" "00" none true,
    .commitBegin 1 2,
    .commitResult 1 2 .success 0,
    .txEnd 1 2,
    .compact 1 1 1,
    .compact 1 1 20,
    .compact 1 1 0
  ]

private def assertProjection : IO Unit := do
  let records :=
    (closed interleavedSegment).mapIdx
      fun index event =>
        { event, seq := index + 1 : Record }
  let initial ←
    match replay {} (records.take 3) with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"projection prefix: {e.message}")
  let segment := (records.drop 3).take interleavedSegment.length
  let final ←
    match replay initial segment with
    | .ok w => pure w
    | .error e => throw (IO.userError s!"projection replay: {e.message}")
  let txs ←
    match projectApplications initial 1 segment with
    | .ok txs => pure txs
    | .error e => throw (IO.userError s!"projection computation: {e.message}")
  let before := (find initial.stores 1).get!
  let after := (find final.stores 1).get!
  if txs.length != 1
      || serialTransactions before.head.data before.head.version txs
          != some after.head.data
      || after.head.version != before.head.version + txs.length then
    throw (IO.userError "selected-store serial projection disagrees with actual replay")

private def run : IO Unit := do
  assertProjection
  match parseLine "{\"seq\":18446744073709551615}" with
  | .error e => throw (IO.userError e)
  | .ok j =>
      if (num j "seq").toOption != some uint64Max then
        throw (IO.userError "uint64 precision was lost")
  IO.println "checker self-tests passed"

#eval run

end Kv.Tests.Replay
