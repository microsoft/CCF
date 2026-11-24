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
The fixture runner also checks model-only verdicts without the adapter's diagnostic guards.
-/

namespace Kv.Tests.Replay

open Lean Kv.Properties Kv.TraceValidation
open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem

private def modelInputs (w : World) : List Record → Except Failure (List Model.Action)
  | [] => .ok []
  | r :: rs => do
      let next ← step w r
      let rest ← modelInputs next rs
      return actions w r.event ++ rest

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

private def assertUnorderedSemantics : IO Unit := do
  let a := (("m", "a"), some "last")
  let b := (("m", "b"), none)
  let writes : Pending := [a, b]
  let output := Output.applied 1 0 writes
  if !reportedMatches (.apply 1 1 1 0 [b, a]) output
      || reportedMatches (.apply 1 1 1 0 [a, a]) output
      || reportedMatches (.apply 1 1 1 0 [a, a]) (.applied 1 0 [a, a])
      || reportedMatches (.apply 1 1 1 0 [a, (("m", "b"), some "")]) output then
    throw (IO.userError "publication echo did not preserve unique per-key writes")
  let staged :=
    stage (stage (stage [] (.write ("m", "a") (some "first"))) (.write ("m", "b") none))
      (.write ("m", "a") (some "last"))
  if !decide (staged.Perm writes) then
    throw (IO.userError "staging did not retain the last write at each address")
  let db : Data := [(("m", "a"), ⟨"one", 1⟩), (("m", "b"), ⟨"two", 2⟩)]
  let reordered : Data := db.reverse
  let changed : Data := [(("m", "a"), ⟨"one", 2⟩), (("m", "b"), ⟨"two", 2⟩)]
  let dep := Dependency.map "m" (image db "m")
  if !dep.holds reordered || dep.holds changed then
    throw (IO.userError "map dependency ignored cells or depended on order")
  let entries := scanAt db [] "m"
  if serialStep db [] (.scan "m" entries.reverse) != some []
      || serialStep db [] (.scan "m" [("a", "wrong"), ("b", "two")]) != none then
    throw (IO.userError "serial scan did not compare complete entries without order")
  let events :=
    start 1 0 0
    ++ [
      .acquire 1 1 "m" 0 0,
      .put 1 1 "m" "a" "first",
      .put 1 1 "m" "b" "two",
      .put 1 1 "m" "a" "last"
    ]
    ++ commit 1 1 [(("m", "b"), some "two"), (("m", "a"), some "last")]
    ++ start 2 1 0
    ++ [
      .acquire 1 2 "m" 1 0,
      .foreachBegin 1 2 "m" 1,
      .foreachEntry 1 2 "m" 1 "b" "two",
      .foreachContinue 1 2 "m" 1 true,
      .foreachEntry 1 2 "m" 1 "a" "last",
      .foreachContinue 1 2 "m" 1 true,
      .foreachEnd 1 2 "m" 1,
      .range 1 2 "m" (some "a") (some "b") [("a", "last")],
      .txEnd 1 2
    ]
  match replay {} ((closed events).mapIdx fun index event => ⟨index + 1, event⟩) with
  | .ok _ => pure ()
  | .error e => throw (IO.userError s!"unordered publication/iteration: {e.message}")

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
  let inputs ←
    match modelInputs initial segment with
    | .ok inputs => pure inputs
    | .error e => throw (IO.userError s!"projection computation: {e.message}")
  let txs ←
    match applicationInputs (initial.model) 1 inputs with
    | some txs => pure txs
    | none => throw (IO.userError "projected model execution is disabled")
  let before := (find initial.model.stores 1).get!
  let after := (find final.model.stores 1).get!
  if txs.length != 1
      || serialTransactions before.head.data before.head.version txs
          != some after.head.data
      || after.head.version != before.head.version + txs.length then
    throw (IO.userError "selected-store serial projection disagrees with actual replay")

private def assertStutters (initial : World) (events : List Event) : IO World := do
  let baseline := initial.model
  let records :=
    events.mapIdx
      fun index event =>
        { event, seq := initial.recording.lastSeq.getD 0 + index + 1 : Record }
  let mut current := initial
  for r in records do
    if !(actions current r.event).isEmpty then
      throw (IO.userError "metadata-only report executed a model input")
    if executeActions (current.model) (actions current r.event)
        != some (baseline, .unit) then
      throw (IO.userError "metadata-only execution did not stutter")
    let next ←
      match step current r with
      | .ok next => pure next
      | .error failure => throw (IO.userError s!"metadata stutter: {failure.message}")
    if next.model != baseline then
      throw (IO.userError "trace metadata changed store/transaction state")
    current := next
  if ((modelInputs initial records).toOption.map List.isEmpty) != some true then
    throw (IO.userError "metadata-only replay accumulated model inputs")
  return current

private def modelRejection (path : System.FilePath) : IO (Option Nat) := do
  let mut w : World := {}
  for line in ← IO.FS.lines path do
    let record ←
      match (parseLine line).bind decode with
      | .ok record => pure record
      | .error message => throw (IO.userError s!"{path}: {message}")
    match executeActions w.model (actions w record.event) with
    | none => return some record.seq
    | some (next, output) =>
        if !reportedMatches record.event output then
          return some record.seq
        w := { model := next, recording := metadata w.recording record.event output }
  return none

/-- Checks rejected fixtures without `guardEvent`; callback visitation remains adapter-only. -/
def checkModelFixtures (directory : System.FilePath) : IO Unit := do
  let mut modelFailures := 0
  let mut callbackFailures := 0
  for entry in ← directory.readDir do
    let report ← checkFile entry.path
    let some rejectedAt := report.seq?
    | throw (IO.userError s!"{entry.fileName}: missing rejection record")
    if report.status != "rejected" then
      throw (IO.userError s!"{entry.fileName}: expected rejection, got {report.status}")
    let adapterOnly :=
      entry.fileName == "iteration.rejected.duplicate-iteration-entry.ndjson"
      || entry.fileName == "iteration.rejected.incomplete-iteration.ndjson"
    let rejectedByModel ← modelRejection entry.path
    let expected := if adapterOnly then none else some rejectedAt
    if rejectedByModel != expected then
      throw
        (IO.userError
          s!"{entry.fileName}: model rejection expected {repr expected}, got {repr rejectedByModel}")
    if adapterOnly then
      callbackFailures := callbackFailures + 1
    else
      modelFailures := modelFailures + 1
  if modelFailures == 0 || callbackFailures != 2 then
    throw (IO.userError "missing model or callback-protocol rejection fixtures")
  IO.println
    s!"{modelFailures}/{modelFailures + callbackFailures} rejected traces independently rejected by model; {callbackFailures} adapter-only callback rejections"

private def run : IO Unit := do
  assertProjection
  assertUnorderedSemantics
  let _ ←
    assertStutters {}
      [
        .traceStart 1,
        .caseBegin "metadata",
        .subcaseBegin "scope",
        .subcaseEnd "scope",
        .caseEnd "metadata" false
      ]
  let records :=
    (closed interleavedSegment).mapIdx
      fun index event =>
        { event, seq := index + 1 : Record }
  let final ←
    match replay {} records with
    | .ok final => pure final
    | .error failure => throw (IO.userError failure.message)
  let inputs ←
    match modelInputs {} records with
    | .ok inputs => pure inputs
    | .error failure => throw (IO.userError failure.message)
  let nextState ←
    inputs.foldlM
      (fun s input =>
        match Model.execute s input with
        | some (next, _) => pure next
        | none => throw (IO.userError "translated interleaved input is disabled"))
      ({} : Model.State)
  if nextState ≠ final.model then
    throw (IO.userError "interleaved adapter replay differs from model execution")
  if !final.recording.knownTerms.isEmpty || !final.recording.attempts.isEmpty then
    throw (IO.userError "closed lifecycles retained term or callback bookkeeping")
  let beforeManifest ←
    match replay {} (records.dropLast) with
    | .ok w => pure w
    | .error failure => throw (IO.userError failure.message)
  let _ ← assertStutters beforeManifest [.traceEnd beforeManifest.recording.count]
  let capturePrefix :=
    [
      .traceStart 1,
      .caseBegin "adapter",
      .storeCreate 1,
      .txCreate 1 1,
      .snapshot 1 1 0 0 9,
      .acquire 1 1 "m" 0 0
    ]
  let w ←
    match replay {} (capturePrefix.mapIdx fun index event => ⟨index + 1, event⟩) with
    | .ok w => pure w
    | .error failure => throw (IO.userError failure.message)
  let callbackWorld ←
    match replay w [⟨7, .put 1 1 "m" "k" "v"⟩, ⟨8, .foreachBegin 1 1 "m" 1⟩] with
    | .ok w => pure w
    | .error failure => throw (IO.userError failure.message)
  let interleaved ←
    match replay callbackWorld
            (([
                .txCreate 1 2,
                .snapshot 1 2 0 0 9,
                .acquire 1 2 "m" 0 0,
                .put 1 2 "m" "other" "second",
                .foreachBegin 1 2 "m" 1,
                .foreachEntry 1 2 "m" 1 "other" "second",
                .foreachContinue 1 2 "m" 1 false,
                .foreachEnd 1 2 "m" 1,
                .txEnd 1 2
              ]
              : List Event).mapIdx
              fun index event => ⟨index + 9, event⟩) with
    | .ok w => pure w
    | .error failure => throw (IO.userError failure.message)
  if interleaved.model != callbackWorld.model
      || (find interleaved.recording.attempts 2).isSome then
    throw (IO.userError "ending an interleaved attempt retained model or callback state")
  let _ ←
    assertStutters interleaved
      [
        .subcaseBegin "callback metadata",
        .subcaseEnd "callback metadata",
        .foreachEntry 1 1 "m" 1 "k" "v",
        .foreachContinue 1 1 "m" 1 false,
        .foreachEnd 1 1 "m" 1
      ]
  match step w ⟨7, .get 1 1 "m" "k" (some "wrong") false⟩ with
  | .error failure =>
      if failure.kind != .rejected then
        throw (IO.userError "reported observation mismatch was not rejected")
  | .ok _ => throw (IO.userError "reported observation replaced model state")
  let ended ←
    match step w ⟨7, .txEnd 1 1⟩ with
    | .ok next => pure next
    | .error failure => throw (IO.userError failure.message)
  match step ended ⟨8, .txCreate 1 1⟩ with
  | .error failure =>
      if failure.kind != .invalidTrace then
        throw (IO.userError "run-unique ID reuse is not an instrumentation error")
  | .ok _ => throw (IO.userError "trace reused an attempt identity")
  match parseLine "{\"seq\":18446744073709551615}" with
  | .error e => throw (IO.userError e)
  | .ok j =>
      if (num j "seq").toOption != some uint64Max then
        throw (IO.userError "uint64 precision was lost")
  IO.println "checker self-tests passed"

#eval run

end Kv.Tests.Replay
