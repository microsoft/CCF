-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.TraceValidation.Records

public section

/-!
Streams schema 1 NDJSON traces through `Model.step`, one record per line, and reports the
first failure or acceptance.
-/

namespace Kv.TraceValidation

open Lean Kv.Model

/-- The outcome of checking a trace, printed as JSON by `kv-replay --json`. -/
structure Report where
  /-- `accepted`, `rejected`, `invalid_trace`, or `unsupported`. -/
  status : String
  /-- Records accepted before the outcome. -/
  events : Nat
  /-- A human-readable diagnostic. -/
  message : String
  /-- The failing record's sequence number, if decoded. -/
  seq? : Option Nat := none
  /-- The failing record's store, if decoded. -/
  store? : Option Nat := none
  /-- The failing record's attempt, if decoded. -/
  tx? : Option Nat := none
deriving Repr, BEq, ToJson

/-- The report status for a failure kind. -/
def statusName : FailureKind → String
  | .rejected => "rejected"
  | .invalidTrace => "invalid_trace"
  | .unsupported => "unsupported"

/-- Reports a failure at the next record, with whatever identifiers `j` carries. -/
def failureReport (w : World) (j : Json) (failure : Failure) : Report :=
  let kind := (str j "type").toOption.getD "<undecoded>"
  let seq := (num j "seq").toOption
  let sid := (num j "store").toOption
  let tid := (num j "tx").toOption
  let id (n : Option Nat) := (n.map toString).getD "<none>"
  {
    status := statusName failure.kind
    events := w.count
    message :=
      s!"event {w.count + 1} type={kind} case={w.currentCase.getD "<none>"} store={id sid} tx={id tid}: {failure.message}"
    seq? := seq,
    store? := sid,
    tx? := tid
  }

/-- Parses, decodes, and applies one line. -/
def checkLine (w : World) (line : String) : Except Report World := do
  let j ←
    match parseLine line with
    | .ok j => pure j
    | .error message => throw (failureReport w .null ⟨.invalidTrace, message⟩)
  let r ←
    match decode j with
    | .ok r => pure r
    | .error message => throw (failureReport w j ⟨.invalidTrace, message⟩)
  match step w r with
  | .ok next => return next
  | .error failure => throw (failureReport w j failure)

/-- Reports acceptance, or a truncated stream if `trace_end` is missing. -/
def finishReport (w : World) : Report :=
  if !w.ended then
    failureReport w .null ⟨.invalidTrace, "truncated stream: missing trace_end"⟩
  else
    {
      status := "accepted",
      events := w.count,
      message := s!"accepted {w.count} events in {w.cases} cases"
    }

/-- Checks every line read from `handle`, stopping at the first failure. -/
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

/-- Checks the trace in the file at `path`. -/
def checkFile (path : System.FilePath) : IO Report :=
  IO.FS.withFile path .read checkHandle

/-- The process exit code: 0 accepted, 1 rejected, 2 invalid trace, 3 unsupported. -/
def Report.exitCode (r : Report) : UInt32 :=
  match r.status with
  | "accepted" => 0
  | "rejected" => 1
  | "unsupported" => 3
  | _ => 2

end Kv.TraceValidation
