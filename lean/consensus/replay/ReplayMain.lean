module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Validator.Lockstep

public section

/--
Validate one trace with `Consensus.TraceValidation.validate` on the arguments
`Consensus.TraceValidation.load` decodes, the validator whose acceptance
`Consensus.TraceValidation.accepted_refines` is about. With `refine`, also run the
diagnostic lock-step check against the clean model and fail on any finding.
-/
def check (refine : Bool) (path : String) : IO Bool := do
  let t0 ← IO.monoMsNow
  let r :=
    (← Consensus.TraceValidation.load path).bind
      fun (env, ss) => (Consensus.TraceValidation.validate env ss).map (env, ·)
  let t1 ← IO.monoMsNow
  match r with
  | .error e => IO.eprintln s!"FAIL {path}: {e}"; return false
  | .ok (env, v) =>
      IO.println
        s!"PASS {path}: nodes={v.keys.length} events={v.observations.length} sections={v.sections} actions={v.actions.length} ms={t1 - t0}"
      if !refine then return true
      match Consensus.TraceValidation.lockstep env v with
      | .error e => IO.eprintln s!"REFINE-ERROR {path}: {e}"; return false
      | .ok [] => return true
      | .ok fs =>
          for f in fs do
            IO.eprintln s!"REFINE {path}: {f}"
          return false

def main (args : List String) : IO UInt32 := do
  let (refine, args) :=
    match args with
    | "--refine" :: rest => (true, rest)
    | _ => (false, args)
  if args.isEmpty then
    IO.eprintln "usage: consensus-replay [--refine] TRACE.ndjson..."
    return 2
  try
    let mut failed := 0
    for path in args do
      unless ← check refine path do
        failed := failed + 1
    if args.length > 1 then
      IO.println s!"{args.length - failed}/{args.length} accepted"
    return if failed == 0 then 0 else 1
  catch error =>
    IO.eprintln s!"{error}"
    return 1
