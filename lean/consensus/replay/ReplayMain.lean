module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Reduction

public section

open Lean Consensus.Replay

def main (args : List String) : IO UInt32 := do
  try
    let (flags, paths) := args.partition (·.startsWith "--")
    match flags.eraseDups, paths with
    | flags, [path] =>
        unless flags.all (· == "--schedule") do
          IO.eprintln s!"unknown option {flags}"
          return 2
        let records ← readLog path
        let reduced := do
          let (streams, declared) ← prepareEvents (← records)
          reduce streams declared
        let (result, ran) :=
          match reduced with
          | .error error => (Except.error error, #[])
          | .ok reduced => (schedule reduced.header reduced.queues).run.run #[]
        unless flags.isEmpty do
          for group in ran do
            IO.eprintln s!"{group.ts.getD group.time} node '{group.node}' {group.label}"
        match result with
        | .error error => IO.eprintln s!"{path}: {error}"; return 1
        | .ok result =>
            let result :=
              Json.mkObj
                [
                  ("status", toJson "ok"),
                  ("groups", toJson result.groups),
                  ("actions", toJson result.actions),
                  ("observations", toJson result.observations)
                ]
            IO.println result.compress
            return 0
    | _, _ => IO.eprintln "usage: consensus-replay [--schedule] TRACE.ndjson"; return 2
  catch error =>
    IO.eprintln s!"{error}"
    return 1
