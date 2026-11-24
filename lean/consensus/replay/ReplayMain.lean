module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Groups

public section

open Lean Consensus.Replay

def main (args : List String) : IO UInt32 := do
  try
    let (flags, paths) := args.partition (·.startsWith "--")
    match flags.eraseDups, paths with
    | flags, [path] =>
        unless flags.all (["--schedule", "--strict=off"].contains ·) do
          IO.eprintln s!"unknown option {flags}"
          return 2
        let strict := !flags.contains "--strict=off"
        let records ← readLog path
        let reduced := do
          let (streams, declared) ← prepareEvents (← records)
          reduce streams declared strict
        let (result, ran) :=
          match reduced with
          | .error error => (Except.error error, #[])
          | .ok reduced =>
              let (result, ran) :=
                (schedule reduced.header reduced.queues strict).run.run #[]
              (
                result.map
                  fun (result : Result) => (reduced.watermark result.ran, result),
                ran
              )
        if flags.contains "--schedule" then
          for group in ran do
            IO.eprintln s!"{group.ts.getD group.m_ts} node '{group.node}' {group.label}"
        match result with
        | .error error => IO.eprintln s!"{path}: {error}"; return 1
        | .ok (watermark, result) =>
            let result :=
              Json.mkObj
                [
                  ("status", toJson "ok"),
                  ("watermark", toJson watermark),
                  ("groups", toJson result.ran.sum),
                  ("actions", toJson result.actions),
                  ("observations", toJson result.observations)
                ]
            IO.println result.compress
            return 0
    | _, _ =>
        IO.eprintln "usage: consensus-replay [--schedule] [--strict=off] TRACE.ndjson";
        return 2
  catch error =>
    IO.eprintln s!"{error}"
    return 1
