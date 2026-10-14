module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Suite

public section

open CCFRaft.Replay

private def usage : String :=
  "usage: ccfraft-replay TRACE.stdout|TRACE.ndjson\n"
  ++ "       ccfraft-replay suite --output DIR [--scenarios DIR] (--driver PATH|--raw-directory DIR) [--timeout-ms N]"

private def parseSuite (args : List String) : Except String SuiteConfig :=
  go { scenarios := "../../tests/raft_scenarios", output := "" } args
where
  go (config : SuiteConfig) : List String → Except String SuiteConfig
    | [] => do
        require (!config.output.toString.isEmpty) "--output is required"
        require (config.driver.isSome != config.rawDirectory.isSome)
          "provide exactly one of --driver and --raw-directory"
        require (config.timeoutMs > 0) "timeout-ms must be positive"
        return config
    | "--output" :: value :: rest => go { config with output := value } rest
    | "--scenarios" :: value :: rest => go { config with scenarios := value } rest
    | "--driver" :: value :: rest => go { config with driver := some value } rest
    | "--raw-directory" :: value :: rest =>
        go { config with rawDirectory := some value } rest
    | "--timeout-ms" :: value :: rest => do
        let some timeoutMs := value.toNat? | throw "invalid timeout-ms"
        go { config with timeoutMs } rest
    | option :: _ => throw s!"unexpected or incomplete suite option '{option}'"

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | "suite" :: args =>
        match parseSuite args with
        | .error error => IO.eprintln s!"{error}\n{usage}"; return 2
        | .ok config =>
            let result ← runSuite config
            IO.println s!"{result.passed}/{result.selected} passed"
            return if result.failed == 0 then 0 else 1
    | [path] =>
        let result ← readLog path
        match result >>= replayRecords with
        | .error error => IO.eprintln error; return 1
        | .ok result => IO.println result.json.compress; return 0
    | _ => IO.eprintln usage; return 2
  catch error =>
    IO.eprintln s!"{error}"
    return 1
