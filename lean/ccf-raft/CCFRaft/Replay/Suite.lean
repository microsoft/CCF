module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Reduction

public section

namespace CCFRaft.Replay

open Lean

/-- Every regular scenario file, recursively and sorted, as in the C++ suite. -/
partial def inventory (directory : System.FilePath) : IO (Array System.FilePath) := do
  unless (← directory.metadata).type == .dir do
    throw (IO.userError s!"{directory}: scenario inventory is not a directory")
  let paths ← collect directory
  if paths.isEmpty then throw (IO.userError s!"{directory}: empty scenario inventory")
  return paths.qsort (fun a b => a.toString < b.toString)
where
  collect (directory : System.FilePath) : IO (Array System.FilePath) := do
    let mut paths := #[]
    for entry in ← directory.readDir do
      let metadata ← entry.path.symlinkMetadata
      if metadata.type == .dir then
        paths := paths ++ (← collect entry.path)
      else if (← entry.path.metadata).type == .file then
        paths := paths.push entry.path
    return paths

private def copyOutput (input output : IO.FS.Handle) : IO Unit := do
  repeat
    let bytes ← input.read 65536
    if bytes.isEmpty then break
    output.write bytes
    output.flush

private partial def waitUntil {config : IO.Process.StdioConfig}
    (child : IO.Process.Child config) (deadline : Nat)
    : IO (Option UInt32) := do
  if let some code ← child.tryWait then return some code
  if (← IO.monoMsNow) >= deadline then return none
  IO.sleep 10
  waitUntil child deadline

/-- Capture bytes unchanged, drain both pipes concurrently, and retain failures. -/
def capture (driver scenario stdout stderr : System.FilePath) (timeoutMs : Nat)
    : IO Unit := do
  let out ← IO.FS.Handle.mk stdout .write
  let err ← IO.FS.Handle.mk stderr .write
  let driver ← IO.FS.realPath driver
  let scenario ← IO.FS.realPath scenario
  let child ←
    IO.Process.spawn
      {
        cmd := driver.toString,
        args := #[scenario.toString]
        stdin := .null,
        stdout := .piped,
        stderr := .piped
      }
  let output ← IO.asTask (copyOutput child.stdout out) .dedicated
  let errors ← IO.asTask (copyOutput child.stderr err) .dedicated
  let code ←
    try
      waitUntil child ((← IO.monoMsNow) + timeoutMs)
    catch error =>
      child.kill
      let _ ← child.wait
      throw error
  if code.isNone then
    child.kill
    let _ ← child.wait
  let _ ← IO.ofExcept output.get
  let _ ← IO.ofExcept errors.get
  let some code := code
  | throw
      (IO.userError
        s!"{scenario}: raft_driver exceeded {timeoutMs}ms; see {stdout} and {stderr}")
  unless code == 0 do
    throw
      (IO.userError s!"{scenario}: raft_driver exited {code}; see {stdout} and {stderr}")
  unless (← stderr.metadata).byteSize == 0 do
    throw (IO.userError s!"{scenario}: raft_driver wrote to stderr; see {stderr}")

def Result.json (result : Result) : Json :=
  Json.mkObj
    [
      ("status", toJson "ok"),
      ("instructions", toJson result.instructions),
      ("actions", toJson result.actions),
      ("observations", toJson result.observations)
    ]

structure SuiteConfig where
  scenarios : System.FilePath
  output : System.FilePath
  driver : Option System.FilePath := none
  rawDirectory : Option System.FilePath := none
  timeoutMs : Nat := 120000

structure SuiteResult where
  selected : Nat
  passed : Nat
  results : Array Json

def SuiteResult.failed (result : SuiteResult) : Nat := result.selected - result.passed

def SuiteResult.json (result : SuiteResult) (inventory : System.FilePath) : Json :=
  Json.mkObj
    [
      ("inventory", toJson inventory.toString),
      ("selected", toJson result.selected),
      ("passed", toJson result.passed),
      ("failed", toJson result.failed),
      ("results", .arr result.results)
    ]

private def removeIfPresent (path : System.FilePath) : IO Unit := do
  try
    IO.FS.removeFile path
  catch
    | .noFileOrDirectory .. => pure ()
    | error => throw error

/--
Attempt the actual inventory, never a fixed count. No stale success survives
an invalid inventory or interrupted run. Each failure keeps its stage and evidence.
-/
def runSuite (config : SuiteConfig) : IO SuiteResult := do
  let summary := config.output / "summary.json"
  removeIfPresent summary
  let scenarios ← IO.FS.realPath config.scenarios
  let selected ← inventory scenarios
  unless config.driver.isSome || config.rawDirectory.isSome do
    throw (IO.userError "provide --driver or --raw-directory")
  unless config.timeoutMs > 0 do
    throw (IO.userError "timeout-ms must be positive")
  IO.FS.createDirAll config.output
  let output ← IO.FS.realPath config.output
  if scenarios.components.isPrefixOf output.components then
    throw (IO.userError "output directory must not be inside the scenario inventory")
  let mut results := #[]
  let mut passed := 0
  for scenario in selected do
    let relative :=
      System.FilePath.mk
        (String.intercalate System.FilePath.pathSeparator.toString
          (scenario.components.drop scenarios.components.length))
    let base := output / relative
    if let some parent := base.parent then IO.FS.createDirAll parent
    let rawBase := config.rawDirectory.map (· / relative) |>.getD base
    let raw := System.FilePath.mk (rawBase.toString ++ ".stdout")
    let stderr := System.FilePath.mk (base.toString ++ ".stderr")
    let resultPath := System.FilePath.mk (base.toString ++ ".result.json")
    removeIfPresent resultPath
    let mut stage := if config.rawDirectory.isSome then "reduction" else "capture"
    let outcome : Except String Result ←
      try
        if config.rawDirectory.isNone then
          let some driver := config.driver | throw
                                              (IO.userError "capture requires a driver")
          capture driver scenario raw stderr config.timeoutMs
        stage := "reduction"
        match ← readLog raw with
        | .error error => pure (.error error)
        | .ok records =>
            match reduce records with
            | .error error => pure (.error error)
            | .ok reduced =>
                stage := "replay"
                pure (replay reduced.header reduced.instructions)
      catch error =>
        pure (.error s!"{error}")
    let fields :=
      [
        ("scenario", toJson relative.toString),
        ("raw", toJson raw.toString),
        ("stage", toJson stage)
      ]
    let result ←
      match outcome with
      | .ok result => do
          passed := passed + 1
          pure
            (Json.mkObj
              (fields
                ++ [
                  ("status", toJson "passed"),
                  ("instructions", toJson result.instructions),
                  ("actions", toJson result.actions),
                  ("observations", toJson result.observations)
                ]))
      | .error error =>
          pure
            (Json.mkObj
              (fields ++ [("status", toJson "failed"), ("error", toJson error)]))
    IO.FS.writeFile resultPath (result.pretty ++ "\n")
    IO.println s!"{relative}: {if outcome.isOk then "passed" else "failed"} ({stage})"
    results := results.push result
  let result := { selected := selected.size, passed, results : SuiteResult }
  IO.FS.writeFile summary ((result.json scenarios).pretty ++ "\n")
  return result

end CCFRaft.Replay
