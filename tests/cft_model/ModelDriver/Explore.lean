-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import ModelDriver.Episode

/-!
Explores what the consensus implementation does when the scenarios are changed.

The commands of each scenario are a seed. A program is changed at random, for example to
hold a message back until later, and run in a process of its own, which checks the run
against the model. A run is kept, to be changed in turn, if it makes the model show an
outcome, or reaches an edge of the implementation, which no run before it has. A run in
which the driver fails, or the driver and the model disagree, is a finding.
-/

open Lean
open Consensus.Replay (string field Outcome)

namespace ModelDriver

/-- How to explore. -/
structure Exploration where
  /-- Where the programs which are run, kept and found are written, with a report. -/
  directory : System.FilePath
  /-- The changes made are a function of the seed. -/
  seed : Nat := 1
  /-- How many changed programs to run. -/
  runs : Nat := 1000
  /-- How many programs to run at once. -/
  jobs : Nat := 8

private abbrev Random := StateM StdGen

/-- A number below `bound`. -/
private def below (bound : Nat) : Random Nat :=
  modifyGet fun generator => randNat generator 0 (bound - 1)

private def insert (steps : Array Step) (index : Nat) (step : Step) : Array Step :=
  steps.extract 0 index ++ #[step] ++ steps.extract index steps.size

/-- Each kind as many times as its weight, so that a kind picked at random is that likely. -/
private def weighted (kinds : List (String × Nat)) : Array String :=
  kinds.toArray.flatMap fun (kind, weight) => Array.replicate weight kind

/-- The kinds of change, and how often each is made. -/
private def changes : Array String :=
  weighted
    [
      ("delay", 6),
      ("tick", 3),
      ("drop", 2),
      ("deliver", 2),
      ("partition", 2),
      ("delete", 2),
      ("burst", 2),
      ("nominate", 1),
      ("write", 1),
      ("sign", 1),
      ("duplicate", 1),
      ("swap", 1),
      ("latest", 1),
      ("truncate", 1)
    ]

/-- The kinds of choice in a burst, and how often each is made. -/
private def choices : Array String :=
  weighted
    [
      ("tick", 2),
      ("hold", 1),
      ("release", 1),
      ("deliver", 1),
      ("drop", 1),
      ("isolate", 1),
      ("rejoin", 1),
      ("nominate", 1),
      ("write", 1),
      ("sign", 1)
    ]

/--
Change a program in one way, and describe the change, or give no description if the
program is as it was. The first step, which starts the network, stays.
-/
private def change (steps : Array Step) : Random (Array Step × String) := do
  let size := steps.size
  let position := 1 + (← below size)
  let value ← below 1000000
  let kind := changes[← below changes.size]!
  match kind with
  | "delay" | "partition" =>
      -- Hold a message, or disconnect a node, and undo that later
      let later := position + (← below (size - position + 1))
      let (first, second) :=
        if kind == "delay" then ("hold", "release") else ("isolate", "rejoin")
      let changed :=
        insert (insert steps later (.choice second value)) position (.choice first value)
      return (changed, s!"{kind} {position}..{later}")
  | "delete" =>
      if position < size then
        return (
          steps.extract 0 position ++ steps.extract (position + 1) size,
          s!"delete {position}"
        )
      return (steps, "")
  | "duplicate" =>
      match steps[position]? with
      | some (.given command) =>
          if command.creates.isEmpty then
            return (insert steps position (.given command), s!"duplicate {position}")
          return (steps, "")
      | _ => return (steps, "")
  | "swap" =>
      match steps[position]?, steps[position + 1]? with
      | some first, some second =>
          return (
            (steps.set! position second).set! (position + 1) first,
            s!"swap {position}"
          )
      | _, _ => return (steps, "")
  | "latest" =>
      let changed :=
        steps.mapIdx
          fun index step =>
            match step with
            | .given command => if index < position then step else .given command.toLatest
            | step => step
      return (changed, s!"latest {position}")
  | "burst" =>
      let count := 3 + (← below 6)
      let mut burst := #[]
      for _ in [0:count] do
        burst := burst.push (.choice choices[← below choices.size]! (← below 1000000))
      return (
        steps.extract 0 position ++ burst ++ steps.extract position size,
        s!"burst {position}+{count}"
      )
  | "truncate" =>
      if position < size then
        return (steps.extract 0 position, s!"truncate {position}")
      return (steps, "")
  | kind => return (insert steps position (.choice kind value), s!"{kind} {position}")

/-- Why a program is run. -/
private inductive Purpose where
  /-- The commands of a scenario, which must run as they are. -/
  | seed
  /-- A changed program. -/
  | explore
  /-- The commands of a run which reached something new, which must do so again. -/
  | confirm
  /-- The commands of the first run with a finding, to tell whether it happens again. -/
  | reproduce (signature : String)

private structure Job where
  /-- The scenario from which the program comes, and the changes made to it. -/
  origin : String
  steps : Array Step
  purpose : Purpose

/-- A program which is changed to make others. -/
private structure Entry where
  origin : String
  commands : Array Command
deriving Inhabited

/-- A program changed in up to four ways. -/
private def changed (corpus : Array Entry) : Random Job := do
  let entry := corpus[← below corpus.size]!
  let count :=
    match ← below 10 with
    | 0 | 1 | 2 | 3 | 4 => 1
    | 5 | 6 | 7 => 2
    | 8 => 3
    | _ => 4
  let mut steps := entry.commands.map Step.given
  let mut made := []
  for _ in [0:count] do
    let (next, description) ← change steps
    steps := next
    unless description.isEmpty do
      made := made ++ [description]
  return {
    origin := s!"{entry.origin} + {", ".intercalate made}", steps, purpose := .explore
  }

/-- What a run reported. -/
private structure Ran where
  /-- As `Report.status`, or `crash` if the run did not report. -/
  status : String
  kind : String := ""
  message : String := ""
  command : String := ""
  /-- The outcomes shown before the driver confirmed progress, each once. -/
  outcomes : List String := []
  /-- The outcomes shown as the driver confirmed progress, each once. -/
  settled : List String := []
  stuck : String := ""
  commands : Array Command := #[]
  edges : ByteArray := ByteArray.empty
  /-- The file of its result, beside which its trace is, if it is a finding. -/
  result : System.FilePath

private def strings (value : Json) (key : String) : Except String (List String) := do
  let items ← (← field value key).getArr?
  return (← items.mapM (·.getStr?)).toList

/-- Read what a run wrote. `exit` is its exit status, and `errors` what it wrote to stderr. -/
private def readRan (result : System.FilePath) (exit : UInt32) (errors : String)
    : IO Ran := do
  if exit != 0 || !(← result.pathExists) then
    let last := ("\n".intercalate ((errors.splitOn "\n").reverse.take 12).reverse)
    return {
      status := "crash"
      kind := "crash"
      message := s!"exit status {exit}: {last}"
      result
    }
  let value ← IO.ofExcept (Json.parse (← IO.FS.readFile result))
  let read : Except String Ran := do
    return {
      status := ← string value "status"
      kind := ← string value "kind"
      message := ← string value "message"
      command := ← string value "command"
      outcomes := (← strings value "outcomes").eraseDups
      settled := (← strings value "settled").eraseDups
      stuck := ← string value "stuck"
      commands := ((← strings value "commands").map Command.parse).toArray
      result
    }
  let ran ← IO.ofExcept read
  return { ran with edges := ← IO.FS.readBinFile (result.withExtension "edges") }

private abbrev quiet : IO.Process.StdioConfig :=
  { stdin := .inherit, stdout := .null, stderr := .piped }

/-- Start this program again with `args`. -/
private def start (args : Array String) : IO (IO.Process.Child quiet) := do
  IO.Process.spawn { toStdioConfig := quiet, cmd := (← IO.appPath).toString, args }

/-- Wait for runs which were started together, and read their results. -/
private def finishRuns (started : Array (IO.Process.Child quiet × System.FilePath))
    : IO (Array Ran) :=
  started.mapM
    fun (child, result) => do
      let errors ← child.stderr.readToEnd
      readRan result (← child.wait) errors

/-- Run programs at once, each in a process of its own. -/
private def runJobs (directory : System.FilePath) (jobs : Array Job)
    : IO (Array Ran) := do
  let mut started := #[]
  for job in jobs, slot in [0:jobs.size] do
    let program := directory / "run" / s!"{slot}.program"
    let result := program.withExtension "json"
    IO.FS.writeFile program (programText [job.origin] job.steps)
    if ← result.pathExists then
      IO.FS.removeFile result
    started :=
      started.push (← start #["--run", program.toString, result.toString], result)
  finishRuns started

/-- A finding, as the first run which had it. -/
private structure Finding where
  kind : String
  /-- Its kind and message, without what differs from run to run. -/
  signature : String
  message : String
  command : String
  origin : String
  /-- How many runs had it. -/
  count : Nat := 1
  /-- Whether its commands had it when they were run again. -/
  reproduced : Option Bool := none

/-- A run which was kept: what it showed and reached which no run before it had. -/
private structure Kept where
  origin : String
  outcomes : List String
  edges : Nat

private structure State where
  corpus : Array Entry := #[]
  /-- The outcomes which the scenarios show. -/
  shown : List String := []
  /-- The outcomes which a run has shown. -/
  outcomes : List String := []
  /-- The edges which a run has reached, each nonzero. -/
  edges : ByteArray := ByteArray.empty
  /-- How many edges the scenarios reach. -/
  reached : Nat := 0
  kept : Array Kept := #[]
  findings : Array Finding := #[]
  /-- Why the driver could not confirm progress, and in how many runs. -/
  stuck : List (String × Nat) := []
  explored : Nat := 0
  ok : Nat := 0
  invalid : Nat := 0
  /-- Runs which reached something new, and did not when they were run again. -/
  unconfirmed : Nat := 0

private def byte (bytes : ByteArray) (index : Nat) : UInt8 :=
  if index < bytes.size then bytes.get! index else 0

/-- How many edges are nonzero. -/
private def countEdges (edges : ByteArray) : Nat :=
  (List.range edges.size).countP fun index => edges.get! index != 0

/-- How many edges `reached` has which `known` lacks. -/
private def freshEdges (known reached : ByteArray) : Nat :=
  (List.range reached.size).countP
    fun index => reached.get! index != 0 && byte known index == 0

private def mergeEdges (known reached : ByteArray) : ByteArray :=
  (List.range reached.size).foldl
    (fun merged index =>
      if reached.get! index != 0 then merged.set! index 1 else merged)
    (known ++ ⟨Array.replicate (reached.size - known.size) 0⟩)

/-- The text without what differs between runs of one kind: its numbers. -/
private def signature (text : String) : String :=
  (text.foldl
    (fun (collapsed, inNumber) character =>
      if character.isDigit then
        (if inNumber then collapsed else collapsed.push 'N', true)
      else
        (collapsed.push character, false))
    ("", false)).1

private def Ran.signature (ran : Ran) : String :=
  s!"{ran.kind}: {ModelDriver.signature ran.message}"

private def copyFile (source target : System.FilePath) : IO Unit := do
  if ← source.pathExists then
    IO.FS.writeBinFile target (← IO.FS.readBinFile source)

/-- Take in the result of a run. Also give a program to run because of it, if any. -/
private def absorb (directory : System.FilePath) (state : State) (job : Job) (ran : Ran)
    : IO (State × Option Job) := do
  let again (purpose : Purpose) : Job :=
    -- A run which did not report is run again as it was
    let steps := if ran.commands.isEmpty then job.steps else ran.commands.map Step.given
    { origin := job.origin, steps, purpose }
  let newOutcomes := ran.outcomes.filter (!state.outcomes.contains ·)
  let newEdges := freshEdges state.edges ran.edges
  let keep (state : State) : IO State := do
    let file := directory / "corpus" / s!"{state.corpus.size}.program"
    let comments := [job.origin, s!"outcomes: {newOutcomes}", s!"edges: {newEdges}"]
    IO.FS.writeFile file (programText comments (ran.commands.map Step.given))
    return {
      state with
        corpus := state.corpus.push { origin := job.origin, commands := ran.commands }
        outcomes := state.outcomes ++ newOutcomes
        edges := mergeEdges state.edges ran.edges
    }
  match job.purpose with
  | .seed =>
      if ran.status == "ok" then
        return (← keep state, none)
      IO.println s!"{job.origin}: not explored, {ran.status}: {ran.message}"
      return (state, none)
  | .confirm =>
      if ran.status == "ok" && (!newOutcomes.isEmpty || newEdges > 0) then
        let kept : Kept :=
          { origin := job.origin, outcomes := newOutcomes, edges := newEdges }
        return ({ (← keep state) with kept := state.kept.push kept }, none)
      return ({ state with unconfirmed := state.unconfirmed + 1 }, none)
  | .reproduce signature =>
      let reproduced := ran.status != "ok" && ran.signature == signature
      let findings :=
        state.findings.map
          fun finding =>
            if finding.signature == signature then
              { finding with reproduced := some reproduced }
            else
              finding
      return ({ state with findings }, none)
  | .explore =>
      let state := { state with explored := state.explored + 1 }
      if ran.status == "ok" then
        let stuck :=
          if ran.stuck.isEmpty then
            state.stuck
          else
            let reason := ModelDriver.signature ran.stuck
            match state.stuck.lookup reason with
            | some count =>
                state.stuck.map
                  fun (other, runs) =>
                    (other, if other == reason then count + 1 else runs)
            | none => state.stuck ++ [(reason, 1)]
        let state := { state with ok := state.ok + 1, stuck }
        if newOutcomes.isEmpty && newEdges == 0 then
          return (state, none)
        return (state, some (again .confirm))
      if ran.status == "invalid" then
        return ({ state with invalid := state.invalid + 1 }, none)
      let signature := ran.signature
      if state.findings.any (·.signature == signature) then
        let findings :=
          state.findings.map
            fun finding =>
              if finding.signature == signature then
                { finding with count := finding.count + 1 }
              else
                finding
        return ({ state with findings }, none)
      let finding : Finding :=
        {
          kind := ran.kind
          signature
          message := ran.message
          command := ran.command
          origin := job.origin
        }
      let follow := again (.reproduce signature)
      let file := directory / "findings" / s!"{state.findings.size}.program"
      let comments := [job.origin, s!"{ran.kind} at '{ran.command}'", ran.message]
      IO.FS.writeFile file (programText (comments.map (·.replace "\n" " ")) follow.steps)
      copyFile (ran.result.withExtension "ndjson") (file.withExtension "ndjson")
      return ({ state with findings := state.findings.push finding }, some follow)

private def cell (text : String) : String :=
  let line := (text.replace "\n" " ").replace "|" "/"
  if line.length > 300 then (line.take 300).toString ++ "..." else line

/-- What the exploration did, in Markdown. -/
private def summary (options : Exploration) (state : State) (seconds : Nat) : String :=
  let found := state.outcomes.filter (!state.shown.contains ·)
  let missing := (Outcome.all.map (·.name)).filter (!state.outcomes.contains ·)
  let count (status : String) (runs : Nat) := s!"| {status} | {runs} |"
  let lines :=
    [
      "# Exploration of the consensus scenarios",
      "",
      s!"Seed {options.seed}: {state.explored} changed programs run in {seconds} s.",
      "",
      "| Runs | |",
      "| --- | ---: |",
      count "Accepted by the model" state.ok,
      count "Not covered by the model" state.invalid,
      count "Findings" ((state.findings.map (·.count)).foldl (· + ·) 0),
      count "Kept" state.kept.size,
      count "New when first run, and not when run again" state.unconfirmed,
      "",
      s!"Outcomes: the scenarios show {state.shown.length} of {Outcome.all.length}, and the runs kept {found.length} more: {found}.",
      s!"No run shows: {missing}.",
      "",
      s!"Edges: the scenarios reach {state.reached} of {state.edges.size}, and the runs kept {countEdges state.edges - state.reached} more.",
      "",
      "## Runs kept",
      "",
      "| Program | From | New outcomes | New edges |",
      "| --- | --- | --- | ---: |"
    ]
    ++ (state.kept.toList.zipIdx (state.corpus.size - state.kept.size)).map
        (fun (kept, index) =>
          s!"| corpus/{index}.program | {cell kept.origin} | {", ".intercalate kept.outcomes} | {kept.edges} |")
    ++ [
      "",
      "## Findings",
      "",
      "| Program | Kind | Runs | Again | From | At | Message |",
      "| --- | --- | ---: | --- | --- | --- | --- |"
    ]
    ++ state.findings.toList.zipIdx.map
        (fun (finding, index) =>
          let again :=
            match finding.reproduced with
            | some true => "yes"
            | some false => "no"
            | none => ""
          s!"| findings/{index}.program | {finding.kind} | {finding.count} | {again} | {cell finding.origin} | {cell finding.command} | {cell finding.message} |")
    ++ [
      "",
      "## Runs after which the driver could not confirm progress",
      "",
      "| Reason | Runs |",
      "| --- | ---: |"
    ]
    ++ state.stuck.map fun (reason, runs) => s!"| {cell reason} | {runs} |"
  "\n".intercalate lines ++ "\n"

/-- The jobs in groups of at most `size`. -/
private def groups (jobs : Array Job) (size : Nat) : List (Array Job) :=
  (List.range ((jobs.size + size - 1) / size)).map
    fun group => jobs.extract (group * size) ((group + 1) * size)

/-- What a shorter program must keep of the run of the program which it shortens. -/
inductive Keep where
  /-- The finding: its kind and its message, numbers aside. -/
  | finding
  /-- An outcome which the model shows, in a run which the model accepts. -/
  | outcome (name : String)
  /--
  Every edge which the run reaches and these lack, each nonzero if reached, in a run
  which the model accepts.
  -/
  | edges (known : ByteArray)

/--
Make the program in `file` shorter: leave out steps for as long as its run keeps what
`keep` asks. Write the program left to `output`.
-/
def shrink (file output : System.FilePath) (keep : Keep) (jobs : Nat) : IO UInt32 := do
  let directory ← IO.FS.createTempDir
  IO.FS.createDirAll (directory / "run")
  let run (programs : Array (Array Step)) : IO (Array Ran) := do
    let mut ran := #[]
    for group
        in groups
            (programs.map ({ origin := file.toString, steps := ·, purpose := .explore }))
            jobs do
      ran := ran ++ (← runJobs directory group)
    return ran
  let given ← readProgram file
  let some first := (← run #[given])[0]? | return 1
  let wanted :=
    match keep with
    | .edges known =>
        (List.range first.edges.size).filter
          fun index => first.edges.get! index != 0 && byte known index == 0
    | _ => []
  let keeps (ran : Ran) : Bool :=
    match keep with
    | .outcome name => ran.status == "ok" && ran.outcomes.contains name
    | .edges _ =>
        ran.status == "ok"
        && !wanted.isEmpty
        && wanted.all fun index => byte ran.edges index != 0
    | .finding =>
        -- The same finding, and still before or after the driver confirms progress
        ran.status != "ok"
        && ran.status != "invalid"
        && ran.status == first.status
        && ran.signature == first.signature
        && (ran.command == "finish") == (first.command == "finish")
  unless keeps first do
    IO.eprintln
      s!"{file}: its run is {first.status}, and does not show what is to be kept: {first.message}"
    IO.FS.removeDirAll directory
    return 1
  let commands (ran : Ran) (steps : Array Step) : Array Step :=
    if ran.commands.isEmpty then steps else ran.commands.map Step.given
  let mut steps := commands first given
  let mut last := first
  -- Leave out parts of `size` steps, after the first step, then smaller parts
  let mut size := max 1 (steps.size / 2)
  let mut rounds := 0
  while rounds < 1000 do
    rounds := rounds + 1
    let parts := (steps.size - 1 + size - 1) / size
    let candidates :=
      (List.range parts).toArray.map
        fun part =>
          steps.extract 0 (1 + part * size)
          ++ steps.extract (1 + (part + 1) * size) steps.size
    let results ← run candidates
    match (candidates.zip results).find? fun (_, ran) => keeps ran with
    | some (candidate, ran) =>
        steps := commands ran candidate
        last := ran
        size := max 1 (min size (steps.size / 2))
    | none =>
        if size == 1 then
          break
        size := (size + 1) / 2
  IO.FS.removeDirAll directory
  let kept :=
    match keep with
    | .outcome name => [s!"shows {name}"]
    | .edges _ => [s!"reaches {wanted.length} edges which the others do not"]
    | .finding => [s!"{last.kind} at '{last.command}'", last.message.replace "\n" " "]
  IO.FS.writeFile output (programText (s!"{file}, shrunk" :: kept) steps)
  IO.println s!"{given.size} steps shrunk to {steps.size}: {kept.head!}"
  return 0

/--
Record the commands of each scenario, change them at random and run the changed programs.
Write the programs kept and found, and a report, to the directory.
-/
def explore (options : Exploration) (scenarios : List String) : IO UInt32 := do
  let directory := options.directory
  for part in ["run", "seeds", "corpus", "findings"] do
    IO.FS.createDirAll (directory / part)
  let began ← IO.monoMsNow
  -- What the scenarios show and reach is not new
  let mut state : State := {}
  let mut seeds : Array Job := #[]
  let recordings : Array Job :=
    scenarios.toArray.map fun name => { origin := name, steps := #[], purpose := .seed }
  for jobs in groups recordings options.jobs do
    let started ←
      jobs.mapM
        fun job => do
          let program := directory / "seeds" / s!"{job.origin}.program"
          return (
            ← start #["--record", job.origin, program.toString],
            program.withExtension "json"
          )
    for job in jobs, ran in (← finishRuns started) do
      if ran.status != "ok" then
        IO.println s!"{job.origin}: not explored, {ran.status}: {ran.message}"
      else
        -- Without the checks of the scenario, which a change would fail
        let commands :=
          ran.commands.filter fun command => !command.observes && !command.shuffles
        seeds := seeds.push { job with steps := commands.map Step.given }
        state :=
          {
            state with
              outcomes := (state.outcomes ++ ran.outcomes ++ ran.settled).eraseDups
              edges := mergeEdges state.edges ran.edges
          }
  state := { state with shown := state.outcomes, reached := countEdges state.edges }
  -- For `shrink`, to keep what a run reaches and the scenarios do not
  IO.FS.writeBinFile (directory / "scenarios.edges") state.edges
  for jobs in groups seeds options.jobs do
    for job in jobs, ran in (← runJobs directory jobs) do
      state := (← absorb directory state job ran).1
  if state.corpus.isEmpty then
    IO.eprintln "no scenario can be explored"
    return 1
  IO.println
    s!"{state.corpus.size} scenarios show {state.shown.length} outcomes and reach {state.reached} of {state.edges.size} edges"
  -- Change, run, and run again what is new
  let mut generator := mkStdGen options.seed
  let mut waiting : Array Job := #[]
  let mut planned := 0
  let mut batches := 0
  while planned < options.runs || !waiting.isEmpty do
    let mut jobs := waiting.extract 0 options.jobs
    waiting := waiting.extract options.jobs waiting.size
    while jobs.size < options.jobs && planned < options.runs do
      let (job, next) := (changed state.corpus).run generator
      generator := next
      jobs := jobs.push job
      planned := planned + 1
    for job in jobs, ran in (← runJobs directory jobs) do
      let (next, follow) ← absorb directory state job ran
      state := next
      if let some follow := follow then
        waiting := waiting.push follow
    batches := batches + 1
    if batches % 50 == 0 then
      IO.println
        s!"{state.explored} runs: {state.kept.size} kept, {state.outcomes.length} outcomes, {countEdges state.edges} edges, {state.findings.size} findings"
  let seconds := ((← IO.monoMsNow) - began) / 1000
  let report := summary options state seconds
  IO.FS.writeFile (directory / "report.md") report
  IO.println report
  return 0

end ModelDriver
