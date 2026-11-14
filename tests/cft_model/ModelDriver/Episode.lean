-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Consensus.Replay.Session
import ModelDriver.Command

/-!
One run of the driver, checked against the model.

A process can start the driver once, so each run has a process of its own. It reports
through files to the process which started it: what the model made of the run, the
commands which it issued, and the edges of the consensus implementation which it reached.
-/

open Lean
open CftDriver
open Consensus Consensus.Replay
open CCF.MultiNodeTransitionSystem (nodeState)

namespace ModelDriver

/-- Fail with `message`. -/
def fail {α : Type} (message : String) : IO α :=
  throw (IO.userError message)

/--
The counters of the edges of the consensus implementation, each nonzero if the process has
run its edge. Empty unless the driver was compiled to count them.
-/
@[extern "cft_edges"]
opaque edges : IO ByteArray

/-- End the process if it is still running after `seconds`. -/
@[extern "cft_time_limit"]
opaque timeLimit (seconds : UInt64) : IO Unit

/-- Take the trace records emitted since the last call, numbered after the `taken` before. -/
def takeRecords (source : String) (taken : Nat) : IO (Array Record) := do
  (← takeTrace).mapIdxM
    fun index line => do
      let value ← IO.ofExcept (Json.parse line)
      return { file := source, line := taken + index + 1, value }

/-- The nodes which have started, by name and model identifier. -/
def started (session : Session) : List (String × Nat) :=
  session.header.declared.zipIdx.filter
    fun (_, id) => (nodeState session.state id).any fun node => !decide node.isFresh

/--
Each message which the driver has not delivered, or holds, must be a distinct envelope in
the network of the model. The model also keeps the messages which the driver has dropped.
-/
def checkPending (session : Session) : IO Unit := do
  let mut queued := session.state.network
  for text in (← undeliveredMessages) ++ (← heldMessages) do
    let message ← IO.ofExcept (Json.parse text)
    let found : Except String (Option Model.Envelope) := do
      let source ← session.header.nodeId (← string message "from")
      let target ← session.header.nodeId (← string message "to")
      let packet ← field message "packet"
      return queued.find?
        fun envelope =>
          envelope.source == source
          && envelope.target == target
          && packetMatches packet envelope.payload
    match found with
    | .ok (some envelope) => queued := queued.erase envelope
    | .ok none => fail s!"the model holds no message like {text}"
    | .error error => fail s!"{error} in {text}"

/-- Why the driver stopped before the end of a run. -/
structure Stop where
  /-- `stuck`, `invariant` or `error`. -/
  kind : String
  message : String
  /-- The command which it could not run. -/
  command : String

/-- What a run did, as the model sees it. -/
structure Report where
  /--
  `ok`, or `finding` if the driver and the model disagree or the driver fails, or `invalid`
  if the model does not cover the run: it does not start a network, or it has a primary
  append what no application would, such as the removal of a node which has not retired.
  -/
  status : String := "ok"
  /-- What kind of finding: `model`, `undelivered`, `invariant` or `error`. -/
  kind : String := ""
  message : String := ""
  /-- The command at which it was found. -/
  command : String := ""
  /--
  The outcomes which the model shows, in order, before the driver confirms that the
  network can make progress.
  -/
  outcomes : Array String := #[]
  /-- The outcomes which the model shows as the driver confirms that. -/
  settled : Array String := #[]
  /--
  Commands which assert the state of each node, as the model has it, before the driver
  confirms that.
  -/
  checks : Array String := #[]
  /-- Why the driver could not confirm that the network can make progress, if so. -/
  stuck : String := ""

private def has (text : String) (parts : List String) : Bool :=
  parts.any fun part => (text.splitOn part).length > 1

/-- Whether the driver failed because the network cannot make progress. -/
private def isStuck (error : String) : Bool :=
  has error ["Failed to reach state sync", "Can't currently loop until sync"]

/--
Why the driver stops when a command fails with `error`, or `none` if the command does not
apply in the state of the driver, which goes on.
-/
private def stopFor (error : String) : Option String :=
  if has error
      [
        "Found no primary in term",
        "No undelivered message at position",
        "No held message at position"
      ] then
    none
  else if has error ["at unsafe commit idx"] then
    some "invariant"
  else if isStuck error then
    some "stuck"
  else
    some "error"

/-- Replay a run by command. An error is with the index of the command which fails. -/
private def replayRun (records : Array Record) : Except (Nat × String) Session := do
  let (_, declared) ← (prepareEvents records).mapError ((0, ·))
  let commands := splitCommands records
  let some first := commands[0]? | throw (0, "the trace has no records")
  let mut session ← (Session.start declared first).mapError ((0, ·))
  for index in [1:commands.size] do
    session ← (session.feed commands[index]!).mapError ((index, ·))
  return session

/-- The command which a record of a trace names, if it is the record of a command. -/
private def commandText (record : Record) : Option String :=
  ((optional record.value "msg").bind (optional · "cmd")).bind (·.getStr?.toOption)

/-- The text of the command at `index` in a trace. -/
private def commandAt (records : Array Record) (index : Nat) : String :=
  (((splitCommands records)[index]?.bind (·[0]?)).bind commandText).getD ""

/-- Commands which assert the leadership and the commit index of each node in the model. -/
private def stateChecks (session : Session) : Array String :=
  (started session).toArray.flatMap
    fun (node, id) =>
      match nodeState session.state id with
      | none => #[]
      | some state =>
          let leadership :=
            match state.role with
            | .none => "None"
            | .follower => "Follower"
            | .preVoteCandidate => "PreVoteCandidate"
            | .candidate => "Candidate"
            | .primary => "Leader"
          #[
            s!"assert_detail,{node},leadership_state,{leadership}",
            s!"assert_commit_idx,{node},{state.commitIndex}"
          ]

/--
Check what the driver has done against the model. Unless it has `stopped`, have it confirm
that the network can still make progress, and check that too. Also give the trace, and the
edges which the run reached before the driver confirmed progress.
-/
private def conclude (stopped : Option Stop)
    : IO (Report × Array Record × ByteArray) := do
  let records ← takeRecords "run" 0
  let counters ← edges
  -- A command which fails may leave a group of events unfinished.
  let whole :=
    if stopped.any (·.kind == "error") then
      (splitCommands records).pop.foldl (· ++ ·) #[]
    else
      records
  match replayRun whole with
  | .error (index, message) =>
      let command := commandAt whole index
      -- The model only lets a primary append what an application would ask of it
      let report : Report :=
        if index == 0 || has message ["disabled model action 'append'"] then
          { status := "invalid", message, command }
        else
          { status := "finding", kind := "model", message, command }
      return (report, records, counters)
  | .ok session =>
      let outcomes := session.result.outcomes.map (·.name)
      let checks := stateChecks session
      let undelivered ←
        try
          checkPending session
          pure none
        catch error =>
          pure (some (toString error))
      if let some message := undelivered then
        return (
          { status := "finding", kind := "undelivered", message, outcomes },
          records,
          counters
        )
      if let some stop := stopped then
        let report : Report :=
          if stop.kind == "stuck" then
            { outcomes, checks, stuck := stop.message }
          else
            {
              status := "finding"
              kind := stop.kind
              message := stop.message
              command := stop.command
              outcomes
            }
        return (report, records, counters)
      let failure ←
        try
          finish
          pure ""
        catch error =>
          pure (toString error)
      let rest ← takeRecords "run" records.size
      let records := records ++ rest
      let report : Report :=
        if !failure.isEmpty && !isStuck failure then
          {
            status := "finding", kind := "error", message := failure, command := "finish"
          }
        else
          match session.feed rest with
          | .error message =>
              { status := "finding", kind := "model", message, command := "finish" }
          | .ok settled =>
              {
                stuck := failure
                settled :=
                  (settled.result.outcomes.extract outcomes.size).map (·.name)
              }
      return ({ report with outcomes, checks }, records, counters)

/-- Write the result of a run to `file`, its edges beside it, and its trace if it is a finding. -/
private def writeResult (file : System.FilePath) (report : Report)
    (commands : Array String) (records : Array Record) (counters : ByteArray)
    : IO Unit := do
  let result :=
    Json.mkObj
      [
        ("status", toJson report.status),
        ("kind", toJson report.kind),
        ("message", toJson report.message),
        ("command", toJson report.command),
        ("outcomes", toJson report.outcomes),
        ("settled", toJson report.settled),
        ("checks", toJson report.checks),
        ("stuck", toJson report.stuck),
        ("commands", toJson commands)
      ]
  IO.FS.writeBinFile (file.withExtension "edges") counters
  if report.status == "finding" then
    IO.FS.writeFile (file.withExtension "ndjson")
      (String.join (records.toList.map (·.value.compress ++ "\n")))
  IO.FS.writeFile file result.compress

/-- Print the status of a run, and give its exit status. -/
private def announce (name : String) (report : Report) : IO UInt32 := do
  if report.status == "ok" then
    let status :=
      Json.mkObj
        [
          ("status", toJson "ok"),
          ("run", toJson name),
          ("outcomes", toJson report.outcomes.size),
          ("stuck", toJson report.stuck)
        ]
    IO.println status.compress
    return 0
  IO.eprintln s!"{name}: {report.kind} at '{report.command}': {report.message}"
  return 1

/--
Run a scenario, and write the commands which it issued to `file`, as a program. Write
the result of the run beside it, as `runProgram` does, but with every edge which the
scenario reached.
-/
def recordScenario (name : String) (steps : IO Unit) (file : System.FilePath)
    : IO UInt32 := do
  timeLimit 120
  startCapture
  let stopped ←
    try
      steps
      pure none
    catch error =>
      pure (some { kind := "error", message := toString error, command := "" : Stop })
  let (report, records, _) ← conclude stopped
  let commands := records.filterMap commandText
  IO.FS.writeFile file (programText [name] (commands.map (.given <| Command.parse ·)))
  writeResult (file.withExtension "json") report commands records (← edges)
  announce name report

/-- A message which the driver reports, with its position among those of its link. -/
private structure Queued where
  source : String
  target : String
  position : Nat

private def queuedMessages (reported : Array String) : IO (Array Queued) := do
  let mut messages : Array Queued := #[]
  for text in reported do
    let message ← IO.ofExcept (Json.parse text)
    let source ← IO.ofExcept (string message "from")
    let target ← IO.ofExcept (string message "to")
    let before :=
      messages.filter fun other => other.source == source && other.target == target
    messages := messages.push { source, target, position := before.size }
  return messages

/--
The command for a choice, if the state of the driver allows one. `nodes` are those which
exist, and `isolated` those which a command has disconnected from every other.
-/
private def choose (kind : String) (value : Nat) (nodes isolated : List String)
    : IO (Option Command) := do
  let pick (items : List String) : Option String := items[value % items.length]?
  let named (name : String) (node : Option String) : Option Command :=
    node.map fun node => { name, args := [node] }
  match kind with
  | "hold" | "deliver" | "drop" =>
      let pending ← queuedMessages (← undeliveredMessages)
      let some message := pending[value % pending.size]? | return none
      let name :=
        if kind == "hold" then
          "hold_nth"
        else if kind == "deliver" then
          "dispatch_nth"
        else
          "drop_nth"
      return some
        { name, args := [message.source, message.target, toString message.position] }
  | "release" =>
      let held ← heldMessages
      if held.isEmpty then
        return none
      return some { name := "dispatch_held", args := [toString (value % held.size)] }
  | "tick" =>
      -- A node which is not primary always starts an election after 100 ms
      let duration := if value / nodes.length % 3 == 0 then "10" else "100"
      return (pick nodes).map
        fun node => { name := "periodic_one", args := [node, duration] }
  | "isolate" => return named "disconnect_node" (pick nodes)
  | "rejoin" => return named "reconnect_node" (pick isolated)
  | "nominate" => return named "nominate_successor" (pick nodes)
  | "write" =>
      return some { name := "replicate", args := ["latest", s!"m{value % 1000}"] }
  | "sign" => return some { name := "replicate", args := ["latest", "$"] }
  | _ => fail s!"unknown choice '{kind}'"

/--
Run a program, and check the run against the model. A step which the state of the
driver does not allow is left out. Give the commands issued, with what `conclude` gives.
-/
private def execute (steps : Array Step)
    : IO (Report × Array Command × Array Record × ByteArray) := do
  timeLimit 120
  startCapture
  let mut issued : Array Command := #[]
  let mut nodes : List String := []
  let mut isolated : List String := []
  let mut stopped : Option Stop := none
  for step in steps do
    let chosen ←
      match step with
      | .given command => pure (some command)
      | .choice kind value => choose kind value nodes isolated
    let some command := chosen | continue
    -- The driver fails these, some after it has created a node
    if command.needs.any (!nodes.contains ·) then
      continue
    if command.name == "start_node" && !nodes.isEmpty then
      continue
    if command.name != "replicate_new_configuration"
        && command.creates.any (nodes.contains ·) then
      continue
    let created := command.creates.filter (!nodes.contains ·)
    nodes := nodes ++ created
    if command.name == "disconnect_node" then
      isolated := command.args ++ isolated
    if command.name == "reconnect_node" then
      isolated := isolated.filter (!command.args.contains ·)
    let failure ←
      try
        command.run
        pure none
      catch error =>
        pure (some (toString error))
    match failure with
    | none => issued := issued.push command
    | some message =>
        match stopFor message with
        | none =>
            -- Left out, unless the driver created its nodes before it failed
            unless created.isEmpty do
              issued := issued.push command
        | some kind =>
            issued := issued.push command
            stopped := some { kind, message, command := command.text }
            break
  let (report, records, counters) ← conclude stopped
  return (report, issued, records, counters)

/--
Run the program in `file`, and check the run against the model. Write to `result`, if
given: the status of the run, the outcomes which the model shows and the commands
issued, as JSON; the edges reached, beside it; and the trace, if the run is a finding.
-/
def runProgram (file : System.FilePath) (result : Option System.FilePath)
    : IO UInt32 := do
  let (report, issued, records, counters) ← execute (← readProgram file)
  match result with
  | some result =>
      writeResult result report (issued.map (·.text)) records counters
      return 0
  | none => announce file.toString report

/--
Run the program in `file`, which the model must accept, and write it to `output` as the
scenario `name` in Lean. The scenario issues the commands of the run, and asserts the
state in which they leave each node.
-/
def writeScenario (file : System.FilePath) (name : String) (output : System.FilePath)
    : IO UInt32 := do
  let (report, issued, _, _) ← execute (← readProgram file)
  if report.status != "ok" then
    discard (announce file.toString report)
    return 1
  let checks := report.checks.map Command.parse
  match scenarioText name (← readComments file) issued checks with
  | .ok text =>
      IO.FS.writeFile output text
      return 0
  | .error error =>
      IO.eprintln s!"{file}: {error}"
      return 1

end ModelDriver
