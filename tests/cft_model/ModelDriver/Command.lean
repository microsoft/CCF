-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import Scenarios

/-!
Driver commands as data.

A trace records each command of a scenario as its name and arguments, separated by commas.
A `Command` is such a record, which can be issued again, so that a scenario can be changed
and run without being compiled. A `Step` of a program is a command, or a choice which is
made when the program runs, among what the state of the driver then allows.
-/

open CftDriver

namespace ModelDriver

/-- A driver command: its name and arguments, as a trace records them. -/
structure Command where
  name : String
  args : List String
deriving BEq, Inhabited

namespace Command

/-- Read a command from the text which a trace records for it. -/
def parse (text : String) : Command :=
  match text.splitOn "," with
  | name :: args => { name, args }
  | [] => { name := text, args := [] }

/-- The text which a trace records for the command. -/
def text (command : Command) : String :=
  ",".intercalate (command.name :: command.args)

private def number (text : String) : IO UInt64 :=
  match text.toNat? with
  | some value => pure value.toUInt64
  | none => throw (IO.userError s!"expected a number, got '{text}'")

private def texts (items : List String) : List Text :=
  items.map Text.mk

/-- The nodes which `swap_nodes` retires and trusts: the trace lists them after `out` and `in`. -/
private def changes (items : List String) : List String × List String :=
  let (retire, trust) := (items.dropWhile (· == "out")).span (· != "in")
  (retire, trust.drop 1)

/-- Issue the command to the driver. -/
def run (command : Command) : IO Unit := do
  match command.name, command.args with
  | "start_node", [node] => startNode node
  | "trust_node", [term, node] => trustNode term node
  | "trust_nodes", term :: nodes => trustNodes term (texts nodes)
  | "swap_node", [term, retire, trust] => swapNode term retire trust
  | "swap_nodes", term :: items =>
      let (retire, trust) := changes items
      swapNodes term (texts retire) (texts trust)
  | "cleanup_nodes", term :: nodes => cleanupNodes term (texts nodes)
  | "nominate_successor", [node] => nominateSuccessor node
  | "nodes", nodes => CftDriver.nodes (texts nodes)
  | "create_new_node", [node] => createNewNode node
  | "replicate_new_configuration", term :: nodes =>
      replicateNewConfiguration term (texts nodes)
  | "replicate", term :: entries => replicate term (texts entries)
  | "periodic_one", [node, ms] => periodicOne node (← number ms)
  | "periodic_all", [ms] => periodicAll (← number ms)
  | "connect", [first, second] => connect first second
  | "disconnect", [first, second] => disconnect first second
  | "disconnect_node", [node] => disconnectNode node
  | "reconnect", [first, second] => reconnect first second
  | "reconnect_node", [node] => reconnectNode node
  | "dispatch_one", [node] => dispatchOne node
  | "dispatch_single", [source, target] => dispatchSingle source target
  | "dispatch_nth", [source, target, position] =>
      dispatchNth source target (← number position)
  | "pending_messages", [source, target] => discard (pendingMessages source target)
  | "dispatch_all_once", [] => dispatchAllOnce
  | "dispatch_all", [] => dispatchAll
  | "drop_pending", [node] => dropPending node
  | "drop_pending_to", [source, target] => dropPendingTo source target
  | "drop_nth", [source, target, position] => dropNth source target (← number position)
  | "hold_nth", [source, target, position] => holdNth source target (← number position)
  | "dispatch_held", [position] => dispatchHeld (← number position)
  | "shuffle_one", [node] => shuffleOne node
  | "shuffle_all", [] => shuffleAll
  | "state_one", [node] => stateOne node
  | "state_all", [] => stateAll
  | "summarise_log", [node] => summariseLog node
  | "summarise_logs_all", [] => summariseLogsAll
  | "summarise_messages", [source, target] => summariseMessages source target
  | "assert_state_sync", [] => assertStateSync
  | "assert_commit_safety", [node] => assertCommitSafety node
  | "assert_commit_idx", [node, idx] => assertCommitIdx node (← number idx)
  | "assert_detail", node :: detail :: expected =>
      assertDetail node detail (",".intercalate expected)
  | "assert_!detail", node :: detail :: unexpected =>
      assertNotDetail node detail (",".intercalate unexpected)
  | "assert_config", node :: idx :: nodes =>
      assertConfig node (← number idx) (texts nodes)
  | "assert_absent_config", [node, idx] => assertAbsentConfig node (← number idx)
  | "assert_last_txid", [node, txid] => assertLastTxid node txid
  | "loop_until_sync", [] => loopUntilSync
  | _, _ => throw (IO.userError s!"unknown command '{command.text}'")

/-- Whether the command checks or prints the state, and so changes nothing. -/
def observes (command : Command) : Bool :=
  command.name.startsWith "assert_"
  || [
        "state_one",
        "state_all",
        "summarise_log",
        "summarise_logs_all",
        "summarise_messages",
        "pending_messages"
      ].contains
      command.name

/-- Whether the command orders messages at random, so that a run cannot be repeated. -/
def shuffles (command : Command) : Bool :=
  command.name.startsWith "shuffle_"

/-- The nodes which the command creates. -/
def creates (command : Command) : List String :=
  match command.name, command.args with
  | "start_node", [node] => [node]
  | "create_new_node", [node] => [node]
  | "trust_node", [_, node] => [node]
  | "swap_node", [_, _, node] => [node]
  | "trust_nodes", _ :: nodes => nodes
  | "replicate_new_configuration", _ :: nodes => nodes
  | "nodes", nodes => nodes
  | "swap_nodes", _ :: items => (changes items).2
  | _, _ => []

/-- The commands which the driver cannot run unless the node which they name first exists. -/
private def namesNode : List String :=
  [
    "nominate_successor",
    "periodic_one",
    "dispatch_one",
    "dispatch_single",
    "dispatch_nth",
    "pending_messages",
    "drop_pending",
    "drop_pending_to",
    "drop_nth",
    "hold_nth",
    "state_one",
    "summarise_log",
    "summarise_messages",
    "assert_commit_safety",
    "assert_commit_idx",
    "assert_detail",
    "assert_!detail",
    "assert_config",
    "assert_absent_config",
    "assert_last_txid"
  ]

/-- The nodes which must exist for the driver to run the command. -/
def needs (command : Command) : List String :=
  if command.name == "cleanup_nodes" then
    command.args.drop 1
  else if namesNode.contains command.name then
    command.args.take 1
  else
    []

/-- The commands whose first argument is the term of the primary which they address. -/
private def namesTerm : List String :=
  [
    "trust_node",
    "trust_nodes",
    "swap_node",
    "swap_nodes",
    "cleanup_nodes",
    "replicate_new_configuration",
    "replicate"
  ]

/-- The command, addressed to the primary in the highest term if it names a term. -/
def toLatest (command : Command) : Command :=
  match command.args with
  | _ :: rest =>
      if namesTerm.contains command.name then
        { command with args := "latest" :: rest }
      else
        command
  | [] => command

/-- A node, a term or a number, as a scenario writes it. -/
private def value (text : String) : String :=
  if text.toNat?.isSome || text == "latest" then text else text.quote

private def list (items : List String) : String :=
  "[" ++ ", ".intercalate items ++ "]"

/-- The line of a scenario in Lean which issues the command. -/
def scenarioLine (command : Command) : Except String String :=
  let call (function : String) (args : List String) : Except String String :=
    pure (" ".intercalate (function :: args))
  let values (function : String) : Except String String :=
    call function (command.args.map value)
  match command.name, command.args with
  | "start_node", [_] => values "startNode"
  | "trust_node", [_, _] => values "trustNode"
  | "trust_nodes", term :: nodes => call "trustNodes" [value term, list (nodes.map value)]
  | "swap_node", [_, _, _] => values "swapNode"
  | "swap_nodes", term :: items =>
      let (retire, trust) := changes items
      call "swapNodes" [value term, list (retire.map value), list (trust.map value)]
  | "cleanup_nodes", term :: nodes =>
      call "cleanupNodes" [value term, list (nodes.map value)]
  | "nominate_successor", [_] => values "nominateSuccessor"
  | "replicate", term :: entries =>
      let entries :=
        entries.map fun entry => if entry == "$" then "signature" else entry.quote
      call "replicate" [value term, list entries]
  | "periodic_one", [_, _] => values "periodicOne"
  | "periodic_all", [_] => values "periodicAll"
  | "connect", [_, _] => values "connect"
  | "disconnect", [_, _] => values "disconnect"
  | "disconnect_node", [_] => values "disconnectNode"
  | "reconnect", [_, _] => values "reconnect"
  | "reconnect_node", [_] => values "reconnectNode"
  | "dispatch_one", [_] => values "dispatchOne"
  | "dispatch_single", [_, _] => values "dispatchSingle"
  | "dispatch_nth", [_, _, _] => values "dispatchNth"
  | "dispatch_all_once", [] => values "dispatchAllOnce"
  | "dispatch_all", [] => values "dispatchAll"
  | "drop_pending", [_] => values "dropPending"
  | "drop_pending_to", [_, _] => values "dropPendingTo"
  | "drop_nth", [_, _, _] => values "dropNth"
  | "hold_nth", [_, _, _] => values "holdNth"
  | "dispatch_held", [_] => values "dispatchHeld"
  | "assert_commit_idx", [_, _] => values "assertCommitIdx"
  | "assert_detail", node :: detail :: expected =>
      call "assertDetail" [value node, detail.quote, value (",".intercalate expected)]
  | "loop_until_sync", [] => values "loopUntilSync"
  | _, _ => throw s!"a scenario cannot issue '{command.text}'"

end Command

/--
The scenario `name` in Lean, which issues the commands, and then the checks. Each of
the `comments` is a line before it.
-/
def scenarioText (name : String) (comments : List String)
    (commands checks : Array Command)
    : Except String String := do
  let lines (commands : Array Command) : Except String (List String) :=
    commands.toList.mapM fun command => ("  " ++ ·) <$> command.scenarioLine
  let header :=
    [
      "-- Copyright (c) Microsoft Corporation. All rights reserved.",
      "-- Licensed under the Apache 2.0 License.",
      "import CftDriver",
      "",
      "open CftDriver",
      ""
    ]
  let issued ← lines commands
  let checked ← lines checks
  let body :=
    comments.map ("-- " ++ ·)
    ++ [s!"initialize scenario {name.quote} do"]
    ++ issued
    ++ (if checked.isEmpty then [] else "" :: checked)
  return "\n".intercalate (header ++ body) ++ "\n"

/-- A step of a program. -/
inductive Step where
  /-- A command which the program gives. -/
  | given (command : Command)
  /--
  A choice of the `kind` of command, such as holding an undelivered message. `value`
  selects among those which the state of the driver allows when the program reaches the
  step, and the step does nothing if there is none.
  -/
  | choice (kind : String) (value : Nat)
deriving Inhabited

namespace Step

/-- The line of a program file for the step. A choice starts with `@`. -/
def text : Step → String
  | .given command => command.text
  | .choice kind value => s!"@{kind} {value}"

/-- Read a line of a program file. -/
def parse (line : String) : Except String Step :=
  if line.startsWith "@" then
    match (line.drop 1).toString.splitOn " " with
    | [kind, value] =>
        match value.toNat? with
        | some value => pure (.choice kind value)
        | none => throw s!"expected a number in '{line}'"
    | _ => throw s!"expected a kind and a number in '{line}'"
  else
    pure (.given (Command.parse line))

end Step

/-- The text of a program file: a step on each line, after comments which start with `#`. -/
def programText (comments : List String) (steps : Array Step) : String :=
  String.join ((comments.map ("# " ++ ·) ++ steps.toList.map Step.text).map (· ++ "\n"))

/-- Read a program file. -/
def readProgram (file : System.FilePath) : IO (Array Step) := do
  let lines := (← IO.FS.readFile file).splitOn "\n"
  let steps ←
    (lines.filter fun line => !line.isEmpty && !line.startsWith "#").mapM
      fun line => IO.ofExcept (Step.parse line)
  return steps.toArray

/-- The comments of a program file. -/
def readComments (file : System.FilePath) : IO (List String) := do
  let lines := (← IO.FS.readFile file).splitOn "\n"
  return (lines.filter (·.startsWith "#")).map
    fun line => (line.drop (if line.startsWith "# " then 2 else 1)).toString

end ModelDriver
