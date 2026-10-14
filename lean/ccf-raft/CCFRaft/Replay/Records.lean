module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay

public section

namespace CCFRaft.Replay

open Lean

def require (condition : Bool) (message : String) : Except String Unit :=
  unless condition do throw message

def object (value : Json) : Except String (List (String × Json)) :=
  (·.toList) <$> value.getObj?

def field (value : Json) (key : String) : Except String Json :=
  (value.getObjVal? key).mapError (fun error => s!"{key}: {error}")

def optional (value : Json) (key : String) : Option Json :=
  (object value).toOption.bind (·.lookup key)

def text (value : Json) : Except String String := do
  let name ← value.getStr?
  require (!name.isEmpty) "expected nonempty string"
  return name

def natural : Json → Except String Nat
  | .num { mantissa := .ofNat value, exponent := 0 } => pure value
  | _ => throw "expected natural number"

def string (value : Json) (key : String) : Except String String :=
  field value key >>= text

def nat (value : Json) (key : String) : Except String Nat :=
  field value key >>= natural

def boolean (value : Json) (key : String) : Except String Bool :=
  field value key >>= Json.getBool?

private def sourceLine (value : Json) : Except String Nat := do
  let digits ← text value
  require (digits.all Char.isDigit) "invalid implementation line"
  let some line := digits.toNat? | throw "invalid implementation line"
  return line

def keys (value : Json) (required optionalKeys : List String) : Except String Unit := do
  let names := (← object value).map Prod.fst
  for name in required do
    require (names.contains name) s!"missing field '{name}'"
  for name in names do
    require (required.contains name || optionalKeys.contains name)
      s!"unsupported field '{name}'"

/--
Lean's JSON object representation coalesces duplicate keys. Check the lexical
keys first, including escaped spellings; use Lean's parser for all JSON syntax.
-/
private def uniqueKeys (input : String) : Except String Unit := do
  let mut scopes : List (Option (List String)) := []
  let mut quoted := false
  let mut escaped := false
  let mut token := ""
  let mut previous : Option String := none
  for char in input.toList do
    if quoted then
      token := token.push char
      if escaped then
        escaped := false
      else if char == '\\' then
        escaped := true
      else if char == '"' then
        quoted := false
        previous := some token
    else if char == '"' then
      token := "\""
      quoted := true
    else if char == '{' then
      scopes := some [] :: scopes
      previous := none
    else if char == '[' then
      scopes := none :: scopes
      previous := none
    else if char == '}' || char == ']' then
      scopes := scopes.tail
      previous := none
    else if char == ':' then
      let some raw := previous | throw "expected object key"
      let key ← Json.parse raw >>= Json.getStr?
      let some names :: rest := scopes | throw "expected object key scope"
      require (!names.contains key) s!"duplicate JSON key '{key}'"
      scopes := some (key :: names) :: rest
      previous := none
    else if !char.isWhitespace then
      previous := none

structure Record where
  file : String
  line : Nat
  value : Json
deriving Inhabited

def Record.location (record : Record) : String := s!"{record.file}:{record.line}"

/--
NDJSON is strict. Captured stdout additionally allows the driver's diagram lines
and well-formed ordinary logger records, never unknown or malformed lines.
-/
def parseLog (file input : String) (stdout : Bool) : Except String (Array Record) := do
  let mut records := #[]
  let lines := input.splitOn "\n"
  let lines := if input.endsWith "\n" then lines.dropLast else lines
  for raw in lines, line in [1:lines.length + 1] do
    let raw := if raw.endsWith "\r" then raw.dropEnd 1 |>.toString else raw
    if stdout && raw.startsWith "<RaftDriver>" then continue
    let parsed : Except String Json := do
      uniqueKeys raw
      let value ← Json.parse raw
      let _ ← object value
      return value
    let value ← parsed.mapError (fun error => s!"{file}:{line}: {error}")
    if !stdout || optional value "tag" == some (.str "raft_trace") then
      records := records.push { file, line, value }
    else
      require
        (["h_ts", "level", "tag", "msg"].all (fun key => (optional value key).isSome))
        s!"{file}:{line}: unrecognized driver output"
  require (!records.isEmpty)
    s!"{file}: empty trace; no Raft events (CCF_RAFT_TRACING=ON required)"
  return records

def readLog (path : System.FilePath) : IO (Except String (Array Record)) := do
  let path ← IO.FS.realPath path
  let bytes ← IO.FS.readBinFile path
  let some input := String.fromUTF8? bytes
  | return .error s!"{path}: invalid UTF-8"
  return parseLog path.toString input (path.extension == some "stdout")

def configuration (value : Json) : Except String (List String) := do
  keys value ["idx", "rid", "nodes"] []
  require ((← nat value "rid") == (← nat value "idx"))
    "configuration rid differs from idx"
  let nodes ← object (← field value "nodes")
  require (!nodes.isEmpty) "empty configuration nodes"
  for (node, metadata) in nodes do
    let _ ← text (.str node)
    require (metadata == Json.mkObj [("address", .str ":")])
      "unsupported driver node metadata"
  return (nodes.map Prod.fst).mergeSort

def configurationArg (message : Json) : Except String (List String) := do
  let args ← field message "args"
  keys args ["configuration"] []
  configuration (← field args "configuration")

private def packetFields : String → Option (List String)
  | "raft_append_entries" =>
      some
        [
          "term",
          "idx",
          "prev_idx",
          "prev_term",
          "leader_commit_idx",
          "term_of_idx",
          "contains_new_view"
        ]
  | "raft_append_entries_response" => some ["term", "last_log_idx", "success"]
  | "raft_request_vote" | "raft_request_pre_vote" =>
      some ["term", "last_committable_idx", "term_of_last_committable_idx"]
  | "raft_request_vote_response" | "raft_request_pre_vote_response" =>
      some ["term", "vote_granted"]
  | "raft_propose_request_vote" => some ["term"]
  | _ => none

def validatePacket (packet : Json) : Except String Unit := do
  let family ← string packet "msg"
  let some fields := packetFields family | throw s!"unsupported packet '{family}'"
  keys packet ("msg" :: fields) []
  for key in fields do
    match key with
    | "success" =>
        require (["OK", "FAIL"].contains (← string packet key))
          "unsupported response success"
    | "vote_granted" | "contains_new_view" => let _ ← boolean packet key; pure ()
    | _ => let _ ← nat packet key; pure ()
  if family == "raft_append_entries" then
    require ((← nat packet "prev_idx") <= (← nat packet "idx")) "reversed append batch"

private def messageFields : String → Option (List String × List String)
  | "add_configuration" => some (["args", "configurations"], [])
  | "become_candidate"
  | "become_follower"
  | "become_leader"
  | "become_pre_vote_candidate" => some (["configurations"], [])
  | "commit" => some (["args", "configurations"], [])
  | "drop_pending_to" => some (["from_node_id", "to_node_id", "packet"], [])
  | "execute_append_entries_sync" => some (["from_node_id"], [])
  | "recv_append_entries"
  | "recv_propose_request_vote"
  | "recv_request_vote"
  | "recv_request_vote_response" => some (["from_node_id", "packet"], [])
  | "recv_append_entries_response" =>
      some (["from_node_id", "packet", "sent_idx", "match_idx"], [])
  | "replicate" => some (["view", "seqno", "globally_committable"], [])
  | "send_append_entries" => some (["to_node_id", "packet", "sent_idx", "match_idx"], [])
  | "send_append_entries_response" | "send_request_vote" | "send_request_vote_response" =>
      some (["to_node_id", "packet"], [])
  | "step_down_and_nominate_successor" => some (["configurations", "to_node_id"], [])
  | _ => none

/-- Every trace snapshot field is either projected or rejected. -/
def stateFacts (state message : Json) : Except String Json := do
  keys state
    [
      "node_id",
      "leadership_state",
      "membership_state",
      "current_view",
      "last_idx",
      "commit_idx",
      "pre_vote_enabled"
    ]
    [
      "retirement_phase",
      "retirement_idx",
      "retirement_committable_idx",
      "retired_committed_idx",
      "committable_indices"
    ]
  let _ ← string state "node_id"
  let role ←
    match ← string state "leadership_state" with
    | "None" => pure "none"
    | "Follower" => pure "follower"
    | "PreVoteCandidate" => pure "preVoteCandidate"
    | "Candidate" => pure "candidate"
    | "Leader" => pure "leader"
    | name => throw s!"invalid role '{name}'"
  let membership ←
    match ← string state "membership_state", optional state "retirement_phase" with
    | "Active", none | "Active", some .null => pure "active"
    | "Retired", some (.str "Ordered") => pure "retirementOrdered"
    | "Retired", some (.str "Signed") => pure "retirementSigned"
    | "Retired", some (.str "Completed") => pure "retirementCompleted"
    | "Retired", some (.str "RetiredCommitted") => pure "retiredCommitted"
    | _, _ => throw "unsupported membership/retirement phase"
  let mut facts :=
    [
      ("role", toJson role),
      ("currentTerm", toJson (← nat state "current_view")),
      ("logLength", toJson (← nat state "last_idx")),
      ("commitIndex", toJson (← nat state "commit_idx")),
      ("preVoteEnabled", toJson (← boolean state "pre_vote_enabled")),
      ("membershipState", toJson membership)
    ]
  for (raw, target)
      in [
        ("retirement_idx", "retirementIndex"),
        ("retirement_committable_idx", "retirementCommittableIndex"),
        ("retired_committed_idx", "retiredCommittedIndex")
      ] do
    let value ←
      match optional state raw with
      | none | some .null => pure Json.null
      | some value => toJson <$> natural value
    facts := facts ++ [(target, value)]
  if let some markers := optional state "committable_indices" then
    let values ← (← markers.getArr?).toList.mapM natural
    require (values == values.mergeSort && values == values.eraseDups)
      "unordered/duplicate committable indices"
    facts := facts ++ [("committableIndices", toJson values)]
  if let some configurations := optional message "configurations" then
    let mut projected := #[]
    let mut previous := 0
    for value in ← configurations.getArr? do
      let names ← configuration value
      let index ← nat value "idx"
      -- Ordered effects may legitimately have the same transaction index.
      require (index >= previous) "unordered configurations"
      previous := index
      projected :=
        projected.push (Json.mkObj [("index", toJson index), ("nodes", toJson names)])
    facts := facts ++ [("configurations", .arr projected)]
  return Json.mkObj facts

structure Event where
  record : Record
  command : Record
  function : String
  node : String
  message : Json
  state : Json
  facts : Json
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  {
    file := event.record.file,
    line := event.record.line,
    function := event.function
    command := (string event.command.value "cmd").toOption.getD ""
    commandLine := event.command.line,
    rule
    implementation := do
      let file ← (string event.record.value "file").toOption
      let line ← (field event.record.value "number" >>= sourceLine).toOption
      return (file, line)
  }

def Event.sameContext (first second : Event) : Bool :=
  first.node == second.node
  && first.command.file == second.command.file
  && first.command.line == second.command.line

private def commands : List String :=
  [
    "pre_vote_enabled",
    "start_node",
    "trust_node",
    "trust_nodes",
    "cleanup_nodes",
    "swap_node",
    "swap_nodes",
    "nodes",
    "connect",
    "disconnect",
    "disconnect_node",
    "periodic_one",
    "periodic_all",
    "state_one",
    "state_all",
    "summarise_log",
    "summarise_logs_all",
    "summarise_messages",
    "dispatch_one",
    "dispatch_all",
    "dispatch_all_once",
    "dispatch_single",
    "drop_pending",
    "drop_pending_to",
    "replicate",
    "emit_signature",
    "assert_state_sync",
    "assert_detail",
    "assert_commit_idx",
    "assert_commit_safety",
    "assert_!detail",
    "assert_config",
    "assert_absent_config",
    "assert_last_txid",
    "replicate_new_configuration",
    "create_new_node",
    "loop_until_sync",
    "nominate_successor",
    "reconnect",
    "reconnect_node"
  ]

/-- Preserve capture order, associate commands, and declare fixed per-node modes. -/
def associate (records : Array Record)
    : Except String (Array Event × List (String × Bool)) := do
  let mut events := #[]
  let mut command : Option Record := none
  let mut modes : List (String × Bool) := []
  let mut defaultMode := true
  for record in records do
    let parse
        : Except String (Array Event × Option Record × List (String × Bool) × Bool) := do
      let mut events := events
      let mut command := command
      let mut modes := modes
      let mut defaultMode := defaultMode
      let row := record.value
      require ((← string row "tag") == "raft_trace") "expected raft_trace record"
      if let some cmd := optional row "cmd" then
        keys row ["tag", "cmd"] []
        let parts := (← text cmd).splitOn ","
        let name := parts.head!
        require (commands.contains name) s!"unsupported command '{name}'"
        let mut created := []
        if name == "pre_vote_enabled" then
          match parts with
          | [_, "true"] => defaultMode := true
          | [_, "false"] => defaultMode := false
          | _ => throw "invalid pre_vote_enabled command"
        else if ["start_node", "create_new_node", "nodes"].contains name then
          created := parts.drop 1
        else if ["trust_node", "trust_nodes"].contains name then
          created := parts.drop 2
        else if name == "swap_node" then
          created := parts.drop 3
        else if name == "swap_nodes" then
          let mut incoming := false
          for part in parts.drop 2 do
            if part == "in" then
              incoming := true
            else if part == "out" then
              incoming := false
            else if incoming then
              created := created ++ [part]
        for node in created do
          let _ ← text (.str node)
          require (!(modes.lookup node).isSome) s!"duplicate node creation '{node}'"
          modes := modes ++ [(node, defaultMode)]
        command := some record
      else
        let some cmd := command | throw "event before command"
        keys row ["tag", "msg"] ["h_ts", "thread_id", "level", "file", "number"]
        if let some file := optional row "file" then let _ ← text file; pure ()
        if let some number := optional row "number" then
          let _ ← sourceLine number; pure ()
        let message ← field row "msg"
        let function ← string message "function"
        let some (required, optionalKeys) := messageFields function
        | throw s!"unsupported function '{function}'"
        keys message (["function", "state"] ++ required) optionalKeys
        let state ← field message "state"
        let facts ← stateFacts state message
        for endpoint in ["from_node_id", "to_node_id"] do
          if let some value := optional message endpoint then let _ ← text value; pure ()
        for key in ["sent_idx", "match_idx", "seqno", "view"] do
          if let some value := optional message key then let _ ← natural value; pure ()
        if function == "replicate" then
          let _ ← boolean message "globally_committable"; pure ()
        if function == "commit" then
          let args ← field message "args"
          keys args ["idx"] []
          let _ ← nat args "idx"
        if function == "add_configuration" then let _ ← configurationArg message; pure ()
        if let some packet := optional message "packet" then validatePacket packet
        let node ← string state "node_id"
        if !(modes.lookup node).isSome then
          modes := modes ++ [(node, ← boolean state "pre_vote_enabled")]
        events :=
          events.push { record, command := cmd, function, node, message, state, facts }
      return (events, command, modes, defaultMode)
    -- All semantic errors retain the raw source location.
    let (nextEvents, nextCommand, nextModes, nextDefault) ←
      parse.mapError (fun error => s!"{record.location}: {error}")
    events := nextEvents
    command := nextCommand
    modes := nextModes
    defaultMode := nextDefault
  require (!events.isEmpty) "trace contains commands but no Raft events"
  return (events, modes.mergeSort (fun a b => a.1 <= b.1))

end CCFRaft.Replay
