module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Replayer

import all CCFRaft.Replay
import CCF.Parsec

public section

open Lean CCFRaft.Replay CCFRaft.Model.Node

private def check (condition : Bool) (message : String) : IO Unit :=
  unless condition do throw (IO.userError message)

private def ok {α : Type} (result : Except String α) : IO α :=
  IO.ofExcept (result.mapError IO.userError)

private def rejects {α : Type} (result : Except String α) (expected : String) : IO Unit :=
  match result with
  | .ok _ => throw (IO.userError s!"unexpectedly accepted: {expected}")
  | .error error =>
      check (error.contains expected) s!"expected '{expected}', got '{error}'"

private def checkObservedFields (make : Json → ReplayState → Except String Unit)
    (current : ReplayState) (fields : List (String × Json))
    : IO Unit := do
  let expected := Json.mkObj fields
  let _ ← ok (make expected current)
  for (key, _) in fields do
    rejects (make (expected.setObjVal! key (toJson "__mismatch__")) current) key
  rejects (make (Json.mkObj []) current) "at least one field"
  rejects (make .null current) "object"
  rejects (make (expected.setObjVal! "unknown" .null) current)
    "unsupported observation field"

-- A function-valued field deliberately prevents requiring equality on events.
private structure ParserTestEvent where
  value : Nat
  transform : Nat → Nat

private def parsecInfrastructureTests : IO Unit := do
  let one : CCF.Parsec.ParserT Nat (List Nat) Nat := do
    let value ← CCF.Parsec.satisfy (· == 1) "expected one"
    modify (· ++ [value])
    return value
  let repeated :=
    CCF.Parsec.many one
    <* CCF.Parsec.optional_ (discard (CCF.Parsec.take))
    <* CCF.Parsec.eof
  let (values, state) ← ok (CCF.Parsec.run #[1, 1, 2] (repeated.run []))
  check (values == [1, 1] && state == [1, 1]) "generic repetition or state threading"
  let (_, state) ←
    ok
      (CCF.Parsec.run #[1, 1] ((CCF.Parsec.many_ (discard one) <* CCF.Parsec.eof).run []))
  check (state == [1, 1]) "generic result-discarding repetition"
  let fallback : CCF.Parsec.ParserT Nat (List Nat) Nat :=
    (do
      modify (· ++ [99])
      CCF.Parsec.failure "unconsumed failure")
    <|> one
  let (value, state) ← ok (CCF.Parsec.run #[1] ((fallback <* CCF.Parsec.eof).run []))
  check (value == 1 && state == [1]) "failed alternative leaked application state"
  let committed : CCF.Parsec.ParserT Nat Unit Unit := do
    let _ ← CCF.Parsec.take
    CCF.Parsec.validated (.error "committed failure")
  rejects (CCF.Parsec.run #[1] ((committed <|> pure ()).run ())) "committed failure"
  rejects (CCF.Parsec.run #[1] ((CCF.Parsec.many committed).run ())) "committed failure"
  rejects (CCF.Parsec.run #[1] ((CCF.Parsec.optionalRule committed).run ()))
    "committed failure"
  let speculative : CCF.Parsec.ParserT Nat (List Nat) Nat := do
    let _ ← one
    modify (· ++ [99])
    CCF.Parsec.failure "speculative mismatch"
  let (value, state) ←
    ok
      (CCF.Parsec.run #[1]
        (((CCF.Parsec.attempt speculative <|> one) <* CCF.Parsec.eof).run []))
  check (value == 1 && state == [1]) "attempt leaked consumed input or application state"
  rejects
    (CCF.Parsec.run #[1]
      ((CCF.Parsec.optionalRule (CCF.Parsec.attempt speculative) *> CCF.Parsec.eof).run
        []))
    "speculative mismatch"
  rejects
    (CCF.Parsec.run #[1]
      (((CCF.Parsec.attempt speculative <|> one)
          *> CCF.Parsec.failure "later failure").run
          []
        : CCF.Parsec.Parser Nat (Unit × List Nat)))
    "later failure"
  rejects
    (CCF.Parsec.run #[2]
      ((CCF.Parsec.attempt one <|> CCF.Parsec.failure "no matching rule").run []))
    "no matching rule"
  let deeper : CCF.Parsec.ParserT Nat Unit Unit := do
    let _ ← CCF.Parsec.take
    let _ ← CCF.Parsec.take
    CCF.Parsec.failure "deeper failure"
  rejects
    (CCF.Parsec.run #[1, 2]
      ((CCF.Parsec.attempt deeper <|> CCF.Parsec.attempt committed).run ()))
    "deeper failure"
  let emitAndFail : CCF.Parsec.ParserT Nat (Array Instruction) Unit := do
    let _ ← CCF.Parsec.take
    modify (·.push (.action (.local "0" .nominateSuccessor) default))
    CCF.Parsec.failure "failed emission"
  let (_, instructions) ←
    ok
      (CCF.Parsec.run #[1]
        (((CCF.Parsec.attempt emitAndFail <|> discard CCF.Parsec.take)
          <* CCF.Parsec.eof).run
          #[]))
  check instructions.isEmpty "attempt leaked an emitted model action"
  rejects (CCF.Parsec.run #[1, 2] ((one <* CCF.Parsec.eof).run [])) "end of input"
  let inspect : CCF.Parsec.ParserT ParserTestEvent Unit Nat := do
    let some next ← CCF.Parsec.peek | CCF.Parsec.failure "missing event"
    let event ← CCF.Parsec.satisfy (·.value == next.value) "value mismatch"
    return event.transform event.value
  let (value, _) ←
    ok
      (CCF.Parsec.run #[{ value := 7, transform := (· + 1) }]
        ((inspect <* CCF.Parsec.eof).run ()))
  check (value == 8) "event parsing required equality or peek consumed input"
  let empty : CCF.Parsec.ParserT ParserTestEvent Unit (Option ParserTestEvent) :=
    CCF.Parsec.peek
  let (next, _) ← ok (CCF.Parsec.run #[] ((empty <* CCF.Parsec.eof).run ()))
  check next.isNone "peek at end of input"
  rejects (CCF.Parsec.run #[] (inspect.run ())) "missing event"
  rejects
    (CCF.Parsec.run (#[] : Array Nat)
      ((CCF.Parsec.take : CCF.Parsec.ParserT Nat Unit Nat).run ()))
    "unexpected end of input"

private def fixture (name : String) : IO (Array Record) := do
  ok (← readLog (System.FilePath.mk "replay/tests/fixtures" / name))

private def observationStates (reduced : Reduced)
    : IO (Array (ReplayState × (ReplayState → Except String Unit) × Origin)) := do
  let mut current : ReplayState := { state := reduced.header.initial }
  let mut observations := #[]
  for instruction in reduced.instructions do
    if let .observe observe origin := instruction then
      observations := observations.push (current, observe, origin)
    current ← ok (runInstruction reduced.header current instruction)
  return observations

-- Spliced protocol tests need a new transport sequence, not a different wire format.
private def resequence (records : Array Record) (start : Nat := 0) : Array Record :=
  records.mapIdx
    fun index record =>
      {
        record with
          value :=
            record.value.setObjVal! "h_ts" (toJson (start + index))
            |>.setObjVal! "process_id" (records[0]!.value.getObjValD "process_id")
      }

private def change (value : Json) (path : List String) (replacement : Json) : Json :=
  match path with
  | [] => replacement
  | key :: rest => value.setObjVal! key (change (value.getObjValD key) rest replacement)

private def mutate (records : Array Record) (index : Nat) (path : List String)
    (replacement : Json)
    : Array Record :=
  records.modify index
    fun record => { record with value := change record.value path replacement }

private def erase (records : Array Record) (index : Nat) : Array Record :=
  resequence (records.extract 0 index ++ records.extract (index + 1) records.size)
    ((nat records[0]!.value "h_ts").toOption.getD 0)

private def function (record : Record) : String :=
  ((record.value.getObjValD "msg").getObjValD "function").getStr?.toOption.getD ""

private def find (records : Array Record) (name : String) : IO Nat := do
  let some index := records.findIdx? (fun record => function record == name)
  | throw (IO.userError s!"fixture has no {name}")
  return index

private def envelope (message : Json) : Json :=
  Json.mkObj
    [
      ("tag", toJson "ccf.raft_trace"),
      ("process_id", toJson "test-process"),
      ("h_ts", toJson (0 : Nat)),
      ("msg", message)
    ]

private def command (cmd : String) : Record :=
  {
    file := "synthetic.ndjson",
    line := 1,
    value := envelope (Json.mkObj [("cmd", toJson cmd)])
  }

private def state : Json :=
  Json.mkObj
    [
      ("node_id", toJson "0"),
      ("leadership_state", toJson "Leader"),
      ("membership_state", toJson "Active"),
      ("current_view", toJson (2 : Nat)),
      ("last_idx", toJson (2 : Nat)),
      ("commit_idx", toJson (2 : Nat)),
      ("committable_indices", toJson ([] : List Nat))
    ]

private def appendPacket : Json :=
  Json.mkObj
    [
      ("msg", toJson "raft_append_entries"),
      ("term", toJson (2 : Nat)),
      ("prev_idx", toJson (2 : Nat)),
      ("idx", toJson (6 : Nat)),
      ("prev_term", toJson (2 : Nat)),
      ("term_of_idx", toJson (2 : Nat)),
      ("leader_commit_idx", toJson (2 : Nat)),
      ("contains_new_view", toJson false)
    ]

private def parserTests : IO Nat := do
  let mut count := 0
  for raw
      in [
        "",
        "\n",
        "{\"x\":NaN}",
        "{\"x\":Infinity}",
        "{\"x\":",
        "{\"x\":true} garbage"
      ] do
    rejects (parseLog "strict.ndjson" raw) "strict.ndjson"
    count := count + 1
  for raw
      in [
        "[]",
        "null",
        "{\"x\":1,\"x\":2}",
        "{\"x\":{\"y\":0,\"y\":1}}",
        "{\"x\":1,\"\\u0078\":2}"
      ] do
    let records ← ok (parseLog "json.ndjson" raw)
    check (records.size == 1 && records[0]!.value == (← ok (Json.parse raw)))
      "record parsing diverged from Lean JSON parsing"
    rejects (reduce records) "json.ndjson:1"
    count := count + 1
  for value
      in [
        Json.bool true,
        .str "1",
        .null,
        .arr #[],
        toJson (-1 : Int),
        toJson (1.5 : Float)
      ] do
    rejects (natural value) "expected natural"
    rejects (nat (appendPacket.setObjVal! "term" value) "term") "expected natural"
    count := count + 2
  for term in [0, 1, 2, 4, 999] do
    let packet := appendPacket.setObjVal! "term" (toJson term)
    check ((← ok (nat packet "term")) == term) "packet term changed"
    let facts ←
      ok (stateFacts (state.setObjVal! "current_view" (toJson term)) (Json.mkObj []))
    check (optional facts "currentTerm" == some (toJson term))
      "term coordinates were changed"
    count := count + 1
  rejects (nat (Json.mkObj []) "term") "term"
  rejects (string (Json.mkObj [("success", .arr #[])]) "success") "String"
  check
    ((← ok (stateFacts (state.setObjVal! "unknown" .null) (Json.mkObj [])))
      == (← ok (stateFacts state (Json.mkObj []))))
    "unused state data changed projected facts"
  rejects
    (stateFacts (state.setObjVal! "leadership_state" (toJson "invented")) (Json.mkObj []))
    "invalid role"
  rejects
    (stateFacts (state.setObjVal! "membership_state" (toJson "Retired")) (Json.mkObj []))
    "retirement phase"
  for markers in [[3, 2], [2, 2]] do
    let facts ←
      ok
        (stateFacts (state.setObjVal! "committable_indices" (toJson markers))
          (Json.mkObj []))
    check (optional facts "committableIndices" == some (toJson markers))
      "record projection reordered or removed signature evidence"
  let facts ←
    ok
      (stateFacts (state.setObjVal! "committable_indices" (toJson [3, 5]))
        (Json.mkObj []))
  check (optional facts "committableIndices" == some (toJson [3, 5]))
    "signature cache became a complete enumeration"
  let config :=
    Json.mkObj
      [
        ("idx", toJson (1 : Nat)),
        ("rid", toJson (1 : Nat)),
        ("nodes", Json.mkObj [("0", Json.mkObj [("address", toJson ":")])])
      ]
  rejects (configuration (config.setObjVal! "nodes" (.bool true))) "object"
  rejects (configuration (Json.mkObj [])) "nodes"
  for value in [.bool true, toJson (2 : Nat)] do
    check ((← ok (configuration (config.setObjVal! "rid" value))) == ["0"])
      "unused configuration rid changed membership"
  for address in [":", "127.0.0.1:8000", "node.example:443"] do
    let nodes := Json.mkObj [("0", Json.mkObj [("address", toJson address)])]
    check ((← ok (configuration (config.setObjVal! "nodes" nodes))) == ["0"])
      "transport address changed configuration membership"
  for metadata
      in [
        Json.null,
        .arr #[],
        Json.mkObj [],
        Json.mkObj [("address", .bool true)],
        Json.mkObj [("address", toJson ":"), ("unknown", .null)]
      ] do
    check
      ((← ok (configuration (config.setObjVal! "nodes" (Json.mkObj [("0", metadata)]))))
        == ["0"])
      "unused node metadata changed membership"
  let configs := Json.mkObj [("configurations", toJson [config, config])]
  let facts ← ok (stateFacts state configs)
  check ((← ok (field facts "configurations" >>= Json.getArr?)).size == 2)
    "record projection discarded configuration evidence"
  let records ←
    ok
      (parseLog "capture.stdout"
        ((envelope (Json.mkObj [("cmd", toJson "state_all")])).compress ++ "\r\n"))
  check (records[0]!.line == 1) "lost physical JSON line"
  rejects (parseLog "capture.stdout" "<RaftDriver> diagram\n") "capture.stdout:1"
  rejects (parseLog "capture.stdout" "not a logger record\n") "capture.stdout:1"
  return count + 15

private def reductionTests : IO Nat := do
  let bootstrap ← fixture "bootstrap.ndjson"
  let reduced ← ok (reduce bootstrap)
  let result ← ok (replay reduced.header reduced.instructions)
  check
    (result.actions == 1 && result.instructions == result.actions + result.observations)
    "bootstrap action contract"
  check
    (reduced.instructions.any fun instruction => instruction.origin.rule == "write-pre")
    "bootstrap signature lost its rule observation"
  let withoutTimestamps :=
    bootstrap.map
      fun row =>
        {
          row with
            value :=
              Json.mkObj ((object row.value).toOption.getD [] |>.filter (·.1 != "h_ts"))
        }
  rejects (replayRecords withoutTimestamps) "h_ts"
  let modes ← ok (reduce (resequence (bootstrap ++ #[command "create_new_node,1"])))
  check (modes.header.declared == ["0", "1"]) "future node declaration"
  let assertions ←
    ok (reduce (resequence (bootstrap.push (command "assert_commit_idx,0,2"))))
  check (assertions.instructions.size == reduced.instructions.size)
    "assertion invented an action"
  let mut count := 4
  for cmd
      in ["shuffle_one,0", "shuffle_all", "new_command,0", "pre_vote_enabled,maybe"] do
    check ((← ok (replayRecords (resequence (bootstrap.push (command cmd))))) == result)
      "unused command invented an action"
    count := count + 1
  let startup ← fixture "startup.ndjson"
  let some write :=
    startup.findIdx?
      (fun row =>
        function row == "replicate"
        && optional (row.value.getObjValD "msg") "seqno" == some (toJson (3 : Nat)))
  | throw (IO.userError "missing post-bootstrap append")
  for (path, value, diagnostic)
      in [
        (["msg", "seqno"], toJson (0 : Nat), "logLength"),
        (["msg", "seqno"], toJson (4 : Nat), "logLength"),
        (["msg", "view"], toJson (3 : Nat), "currentTerm")
      ] do
    let reduced ← ok (reduce (mutate startup write path value))
    rejects (replay reduced.header reduced.instructions) diagnostic
    count := count + 1
  for key in ["seqno", "view", "globally_committable"] do
    let message ← ok (object (startup[write]!.value.getObjValD "msg"))
    let missing := mutate startup write ["msg"] (Json.mkObj (message.filter (·.1 != key)))
    rejects (reduce missing) key
    rejects (reduce missing) startup[write]!.location
  for event
      in [
        "execute_append_entries_sync",
        "send_append_entries_response",
        "send_request_vote_response"
      ] do
    let original ←
      fixture
        (if event == "send_request_vote_response" then
            "vote_responses.ndjson"
          else
            "retire_follower.stdout")
    let source := original[← find original event]!
    rejects (reduce (resequence (bootstrap ++ #[command "dispatch_all", source])))
      "ungrouped event"
    count := count + 1
  let commit ← find bootstrap "commit"
  for (path, value)
      in [
        (["msg", "state", "commit_idx"], toJson (1 : Nat)),
        (["msg", "idx"], toJson (0 : Nat))
      ] do
    let reduced ← ok (reduce (mutate bootstrap commit path value))
    rejects (replay reduced.header reduced.instructions) "commitIndex"
  for (path, value, diagnostic)
      in [
        (["msg", "idx"], toJson (3 : Nat), "commit-target"),
        (["msg", "state", "last_idx"], toJson (3 : Nat), "commit-in-action"),
        (["msg", "state", "committable_indices"], toJson [1], "signature-marker")
      ] do
    rejects (replayRecords (mutate bootstrap commit path value)) diagnostic
    count := count + 1
  let unknown := mutate startup write ["msg", "function"] (toJson "new_function")
  rejects (reduce unknown) "ungrouped event new_function"
  rejects (reduce (mutate bootstrap 0 ["tag"] (toJson "other"))) "expected ccf.raft_trace"
  rejects (reduce (mutate bootstrap 2 ["tag"] (.bool true))) "String"
  for path in [["unknown"], ["msg", "unknown"], ["msg", "state", "unknown"]] do
    check ((← ok (replayRecords (mutate bootstrap 2 path .null))) == result)
      "unused JSON changed replay"
  let configuration ← find bootstrap "add_configuration"
  check
    ((← ok (replayRecords (mutate bootstrap configuration ["msg", "rid"] (.bool true))))
      == result)
    "unused configuration metadata changed replay"
  rejects (reduce (resequence (bootstrap.extract 2 bootstrap.size)))
    "event before command"
  rejects (reduce #[command "state_all"]) "no Raft events"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let configuredReduction ← ok (reduce configured)
  let configuredResult ←
    ok (replay configuredReduction.header configuredReduction.instructions)
  let configWrite ← find config "replicate"
  let configIndex ← find config "add_configuration"
  for index in [configWrite, configIndex] do
    check
      ((← ok
            (replayRecords
              (bootstrap ++ mutate config index ["msg", "state", "unused"] (.bool true))))
        == configuredResult)
      "unused paired state metadata changed replay"
  for (key, value, diagnostic)
      in [
        ("current_view", toJson (999 : Nat), "currentTerm"),
        ("last_idx", toJson (999 : Nat), "logLength"),
        ("commit_idx", toJson (999 : Nat), "commitIndex"),
        ("leadership_state", toJson "Candidate", "role"),
        ("committable_indices", toJson [1], "signature-marker")
      ] do
    let reduced ←
      ok (reduce (bootstrap ++ mutate config configIndex ["msg", "state", key] value))
    rejects (replay reduced.header reduced.instructions) diagnostic
  let heartbeat ← find config "send_append_entries"
  check
    ((← ok (replayRecords (bootstrap ++ erase config heartbeat))).actions
      == configuredResult.actions)
    "omitted constructor heartbeat changed model actions"
  let wrongDestination ←
    ok (reduce (bootstrap ++ mutate config heartbeat ["msg", "to_node_id"] (toJson "0")))
  rejects (replay wrongDestination.header wrongDestination.instructions) "sentIndex"
  let wrongSentinel ←
    ok
      (reduce
        (bootstrap ++ mutate config heartbeat ["msg", "sent_idx"] (toJson (2 : Nat))))
  rejects (replay wrongSentinel.header wrongSentinel.instructions) "logLength"
  let duplicated :=
    config.extract 0 (heartbeat + 1)
    ++ #[config[configIndex]!]
    ++ config.extract (heartbeat + 1) config.size
  rejects (reduce (resequence (bootstrap ++ duplicated)))
    "ungrouped event add_configuration"
  let missing :=
    config.modify configIndex
      fun row =>
        {
          row with
            value :=
              (row.value.setObjVal! "msg"
                (Json.mkObj
                  (((object (row.value.getObjValD "msg")).toOption.getD []).filter
                    (·.1 != "configurations"))))
        }
  check
    ((← ok (replayRecords (bootstrap ++ missing))).actions == configuredResult.actions)
    "omitted configuration cache changed model actions"
  let missingPrefix := configured ++ (← fixture "missing_prefix_response.ndjson")
  let prefixReduction ← ok (reduce missingPrefix)
  let _ ← ok (replay prefixReduction.header prefixReduction.instructions)
  let response := missingPrefix[← find missingPrefix "send_append_entries_response"]!
  let packet := (response.value.getObjValD "msg").getObjValD "packet"
  check
    (optional packet "success" == some (toJson "FAIL")
      && optional packet "last_log_idx" == some (toJson (0 : Nat)))
    "fixture lost its missing-prefix NACK"
  let some (current, observe, _) :=
    (← observationStates prefixReduction).find?
      (fun (_, _, origin) =>
        origin.rule == "response-post"
        && origin.file == response.file
        && origin.line == response.line)
  | throw (IO.userError "missing-prefix NACK lost its observation")
  for (success, index, diagnostic)
      in [(true, 0, "success"), (false, 1, "last_log_idx")] do
    let network :=
      current.state.network.map
        fun envelope =>
          match envelope.payload with
          | .appendEntriesResponse response =>
              {
                envelope with
                  payload :=
                    .appendEntriesResponse
                      { response with success, lastLogIndex := index }
              }
          | _ => envelope
    rejects (observe { current with state := { current.state with network } }) diagnostic
  let dropRecords ← fixture "drop_resend.ndjson"
  let drop ← ok (reduce dropRecords)
  let dropIndex ← find dropRecords "drop_pending_to"
  let wrongSender ←
    ok (reduce (mutate dropRecords dropIndex ["msg", "from_node_id"] (toJson "1")))
  rejects (replay wrongSender.header wrongSender.instructions) "drop sender mismatch"
  let some ordinarySend :=
    drop.instructions.find?
      fun instruction =>
        match instruction with
        | .action (.local _ (.sendEntries ..)) _ => true
        | _ => false
  | throw (IO.userError "missing standalone send")
  let some send :=
    dropRecords.findIdx?
      fun row =>
        row.file == ordinarySend.origin.file && row.line == ordinarySend.origin.line
  | throw (IO.userError "missing standalone send record")
  for (path, diagnostic)
      in [
        (["msg", "packet", "prev_idx"], "prev_idx"),
        (["msg", "sent_idx"], "sentIndex")
      ] do
    let reduced ← ok (reduce (mutate dropRecords send path (toJson (999 : Nat))))
    rejects (replay reduced.header reduced.instructions) diagnostic
  let actions :=
    drop.instructions.toList.filterMap
      fun instruction =>
        match instruction with
        | .action step _ => some step.name
        | _ => none
  check
    (actions.drop (actions.length - 6)
      == ["sendEntries", "sendEntries", "drop", "drop", "sendEntries", "receive"])
    "drop/resend reduction changed"
  return count + 15

private def parsecReductionTests : IO Unit := do
  let bootstrap ← fixture "bootstrap.ndjson"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let baseline ← ok (reduce configured)
  -- Alternatives must not lose or duplicate the instruction batches they emit.
  check
    (baseline.instructions.toList.filterMap
        (fun instruction =>
          match instruction with
          | .action step _ => some step.name
          | _ => none)
      == ["append", "append", "append"])
    "operation alternatives lost or duplicated append instructions"
  let heartbeat ← find config "send_append_entries"
  let _ ← ok (replayRecords (bootstrap ++ erase config heartbeat))
  let wrongSentinel ←
    ok
      (reduce
        (bootstrap ++ mutate config heartbeat ["msg", "sent_idx"] (toJson (999 : Nat))))
  rejects (replay wrongSentinel.header wrongSentinel.instructions) "logLength"
  let source := config[← find config "add_configuration"]!
  let message :=
    Json.mkObj
      [
        ("function", toJson "execute_append_entries_sync"),
        ("state", (source.value.getObjValD "msg").getObjValD "state"),
        ("from_node_id", toJson "0")
      ]
  let event := { source with value := source.value.setObjVal! "msg" message }
  rejects (reduce (resequence (configured.push event)))
    "ungrouped event execute_append_entries_sync"
  let votes ← fixture "vote_responses.ndjson"
  let reduced ← ok (reduce votes)
  check
    ((reduced.instructions.filter
        fun instruction =>
          match instruction with
          | .action (.local _ (.sendEntries ..)) _ => true
          | _ => false).size
      > 1)
    "many stopped after the first send rule"

private def receiveGrammarTests : IO Unit := do
  for (family, capture)
      in [
        ("recv_append_entries", "vote_responses.ndjson"),
        ("recv_append_entries_response", "vote_responses.ndjson"),
        ("recv_request_vote", "vote_responses.ndjson"),
        ("recv_request_vote_response", "vote_responses.ndjson"),
        ("recv_propose_request_vote", "nominate_successor.stdout")
      ] do
    let records ← fixture capture
    let _ ← ok (replayRecords records)
    let head ← find records family
    -- All fields are valid, but the named grammar must reject another family.
    let packet :=
      if family == "recv_propose_request_vote" then
        Json.mkObj
          [
            ("msg", toJson "raft_request_vote"),
            ("term", toJson (2 : Nat)),
            ("last_committable_idx", toJson (2 : Nat)),
            ("term_of_last_committable_idx", toJson (2 : Nat))
          ]
      else
        Json.mkObj
          [("msg", toJson "raft_propose_request_vote"), ("term", toJson (2 : Nat))]
    rejects (reduce (mutate records head ["msg", "packet"] packet))
      "receive function/packet mismatch"
  let votes ← fixture "vote_responses.ndjson"
  let response ← find votes "send_request_vote_response"
  let packet :=
    ((votes[response]!.value.getObjValD "msg").getObjValD "packet")
    |>.setObjVal! "msg" (toJson "raft_append_entries_response")
  let packet :=
    Json.mkObj
      [
        ("msg", packet.getObjValD "msg"),
        ("term", packet.getObjValD "term"),
        ("last_log_idx", toJson (0 : Nat)),
        ("success", toJson "FAIL")
      ]
  rejects (reduce (mutate votes response ["msg", "packet"] packet))
    "vote response does not match request"

private def sendObservationTests : IO Unit := do
  let records ← fixture "vote_responses.ndjson"
  let baseline ← ok (replayRecords records)
  let heartbeat ← find records "send_append_entries"
  check
    (function records[heartbeat - 1]! == "add_configuration"
      && function records[heartbeat + 1]! == "send_append_entries")
    "fixture needs two constructor heartbeats"
  for changed
      in [
        erase records heartbeat,
        resequence
          (records.extract 0 heartbeat ++ records.extract (heartbeat + 2) records.size),
        resequence
          (records.set! heartbeat records[heartbeat + 1]!
            |>.set! (heartbeat + 1) records[heartbeat]!),
        resequence
          (records.extract 0 heartbeat
            ++ #[records[heartbeat]!]
            ++ records.extract heartbeat records.size)
      ] do
    check ((← ok (replayRecords changed)).actions == baseline.actions)
      "constructor heartbeat observations changed model actions"
  for family in ["raft_request_pre_vote", "raft_request_vote"] do
    let isRequest (record : Record) :=
      function record == "send_request_vote"
      && optional ((record.value.getObjValD "msg").getObjValD "packet") "msg"
          == some (toJson family)
    let some index := records.findIdx? isRequest
    | throw (IO.userError s!"missing {family}")
    check (isRequest records[index + 1]!) "election fixture needs adjacent requests"
    for changed
        in [
          erase records index,
          resequence
            (records.extract 0 index ++ records.extract (index + 2) records.size),
          resequence
            (records.set! index records[index + 1]! |>.set! (index + 1) records[index]!),
          resequence
            (records.extract 0 index
              ++ #[records[index]!]
              ++ records.extract index records.size)
        ] do
      let result ← ok (replayRecords changed)
      check (result.actions == baseline.actions)
        "election send observations changed model actions"
    let source ←
      ok (field (records[index]!.value.getObjValD "msg") "state" >>= (string · "node_id"))
    for (path, value, diagnostic)
        in [
          (["msg", "to_node_id"], toJson source, "no pending packet"),
          (["msg", "packet", "term"], toJson (999 : Nat), "term")
        ] do
      let reduced ← ok (reduce (mutate records index path value))
      rejects (replay reduced.header reduced.instructions) diagnostic

private def retirementNodeSetTests : IO Unit := do
  let records ← fixture "self_quorum.stdout"
  let baseline ← ok (replayRecords records)
  let some cleanup :=
    records.findIdx?
      fun row =>
        ((row.value.getObjValD "msg").getObjValD "cmd").getStr?.toOption
        |>.any (·.startsWith "cleanup_nodes,")
  | throw (IO.userError "missing retirement confirmation command")
  let command ← ok (field records[cleanup]!.value "msg" >>= (string · "cmd"))
  let some node := (command.splitOn ",").getLast?
  | throw (IO.userError "missing retirement node")
  let duplicate := mutate records cleanup ["msg", "cmd"] (toJson s!"{command},{node}")
  check ((← ok (replayRecords duplicate)) == baseline)
    "duplicate retirement node changed its model set"
  check (function records[cleanup + 1]! == "replicate")
    "retirement command must precede its append"
  let throughAppend := records.extract 0 (cleanup + 2)
  let empty := String.intercalate "," ((command.splitOn ",").take 2)
  let empty ← ok (reduce (mutate throughAppend cleanup ["msg", "cmd"] (toJson empty)))
  let _ ← ok (replay empty.header empty.instructions)
  rejects (reduce (mutate throughAppend cleanup ["msg", "cmd"] (toJson s!"{command},")))
    "undeclared"

private def speculativeGrammarTests : IO Unit := do
  let votes ← fixture "vote_responses.ndjson"
  let some promotion :=
    votes.findIdx?
      (fun record =>
        function record == "become_leader"
        && optional ((record.value.getObjValD "msg").getObjValD "state") "node_id"
            == some (toJson "1"))
  | throw (IO.userError "missing multi-node leadership promotion")
  let configurations ←
    ok
      (field (votes[promotion]!.value.getObjValD "msg") "configurations" >>= Json.getArr?)
  let members ← configurations.toList.mapM fun value => ok (configuration value)
  let peers := members.flatten.eraseDups.filter (· != "1")
  check (peers.length == 2) "leadership fixture no longer has two peers"
  let endOfPromotion := promotion + 1 + peers.length
  let promotionRecords := votes.extract 0 endOfPromotion
  let baseline ← ok (reduce promotionRecords)
  let changedTerm ←
    ok
      (reduce
        (mutate promotionRecords (promotion + 1)
          ["msg", "state", "current_view"] (toJson (999 : Nat))))
  rejects (replay changedTerm.header changedTerm.instructions) "currentTerm"
  let periodic := { votes[promotion + 1]! with file := "periodic.ndjson", line := 1 }
  let extended :=
    resequence (promotionRecords ++ #[command "periodic_one,1,10", periodic])
  let reduced ← ok (reduce extended)
  let sends (reduced : Reduced) :=
    reduced.instructions.filter
      fun instruction =>
        match instruction with
        | .action (.local _ (.sendEntries ..)) _ => true
        | _ => false
  check ((sends reduced).size == (sends baseline).size + 1)
    "promotion consumed the following periodic heartbeat"
  let _ ← ok (replayRecords extended)
  let baselineResult ← ok (replay baseline.header baseline.instructions)
  for endOfGroup in [promotion + 1, endOfPromotion - 1] do
    check
      ((← ok (replayRecords (promotionRecords.extract 0 endOfGroup))).actions
        == baselineResult.actions)
      "omitted promotion heartbeat changed model actions"
  let selfHeartbeat ←
    ok
      (reduce
        (mutate promotionRecords (promotion + 1) ["msg", "to_node_id"] (toJson "1")))
  rejects (replay selfHeartbeat.header selfHeartbeat.instructions) "no pending packet"
  let destination ← ok (string (periodic.value.getObjValD "msg") "to_node_id")
  let duplicate ←
    ok
      (reduce
        (mutate promotionRecords (endOfPromotion - 1) ["msg", "to_node_id"]
          (toJson destination)))
  check ((sends duplicate).size == (sends baseline).size + 1)
    "duplicate promotion destination did not become a standalone send"
  let _ ← ok (replay duplicate.header duplicate.instructions)
  let retired ← fixture "self_quorum.stdout"
  let some promotion :=
    retired.findIdx?
      (fun record =>
        function record == "become_leader"
        && optional ((record.value.getObjValD "msg").getObjValD "state") "node_id"
            == some (toJson "1"))
  | throw (IO.userError "missing promotion with a retired peer")
  let retiredHeartbeat := retired[promotion + 1]!
  check (function retiredHeartbeat == "send_append_entries")
    "retired-peer fixture no longer sends a promotion heartbeat"
  let reduced ← ok (reduce (retired.extract 0 (promotion + 2)))
  check
    (reduced.instructions.any
      fun instruction =>
        instruction.origin.file == retiredHeartbeat.file
        && instruction.origin.line == retiredHeartbeat.line
        && instruction.origin.rule == "leader-heartbeat-post")
    "retired-peer promotion heartbeat became a separate send action"

  let bootstrap ← fixture "bootstrap.ndjson"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let configMessage := config[← find config "add_configuration"]!.value.getObjValD "msg"
  let configurations ← ok (field configMessage "configurations" >>= Json.getArr?)
  let newConfiguration :=
    Json.mkObj
      ((← ok (object configMessage)).filter
        (fun (key, _) => ["idx", "rid", "nodes"].contains key))
  let configurations := configurations.push newConfiguration
  let leaderState :=
    state.setObjVal! "last_idx" (toJson (4 : Nat))
    |>.setObjVal! "committable_indices" (toJson [4])
  let event (line : Nat) (message : Json) : Record :=
    { file := "receive-boundary.ndjson", line, value := envelope message }
  let receive (name : String) (packet : Json) (role : String) :=
    event 1
      (Json.mkObj
        [
          ("function", toJson name),
          ("state", leaderState.setObjVal! "leadership_state" (toJson role)),
          ("from_node_id", toJson "1"),
          ("packet", packet)
        ])
  let follower (term : Nat) :=
    event 2
      (Json.mkObj
        [
          ("function", toJson "become_follower"),
          (
            "state",
            leaderState.setObjVal! "leadership_state" (toJson "Follower")
            |>.setObjVal! "current_view" (toJson term)
          ),
          ("configurations", toJson configurations)
        ])
  let voteResponse (family : String) (term : Nat) :=
    Json.mkObj
      [("msg", toJson family), ("term", toJson term), ("vote_granted", .bool false)]
  let timeouts (reduced : Reduced) :=
    reduced.instructions.filter
      fun instruction =>
        match instruction with
        | .action (.local _ (.timeout .checkQuorum)) _ => true
        | _ => false
  let adoptions (reduced : Reduced) :=
    reduced.instructions.filter
      fun instruction =>
        instruction.origin.rule == "receive-term-adoption"
  for family in ["raft_request_vote_response", "raft_request_pre_vote_response"] do
    let records :=
      configured
      ++ #[
        command "dispatch_all",
        receive "recv_request_vote_response" (voteResponse family 2) "Leader",
        command "periodic_one,0,100",
        follower 2
      ]
    let reduced ← ok (reduce (resequence records))
    check ((timeouts reduced).size == 1 && (adoptions reduced).isEmpty)
      "ignored same-term response consumed a check-quorum transition"
    let records :=
      configured
      ++ #[
        command "dispatch_all",
        receive "recv_request_vote_response" (voteResponse family 3) "Leader",
        follower 3
      ]
    let reduced ← ok (reduce (resequence records))
    check ((timeouts reduced).isEmpty && (adoptions reduced).size == 1)
      "higher-term response lost its term-adoption evidence"
  for role in ["Candidate", "PreVoteCandidate"] do
    let records :=
      configured
      ++ #[
        command "dispatch_all",
        receive "recv_append_entries" appendPacket role,
        follower 2
      ]
    let reduced ← ok (reduce (resequence records))
    check ((timeouts reduced).isEmpty && (adoptions reduced).size == 1)
      "same-term AppendEntries demotion became a check-quorum action"

/-- Raw mutations exercise the reducer's projections, not merely the final checker. -/
private def fixtureMutations : IO Nat := do
  let mut count := 0
  for name
      in [
        "bootstrap.ndjson",
        "startup.ndjson",
        "vote_responses.ndjson",
        "retire_follower.stdout"
      ] do
    let records ← fixture name
    let reduced ← ok (reduce records)
    let result ← ok (replay reduced.header reduced.instructions)
    let (events, _) ← ok (associate records)
    check
      (result.instructions == reduced.instructions.size
        && result.actions + result.observations == result.instructions)
      s!"{name}: unconsumed instructions"
    count := count + 1
    for (current, observe, origin) in ← observationStates reduced do
      let _ ← ok (observe current)
      check (!(observe { state := { nodes := [] } }).isOk)
        s!"{origin.label}: observation accepted missing model evidence"
      if ["write-pre", "receive-pre", "receive-post"].contains origin.rule then
        let some event :=
          events.find?
            (fun event =>
              event.record.file == origin.file && event.record.line == origin.line)
        | throw (IO.userError "observation lost its source event")
        let fields := (← ok (object event.facts)).filter (·.1 != "committableIndices")
        checkObservedFields (observeState reduced.header event.node none) current fields
      count := count + 1
    -- Fields stable at a event are selected by event kind, not their values.
    for (raw, projected)
        in [
          ("leadership_state", "role"),
          ("current_view", "currentTerm"),
          ("last_idx", "logLength"),
          ("commit_idx", "commitIndex"),
          ("retirement_idx", "retirementIndex"),
          ("retirement_committable_idx", "retirementCommittableIndex"),
          ("retired_committed_idx", "retiredCommittedIndex")
        ] do
      for instruction in reduced.instructions do
        if let .observe _ origin := instruction then
          let some event :=
            events.find?
              (fun event =>
                event.record.file == origin.file && event.record.line == origin.line)
          | throw (IO.userError "observation lost its source event")
          if (origin.rule == "receive-post"
                || (origin.rule == "event-term" && projected == "currentTerm"))
              && event.function != "add_configuration" then
            let some index :=
              records.findIdx?
                (fun row => row.file == origin.file && row.line == origin.line)
            | throw (IO.userError "lost raw origin")
            let replacement :=
              if projected == "role" then
                toJson "Candidate"
              else
                toJson (999 : Nat)
            let command ← ok (field event.command.value "msg" >>= (string · "cmd"))
            rejects
              (replayRecords (mutate records index ["msg", "state", raw] replacement))
              (if event.function == "become_leader"
                  && command.startsWith "start_node," then
                  "bootstrap state differs from audited prelude"
                else
                  projected)
            count := count + 1
            break
  let original ← fixture "vote_responses.ndjson"
  let withoutResponseSends :=
    original.filter (fun row => function row != "send_request_vote_response")
  let _ ← ok (replayRecords (resequence withoutResponseSends))
  count := count + 1
  for family in ["raft_request_vote_response", "raft_request_pre_vote_response"] do
    let some index :=
      original.findIdx?
        (fun row =>
          function row == "send_request_vote_response"
          && optional ((row.value.getObjValD "msg").getObjValD "packet") "msg"
              == some (toJson family))
    | throw (IO.userError s!"missing {family}")
    for (key, value, diagnostic)
        in [
          ("term", toJson (999 : Nat), "term"),
          ("vote_granted", .bool false, "vote_granted")
        ] do
      let old :=
        ((original[index]!.value.getObjValD "msg").getObjValD "packet").getObjValD key
      let value := if value == old then .bool true else value
      rejects (replayRecords (mutate original index ["msg", "packet", key] value))
        diagnostic
      count := count + 1
    rejects (reduce (mutate original index ["msg", "to_node_id"] (toJson "unexpected")))
      "does not match request"
    count := count + 1
  rejects (← readLog "replay/tests/fixtures/terminal_retirement.stdout")
    "terminal_retirement.stdout:4"
  let terminal ← fixture "self_quorum.stdout"
  let _ ← ok (replayRecords terminal)
  let nomination ← find terminal "step_down_and_nominate_successor"
  rejects (replayRecords (mutate terminal nomination ["msg", "to_node_id"] (toJson "0")))
    "no pending packet"
  rejects
    (reduce
      (mutate terminal nomination ["msg", "state", "leadership_state"]
        (toJson "Follower")))
    "nomination outside a nominate_successor command"
  let reduced ← ok (reduce terminal)
  check
    (!(reduced.instructions.any
        fun instruction =>
          match instruction with
          | .action (.local _ .nominateSuccessor) _ => true
          | _ => false))
    "retirement invented a nomination action"
  let some cache :=
    reduced.instructions.find?
      (fun instruction =>
        match instruction with
        | .observe _ origin => origin.rule == "configuration-pre"
        | _ => false)
  | throw (IO.userError "missing configuration snapshot coverage")
  let origin := cache.origin
  let some index := terminal.findIdx? (fun row => row.line == origin.line)
  | throw (IO.userError "missing event configuration raw record")
  let configurations :=
    ((terminal[index]!.value.getObjValD "msg").getObjValD
      "configurations").getArr?.toOption.getD
      #[]
  let mutated :=
    configurations.modify 0
      (fun value =>
        value.setObjVal! "nodes"
          (Json.mkObj [("unexpected-node", Json.mkObj [("address", toJson ":")])]))
  rejects (replayRecords (mutate terminal index ["msg", "configurations"] (.arr mutated)))
    "configuration-pre"
  let startup ← fixture "startup.ndjson"
  let some write :=
    startup.findIdx?
      (fun row =>
        function row == "replicate"
        && optional (row.value.getObjValD "msg") "seqno" == some (toJson (3 : Nat)))
  | throw (IO.userError "missing post-bootstrap signature")
  rejects
    (replayRecords
      (mutate startup write ["msg", "state", "committable_indices"] (toJson [1])))
    "signature-marker"
  let some committedPrefix :=
    reduced.instructions.find?
      (fun instruction =>
        match instruction with
        | .observe _ origin =>
            origin.rule == "event-committed-prefix"
            && terminal.any
                (fun row =>
                  row.file == origin.file
                  && row.line == origin.line
                  && function row == "become_leader")
        | _ => false)
  | throw (IO.userError "missing committed-prefix coverage")
  let some prefixIndex :=
    terminal.findIdx? (fun row => row.line == committedPrefix.origin.line)
  | throw (IO.userError "lost prefix source record")
  rejects
    (replayRecords
      (mutate terminal prefixIndex ["msg", "state", "commit_idx"] (toJson (999 : Nat))))
    "event-committed-prefix"
  return count + 6

private def emissionTests : IO Unit := do
  let records ← fixture "vote_responses.ndjson"
  let reduced ← ok (reduce records)
  let (events, _) ← ok (associate records)
  let sameOrigin (origin : Origin) (event : CCFRaft.Replay.Event) :=
    origin.file == event.record.file && origin.line == event.record.line
  for (current, observe, origin) in ← observationStates reduced do
    let some event := events.find? (sameOrigin origin)
    | throw (IO.userError "observation lost its source event")
    if event.function.startsWith "recv_" then
      let _ ← ok (observe { current with state := { current.state with network := [] } })
  for instruction in reduced.instructions, position in [:reduced.instructions.size] do
    if let .action (.receive ..) head := instruction then
      let some headEvent := events.find? (sameOrigin head)
      | throw (IO.userError "receive action lost its source event")
      for later in reduced.instructions, observedAt in [:reduced.instructions.size] do
        let event :=
          events.any
            fun event =>
              event.sameContext headEvent
              && event.record.line > head.line
              && sameOrigin later.origin event
        if event then
          check (observedAt > position) "event evidence preceded its receive action"
  let baseline ← ok (replayRecords records)
  for name in ["send_append_entries", "recv_append_entries_response"] do
    let index ← find records name
    let fields ← ok (object (records[index]!.value.getObjValD "msg"))
    for key in ["sent_idx", "match_idx"] do
      let missing :=
        mutate records index ["msg"] (Json.mkObj (fields.filter (·.1 != key)))
      rejects (replayRecords missing) key
      rejects (replayRecords missing) records[index]!.location
  for (name, key, value, diagnostic)
      in [
        ("send_append_entries", "term", .bool true, "term"),
        ("send_append_entries", "idx", toJson (999 : Nat), "logLength"),
        ("send_append_entries_response", "success", .arr #[], "success")
      ] do
    let index ← find records name
    rejects (replayRecords (mutate records index ["msg", "packet", key] value)) diagnostic
  for name in ["execute_append_entries_sync", "add_configuration", "commit"] do
    let some index :=
      records.findIdx?
        fun row =>
          function row == name
          && optional ((row.value.getObjValD "msg").getObjValD "state") "leadership_state"
              == some (toJson "Follower")
    | throw (IO.userError s!"missing follower {name} evidence")
    for raw
        in [
          "last_idx",
          "retirement_idx",
          "retirement_committable_idx",
          "retired_committed_idx"
        ] do
      let internal := mutate records index ["msg", "state", raw] (toJson (999 : Nat))
      check ((← ok (replayRecords internal)) == baseline)
        s!"{name} {raw} still depended on later event snapshots"
    rejects
      (replayRecords
        (mutate records index ["msg", "state", "retirement_idx"] (.bool true)))
      "natural"
    if name == "commit" then
      rejects
        (replayRecords (mutate records index ["msg", "idx"] (toJson (999 : Nat))))
        "no log entry"
    if name == "add_configuration" then
      let bad := mutate records index ["msg", "idx"] (toJson (999 : Nat))
      let bad := mutate bad index ["msg", "rid"] (toJson (999 : Nat))
      rejects (replayRecords bad) "no log entry"
  let receive ← find records "recv_append_entries"
  rejects
    (replayRecords
      (mutate records receive ["msg", "packet", "term"] (toJson (999 : Nat))))
    "ungrouped event send_append_entries_response"
  let some adoption :=
    records.findIdx?
      fun row =>
        function row == "become_follower"
        && optional ((row.value.getObjValD "msg").getObjValD "state") "current_view"
            == some (toJson (3 : Nat))
  | throw (IO.userError "missing term adoption")
  check (function records[adoption + 1]! == "send_request_vote_response")
    "missing optional response after adoption"
  let terminalAdoption := erase records (adoption + 1)
  let baseline ← ok (replayRecords terminalAdoption)
  check
    ((← ok
          (replayRecords
            (mutate terminalAdoption adoption ["msg", "state", "last_idx"]
              (toJson (999 : Nat)))))
      == baseline)
    "terminal adoption was conditionally promoted to an endpoint"

private def configurationCache (index : Nat) (nodes : List String) : Json :=
  toJson
    [Json.mkObj
      [
        ("idx", toJson index),
        ("rid", toJson index),
        (
          "nodes",
          Json.mkObj
            (nodes.map (fun node => (node, Json.mkObj [("address", toJson ":")])))
        )
      ]]

private def stateCorruptions : List (String × Json × String) :=
  [
    ("leadership_state", toJson "Candidate", "role"),
    ("current_view", toJson (999 : Nat), "currentTerm"),
    ("last_idx", toJson (999 : Nat), "logLength"),
    ("commit_idx", toJson (999 : Nat), "commitIndex"),
    ("retirement_idx", toJson (999 : Nat), "retirementIndex"),
    ("retirement_committable_idx", toJson (999 : Nat), "retirementCommittableIndex"),
    ("retired_committed_idx", toJson (999 : Nat), "retiredCommittedIndex")
  ]

private def observationTests : IO Nat := do
  let startup ← fixture "startup.ndjson"
  let votes ← fixture "vote_responses.ndjson"
  let receive ← find votes "recv_append_entries"
  let timeout ← find votes "become_pre_vote_candidate"
  let mut count := 0
  for index in [receive, timeout] do
    let _ ← ok (replayRecords votes)
    for (raw, value, projected) in stateCorruptions do
      if raw == "leadership_state" && index == timeout then continue
      rejects (replayRecords (mutate votes index ["msg", "state", raw] value))
        (if index == receive && raw == "current_view" then
            "ungrouped event send_append_entries_response"
          else
            projected)
      count := count + 1
  let startupReduction ← ok (reduce startup)
  check
    (startupReduction.instructions.any
      fun instruction => instruction.origin.rule == "write-pre")
    "missing rule observations"
  let candidate ← find votes "become_candidate"
  let _ ←
    ok
      (replayRecords
        (mutate votes candidate ["msg", "state", "last_idx"] (toJson (999 : Nat))))
  rejects
    (replayRecords
      (mutate votes candidate ["msg", "state", "retirement_idx"] (.bool true)))
    "natural"
  return count + 3

private def origin : Origin :=
  { file := "direct.ndjson", line := 17, rule := "unit" }

private def header : Header :=
  {
    declared := ["alpha", "beta", "future"]
    bootstrap := {0, 1}
    requests := ["", "tx-1", "configuration", "retired", "tx", "other", "unknown"]
  }

private def act (step : Step) : Instruction := .action step origin

private def observe (node : String) (fields : List (String × Json))
    (identities : Header := header)
    : Instruction :=
  .observe (observeState identities node none (Json.mkObj fields)) origin

private def sent (source destination : String) (fields : List (String × Json))
    : Instruction :=
  .observe (observeMessage header source destination (Json.mkObj fields) .latest) origin

-- This includes function-valued peer tables and every dropped occurrence.
example (identities : Header) (current : ReplayState)
    (observer : ReplayState → Except String Unit) (source : Origin)
    (succeeds : observer current = .ok ())
    : runInstruction identities current (.observe observer source) = .ok current := by
  simp [runInstruction, succeeds]

private def observationClosureTests : IO Unit := do
  let steps :=
    #[
      act (.local "alpha" (.append [.transaction 1 {}])),
      act (.local "alpha" (.append [.signature])),
      act (.local "alpha" (.sendEntries 1 3)),
      act (.receive "alpha" "beta" (Json.mkObj [("msg", toJson "raft_append_entries")])),
      act
        (.receive "beta" "alpha"
          (Json.mkObj [("msg", toJson "raft_append_entries_response")]))
    ]
  let current ←
    steps.foldlM (fun current step => ok (runInstruction header current step))
      { state := header.initial }
  let identities := { header with bootstrap := ∅ }
  let fields :=
    [
      ("role", toJson "leader"),
      ("currentTerm", toJson (2 : Nat)),
      ("logLength", toJson (3 : Nat)),
      ("commitIndex", toJson (3 : Nat)),
      (
        "configurations",
        toJson
          [Json.mkObj [("index", toJson (1 : Nat)), ("nodes", toJson ["alpha", "beta"])]]
      ),
      ("membershipState", toJson "active"),
      ("retirementIndex", Json.null),
      ("retirementCommittableIndex", Json.null),
      ("retiredCommittedIndex", Json.null)
    ]
  checkObservedFields (observeState identities "alpha" (some "beta")) current
    (fields ++ [("sentIndex", toJson (3 : Nat)), ("matchIndex", toJson (3 : Nat))])
  let before :=
    fields.map
      fun (key, value) =>
        (key, if key == "commitIndex" then toJson (1 : Nat) else value)
  checkObservedFields (observeBeforeCommit identities "alpha" 1) current before
  rejects (observeBeforeCommit identities "alpha" 3 (Json.mkObj before) current)
    "pre-commit frontier must precede final commitIndex"
  checkObservedFields (observeEntry identities "alpha" 2) current
    [
      ("term", toJson (2 : Nat)),
      ("committed", .bool true),
      ("kind", toJson "transaction"),
      ("transaction", toJson "tx-1"),
      ("configurations", toJson ([] : List (List String))),
      ("retiredCommitted", toJson ([] : List String))
    ]
  checkObservedFields (observeEntry identities "alpha" 3) current
    [("term", toJson (2 : Nat)), ("committed", .bool true), ("kind", toJson "signature")]
  rejects
    (observeEntry { identities with requests := [""] } "alpha" 2
      (Json.mkObj [("kind", toJson "transaction")]) current)
    "unknown model request identifier"
  let messages : List CCFRaft.Model.Node.Message :=
    [
      .appendEntriesRequest
        {
          term := 2,
          prevLogIndex := 0,
          prevLogTerm := 0,
          entries := [],
          primaryCommit := 0
        },
      .appendEntriesResponse { term := 2, success := false, lastLogIndex := 0 },
      .requestVoteRequest
        { term := 3, lastCommittableTerm := 2, lastCommittableIndex := 3 },
      .requestVoteResponse { term := 3, voteGranted := true },
      .requestPreVoteRequest
        { term := 2, lastCommittableTerm := 2, lastCommittableIndex := 3 },
      .requestPreVoteResponse { term := 2, voteGranted := true },
      .proposeRequestVoteRequest 2
    ]
  for message in messages do
    let envelope : Envelope := { source := 0, target := 1, payload := message }
    let queued :=
      {
        current with
          state := { current.state with network := [envelope, envelope] },
          dropped := [envelope]
      }
    for selection in [PacketSelection.head, .latest] do
      checkObservedFields
        (fun fields => observeMessage identities "alpha" "beta" fields selection)
        queued (← ok (object (messageJson message)))
    let observer : ReplayState → Except String Unit :=
      fun state => do
        require (state.dropped == [envelope] && state.pending 0 1 == [envelope])
          "closure lost packet multiplicity or dropped evidence"
        observeState identities "alpha" (some "beta")
          (Json.mkObj
            [("commitIndex", toJson (3 : Nat)), ("matchIndex", toJson (3 : Nat))])
          state
    let unchanged ← ok (runInstruction header queued (.observe observer origin))
    let _ ← ok (observer unchanged)
    check
      (unchanged.state.network == queued.state.network
        && unchanged.dropped == queued.dropped)
      "observation changed packet accounting"
  let failure := Instruction.observe (fun _ => .error "closure sentinel") origin
  rejects (replay header #[failure]) s!"instruction 1 at {origin.label}: closure sentinel"

private def directTests : IO Nat := do
  let append := Json.mkObj [("msg", toJson "raft_append_entries")]
  let response := Json.mkObj [("msg", toJson "raft_append_entries_response")]
  let start :=
    #[
      observe "future"
        [
          ("role", toJson "none"),
          ("currentTerm", toJson (0 : Nat)),
          ("membershipState", toJson "active")
        ],
      act (.local "alpha" (.append [.transaction 1 {}])),
      act (.local "alpha" (.append [.signature])),
      act (.local "alpha" (.sendEntries 1 3)),
      sent "alpha" "beta"
        [
          ("msg", toJson "raft_append_entries"),
          ("prev_idx", toJson (0 : Nat)),
          ("idx", toJson (3 : Nat))
        ]
    ]
  let complete :=
    start
    ++ #[
      act (.receive "alpha" "beta" append),
      sent "beta" "alpha"
        [("msg", toJson "raft_append_entries_response"), ("success", toJson "OK")],
      observe "beta" [("role", toJson "follower"), ("logLength", toJson (3 : Nat))],
      act (.receive "beta" "alpha" response),
      .observe
        (observeState header "alpha" (some "beta")
          (Json.mkObj
            [
              ("commitIndex", toJson (3 : Nat)),
              ("sentIndex", toJson (3 : Nat)),
              ("matchIndex", toJson (3 : Nat))
            ]))
        origin
    ]
  check
    ((← ok (replay header complete))
      == { instructions := 10, actions := 5, observations := 5 })
    "direct instruction consumption"
  rejects (replay header #[]) "must not be empty"
  for (step, diagnostic)
      in [
        (Step.receive "alpha" "beta" append, "no pending packet"),
        (.drop "alpha" "beta", "no pending packet"),
        (.local "beta" (.append [.signature]), "disabled model action 'append'"),
        (.local "alpha" (.append []), "disabled model action 'append'"),
        (.local "unknown" (.timeout .election), "undeclared node"),
        (.local "alpha" (.sendEntries 1 99), "disabled model action 'sendEntries'")
      ] do
    rejects (replay header #[act step]) diagnostic
  rejects (replay header #[observe "alpha" []]) "at least one"
  rejects (replay header #[observe "alpha" [("unknown", toJson (0 : Nat))]])
    "unsupported observation field"
  rejects
    (replay header
      #[
        .observe
          (observeEntry header "alpha" 0 (Json.mkObj [("kind", toJson "signature")]))
          origin
      ])
    "positive"
  rejects
    (replay header
      #[
        .observe
          (observeEntry header "alpha" 2 (Json.mkObj [("kind", toJson "signature")]))
          origin
      ])
    "no log entry"
  rejects
    (replay header
      (start.push
        (.observe
          (observeEntry header "alpha" 1 (Json.mkObj [("kind", toJson "signature")]))
          origin)))
    "kind"
  rejects
    (replay header
      (start.push
        (.observe (observeEntry header "alpha" 2 (Json.mkObj [("committed", .bool true)]))
          origin)))
    "committed"
  let twice :=
    start
    ++ #[
      act (.local "alpha" (.sendEntries 1 3)),
      sent "alpha" "beta" [("prev_idx", toJson (3 : Nat)), ("idx", toJson (3 : Nat))]
    ]
  let head :=
    Instruction.observe
      (observeMessage header "alpha" "beta"
        (Json.mkObj [("prev_idx", toJson (0 : Nat)), ("idx", toJson (3 : Nat))]) .head)
      origin
  let _ ← ok (replay header (twice.push head))
  let wrong :=
    Instruction.observe
      (observeMessage header "alpha" "beta" (Json.mkObj [("prev_idx", toJson (3 : Nat))])
        .head)
      origin
  rejects (replay header (twice.push wrong)) "prev_idx"
  let dropped :=
    twice ++ #[head, act (.drop "alpha" "beta"), wrong, act (.drop "alpha" "beta")]
  let _ ← ok (replay header dropped)
  rejects (replay header (dropped.push head)) "no pending packet"
  -- Equal copies remain distinct: dropping one cannot hide/deliver both.
  let heartbeat :=
    #[
      act (.local "alpha" (.sendEntries 1 0)),
      sent "alpha" "beta" [("idx", toJson (0 : Nat))]
    ]
  let duplicate :=
    heartbeat
    ++ heartbeat
    ++ #[
      act (.drop "alpha" "beta"),
      act (.receive "alpha" "beta" append),
      sent "beta" "alpha" [("success", toJson "OK")]
    ]
  let _ ← ok (replay header duplicate)
  rejects (replay header (duplicate.push (act (.receive "alpha" "beta" append))))
    "no pending packet"
  -- Send telemetry is not a complete or exactly-once enumeration of model outputs.
  let _ ← ok (replay header (start.extract 0 4))
  let _ ← ok (replay header (complete.extract 0 4 ++ complete.extract 5 complete.size))
  let envelope : Envelope :=
    { source := 0, target := 1, payload := .proposeRequestVoteRequest 2 }
  let repeated : ReplayState :=
    { state := { header.initial with network := [envelope, envelope] } }
  let observation :=
    sent "alpha" "beta"
      [("msg", toJson "raft_propose_request_vote"), ("term", toJson (2 : Nat))]
  let once ← ok (runInstruction header repeated observation)
  let twice ← ok (runInstruction header once observation)
  check (twice.state.network.length == 2)
    "repeated telemetry consumed or duplicated a model packet"
  let _ ←
    ok (replay header (start.push (sent "alpha" "beta" [("idx", toJson (3 : Nat))])))
  let observedRepeatedly :=
    heartbeat
    ++ #[
      sent "alpha" "beta" [("idx", toJson (0 : Nat))],
      sent "alpha" "beta" [("idx", toJson (0 : Nat))],
      act (.receive "alpha" "beta" append),
      sent "beta" "alpha" [("success", toJson "OK")]
    ]
  let _ ← ok (replay header observedRepeatedly)
  rejects (replay header (observedRepeatedly.push (act (.receive "alpha" "beta" append))))
    "no pending packet"
  rejects (replay header (observedRepeatedly.push (act (.drop "alpha" "beta"))))
    "no pending packet"
  let early := start.push (observe "alpha" [("logLength", toJson (99 : Nat))])
  rejects (replay header (early.push (act (.receive "missing" "missing" append))))
    "instruction 6"
  rejects (replay header early) "direct.ndjson:17 [unit]"
  let configured :=
    #[
      act (.local "alpha" (.append [.transaction 2 { configuration := some {0} }])),
      .observe
        (observeEntry header "alpha" 2
          (Json.mkObj
            [
              ("configurations", toJson [["alpha"]]),
              ("retiredCommitted", toJson ([] : List String))
            ])) origin
    ]
  let _ ← ok (replay header configured)
  let retired :=
    configured
    ++ #[
      act (.local "alpha" (.append [.signature])),
      act (.local "alpha" (.sendEntries 1 3)),
      act (.receive "alpha" "beta" append),
      act (.receive "beta" "alpha" response),
      act (.local "alpha" (.append [.transaction 3 { retirementConfirmations := {1} }]))
    ]
  let retirementEntry (nodes : List String) :=
    Instruction.observe
      (observeEntry header "alpha" 4
        (Json.mkObj
          [
            ("retiredCommitted", toJson nodes),
            ("configurations", toJson ([] : List (List String)))
          ]))
      origin
  let _ ← ok (replay header (retired.push (retirementEntry ["beta"])))
  rejects (replay header (retired.push (retirementEntry []))) "retiredCommitted"
  for metadata in [{ configuration := some {99} }, { retirementConfirmations := {99} }] do
    rejects
      (replay header #[act (.local "alpha" (.append [.transaction 6 metadata]))])
      "undeclared model node 99"
  return 34

private def receiveFifoTests : IO Unit := do
  let setup :=
    #[
      act (.local "alpha" (.append [.transaction 4 {}, .signature])),
      act (.local "alpha" (.sendEntries 1 3)),
      act (.local "alpha" (.sendEntries 1 3))
    ]
  let initial : ReplayState := { state := header.initial }
  let queued ←
    setup.foldlM (fun state next => ok (runInstruction header state next)) initial
  let packets := queued.pending 0 1
  check (packets.length == 2) "expected data followed by heartbeat"
  let some first := packets.head? | throw (IO.userError "missing first packet")
  let some second := packets.getLast? | throw (IO.userError "missing second packet")
  let firstFields := messageJson first.payload
  let secondFields := messageJson second.payload
  let receive packet := act (.receive "alpha" "beta" packet)
  let observed packet :=
    Instruction.observe (observeMessage header "alpha" "beta" packet .head) origin
  let _ ←
    ok
      (replay header
        (setup
          ++ #[
            observed firstFields,
            receive firstFields,
            sent "beta" "alpha" [("success", toJson "OK")],
            observed secondFields,
            receive secondFields
          ]))
  let observedOnly ← ok (runInstruction header queued (observed firstFields))
  check (observedOnly.pending 0 1 == packets)
    "head observation changed packet occurrences"
  rejects (runInstruction header queued (observed secondFields)) "prev_idx"
  rejects (runInstruction header queued (receive secondFields)) "prev_idx"
  let afterFirst ← ok (runInstruction header queued (receive firstFields))
  check (afterFirst.pending 0 1 == [second])
    "FIFO receive did not retain the second packet"
  let afterSecond ← ok (runInstruction header afterFirst (receive secondFields))
  check ((afterSecond.pending 0 1).isEmpty) "receive did not consume one copy"
  rejects (runInstruction header afterSecond (receive secondFields)) "no pending packet"
  rejects (runInstruction header queued (receive (Json.mkObj []))) "at least one field"
  rejects (runInstruction header queued (receive (Json.mkObj [("unknown", .null)])))
    "unsupported observation field"
  let unavailable := secondFields.setObjVal! "prev_idx" (toJson (99 : Nat))
  rejects (runInstruction header queued (observed unavailable)) "prev_idx"
  rejects (runInstruction header queued (receive unavailable)) "prev_idx"
  let dropped ← ok (runInstruction header queued (act (.drop "alpha" "beta")))
  let delivered ← ok (runInstruction header dropped (receive secondFields))
  rejects (runInstruction header delivered (receive firstFields)) "no pending packet"
  let some differing :=
    match first.payload with
    | .appendEntriesRequest request =>
        some
          {
            first with
              payload :=
                .appendEntriesRequest
                  {
                    request with
                      entries :=
                        request.entries.map
                          fun entry =>
                            match entry.content with
                            | .transaction _ metadata =>
                                { entry with content := .transaction 5 metadata }
                            | .signature => entry
                  }
          }
    | _ => none
  | throw (IO.userError "expected AppendEntries payload")
  check (first != differing && messageJson differing.payload == firstFields)
    "FIFO payload test requires equal projected headers, different contents"
  for (head, tail, transaction)
      in [(first, differing, "tx"), (differing, first, "other")] do
    let indistinguishable :=
      { queued with state := { queued.state with network := [head, tail] } }
    let _ ← ok (runInstruction header indistinguishable (observed firstFields))
    let delivered ← ok (runInstruction header indistinguishable (receive firstFields))
    check (delivered.pending 0 1 == [tail]) "FIFO selected a later matching payload"
    let _ ←
      ok
        (observeEntry header "beta" 2
          (Json.mkObj [("transaction", toJson transaction)]) delivered)
  let equalCopies :=
    { queued with state := { queued.state with network := [first, first] } }
  let one ← ok (runInstruction header equalCopies (receive firstFields))
  check (one.pending 0 1 == [first]) "equal envelopes lost multiplicity"
  let exhausted ← ok (runInstruction header one (receive firstFields))
  rejects (runInstruction header exhausted (receive firstFields)) "no pending packet"

private def identityTests : IO Unit := do
  let lexical : Header :=
    { declared := ["1", "10", "2"], bootstrap := {2}, requests := ["", "request"] }
  check ((← ok (lexical.nodeId "10")) == 1 && (← ok (lexical.nodeId "2")) == 2)
    "node names must map by lexical rank, not numeric parsing"
  check (lexical.initial.nodes.map Prod.fst == [0, 1, 2])
    "initialization changed the declared population"
  let _ ←
    ok
      (replay lexical
        #[
          observe "2" [("role", toJson "leader"), ("logLength", toJson (1 : Nat))]
            lexical,
          observe "1" [("role", toJson "none"), ("logLength", toJson (0 : Nat))] lexical,
          .observe
            (observeEntry lexical "2" 1
              (Json.mkObj
                [("transaction", toJson ""), ("configurations", toJson [["2"]])]))
            origin
        ])
  for (invalid, diagnostic)
      in [
        ({ lexical with bootstrap := ∅ }, "membership must be nonempty"),
        ({ lexical with bootstrap := {3} }, "undeclared model node"),
        ({ lexical with declared := ["1", "2", "10"] }, "sorted lexically"),
        ({ lexical with requests := ["not-genesis"] }, "reserve zero"),
        ({ lexical with requests := ["", "same", "same"] }, "must be distinct"),
        ({ lexical with requests := ["", ""] }, "reserve zero")
      ] do
    rejects (replay invalid #[observe "2" [("role", toJson "leader")] lexical]) diagnostic
  for request in [0, 2] do
    rejects (replay lexical #[act (.local "2" (.append [.transaction request {}]))])
      "undeclared or reserved model request"
  rejects
    (replay lexical #[observe "2" [("preVoteEnabled", .bool false)] lexical])
    "unsupported observation field"
  let _ ←
    ok
      (replay lexical
        #[
          act (.local "2" (.append [.transaction 1 {}])),
          .observe
            (observeEntry lexical "2" 2 (Json.mkObj [("transaction", toJson "request")]))
            origin
        ])

/-- Current Fluentd records retain their envelope, order and native field layout. -/
private def transportTests : IO Unit := do
  let records ← fixture "startup.ndjson"
  let baseline ← ok (replayRecords records)
  let (events, _) ← ok (associate records)
  for event in events do
    check (event.message == event.record.value.getObjValD "msg")
      "event projection changed the native message"
    let _ ← ok (field event.command.value "msg" >>= (string · "cmd"))
    check (event.command.line < event.record.line)
      "event was not associated with its preceding command"
    check (optional event.command.value "tag" == some (toJson "ccf.raft_trace"))
      "command provenance lost the Fluentd envelope"
  let addressed ←
    records.mapM
      fun record => do
        let encoded :=
          record.value.compress.replace "\"address\":\":\""
            "\"address\":\"127.0.0.1:8000\""
        return { record with value := ← ok (Json.parse encoded) }
  check (addressed.any (fun record => record.value.compress.contains "127.0.0.1:8000"))
    "address regression did not replace any configuration metadata"
  check ((← ok (replayRecords addressed)) == baseline) "transport address changed replay"
  for sequence in [0, 2] do
    rejects (reduce (mutate records 1 ["h_ts"] (toJson sequence))) "trace sequence"
  rejects (reduce (mutate records 0 ["h_ts"] (toJson (1 : Nat)))) "trace sequence"
  rejects (reduce (records.extract 0 1 ++ records.extract 2 records.size))
    "trace sequence"
  rejects (reduce (records.set! 1 records[2]! |>.set! 2 records[1]!)) "trace sequence"
  rejects (reduce (mutate records 1 ["process_id"] (toJson "another"))) "mixed trace"
  for (key, value) in [("process_id", .bool true), ("h_ts", .bool true)] do
    rejects (reduce (mutate records 1 [key] value)) records[1]!.location
  for key in ["process_id", "h_ts", "msg"] do
    let fields ← ok (object records[1]!.value)
    let missing := mutate records 1 [] (Json.mkObj (fields.filter (·.1 != key)))
    rejects (reduce missing) key
    rejects (reduce missing) records[1]!.location
  for index in [0, 1] do
    rejects (reduce (mutate records index ["tag"] (toJson "raft_trace")))
      "expected ccf.raft_trace"
  for raw
      in [
        "{\"tag\":\"raft_trace\",\"cmd\":\"state_all\"}",
        "{\"tag\":\"raft_trace\",\"h_ts\":0,\"level\":\"trace\",\"msg\":{}}"
      ] do
    rejects (reduce (← ok (parseLog "legacy.stdout" raw))) "expected ccf.raft_trace"
    rejects (reduce (← ok (parseLog "legacy.ndjson" raw))) "expected ccf.raft_trace"
  check
    ((← ok (replayRecords (mutate records 0 ["unexpected"] .null))) == baseline)
    "unused envelope data changed replay"
  let config ← find records "add_configuration"
  check
    ((← ok (replayRecords (mutate records config ["msg", "rid"] (toJson (99 : Nat)))))
      == baseline)
    "unused native rid changed replay"
  for (name, keys, required)
      in [
        ("commit", ["idx"], "idx"),
        ("add_configuration", ["idx", "rid", "nodes"], "nodes")
      ] do
    let index ← find records name
    let fields ← ok (object (records[index]!.value.getObjValD "msg"))
    let native := Json.mkObj (fields.filter (fun (key, _) => keys.contains key))
    let args :=
      if name == "commit" then native else Json.mkObj [("configuration", native)]
    let legacy :=
      Json.mkObj (fields.filter (fun (key, _) => !keys.contains key) ++ [("args", args)])
    rejects (reduce (mutate records index ["msg"] legacy)) required
    check
      ((← ok (replayRecords (mutate records index ["msg", "args"] (.bool false))))
        == baseline)
      "unused legacy-shaped metadata replaced native fields"
    for key in keys.filter (· != "rid") do
      rejects
        (reduce (mutate records index ["msg"] (Json.mkObj (fields.filter (·.1 != key)))))
        key
  let message ← ok (object (records[0]!.value.getObjValD "msg"))
  let legacyCommand := mutate records 0 ["cmd"] (toJson "start_node,0")
  let legacyCommand :=
    mutate legacyCommand 0 ["msg"] (Json.mkObj (message.filter (·.1 != "cmd")))
  rejects (reduce legacyCommand) "event before command"
  let located := mutate records 1 ["file"] (toJson "src/consensus/aft/raft.h")
  let located := mutate located 1 ["number"] (toJson "123")
  let (events, _) ← ok (associate located)
  check ((events[0]!.origin "test").label == s!"{records[1]!.location} [test]")
    "origin lost its trace location or reduction rule"
  check ((← ok (replayRecords (mutate located 1 ["number"] (.bool false)))) == baseline)
    "unused implementation metadata changed replay"
  let votes ← fixture "vote_responses.ndjson"
  let timeout ← find votes "become_pre_vote_candidate"
  let disabled := mutate votes timeout ["msg", "function"] (toJson "become_candidate")
  rejects (reduce disabled) "ungrouped event become_candidate"

def main : IO UInt32 := do
  let _ ← parserTests
  let _ ← reductionTests
  parsecInfrastructureTests
  parsecReductionTests
  receiveGrammarTests
  sendObservationTests
  retirementNodeSetTests
  speculativeGrammarTests
  emissionTests
  let _ ← fixtureMutations
  let observations ← observationTests
  let _ ← directTests
  observationClosureTests
  receiveFifoTests
  identityTests
  transportTests
  IO.println s!"Raw event observation cases passed: {observations}."
  IO.println "Lean replay regressions passed."
  return 0
