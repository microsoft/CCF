module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Reduction

import all CCFRaft.Replay.Interpreter
import CCF.Parsec

public section

open Lean CCFRaft.Replay CCFRaft.Model.Node

private def reduceRecords (records : Array Record) : Except String Reduced := do
  let (events, declared) ← prepareEvents records
  CCFRaft.Replay.reduce events declared

private def replayRecords (records : Array Record) : Except String Result := do
  let reduced ← reduceRecords records
  replay reduced.header reduced.instructions

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

private def capture (directory : System.FilePath) (name : String)
    : IO (Array Record) := do
  ok (← readLog (directory / name))

private def observationStates (reduced : Reduced)
    : IO (Array (ReplayState × (ReplayState → Except String Unit) × Origin)) := do
  let mut current : ReplayState := { state := reduced.header.initial }
  let mut observations := #[]
  for instruction in reduced.instructions do
    if let .observe observe origin := instruction then
      observations := observations.push (current, observe, origin)
    current ← ok (runInstruction reduced.header current instruction)
  return observations

private def change (value : Json) (path : List String) (replacement : Json) : Json :=
  match path with
  | [] => replacement
  | key :: rest => value.setObjVal! key (change (value.getObjValD key) rest replacement)

private def mutate (records : Array Record) (index : Nat) (path : List String)
    (replacement : Json)
    : Array Record :=
  records.modify index
    fun record => { record with value := change record.value path replacement }

private def function (record : Record) : String :=
  ((record.value.getObjValD "msg").getObjValD "function").getStr?.toOption.getD ""

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
    rejects (reduceRecords records) "json.ndjson:1"
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
    check
      ((← ok (nat (state.setObjVal! "current_view" (toJson term)) "current_view"))
        == term)
      "state term coordinates were changed"
    count := count + 1
  rejects (nat (Json.mkObj []) "term") "term"
  rejects (string (Json.mkObj [("success", .arr #[])]) "success") "String"
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
  for markers in [[3, 2], [2, 2], [3, 5]] do
    let raw :=
      state.setObjVal! "committable_indices" (toJson markers)
      |>.setObjVal! "unknown" .null
    let message :=
      Json.mkObj
        [
          ("function", toJson "replicate"),
          ("state", raw),
          ("configurations", toJson [config, config])
        ]
    let row : Record :=
      {
        file := "native.ndjson",
        line := 2,
        value := (envelope message).setObjVal! "h_ts" (toJson (1 : Nat))
      }
    let (events, _) ← ok (prepareEvents #[command "start_node,0", row])
    check (events[0]!.state == raw && events[0]!.message == message)
      "record association changed native JSON evidence"
  for (key, value, diagnostic)
      in [
        ("leadership_state", toJson "invented", "invalid role"),
        ("membership_state", toJson "Retired", "retirement phase"),
        ("retirement_phase", toJson "Completed", "retirement phase")
      ] do
    let message :=
      Json.mkObj [("function", toJson "replicate"), ("state", state.setObjVal! key value)]
    let row : Record :=
      {
        file := "native.ndjson",
        line := 2,
        value := (envelope message).setObjVal! "h_ts" (toJson (1 : Nat))
      }
    rejects (prepareEvents #[command "start_node,0", row]) diagnostic
  let records ←
    ok
      (parseLog "capture.stdout"
        ((envelope (Json.mkObj [("cmd", toJson "state_all")])).compress ++ "\r\n"))
  check (records[0]!.line == 1) "lost physical JSON line"
  rejects (parseLog "capture.stdout" "<RaftDriver> diagram\n") "capture.stdout:1"
  rejects (parseLog "capture.stdout" "not a logger record\n") "capture.stdout:1"
  return count + 15

private def boundaryObservationTests (directory : System.FilePath) : IO Unit := do
  let rules := ["send-pre", "send-post-state", "nomination-post"]
  let mut seen := []
  for name in ["pre_vote.stdout", "nominate_successor.stdout"] do
    let reduced ← ok (reduceRecords (← capture directory name))
    for (current, observe, origin) in ← observationStates reduced do
      unless rules.contains origin.rule do
        continue
      let changed (change : NodeState → NodeState) : ReplayState :=
        {
          current with
            state :=
              {
                current.state with
                  nodes :=
                    current.state.nodes.map fun (node, state) => (node, change state)
              }
        }
      rejects
        (observe
          (changed fun state => { state with currentTerm := state.currentTerm + 1 }))
        "current_view"
      rejects
        (observe
          (changed fun state => { state with commitIndex := state.commitIndex + 1 }))
        "commit_idx"
      if origin.rule != "nomination-post" then
        rejects
          (observe
            (changed
              fun state =>
                { state with matchIndex := fun peer => state.matchIndex peer + 1 }))
          "match_idx"
        let sent :=
          changed
            fun state => { state with sentIndex := fun peer => state.sentIndex peer + 1 }
        if origin.rule == "send-pre" then
          rejects (observe sent) "sent_idx"
        else
          let _ ← ok (observe sent)
      seen := origin.rule :: seen
  check (rules.all seen.contains) "missing combined or post-action state observation"

private def receivePhaseObservationTests (directory : System.FilePath) : IO Unit := do
  for (name, kind, sameLog, sameCommit, path, value)
      in [
        (
          "reconfig_0_1.stdout",
          "become_follower",
          true,
          true,
          ["state", "committable_indices"],
          toJson [999]
        ),
        (
          "pre_vote.stdout",
          "become_follower",
          true,
          false,
          ["state", "last_idx"],
          toJson (999 : Nat)
        ),
        (
          "retire_one.stdout",
          "execute_append_entries_sync",
          false,
          true,
          ["state", "commit_idx"],
          toJson (0 : Nat)
        ),
        (
          "retire_one.stdout",
          "execute_append_entries_sync",
          false,
          true,
          ["state", "retired_committed_idx"],
          toJson (999 : Nat)
        ),
        (
          "retire_one.stdout",
          "commit",
          true,
          false,
          ["state", "committable_indices"],
          toJson [11, 11]
        ),
        ("retire_one.stdout", "commit", true, false, ["idx"], toJson (4 : Nat))
      ] do
    let key := path.getLast!
    let records ← capture directory name
    let _ ← ok (replayRecords records)
    let mut receive : Option Nat := none
    let mut selected : Option (Nat × Nat) := none
    for record in records, index in [:records.size] do
      let fn := function record
      if fn == "recv_append_entries" then
        receive := some index
      else if [
                "become_follower",
                "execute_append_entries_sync",
                "add_configuration",
                "commit"
              ].contains
                fn then
        if let some head := receive then
          let message := records[head]!.value.getObjValD "msg"
          let packet ← ok (field message "packet")
          let last ← ok (nat packet "idx")
          let previous ← ok (nat packet "prev_idx")
          let leaderCommit ← ok (nat packet "leader_commit_idx")
          let committed ← ok (nat (← ok (field message "state")) "commit_idx")
          if fn == kind
              && (last == previous) == sameLog
              && (min last leaderCommit <= committed) == sameCommit then
            selected := some (head, index)
            break
      else
        receive := none
    let some (head, index) := selected
    | throw (IO.userError s!"missing receive phase for {name}: {key}")
    let message := records[index]!.value.getObjValD "msg"
    check (path.foldl Json.getObjValD message != value)
      "receive mutation changed no value"
    let bad := mutate records index ("msg" :: path) value
    let _ ← ok (reduceRecords bad)
    let result := replayRecords bad
    rejects result
      (if path == ["idx"] then "receive-commit-target" else "receive-internal")
    rejects result key
    let packet := (records[head]!.value.getObjValD "msg").getObjValD "packet"
    let fields ← ok (object packet)
    let omitted :=
      mutate records head ["msg", "packet"] (Json.mkObj (fields.filter (·.1 != "idx")))
    let _ ← ok (replayRecords omitted)
    let malformed := mutate records head ["msg", "packet", "idx"] (toJson "bad")
    let _ ← ok (reduceRecords malformed)
    rejects (replayRecords malformed) "atomic-receive"

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

private def jsonPathTests : IO Unit := do
  let equal (expected : Json) (value : Json) : Except String Unit :=
    require (value == expected) "path mismatch"
  let resolve : JsonPath → Option (Json → Except String Unit)
    | [.field "state", .field "current_view"] => some (equal (toJson (2 : Nat)))
    | [.field "packets", .index 0, .field "term"] => some (equal (toJson (3 : Nat)))
    | [.field "packets", .index 1, .field "term"] => some (equal (toJson (4 : Nat)))
    | [.field "opaque"] =>
        some
          fun value => do
            let number ← value.getObjValAs? Nat "value"
            require (number * 2 == 6) "interpreted value mismatch"
    | [.field "nullable"] => some (equal .null)
    | [.field "empty_array"] => some (equal (.arr #[]))
    | [.field "empty_object"] => some (equal (Json.mkObj []))
    | _ => none
  let expected :=
    Json.mkObj
      [
        ("state", Json.mkObj [("current_view", toJson (2 : Nat))]),
        (
          "packets",
          toJson
            [
              Json.mkObj [("term", toJson (3 : Nat))],
              Json.mkObj [("term", toJson (4 : Nat))]
            ]
        ),
        (
          "opaque",
          Json.mkObj [("value", toJson (3 : Nat)), ("ignored_metadata", Json.mkObj [])]
        ),
        ("nullable", .null),
        ("empty_array", .arr #[]),
        ("empty_object", Json.mkObj [])
      ]
  let _ ← ok (checkJsonPaths resolve expected)
  let _ ←
    ok
      (checkJsonPaths resolve
        (Json.mkObj [("state", Json.mkObj [("current_view", toJson (2 : Nat))])]))
  rejects
    (checkJsonPaths resolve
      (expected.setObjVal! "state" (Json.mkObj [("current_view", toJson (5 : Nat))])))
    "$[\"state\"][\"current_view\"]: path mismatch"
  rejects
    (checkJsonPaths resolve
      (expected.setObjVal! "packets"
        (toJson
          [
            Json.mkObj [("term", toJson (3 : Nat))],
            Json.mkObj [("term", toJson (5 : Nat))]
          ])))
    "$[\"packets\"][1][\"term\"]: path mismatch"
  rejects
    (checkJsonPaths resolve
      (expected.setObjVal! "opaque" (Json.mkObj [("value", toJson (4 : Nat))])))
    "$[\"opaque\"]: interpreted value mismatch"
  for unknown in [.null, .arr #[], Json.mkObj []] do
    rejects (checkJsonPaths resolve (expected.setObjVal! "unknown" unknown))
      "unsupported observation field '$[\"unknown\"]'"
    rejects
      (checkJsonPaths resolve
        (expected.setObjVal! "state" (Json.mkObj [("future", unknown)])))
      "unsupported observation field '$[\"state\"][\"future\"]'"
  for invalid in [toJson (2 : Nat), Json.mkObj []] do
    rejects (checkJsonPaths resolve (expected.setObjVal! "state" invalid))
      "unsupported observation field '$[\"state\"]'"
  rejects
    (checkJsonPaths resolve
      (Json.mkObj
        [("packets", Json.mkObj [("0", Json.mkObj [("term", toJson (3 : Nat))])])]))
    "unsupported observation field '$[\"packets\"][\"0\"][\"term\"]'"
  rejects (checkJsonPaths resolve (Json.mkObj [("state.current_view", toJson (2 : Nat))]))
    "unsupported observation field '$[\"state.current_view\"]'"
  rejects (checkJsonPaths resolve (Json.mkObj [])) "at least one field"
  for invalid in [.null, .arr #[], toJson (2 : Nat)] do
    rejects (checkJsonPaths resolve invalid) "object"
  check (JsonPath.label [.field "a\"b", .index 0] == "$[\"a\\\"b\"][0]")
    "path diagnostics did not escape object keys"

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
      ("leadership_state", toJson "Leader"),
      ("current_view", toJson (2 : Nat)),
      ("last_idx", toJson (3 : Nat)),
      ("commit_idx", toJson (3 : Nat)),
      ("committable_indices", toJson ([] : List Nat)),
      (
        "configurations",
        toJson
          [Json.mkObj
            [
              ("idx", toJson (1 : Nat)),
              ("nodes", Json.mkObj [("alpha", .null), ("beta", .null)])
            ]]
      ),
      ("membership_state", toJson "Active"),
      ("retirement_phase", Json.null),
      ("retirement_idx", Json.null),
      ("retirement_committable_idx", Json.null),
      ("retired_committed_idx", Json.null)
    ]
  checkObservedFields (observeState identities "alpha" (some "beta")) current
    (fields ++ [("sent_idx", toJson (3 : Nat)), ("match_idx", toJson (3 : Nat))])
  for key in ["sent_idx", "match_idx"] do
    rejects
      (observeState identities "alpha" none
        (Json.mkObj [(key, toJson (3 : Nat))]) current)
      s!"unsupported observation field '$[\"{key}\"]'"
  let before :=
    fields.map
      fun (key, value) =>
        (
          key,
          if key == "commit_idx" then
            toJson (1 : Nat)
          else if key == "committable_indices" then
            toJson ([3] : List Nat)
          else
            value
        )
  checkObservedFields (observeBeforeCommit identities "alpha" 1) current before
  rejects (observeBeforeCommit identities "alpha" 3 (Json.mkObj before) current)
    "pre-commit frontier must precede final commitIndex"
  let uncommitted ←
    ok
      (runInstruction header current
        (act (.local "alpha" (.append [.signature, .signature]))))
  let cache (indices : List Nat) := Json.mkObj [("committable_indices", toJson indices)]
  let _ ← ok (observeState identities "alpha" none (cache [4, 5]) uncommitted)
  for indices in [[5, 4], [4], [4, 4, 5], [3, 4, 5]] do
    rejects (observeState identities "alpha" none (cache indices) uncommitted)
      "committable_indices"
  let uncommitted ←
    ok (runInstruction header uncommitted (act (.local "alpha" (.append [.signature]))))
  let committed ←
    #[
      act (.local "alpha" (.sendEntries 1 6)),
      act (.receive "alpha" "beta" (Json.mkObj [("msg", toJson "raft_append_entries")])),
      act
        (.receive "beta" "alpha"
          (Json.mkObj [("msg", toJson "raft_append_entries_response")]))
    ].foldlM
      (fun state step => ok (runInstruction header state step)) uncommitted
  for (observe, state)
      in [
        (observeState identities "alpha" none, uncommitted),
        (observeBeforeCommit identities "alpha" 3, committed)
      ] do
    let _ ← ok (observe (cache [4, 6]) state)
    for indices in [[], [4], [6], [6, 4], [4, 5], [5, 6], [4, 4], [4, 4, 6], [4, 5, 6]] do
      rejects (observe (cache indices) state) "committable_indices"
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
          (Json.mkObj [("commit_idx", toJson (3 : Nat)), ("match_idx", toJson (3 : Nat))])
          state
    let unchanged ← ok (runInstruction header queued (.observe observer origin))
    let _ ← ok (observer unchanged)
    check
      (unchanged.state.network == queued.state.network
        && unchanged.dropped == queued.dropped)
      "observation changed packet accounting"
  let failure := Instruction.observe (fun _ => .error "closure sentinel") origin
  rejects (replay header #[failure]) s!"instruction 1 at {origin.label}: closure sentinel"

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
          observe "2"
            [("leadership_state", toJson "Leader"), ("last_idx", toJson (1 : Nat))]
            lexical,
          observe "1"
            [("leadership_state", toJson "None"), ("last_idx", toJson (0 : Nat))] lexical,
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
    rejects
      (replay invalid #[observe "2" [("leadership_state", toJson "Leader")] lexical])
      diagnostic
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

def main (args : List String) : IO UInt32 := do
  let _ ← parserTests
  parsecInfrastructureTests
  jsonPathTests
  observationClosureTests
  receiveFifoTests
  identityTests
  match args with
  | [] => pure ()
  | [directory] =>
      boundaryObservationTests directory
      receivePhaseObservationTests directory
  | _ => throw (IO.userError "usage: replay-checks [CAPTURE_DIRECTORY]")
  IO.println "Lean replay rejection and observation checks passed."
  return 0
