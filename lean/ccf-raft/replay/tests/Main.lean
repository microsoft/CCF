module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Suite

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

private def fixture (name : String) : IO (Array Record) := do
  ok (← readLog (System.FilePath.mk "replay/tests/fixtures" / name))

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
  records.extract 0 index ++ records.extract (index + 1) records.size

private def function (record : Record) : String :=
  ((record.value.getObjValD "msg").getObjValD "function").getStr?.toOption.getD ""

private def find (records : Array Record) (name : String) : IO Nat := do
  let some index := records.findIdx? (fun record => function record == name)
  | throw (IO.userError s!"fixture has no {name}")
  return index

private def command (cmd : String) : Record :=
  {
    file := "synthetic.ndjson",
    line := 1,
    value := Json.mkObj [("tag", toJson "raft_trace"), ("cmd", toJson cmd)]
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
      ("pre_vote_enabled", toJson false),
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

private def record (name : String) (fields : List (String × Json) := []) : Record :=
  {
    file := "synthetic.ndjson",
    line := 2,
    value :=
      Json.mkObj
        [
          ("tag", toJson "raft_trace"),
          ("msg", Json.mkObj ([("function", toJson name), ("state", state)] ++ fields))
        ]
  }

private def parserTests : IO Nat := do
  let mut count := 0
  for raw
      in [
        "",
        "\n",
        "[]",
        "null",
        "{\"x\":1,\"x\":2}",
        "{\"x\":{\"y\":0,\"y\":1}}",
        "{\"x\":1,\"\\u0078\":2}",
        "{\"x\":NaN}",
        "{\"x\":Infinity}",
        "{\"x\":",
        "{\"x\":true} garbage"
      ] do
    rejects (parseLog "strict.ndjson" raw false) "strict.ndjson"
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
    rejects (validatePacket (appendPacket.setObjVal! "term" value)) "expected natural"
    count := count + 2
  for term in [0, 1, 2, 4, 999] do
    let packet := appendPacket.setObjVal! "term" (toJson term)
    ok (validatePacket packet)
    let facts ←
      ok (stateFacts (state.setObjVal! "current_view" (toJson term)) (Json.mkObj []))
    check (optional facts "currentTerm" == some (toJson term))
      "term coordinates were changed"
    count := count + 1
  rejects (validatePacket (appendPacket.setObjVal! "unknown" .null)) "unsupported field"
  rejects (validatePacket (appendPacket.setObjVal! "idx" (toJson (1 : Nat)))) "reversed"
  rejects
    (validatePacket
      (Json.mkObj
        [
          ("msg", toJson "raft_append_entries_response"),
          ("term", toJson (2 : Nat)),
          ("last_log_idx", toJson (2 : Nat)),
          ("success", .arr #[])
        ]))
    "String"
  rejects (stateFacts (state.setObjVal! "unknown" .null) (Json.mkObj []))
    "unsupported field"
  rejects
    (stateFacts (state.setObjVal! "leadership_state" (toJson "invented")) (Json.mkObj []))
    "invalid role"
  rejects
    (stateFacts (state.setObjVal! "membership_state" (toJson "Retired")) (Json.mkObj []))
    "retirement phase"
  for markers in [[3, 2], [2, 2]] do
    rejects
      (stateFacts (state.setObjVal! "committable_indices" (toJson markers))
        (Json.mkObj []))
      "unordered/duplicate"
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
  rejects (configuration (config.setObjVal! "rid" (.bool true))) "natural"
  rejects (configuration (config.setObjVal! "rid" (toJson (2 : Nat)))) "rid differs"
  rejects (configuration (config.setObjVal! "nodes" (Json.mkObj []))) "empty"
  let configs := Json.mkObj [("configurations", toJson [config, config])]
  let _ ← ok (stateFacts state configs)
  let _ ←
    ok
      (parseLog "capture.stdout"
        "<RaftDriver> diagram\r\n{\"tag\":\"raft_trace\",\"cmd\":\"state_all\"}\r\n" true)
  rejects (parseLog "capture.stdout" "not a logger record\n" true) "capture.stdout:1"
  rejects (parseLog "capture.stdout" "{\"tag\":\"other\"}\n" true) "unrecognized"
  return count + 15

private def reductionTests : IO Nat := do
  let bootstrap ← fixture "bootstrap.ndjson"
  let reduced ← ok (reduce bootstrap)
  let result ← ok (replay reduced.header reduced.instructions)
  check (result == { instructions := 5, actions := 1, observations := 4 })
    "bootstrap instruction contract"
  let withoutTimestamps :=
    bootstrap.map
      fun row =>
        {
          row with
            value :=
              Json.mkObj ((object row.value).toOption.getD [] |>.filter (·.1 != "h_ts"))
        }
  check ((← ok (replayRecords withoutTimestamps)) == result)
    "timestamps affected capture order"
  let modes ←
    ok
      (reduce
        (bootstrap ++ #[command "pre_vote_enabled,true", command "create_new_node,1"]))
  check
    (modes.header.declared == ["0", "1"]
      && modes.header.bootstrap.preVoteStatus "1" == .enabled)
    "future node pre-vote declaration"
  let assertions ← ok (reduce (bootstrap.push (command "assert_commit_idx,0,2")))
  check (assertions.instructions.size == reduced.instructions.size)
    "assertion invented an action"
  let mut count := 4
  for cmd
      in ["shuffle_one,0", "shuffle_all", "new_command,0", "pre_vote_enabled,maybe"] do
    rejects (reduce (bootstrap.push (command cmd)))
      (if cmd.startsWith "pre_vote" then "invalid" else "unsupported command")
    count := count + 1
  let write :=
    record "replicate"
      [
        ("seqno", toJson (3 : Nat)),
        ("view", toJson (2 : Nat)),
        ("globally_committable", toJson false)
      ]
  for (path, value)
      in [(["msg", "seqno"], toJson (4 : Nat)), (["msg", "view"], toJson (3 : Nat))] do
    rejects
      (reduce
        (bootstrap
          ++ #[
            command "replicate,2,a",
            { write with value := change write.value path value }
          ]))
      "write coordinates"
    count := count + 1
  for callback
      in [
        "execute_append_entries_sync",
        "send_append_entries_response",
        "send_request_vote_response"
      ] do
    let original ←
      fixture
        (if callback == "send_request_vote_response" then
            "vote_responses.ndjson"
          else
            "retire_follower.stdout")
    let source := original[← find original callback]!
    rejects (reduce (bootstrap ++ #[command "dispatch_all", source])) "ungrouped callback"
    count := count + 1
  for (path, value, diagnostic)
      in [
        (["msg", "args", "idx"], toJson (3 : Nat), "bootstrap commit target"),
        (["msg", "state", "last_idx"], toJson (3 : Nat), "bootstrap state"),
        (["msg", "state", "committable_indices"], toJson [1], "bootstrap committable")
      ] do
    rejects (reduce (mutate bootstrap (bootstrap.size - 1) path value)) diagnostic
    count := count + 1
  let unknown := mutate bootstrap 2 ["msg", "function"] (toJson "new_function")
  rejects (reduce unknown) "unsupported function"
  rejects (reduce (mutate bootstrap 0 ["tag"] (toJson "other"))) "expected raft_trace"
  rejects (reduce (mutate bootstrap 2 ["tag"] (.bool true))) "String"
  rejects (reduce (mutate bootstrap 2 ["msg", "unknown"] .null)) "unsupported field"
  rejects (reduce (mutate bootstrap 2 ["unknown"] .null)) "unsupported field"
  rejects
    (reduce (mutate bootstrap 4 ["msg", "args", "configuration", "rid"] (.bool true)))
    "natural"
  rejects (reduce (bootstrap.extract 2 bootstrap.size)) "event before command"
  rejects (reduce #[command "state_all"]) "no Raft events"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let configuredReduction ← ok (reduce configured)
  let _ ← ok (replay configuredReduction.header configuredReduction.instructions)
  let heartbeat ← find config "send_append_entries"
  rejects (reduce (bootstrap ++ erase config heartbeat)) "missing new-peer"
  rejects
    (reduce (bootstrap ++ mutate config heartbeat ["msg", "to_node_id"] (toJson "0")))
    "destinations differ"
  rejects
    (reduce (bootstrap ++ mutate config heartbeat ["msg", "sent_idx"] (toJson (2 : Nat))))
    "callback heartbeat"
  let configIndex ← find config "add_configuration"
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
  rejects (reduce (bootstrap ++ missing)) "missing field 'configurations'"
  let missingPrefix := configured ++ (← fixture "missing_prefix_response.ndjson")
  let prefixReduction ← ok (reduce missingPrefix)
  let _ ← ok (replay prefixReduction.header prefixReduction.instructions)
  check
    (prefixReduction.instructions.any
      fun instruction =>
        match instruction with
        | .message _ _ packet _ _ =>
            optional packet "success" == some (toJson "FAIL")
            && optional packet "last_log_idx" == some (toJson (0 : Nat))
        | _ => false)
    "missing-prefix NACK lost"
  let drop ← ok (reduce (bootstrap ++ (← fixture "drop_resend.ndjson")))
  let actions :=
    drop.instructions.toList.filterMap
      fun instruction =>
        match instruction with
        | .action step origins =>
            if origins.any (·.rule == "bootstrap") then none else some step.name
        | _ => none
  check (actions == ["sendEntries", "drop", "sendEntries", "receive"])
    "drop/resend reduction changed"
  return count + 14

/-- Raw mutations exercise the reducer's projections, not merely the final checker. -/
private def fixtureMutations : IO Nat := do
  let mut count := 0
  for name
      in [
        "bootstrap.ndjson",
        "startup.ndjson",
        "vote_responses.ndjson",
        "terminal_retirement.stdout",
        "retire_follower.stdout"
      ] do
    let records ← fixture name
    let reduced ← ok (reduce records)
    let result ← ok (replay reduced.header reduced.instructions)
    check
      (result.instructions == reduced.instructions.size
        && result.actions + result.observations == result.instructions)
      s!"{name}: unconsumed instructions"
    count := count + 1
    -- Every projected field must still be compared, including future additions.
    for instruction in reduced.instructions, position in [:reduced.instructions.size] do
      let fields :=
        match instruction with
        | .state _ _ fields _ | .entry _ _ fields _ | .message _ _ fields _ _ =>
            some fields
        | _ => none
      if let some fields := fields then
        for (key, _) in ← ok (object fields) do
          let replacement := fields.setObjVal! key (toJson "__mismatch__")
          let changed :=
            match instruction with
            | .state node peer _ origin => .state node peer replacement origin
            | .entry node index _ origin => .entry node index replacement origin
            | .message source target _ latest origin =>
                .message source target replacement latest origin
            | other => other
          rejects (replay reduced.header (reduced.instructions.set! position changed)) key
          count := count + 1
    -- Fields stable at a callback are selected by callback kind, not their values.
    for (raw, projected)
        in [
          ("leadership_state", "role"),
          ("current_view", "currentTerm"),
          ("last_idx", "logLength"),
          ("commit_idx", "commitIndex"),
          ("retirement_idx", "retirementIndex"),
          ("retirement_committable_idx", "retirementCommittableIndex"),
          ("retired_committed_idx", "retiredCommittedIndex"),
          ("pre_vote_enabled", "preVoteEnabled")
        ] do
      for instruction in reduced.instructions do
        if let .state _ _ fields origin := instruction then
          if ["append-callback", "receive-follower-post", "receive-post"].contains
                origin.rule
              && (optional fields projected).isSome then
            let some index :=
              records.findIdx?
                (fun row => row.file == origin.file && row.line == origin.line)
            | throw (IO.userError "lost raw origin")
            let replacement :=
              if projected == "role" then
                toJson "Candidate"
              else if projected == "preVoteEnabled" then
                .bool (!(optional fields projected == some (.bool true)))
              else
                toJson (999 : Nat)
            let diagnostic :=
              if origin.rule == "receive-follower-post" && projected == "currentTerm" then
                "follower term differs"
              else
                projected
            rejects
              (replayRecords (mutate records index ["msg", "state", raw] replacement))
              diagnostic
            count := count + 1
            break
  let original ← fixture "vote_responses.ndjson"
  let withoutResponseSends :=
    original.filter (fun row => function row != "send_request_vote_response")
  let _ ← ok (replayRecords withoutResponseSends)
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
  let terminal ← fixture "terminal_retirement.stdout"
  let nomination ← find terminal "step_down_and_nominate_successor"
  rejects (replayRecords (mutate terminal nomination ["msg", "to_node_id"] (toJson "0")))
    "no pending packet"
  rejects
    (reduce
      (mutate terminal nomination ["msg", "state", "leadership_state"]
        (toJson "Follower")))
    "terminal-retirement nomination boundary"
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
        | .entry _ _ _ origin => origin.rule == "callback-configuration"
        | _ => false)
  | throw (IO.userError "missing callback configuration coverage")
  let origin := cache.origins.head!
  let some index := terminal.findIdx? (fun row => row.line == origin.line)
  | throw (IO.userError "missing callback configuration raw record")
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
    "callback-configuration"
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
        | .entry _ _ _ origin => origin.rule == "callback-committed-prefix"
        | _ => false)
  | throw (IO.userError "missing committed-prefix coverage")
  let some prefixIndex :=
    terminal.findIdx? (fun row => row.line == committedPrefix.origins.head!.line)
  | throw (IO.userError "lost prefix source record")
  rejects
    (replayRecords
      (mutate terminal prefixIndex ["msg", "state", "commit_idx"] (toJson (999 : Nat))))
    "callback-committed-prefix"
  return count + 6

private def origin : Origin :=
  {
    file := "direct.ndjson",
    line := 17,
    function := "test",
    command := "test",
    commandLine := 1,
    rule := "unit"
  }

private def header : Header :=
  {
    declared := ["alpha", "beta", "future"]
    bootstrap :=
      {
        configuration := {"alpha", "beta"},
        leader := "alpha",
        leader_mem := by decide
        preVoteStatus := fun node => if node == "future" then .enabled else .capable
      }
  }

private def act (step : Step) : Instruction := .action step [origin]

private def observe (node : String) (fields : List (String × Json)) : Instruction :=
  .state node none (Json.mkObj fields) origin

private def sent (source destination : String) (fields : List (String × Json))
    : Instruction :=
  .message source destination (Json.mkObj fields) true origin

private def directTests : IO Nat := do
  let start :=
    #[
      observe "future"
        [
          ("role", toJson "none"),
          ("currentTerm", toJson (0 : Nat)),
          ("preVoteEnabled", .bool true)
        ],
      act (.local "alpha" (.append [.transaction "tx-1" []])),
      act (.local "alpha" (.append [.signature])),
      act (.local "alpha" (.sendEntries "beta" 3)),
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
      act (.receive "alpha" "beta"),
      sent "beta" "alpha"
        [("msg", toJson "raft_append_entries_response"), ("success", toJson "OK")],
      observe "beta" [("role", toJson "follower"), ("logLength", toJson (3 : Nat))],
      act (.receive "beta" "alpha"),
      .state "alpha" (some "beta")
        (Json.mkObj
          [
            ("commitIndex", toJson (3 : Nat)),
            ("sentIndex", toJson (3 : Nat)),
            ("matchIndex", toJson (3 : Nat))
          ])
        origin
    ]
  check
    ((← ok (replay header complete))
      == { instructions := 10, actions := 5, observations := 5 })
    "direct instruction consumption"
  rejects (replay header #[]) "must not be empty"
  rejects (replay header #[.action (.receive "alpha" "beta") []]) "missing origin"
  for (step, diagnostic)
      in [
        (Step.receive "alpha" "beta", "disabled model action 'receive'"),
        (.drop "alpha" "beta", "no pending packet"),
        (.local "beta" (.append [.signature]), "disabled model action 'append'"),
        (.local "alpha" (.append []), "disabled model action 'append'"),
        (.local "unknown" (.timeout .election), "undeclared node"),
        (.local "alpha" (.sendEntries "beta" 99), "disabled model action 'sendEntries'")
      ] do
    rejects (replay header #[act step]) diagnostic
  rejects (replay header #[observe "alpha" []]) "at least one"
  rejects (replay header #[observe "alpha" [("unknown", toJson (0 : Nat))]])
    "unsupported observation field"
  rejects
    (replay header #[.entry "alpha" 0 (Json.mkObj [("kind", toJson "signature")]) origin])
    "positive"
  rejects
    (replay header #[.entry "alpha" 2 (Json.mkObj [("kind", toJson "signature")]) origin])
    "no log entry"
  rejects
    (replay header
      (start.push (.entry "alpha" 1 (Json.mkObj [("kind", toJson "signature")]) origin)))
    "kind"
  rejects
    (replay header
      (start.push (.entry "alpha" 2 (Json.mkObj [("committed", .bool true)]) origin)))
    "committed"
  let twice :=
    start
    ++ #[
      act (.local "alpha" (.sendEntries "beta" 3)),
      sent "alpha" "beta" [("prev_idx", toJson (3 : Nat)), ("idx", toJson (3 : Nat))]
    ]
  let head :=
    Instruction.message "alpha" "beta"
      (Json.mkObj [("prev_idx", toJson (0 : Nat)), ("idx", toJson (3 : Nat))]) false
      origin
  let _ ← ok (replay header (twice.push head))
  let wrong :=
    Instruction.message "alpha" "beta" (Json.mkObj [("prev_idx", toJson (3 : Nat))]) false
      origin
  rejects (replay header (twice.push wrong)) "prev_idx"
  let dropped :=
    twice ++ #[head, act (.drop "alpha" "beta"), wrong, act (.drop "alpha" "beta")]
  let _ ← ok (replay header dropped)
  rejects (replay header (dropped.push head)) "no pending packet"
  -- Equal copies remain distinct: dropping one cannot hide/deliver both.
  let heartbeat :=
    #[
      act (.local "alpha" (.sendEntries "beta" 0)),
      sent "alpha" "beta" [("idx", toJson (0 : Nat))]
    ]
  let duplicate :=
    heartbeat
    ++ heartbeat
    ++ #[
      act (.drop "alpha" "beta"),
      act (.receive "alpha" "beta"),
      sent "beta" "alpha" [("success", toJson "OK")]
    ]
  let _ ← ok (replay header duplicate)
  rejects (replay header (duplicate.push (act (.receive "alpha" "beta"))))
    "no pending packet"
  -- Send telemetry is not a complete or exactly-once enumeration of model outputs.
  let _ ← ok (replay header (start.extract 0 4))
  let _ ← ok (replay header (complete.extract 0 4 ++ complete.extract 5 complete.size))
  let envelope : Envelope :=
    { source := "alpha", target := "beta", payload := .proposeVoteRequest 2 }
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
      act (.receive "alpha" "beta"),
      sent "beta" "alpha" [("success", toJson "OK")]
    ]
  let _ ← ok (replay header observedRepeatedly)
  rejects (replay header (observedRepeatedly.push (act (.receive "alpha" "beta"))))
    "no pending packet"
  rejects (replay header (observedRepeatedly.push (act (.drop "alpha" "beta"))))
    "no pending packet"
  let early := start.push (observe "alpha" [("logLength", toJson (99 : Nat))])
  rejects (replay header (early.push (act (.receive "missing" "missing"))))
    "instruction 6"
  rejects (replay header early) "direct.ndjson:17 [unit]"
  -- Transaction effects are ordered and may share one physical index.
  let multi :=
    #[
      act
        (.local "alpha"
          (.append
            [.transaction "multi"
              [.reconfiguration {"alpha"}, .reconfiguration {"alpha", "beta"}]])),
      .entry "alpha" 2
        (Json.mkObj [("configurations", toJson [["alpha"], ["alpha", "beta"]])]) origin
    ]
  let _ ← ok (replay header multi)
  return 31

private def expectIOError (action : IO Unit) (expected : String) : IO Unit := do
  let result ← action.toBaseIO
  match result with
  | .ok _ => throw (IO.userError s!"unexpected IO success: {expected}")
  | .error error =>
      check ((toString error).contains expected) s!"expected {expected}, got {error}"

/-- The test executable itself supplies deterministic driver failure modes. -/
private def fakeDriver (scenario : System.FilePath) : IO UInt32 := do
  match ← IO.FS.readFile scenario with
  | "empty" => return 0
  | "fail" => IO.println "partial trace"; IO.eprintln "driver error"; return 3
  | "stderr" => IO.eprintln "driver warning"; return 0
  | "timeout" =>
      IO.println "partial trace"
      (← IO.getStdout).flush
      IO.sleep 30000
      return 0
  | "invalid" =>
      (← IO.getStdout).write (ByteArray.mk #[255, 10])
      return 0
  | _ =>
      IO.print "<RaftDriver> diagram\r\n"
      IO.print (← IO.FS.readFile "replay/tests/fixtures/bootstrap.ndjson")
      return 0

private def suiteTests : IO Nat :=
  IO.FS.withTempDir
    fun root => do
      let scenarios := root / "scenarios"
      let output := root / "output"
      let raw := root / "raw"
      IO.FS.createDirAll (scenarios / "nested")
      IO.FS.createDirAll output
      IO.FS.createDirAll raw
      IO.FS.writeFile (output / "summary.json") "{\"passed\":53,\"failed\":0}"
      expectIOError (discard (runSuite { scenarios, output, driver := some "missing" }))
        "empty scenario inventory"
      check (!(← (output / "summary.json").pathExists))
        "stale success survived invalid inventory"
      for name in ["plain", "dotted.1", "nested/inside"] do
        IO.FS.writeFile (scenarios / name) "ok"
      let paths ← inventory scenarios
      check (paths.size == 3) "recursive inventory omitted a file"
      let driver ← IO.appPath
      let captured := root / "capture.stdout"
      let stderr := root / "capture.stderr"
      capture driver (scenarios / "plain") captured stderr 5000
      check
        ((← IO.FS.readBinFile captured)
          == ("<RaftDriver> diagram\r\n"
              ++ (← IO.FS.readFile "replay/tests/fixtures/bootstrap.ndjson")).toUTF8)
        "capture changed stdout bytes"
      let records ← ok (← readLog captured)
      check (records[0]!.line == 2 && records[records.size - 1]!.line == 10)
        "physical line provenance"
      let positive ← runSuite { scenarios, output, driver := some driver }
      check (positive.selected == 3 && positive.passed == 3 && positive.failed == 0)
        "fresh suite"
      for (mode, diagnostic, stdout, err)
          in [
            ("fail", "exited 3", "partial trace\n", "driver error\n"),
            ("stderr", "wrote to stderr", "", "driver warning\n"),
            ("timeout", "exceeded", "partial trace\n", "")
          ] do
        IO.FS.writeFile (scenarios / "plain") mode
        expectIOError (capture driver (scenarios / "plain") captured stderr 5000)
          diagnostic
        check ((← IO.FS.readFile captured) == stdout && (← IO.FS.readFile stderr) == err)
          s!"lost {mode} capture"
      for (name, mode)
          in [("plain", "empty"), ("dotted.1", "invalid"), ("nested/inside", "fail")] do
        IO.FS.writeFile (scenarios / name) mode
      let failures ← runSuite { scenarios, output, driver := some driver }
      check (failures.selected == 3 && failures.failed == 3)
        "did not attempt all capture/parser failures"
      check
        ((failures.results.filter
            (fun result => optional result "stage" == some (toJson "capture"))).size
          == 1)
        "failure stages lost"
      let absent ← runSuite { scenarios, output, rawDirectory := some raw }
      check (absent.selected == 3 && absent.failed == 3) "missing captures were skipped"
      for name in ["plain", "dotted.1", "nested/inside"] do
        if name == "nested/inside" then IO.FS.createDirAll (raw / "nested")
        IO.FS.writeBinFile (System.FilePath.mk ((raw / name).toString ++ ".stdout"))
          (ByteArray.mk #[255, 10])
      let encoding ← runSuite { scenarios, output, rawDirectory := some raw }
      check
        (encoding.failed == 3
          && encoding.results.all
              (fun result =>
                (optional result "error" >>= (·.getStr?.toOption)).any
                  (·.contains "invalid UTF-8")))
        "invalid encoding aborted or passed corpus"
      let invalid := "{malformed"
      IO.FS.writeFile (raw / "plain.stdout") invalid
      let corpus ←
        runSuite
          { scenarios, output, rawDirectory := some raw, driver := some "must-not-run" }
      check (corpus.failed == 3) "corpus mode recaptured or skipped a missing file"
      IO.FS.writeFile (raw / "plain.stdout")
        (← IO.FS.readFile "replay/tests/fixtures/bootstrap.ndjson")
      let mixed ←
        runSuite
          { scenarios, output, rawDirectory := some raw, driver := some "must-not-run" }
      check (mixed.passed == 1 && mixed.failed == 2)
        "corpus mode recaptured or failed to check valid input"
      return 15

def main (args : List String) : IO UInt32 := do
  if let [scenario] := args then return ← fakeDriver scenario
  let _ ← parserTests
  let _ ← reductionTests
  let _ ← fixtureMutations
  let _ ← directTests
  let _ ← suiteTests
  IO.println "Lean replay regressions passed."
  return 0
