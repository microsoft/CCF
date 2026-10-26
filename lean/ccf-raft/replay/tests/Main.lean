module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Suite

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
    modify (·.push (.action (.local "0" .nominateSuccessor) []))
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
  let records ← ok (← readLog (System.FilePath.mk "replay/tests/fixtures" / name))
  -- Isolate protocol mutations from transport-sequence failures.
  records.mapM
    fun record => do
      let value ← ok (normalize record.value)
      let value :=
        match optional record.value "h_ts" with
        | some timestamp =>
            if (optional value "msg").isSome then
              value.setObjVal! "h_ts" timestamp
            else
              value
        | none => value
      return { record with value }

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
  rejects (stateFacts state configs) "unordered/duplicate configurations"
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
  check
    (result.actions == 1 && result.instructions == result.actions + result.observations)
    "bootstrap action contract"
  check
    (reduced.instructions.any
      fun instruction => instruction.origins.any (·.rule == "write-pre"))
    "bootstrap signature lost its rule observation"
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
  let modes ← ok (reduce (bootstrap ++ #[command "create_new_node,1"]))
  check (modes.header.declared == ["0", "1"]) "future node declaration"
  let assertions ← ok (reduce (bootstrap.push (command "assert_commit_idx,0,2")))
  check (assertions.instructions.size == reduced.instructions.size)
    "assertion invented an action"
  let mut count := 4
  for cmd
      in ["shuffle_one,0", "shuffle_all", "new_command,0", "pre_vote_enabled,maybe"] do
    rejects (reduce (bootstrap.push (command cmd))) "unsupported command"
    count := count + 1
  let startup ← fixture "startup.ndjson"
  let some write :=
    startup.findIdx?
      (fun row =>
        function row == "replicate"
        && optional (row.value.getObjValD "msg") "seqno" == some (toJson (3 : Nat)))
  | throw (IO.userError "missing post-bootstrap append")
  for (path, value)
      in [(["msg", "seqno"], toJson (4 : Nat)), (["msg", "view"], toJson (3 : Nat))] do
    rejects (reduce (mutate startup write path value)) "write coordinates"
    count := count + 1
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
    rejects (reduce (bootstrap ++ #[command "dispatch_all", source])) "ungrouped event"
    count := count + 1
  let commit ← find bootstrap "commit"
  for (path, value, diagnostic)
      in [
        (["msg", "args", "idx"], toJson (3 : Nat), "commit-target"),
        (["msg", "state", "last_idx"], toJson (3 : Nat), "commit-in-action"),
        (["msg", "state", "committable_indices"], toJson [1], "signature-marker")
      ] do
    rejects (replayRecords (mutate bootstrap commit path value)) diagnostic
    count := count + 1
  let unknown := mutate bootstrap 2 ["msg", "function"] (toJson "new_function")
  rejects (reduce unknown) "unsupported function"
  rejects (reduce (mutate bootstrap 0 ["tag"] (toJson "other"))) "expected raft_trace"
  rejects (reduce (mutate bootstrap 2 ["tag"] (.bool true))) "String"
  rejects (reduce (mutate bootstrap 2 ["msg", "unknown"] .null)) "unsupported field"
  rejects (reduce (mutate bootstrap 2 ["unknown"] .null)) "unsupported field"
  let configuration ← find bootstrap "add_configuration"
  rejects
    (reduce
      (mutate bootstrap configuration ["msg", "args", "configuration", "rid"]
        (.bool true)))
    "natural"
  rejects (reduce (bootstrap.extract 2 bootstrap.size)) "event before command"
  rejects (reduce #[command "state_all"]) "no Raft events"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let configuredReduction ← ok (reduce configured)
  let _ ← ok (replay configuredReduction.header configuredReduction.instructions)
  let heartbeat ← find config "send_append_entries"
  rejects (reduce (bootstrap ++ erase config heartbeat)) "expected send_append_entries"
  rejects
    (reduce (bootstrap ++ mutate config heartbeat ["msg", "to_node_id"] (toJson "0")))
    "destinations differ"
  rejects
    (reduce (bootstrap ++ mutate config heartbeat ["msg", "sent_idx"] (toJson (2 : Nat))))
    "event heartbeat"
  let configIndex ← find config "add_configuration"
  let duplicated :=
    config.extract 0 (heartbeat + 1)
    ++ #[config[configIndex]!]
    ++ config.extract (heartbeat + 1) config.size
  rejects (reduce (bootstrap ++ duplicated)) "ungrouped event add_configuration"
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
  let drop ← ok (reduce (← fixture "drop_resend.ndjson"))
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
  rejects (reduce (bootstrap ++ erase config heartbeat)) "expected send_append_entries"
  rejects
    (reduce
      (bootstrap ++ mutate config heartbeat ["msg", "sent_idx"] (toJson (999 : Nat))))
    "event heartbeat"
  let source := config[← find config "add_configuration"]!
  let message :=
    Json.mkObj
      [
        ("function", toJson "execute_append_entries_sync"),
        ("state", (source.value.getObjValD "msg").getObjValD "state"),
        ("from_node_id", toJson "0")
      ]
  let event := { source with value := source.value.setObjVal! "msg" message }
  rejects (reduce (configured.push event)) "ungrouped event execute_append_entries_sync"
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
  let periodic := { votes[promotion + 1]! with file := "periodic.ndjson", line := 1 }
  let extended := promotionRecords ++ #[command "periodic_one,1,10", periodic]
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
  rejects (reduce (promotionRecords.extract 0 (endOfPromotion - 1)))
    "missing active-peer leadership heartbeat"
  let destination ← ok (string (periodic.value.getObjValD "msg") "to_node_id")
  rejects
    (reduce
      (mutate promotionRecords (endOfPromotion - 1) ["msg", "to_node_id"]
        (toJson destination)))
    "duplicate leadership heartbeat destination"
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
        instruction.origins.any
          fun origin =>
            origin.file == retiredHeartbeat.file
            && origin.line == retiredHeartbeat.line
            && origin.rule == "leader-heartbeat-post")
    "retired-peer promotion heartbeat became a separate send action"

  let bootstrap ← fixture "bootstrap.ndjson"
  let config ← fixture "configuration_callback.ndjson"
  let configured := bootstrap ++ config
  let configMessage := config[← find config "add_configuration"]!.value.getObjValD "msg"
  let configurations ← ok (field configMessage "configurations" >>= Json.getArr?)
  let newConfiguration ← ok (field configMessage "args" >>= (field · "configuration"))
  let configurations := configurations.push newConfiguration
  let leaderState :=
    state.setObjVal! "last_idx" (toJson (4 : Nat))
    |>.setObjVal! "committable_indices" (toJson [4])
  let event (line : Nat) (message : Json) : Record :=
    {
      file := "receive-boundary.ndjson",
      line,
      value := Json.mkObj [("tag", toJson "raft_trace"), ("msg", message)]
    }
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
        instruction.origins.any (·.rule == "receive-term-adoption")
  for family in ["raft_request_vote_response", "raft_request_pre_vote_response"] do
    let records :=
      configured
      ++ #[
        command "dispatch_all",
        receive "recv_request_vote_response" (voteResponse family 2) "Leader",
        command "periodic_one,0,100",
        follower 2
      ]
    let reduced ← ok (reduce records)
    check ((timeouts reduced).size == 1 && (adoptions reduced).isEmpty)
      "ignored same-term response consumed a check-quorum transition"
    let records :=
      configured
      ++ #[
        command "dispatch_all",
        receive "recv_request_vote_response" (voteResponse family 3) "Leader",
        follower 3
      ]
    let reduced ← ok (reduce records)
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
    let reduced ← ok (reduce records)
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
    check
      (result.instructions == reduced.instructions.size
        && result.actions + result.observations == result.instructions)
      s!"{name}: unconsumed instructions"
    count := count + 1
    -- Every projected field must still be compared, including future additions.
    for instruction in reduced.instructions, position in [:reduced.instructions.size] do
      let fields :=
        match instruction with
        | .state _ _ fields _
        | .stateBeforeCommit _ _ fields _
        | .entry _ _ fields _
        | .message _ _ fields _ _ =>
            some fields
        | _ => none
      if let some fields := fields then
        for (key, _) in ← ok (object fields) do
          let replacement := fields.setObjVal! key (toJson "__mismatch__")
          let changed :=
            match instruction with
            | .state node peer _ origin => .state node peer replacement origin
            | .stateBeforeCommit node frontier _ origin =>
                .stateBeforeCommit node frontier replacement origin
            | .entry node index _ origin => .entry node index replacement origin
            | .message source target _ selection origin =>
                .message source target replacement selection origin
            | other => other
          rejects (replay reduced.header (reduced.instructions.set! position changed)) key
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
        if let .state _ _ fields origin := instruction then
          if ["event-term", "receive-post"].contains origin.rule
              && origin.function != "add_configuration"
              && (optional fields projected).isSome then
            let some index :=
              records.findIdx?
                (fun row => row.file == origin.file && row.line == origin.line)
            | throw (IO.userError "lost raw origin")
            let replacement :=
              if projected == "role" then
                toJson "Candidate"
              else
                toJson (999 : Nat)
            rejects
              (replayRecords (mutate records index ["msg", "state", raw] replacement))
              (if origin.function == "become_leader"
                  && origin.command.startsWith "start_node," then
                  "bootstrap state differs from audited prelude"
                else
                  projected)
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
  let historical ← fixture "terminal_retirement.stdout"
  rejects (replayRecords historical) "unsupported field 'pre_vote_enabled'"
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
        | .entry _ _ _ origin => origin.rule == "event-configuration"
        | _ => false)
  | throw (IO.userError "missing event configuration coverage")
  let origin := cache.origins.head!
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
    "event-configuration"
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
        | .entry _ _ _ origin =>
            origin.rule == "event-committed-prefix" && origin.function == "become_leader"
        | _ => false)
  | throw (IO.userError "missing committed-prefix coverage")
  let some prefixIndex :=
    terminal.findIdx? (fun row => row.line == committedPrefix.origins.head!.line)
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
  check
    (!(reduced.instructions.any
        fun instruction =>
          match instruction with
          | .message _ _ _ .matching _ => true
          | _ => false))
    "receive emitted a redundant packet-binding observation"
  for instruction in reduced.instructions, position in [:reduced.instructions.size] do
    if let .action (.receive ..) origins := instruction then
      check (origins.length == 1) "receive action retained a event buffer"
      let head := origins.head!
      let some headEvent := events.find? (sameOrigin head)
      | throw (IO.userError "receive action lost its source event")
      for later in reduced.instructions, observedAt in [:reduced.instructions.size] do
        let event :=
          later.origins.any
            fun origin =>
              events.any
                fun event =>
                  event.sameContext headEvent
                  && event.record.line > head.line
                  && sameOrigin origin event
        if event then
          check (observedAt > position) "event evidence preceded its receive action"
  let baseline ← ok (replayRecords records)
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
        (replayRecords (mutate records index ["msg", "args", "idx"] (toJson (999 : Nat))))
        "no log entry"
    if name == "add_configuration" then
      let bad :=
        mutate records index ["msg", "args", "configuration", "idx"] (toJson (999 : Nat))
      let bad :=
        mutate bad index ["msg", "args", "configuration", "rid"] (toJson (999 : Nat))
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
      fun instruction => instruction.origins.any (·.rule == "write-pre"))
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
    bootstrap := {0, 1}
    requests := ["", "tx-1", "configuration", "retired", "tx", "other", "unknown"]
  }

private def act (step : Step) : Instruction := .action step [origin]

private def observe (node : String) (fields : List (String × Json)) : Instruction :=
  .state node none (Json.mkObj fields) origin

private def sent (source destination : String) (fields : List (String × Json))
    : Instruction :=
  .message source destination (Json.mkObj fields) .latest origin

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
  rejects (replay header #[.action (.receive "alpha" "beta" append) []]) "missing origin"
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
      act (.local "alpha" (.sendEntries 1 3)),
      sent "alpha" "beta" [("prev_idx", toJson (3 : Nat)), ("idx", toJson (3 : Nat))]
    ]
  let head :=
    Instruction.message "alpha" "beta"
      (Json.mkObj [("prev_idx", toJson (0 : Nat)), ("idx", toJson (3 : Nat))]) .head
      origin
  let _ ← ok (replay header (twice.push head))
  let wrong :=
    Instruction.message "alpha" "beta" (Json.mkObj [("prev_idx", toJson (3 : Nat))]) .head
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
      .entry "alpha" 2
        (Json.mkObj
          [
            ("configurations", toJson [["alpha"]]),
            ("retiredCommitted", toJson ([] : List String))
          ]) origin
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
    Instruction.entry "alpha" 4
      (Json.mkObj
        [
          ("retiredCommitted", toJson nodes),
          ("configurations", toJson ([] : List (List String)))
        ])
      origin
  let _ ← ok (replay header (retired.push (retirementEntry ["beta"])))
  rejects (replay header (retired.push (retirementEntry []))) "retiredCommitted"
  for metadata in [{ configuration := some {99} }, { retirementConfirmations := {99} }] do
    rejects
      (replay header #[act (.local "alpha" (.append [.transaction 6 metadata]))])
      "undeclared model node 99"
  return 35

private def receiveMatchingTests : IO Unit := do
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
  let observed packet := Instruction.message "alpha" "beta" packet .matching origin
  let _ ←
    ok
      (replay header
        (setup
          ++ #[
            observed secondFields,
            receive secondFields,
            sent "beta" "alpha" [("success", toJson "FAIL")],
            observed firstFields,
            receive firstFields
          ]))
  let observedOnly ← ok (runInstruction header queued (observed secondFields))
  check (observedOnly.pending 0 1 == packets)
    "matching observation changed packet occurrences"
  let afterSecond ← ok (runInstruction header queued (receive secondFields))
  check (afterSecond.pending 0 1 == [first])
    "out-of-order receive lost the earlier packet"
  let afterFirst ← ok (runInstruction header afterSecond (receive firstFields))
  check ((afterFirst.pending 0 1).isEmpty) "receive did not consume one copy"
  rejects (runInstruction header afterFirst (receive secondFields)) "no pending packet"
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
    "ambiguous-payload test requires equal projected headers, different contents"
  let ambiguous :=
    { queued with state := { queued.state with network := [first, differing] } }
  rejects (runInstruction header ambiguous (observed firstFields))
    "ambiguous pending packets"
  rejects (runInstruction header ambiguous (receive firstFields))
    "ambiguous pending packets"
  let equalCopies :=
    { queued with state := { queued.state with network := [first, first] } }
  let one ← ok (runInstruction header equalCopies (receive firstFields))
  check (one.pending 0 1 == [first]) "equal envelopes lost multiplicity"
  let exhausted ← ok (runInstruction header one (receive firstFields))
  rejects (runInstruction header exhausted (receive firstFields)) "no pending packet"

private def expectIOError (action : IO Unit) (expected : String) : IO Unit := do
  let result ← action.toBaseIO
  match result with
  | .ok _ => throw (IO.userError s!"unexpected IO success: {expected}")
  | .error error =>
      check ((toString error).contains expected) s!"expected {expected}, got {error}"

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
          observe "2" [("role", toJson "leader"), ("logLength", toJson (1 : Nat))],
          observe "1" [("role", toJson "none"), ("logLength", toJson (0 : Nat))],
          .entry "2" 1
            (Json.mkObj [("transaction", toJson ""), ("configurations", toJson [["2"]])])
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
    rejects (replay invalid #[observe "2" [("role", toJson "leader")]]) diagnostic
  for request in [0, 2] do
    rejects (replay lexical #[act (.local "2" (.append [.transaction request {}]))])
      "undeclared or reserved model request"
  rejects
    (replay lexical #[observe "2" [("preVoteEnabled", .bool false)]])
    "unsupported observation field"
  let _ ←
    ok
      (replay lexical
        #[
          act (.local "2" (.append [.transaction 1 {}])),
          .entry "2" 2 (Json.mkObj [("transaction", toJson "request")]) origin
        ])

/-- Current Fluentd records retain order and decode only the native field layout. -/
private def transportTests : IO Unit := do
  let original ← fixture "startup.ndjson"
  let records ←
    original.mapIdxM
      fun index record => do
        let message ←
          if let some command := optional record.value "cmd" then
            pure (Json.mkObj [("cmd", command)])
          else do
            let message ← ok (field record.value "msg")
            let fields ← ok (object message)
            if function record == "commit" then
              pure
                (Json.mkObj
                  (fields.filter (·.1 != "args")
                    ++ [("idx", ← ok (field message "args" >>= (field · "idx")))]))
            else if function record == "add_configuration" then
              let config ← ok (field message "args" >>= (field · "configuration"))
              pure (Json.mkObj (fields.filter (·.1 != "args") ++ (← ok (object config))))
            else
              pure message
        pure
          {
            record with
              value :=
                Json.mkObj
                  [
                    ("tag", toJson "ccf.raft_trace"),
                    ("process_id", toJson "test-process"),
                    ("h_ts", toJson index),
                    ("msg", message)
                  ]
          }
  check ((← ok (replayRecords records)) == (← ok (replayRecords original)))
    "transport decoding changed replay instructions"
  for sequence in [0, 2] do
    rejects (reduce (mutate records 1 ["h_ts"] (toJson sequence))) "trace sequence"
  rejects (reduce (mutate records 1 ["process_id"] (toJson "another"))) "mixed trace"
  rejects (reduce (records.set! 1 original[1]!)) "mixed legacy/current"
  rejects (reduce (records.set! 0 original[0]!)) "mixed legacy/current"
  rejects (reduce (mutate records 0 ["unexpected"] .null)) "unsupported field"
  let config ← find original "add_configuration"
  rejects (reduce (mutate records config ["msg", "rid"] (toJson (99 : Nat))))
    "rid differs"
  let votes ← fixture "vote_responses.ndjson"
  let timeout ← find votes "become_pre_vote_candidate"
  let disabled := mutate votes timeout ["msg", "function"] (toJson "become_candidate")
  rejects (reduce disabled) "ungrouped event become_candidate"

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
  | "descendant" =>
      let _ ← IO.Process.spawn { cmd := "sleep", args := #["30"] }
      IO.println "partial trace"
      (← IO.getStdout).flush
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
      let guarded := root / "protected"
      IO.FS.createDirAll guarded
      let input := guarded / "summary.json"
      IO.FS.writeFile input "scenario,not,a,suite,summary"
      for destination
          in [
            guarded,
            guarded / "missing" / "nested",
            guarded / ".." / "protected",
            root
          ] do
        expectIOError
          (discard
            (runSuite
              { scenarios := guarded, output := destination, rawDirectory := some raw }))
          "output directory must be disjoint"
        check ((← IO.FS.readFile input) == "scenario,not,a,suite,summary")
          "unsafe output changed the scenario inventory"
        check (!(← (guarded / "missing").pathExists))
          "unsafe output created a directory inside the inventory"
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
      check (records[0]!.line == 2 && records[records.size - 1]!.line == records.size + 1)
        "physical line provenance"
      let positive ← runSuite { scenarios, output, driver := some driver }
      check (positive.selected == 3 && positive.passed == 3 && positive.failed == 0)
        "fresh suite"
      for (mode, diagnostic, stdout, err)
          in [
            ("fail", "exited 3", "partial trace\n", "driver error\n"),
            ("stderr", "wrote to stderr", "", "driver warning\n"),
            ("timeout", "exceeded", "partial trace\n", ""),
            ("descendant", "exceeded", "partial trace\n", "")
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
      return 20

def main (args : List String) : IO UInt32 := do
  if args != ["--no-cleanup"] then
    if let [scenario] := args then return ← fakeDriver scenario
  let _ ← parserTests
  let _ ← reductionTests
  parsecInfrastructureTests
  parsecReductionTests
  receiveGrammarTests
  speculativeGrammarTests
  emissionTests
  let _ ← fixtureMutations
  let observations ← observationTests
  let _ ← directTests
  receiveMatchingTests
  identityTests
  transportTests
  unless args == ["--no-cleanup"] do
    let _ ← suiteTests
  IO.println s!"Raw event observation cases passed: {observations}."
  IO.println "Lean replay regressions passed."
  return 0
