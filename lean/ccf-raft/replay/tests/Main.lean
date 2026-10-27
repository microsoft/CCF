module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Reduction

import all CCFRaft.Replay.Interpreter
import all CCFRaft.Replay.Reduction
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
  for invalid in [Json.null, .arr #[], toJson (2 : Nat)] do
    rejects (make invalid current) "object"
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
    modify (·.push (.observeNodeState "0" (Json.mkObj []) default))
    CCF.Parsec.failure "failed emission"
  let (_, instructions) ←
    ok
      (CCF.Parsec.run #[1]
        (((CCF.Parsec.attempt emitAndFail <|> discard CCF.Parsec.take)
          <* CCF.Parsec.eof).run
          #[]))
  check instructions.isEmpty "attempt leaked an emitted instruction"
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
    rejects
      (do
        let (events, declared) ← prepareEvents records
        CCFRaft.Replay.reduce events declared)
      "json.ndjson:1"
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

private def origin : Origin :=
  { file := "direct.ndjson", line := 17, rule := "unit" }

private def header : Header :=
  {
    declared := ["alpha", "beta", "future"]
    bootstrap := {0, 1}
    requests := ["", "tx-1", "configuration", "retired", "tx", "other", "unknown"]
  }

private def act (step : Step) : Instruction := .action step origin

private def observe (node : String) (fields : List (String × Json)) : Instruction :=
  .observeNodeState node (Json.mkObj fields) origin

open CCFRaft.Replay.Reducer in
private def reductionRuleTests : IO Unit := do
  let snapshot :=
    state.setObjVal! "node_id" (toJson "alpha")
    |>.setObjVal! "last_idx" (toJson (1 : Nat))
    |>.setObjVal! "commit_idx" (toJson (0 : Nat))
  let event (function : String) (snapshot : Json) (line : Nat)
      (fields : List (String × Json) := [])
      : CCFRaft.Replay.Event :=
    let message :=
      Json.mkObj (("function", toJson function) :: ("state", snapshot) :: fields)
    {
      record := { file := "reduction.ndjson", line, value := envelope message }
      command := command "dispatch_all"
      node := "alpha"
      function
      state := snapshot
      message
    }
  let actionLines (instructions : Array Instruction) :=
    instructions.filterMap
      fun
      | .action _ source => some source.line
      | _ => none
  let actions (instructions : Array Instruction) :=
    instructions.filter
      fun instruction =>
        match instruction with
        | .action .. => true
        | _ => false
  let run (events : Array CCFRaft.Replay.Event) (rule : Reduction Unit)
      (identities : Header := header)
      : Except String (Unit × ReductionState) :=
    CCF.Parsec.run events ((rule <* CCF.Parsec.eof).run { header := identities })
  let promotion := event "become_leader" snapshot 1
  let voteResponse :=
    event "recv_request_vote_response" snapshot 0
      [
        ("packet", Json.mkObj [("msg", toJson "raft_request_vote_response")]),
        ("from_node_id", toJson "beta")
      ]
  let appendRequest :=
    event "recv_append_entries" snapshot 0
      [
        ("packet", Json.mkObj [("msg", toJson "raft_append_entries")]),
        ("from_node_id", toJson "beta")
      ]
  let packet :=
    appendPacket.setObjVal! "prev_idx" (toJson (1 : Nat))
    |>.setObjVal! "idx" (toJson (1 : Nat))
  let heartbeat (line : Nat) :=
    event "send_append_entries" snapshot line
      [
        ("packet", packet),
        ("to_node_id", toJson "beta"),
        ("sent_idx", toJson (1 : Nat)),
        ("match_idx", toJson (0 : Nat))
      ]
  let (_, reduced) ←
    ok
      (run
        #[
          voteResponse,
          promotion,
          heartbeat 2,
          heartbeat 3,
          event "tick" snapshot 4,
          heartbeat 5
        ]
        (CCF.Parsec.many_ ruleStep))
  check (actionLines reduced.instructions == #[0, 5] && reduced.instructions.size == 4)
    "tick entry did not separate promotion heartbeats from timer sends"
  check
    (match ((actions reduced.instructions)[1]? : Option Instruction) with
      | some (.action (.local "alpha" (.sendEntries 1 1)) _) => true
      | _ => false)
    "send arguments were not taken from the peeked event"

  for (opening, callback, rule)
      in [
        (#[voteResponse, promotion], heartbeat 2, ruleRecvRequestVoteResponse),
        (
          #[appendRequest, event "add_configuration" snapshot 1],
          heartbeat 2,
          ruleRecvAppendEntries
        ),
        (
          #[appendRequest, event "commit" snapshot 1],
          event "step_down_and_nominate_successor" snapshot 2,
          ruleRecvAppendEntries
        ),
        (
          #[event "tick" snapshot 0, event "become_pre_vote_candidate" snapshot 1],
          event "send_request_vote" snapshot 2,
          ruleTick
        )
      ] do
    let _ ← ok (run opening rule)
    let _ ← ok (run (opening.push callback) rule)
    rejects
      (run (opening.push { callback with node := "beta" }) rule)
      "expected event on node alpha"
    rejects
      (run
        (opening.push
          { callback with command := { command "dispatch_all" with line := 99 } })
        rule)
      "crosses a command boundary"
  let wrongNode := { heartbeat 2 with node := "beta" }
  let fallback : Reduction Unit := CCF.Parsec.many_ (discard CCF.Parsec.take)
  rejects
    (run #[voteResponse, promotion, wrongNode] (ruleRecvRequestVoteResponse <|> fallback))
    "expected event on node alpha"
  let (_, reduced) ←
    ok
      (run #[voteResponse, promotion, wrongNode]
        (CCF.Parsec.attempt ruleRecvRequestVoteResponse <|> fallback))
  check reduced.instructions.isEmpty "failed callback leaked an instruction"
  let (_, reduced) ←
    ok (run #[event "tick" snapshot 1, wrongNode] (ruleStep <|> fallback))
  check reduced.instructions.isEmpty "failed step leaked its node-state observation"
  let (_, reduced) ← ok (run #[] (CCF.Parsec.many_ ruleStep))
  check reduced.instructions.isEmpty "end of input emitted an observation"

  for function in ["tick", "nomination"] do
    let (_, reduced) ← ok (run #[event function snapshot 1] ruleStep)
    check
      ((← ok (replay header reduced.instructions))
        == { instructions := 1, actions := 0, observations := 1 })
      s!"empty {function} must observe its entry without inventing a model action"
    let mismatched := snapshot.setObjVal! "commit_idx" (toJson (99 : Nat))
    let (_, reduced) ← ok (run #[event function mismatched 1] ruleStep)
    rejects (replay header reduced.instructions) "commit_idx"

  let (_, reduced) ←
    ok
      (run
        #[
          event "tick" snapshot 1,
          heartbeat 2,
          heartbeat 3,
          event "become_follower" snapshot 4
        ]
        ruleStep)
  check
    (match reduced.instructions.toList with
      | [
        .observeNodeState "alpha" _ _,
        .action (.local "alpha" (.sendEntries 1 1)) _,
        .action (.local "alpha" (.sendEntries 1 1)) _,
        .action (.local "alpha" (.timeout .checkQuorum)) _
      ] => true
      | _ => false)
    "tick must emit every send before quorum demotion, with one entry observation"
  let _ ← ok (replay header reduced.instructions)
  rejects
    (run
      #[
        event "tick" snapshot 1,
        event "become_follower" snapshot 2,
        heartbeat 3
      ]
      ruleTick)
    "end of input"

  let write :=
    event "replicate" snapshot 1
      [
        ("seqno", toJson (2 : Nat)),
        ("view", toJson (2 : Nat)),
        ("globally_committable", toJson false)
      ]
  let configuration :=
    event "add_configuration" snapshot 2
      [
        ("idx", toJson (2 : Nat)),
        ("nodes", Json.mkObj [("alpha", Json.mkObj []), ("beta", Json.mkObj [])])
      ]
  let identities := { header with requests := ["", write.record.location] }
  let (_, reduced) ←
    ok
      (run
        #[
          write,
          configuration,
          heartbeat 3,
          event "commit" snapshot 4,
          event "step_down_and_nominate_successor" snapshot 5,
          event "nomination" snapshot 6,
          event "step_down_and_nominate_successor" snapshot 7,
          event "tick" snapshot 8,
          heartbeat 9
        ]
        (CCF.Parsec.many_ ruleStep) identities)
  check (actionLines reduced.instructions == #[1, 6, 9] && reduced.instructions.size == 6)
    "configuration or commit callbacks swallowed a subsequent action"
  check
    (match ((actions reduced.instructions)[0]? : Option Instruction) with
      | some (.action (.local "alpha" (.append [⟨.transaction 1 metadata, []⟩])) _) =>
          metadata.configuration == some {0, 1} && metadata.retirementConfirmations == ∅
      | _ => false)
    "configuration input was not taken from the peek before consumption"
  let flushed :=
    {
      heartbeat 6 with
        state := snapshot.setObjVal! "last_idx" (toJson (2 : Nat))
        message :=
          (heartbeat 6).message.setObjVal! "packet"
            (packet.setObjVal! "idx" (toJson (2 : Nat)))
    }
  let opening :=
    #[
      write,
      configuration,
      heartbeat 3,
      event "batch_flush" snapshot 5
    ]
  let (_, reduced) ←
    ok
      (run
        (opening
          ++ #[
            flushed,
            event "commit" snapshot 7,
            event "tick" snapshot 8,
            heartbeat 9
          ])
        (CCF.Parsec.many_ ruleStep) identities)
  check (actionLines reduced.instructions == #[1, 9] && reduced.instructions.size == 4)
    "append flush emitted a separate action or observation"
  check
    (match ((actions reduced.instructions)[0]? : Option Instruction) with
      | some
          (.action (.local "alpha" (.append [⟨.transaction 1 metadata, flushes⟩])) _) =>
          metadata.configuration == some {0, 1} && flushes == [(1, 2)]
      | _ => false)
    "constructor heartbeat and append flush choices were not separated"
  let (_, reduced) ← ok (run (opening ++ #[flushed, flushed]) ruleAppend identities)
  check
    (match (reduced.instructions[0]? : Option Instruction) with
      | some (.action (.local "alpha" (.append [⟨_, flushes⟩])) _) =>
          flushes == [(1, 2), (1, 2)]
      | _ => false)
    "flush choices lost packet order or multiplicity"
  for (invalid, diagnostic)
      in [
        ({ flushed with node := "beta" }, "expected event on node alpha"),
        (
          { flushed with command := { flushed.command with line := 99 } },
          "command boundary"
        ),
        (
          {
            flushed with
              message := flushed.message.setObjVal! "to_node_id" (toJson "missing")
          },
          "undeclared node"
        ),
        (
          {
            flushed with
              message :=
                flushed.message.setObjVal! "packet"
                  (packet.setObjVal! "idx" (toJson "invalid"))
          },
          "expected natural number"
        )
      ] do
    rejects (run (opening.push invalid) (CCF.Parsec.many_ ruleStep) identities) diagnostic
  let signature :=
    {
      write with
        message := write.message.setObjVal! "globally_committable" (toJson true)
    }
  let singleton := { identities with bootstrap := {0} }
  let (_, reduced) ←
    ok
      (run
        #[
          signature,
          event "batch_flush" (snapshot.setObjVal! "last_idx" (toJson (2 : Nat))) 2,
          event "commit" snapshot 3
        ]
        ruleStep singleton)
  check (reduced.instructions.size == 2) "empty flush introduced a mid-append observation"
  let _ ← ok (replay singleton reduced.instructions)
  rejects
    (run
      #[
        write,
        {
          configuration with
            message := configuration.message.setObjVal! "idx" (toJson (99 : Nat))
        }
      ]
      ruleAppend identities)
    "configuration write pair mismatch"
  let cleanup := { write with command := command "cleanup_nodes,alpha,beta" }
  let (_, reduced) ← ok (run #[cleanup] ruleAppend identities)
  check
    (match (reduced.instructions[0]? : Option Instruction) with
      | some (.action (.local "alpha" (.append [⟨.transaction 1 metadata, []⟩])) _) =>
          metadata.configuration.isNone && metadata.retirementConfirmations == {1}
      | _ => false)
    "cleanup action lost its retirement confirmations"

  for (function, family)
      in [
        ("recv_append_entries", "raft_append_entries"),
        ("recv_append_entries_response", "raft_append_entries_response"),
        ("recv_request_vote", "raft_request_vote"),
        ("recv_request_vote", "raft_request_pre_vote"),
        ("recv_request_vote_response", "raft_request_vote_response"),
        ("recv_request_vote_response", "raft_request_pre_vote_response")
      ] do
    for callback in [false, true] do
      let term := 2
      let packet := Json.mkObj [("msg", toJson family), ("term", toJson term)]
      let receive :=
        event function snapshot 1 [("packet", packet), ("from_node_id", toJson "beta")]
      let events :=
        #[receive]
        ++ (if callback then #[event "become_follower" snapshot 2] else #[])
        ++ #[event "tick" snapshot 3, event "become_follower" snapshot 4]
      let (_, reduced) ← ok (run events (CCF.Parsec.many_ ruleStep))
      check
        (actionLines reduced.instructions == #[1, 3] && reduced.instructions.size == 4)
        s!"{family}: follower callback and quorum timeout were not separated"
  rejects (run #[event "become_follower" snapshot 1] ruleTick) "expected tick"
  let (_, reduced) ←
    ok (run #[event "tick" snapshot 1, event "become_follower" snapshot 2] ruleTick)
  rejects (replay { header with bootstrap := {0} } reduced.instructions)
    "disabled model action"

  let election :=
    #[
      event "tick" snapshot 0,
      event "become_pre_vote_candidate" snapshot 1,
      event "become_candidate" snapshot 2,
      event "become_leader" snapshot 3,
      event "commit" snapshot 4,
      event "step_down_and_nominate_successor" snapshot 5,
      heartbeat 7,
      event "send_request_vote" snapshot 9,
      event "tick" snapshot 10,
      heartbeat 11
    ]
  let (_, reduced) ← ok (run election (CCF.Parsec.many_ ruleStep))
  check (actionLines reduced.instructions == #[0, 11] && reduced.instructions.size == 4)
    "nested election callbacks emitted actions or swallowed the following send"
  for callback in ["recv_propose_request_vote", "recv_request_vote_response"] do
    let family :=
      if callback == "recv_propose_request_vote" then
        "raft_propose_request_vote"
      else
        "raft_request_vote_response"
    let receive :=
      event callback snapshot 1
        [("packet", Json.mkObj [("msg", toJson family)]), ("from_node_id", toJson "beta")]
    let events :=
      #[receive] ++ election[2:8].toArray ++ #[event "tick" snapshot 10, heartbeat 11]
    let (_, reduced) ← ok (run events (CCF.Parsec.many_ ruleStep))
    check (actionLines reduced.instructions == #[1, 11] && reduced.instructions.size == 4)
      "receive promotion swallowed the following send"

  let genesisConfig :=
    {
      configuration with
        record := { configuration.record with line := 4 }
        message :=
          configuration.message.setObjVal! "nodes" (Json.mkObj [("alpha", Json.mkObj [])])
    }
  let bootstrap :=
    #[
      promotion,
      { write with record := { write.record with line := 3 } },
      genesisConfig
    ]
  let signature :=
    {
      write with
        record := { write.record with line := 6 }
        message := write.message.setObjVal! "globally_committable" (toJson true)
    }
  let reduced ← ok (CCFRaft.Replay.reduce (bootstrap.push signature) header.declared)
  check (reduced.header.bootstrap == {0}) "bootstrap membership changed"
  check
    (match reduced.instructions.toList with
      | [.observeNodeState "alpha" expected before, .action _ after] =>
          expected == signature.state
          && before.rule == "step"
          && before.line == 6
          && after.line == 6
      | _ => false)
    "dispatcher did not emit exactly one node-state observation before the action"
  check
    ((← ok (replay reduced.header reduced.instructions))
      == { instructions := 2, actions := 1, observations := 1 })
    "replay did not count the node-state observation separately"
  for (key, value)
      in [
        ("node_id", toJson "beta"),
        ("current_view", toJson (3 : Nat)),
        ("last_idx", toJson (99 : Nat)),
        ("commit_idx", toJson (1 : Nat)),
        ("leadership_state", toJson "Follower"),
        ("unknown", Json.null)
      ] do
    let mismatched := { signature with state := signature.state.setObjVal! key value }
    let reduced ← ok (CCFRaft.Replay.reduce (bootstrap.push mismatched) header.declared)
    rejects (replay reduced.header reduced.instructions) key
    rejects (replay reduced.header reduced.instructions) "instruction 1"
  for function
      in [
        "unknown",
        "send_append_entries",
        "become_follower",
        "step_down_and_nominate_successor",
        "election_timeout",
        "check_quorum",
        "become_pre_vote_candidate_end",
        "become_leader_end",
        "add_configuration_end",
        "commit_end"
      ] do
    rejects
      (CCFRaft.Replay.reduce (bootstrap.push (event function snapshot 6)) header.declared)
      s!"ungrouped event {function}"

example (identities : Header) (current : ReplayState)
    (node : String) (expected : Json) (source : Origin)
    (succeeds : observeState identities node expected current = .ok ())
    : runInstruction identities current (.observeNodeState node expected source)
      = .ok current := by
  simp [runInstruction, succeeds]

private def nodeStateObservationTests : IO Unit := do
  let steps :=
    #[
      act (.local "alpha" (.append [{ content := .transaction 1 {} }])),
      act (.local "alpha" (.append [{ content := .signature }])),
      act (.local "alpha" (.sendEntries 1 3)),
      act (.receive "alpha" "beta" (Json.mkObj [("msg", toJson "raft_append_entries")])),
      act
        (.receive "beta" "alpha"
          (Json.mkObj [("msg", toJson "raft_append_entries_response")]))
    ]
  let current ←
    steps.foldlM (fun current step => ok (runInstruction header current step))
      { state := header.initial }
  let fields :=
    [
      ("node_id", toJson "alpha"),
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
  checkObservedFields (observeState header "alpha") current fields
  for key in ["sent_idx", "match_idx", "state.current_view"] do
    rejects
      (observeState header "alpha" (Json.mkObj [(key, toJson (3 : Nat))]) current)
      s!"unsupported observation field '$[{(toJson key).compress}]'"
  rejects (observeState header "alpha" (Json.mkObj [("a\"b", .null)]) current)
    "unsupported observation field '$[\"a\\\"b\"]'"
  for unknown in [.null, .arr #[], Json.mkObj [], Json.mkObj [("commit_idx", .null)]] do
    rejects
      (observeState header "alpha" (Json.mkObj [("unknown", unknown)]) current)
      "unsupported observation field '$[\"unknown\"]'"
  for invalid in [Json.mkObj [], .arr #[], .null] do
    rejects
      (observeState header "alpha" (Json.mkObj [("commit_idx", invalid)]) current)
      "$[\"commit_idx\"]: observed"
  rejects (observeState header "missing" (Json.mkObj fields) current) "undeclared node"
  rejects
    (observeState header "alpha" (Json.mkObj fields)
      { current with state := { current.state with nodes := [] } })
    "not in the network"
  let unchanged ← ok (runInstruction header current (observe "alpha" fields))
  let _ ← ok (observeState header "alpha" (Json.mkObj fields) unchanged)
  check
    (unchanged.state.network == current.state.network
      && unchanged.dropped == current.dropped)
    "node-state observation changed replay state"
  rejects (replay header #[observe "alpha" [("unknown", .null)]])
    s!"instruction 1 at {origin.label}: unsupported observation field"
  let uncommitted ←
    ok
      (runInstruction header current
        (act
          (.local "alpha"
            (.append [{ content := .signature }, { content := .signature }]))))
  let cache (indices : List Nat) := Json.mkObj [("committable_indices", toJson indices)]
  let _ ← ok (observeState header "alpha" (cache [4, 5]) uncommitted)
  for indices in [[5, 4], [4], [4, 4, 5], [3, 4, 5]] do
    rejects (observeState header "alpha" (cache indices) uncommitted)
      "committable_indices"
  let uncommitted ←
    ok
      (runInstruction header uncommitted
        (act (.local "alpha" (.append [{ content := .signature }]))))
  let _ ← ok (observeState header "alpha" (cache [4, 6]) uncommitted)
  for indices in [[], [4], [6], [6, 4], [4, 5], [5, 6], [4, 4], [4, 4, 6], [4, 5, 6]] do
    rejects (observeState header "alpha" (cache indices) uncommitted)
      "committable_indices"

private def packetFieldTests : IO Unit := do
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
    let queued : ReplayState :=
      {
        state := { header.initial with network := [envelope, envelope] },
        dropped := [envelope]
      }
    checkObservedFields
      (fun fields state => discard (selectPacket state 0 1 fields))
      queued (← ok (object (messageJson message)))

private def receiveFifoTests : IO Unit := do
  let setup :=
    #[
      act
        (.local "alpha"
          (.append [{ content := .transaction 4 {} }, { content := .signature }])),
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
  let _ ←
    ok
      (replay header
        (setup
          ++ #[
            receive firstFields,
            act (.receive "beta" "alpha" (Json.mkObj [("success", toJson "OK")])),
            receive secondFields
          ]))
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
  rejects (runInstruction header queued (receive unavailable)) "prev_idx"
  let dropped ← ok (runInstruction header queued (act (.drop "alpha" "beta")))
  let delivered ← ok (runInstruction header dropped (receive secondFields))
  rejects (runInstruction header delivered (receive firstFields)) "no pending packet"
  let differing : Option Envelope :=
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
  let some differing := differing
  | throw (IO.userError "expected AppendEntries payload")
  check (first != differing && messageJson differing.payload == firstFields)
    "FIFO payload test requires equal projected headers, different contents"
  for (head, tail, transaction) in [(first, differing, 4), (differing, first, 5)] do
    let indistinguishable :=
      { queued with state := { queued.state with network := [head, tail] } }
    let delivered ← ok (runInstruction header indistinguishable (receive firstFields))
    check (delivered.pending 0 1 == [tail]) "FIFO selected a later matching payload"
    let node ← ok (lookup header delivered "beta")
    check ((entryAt? node.log 2).map (·.content) == some (.transaction transaction {}))
      "receive reconstructed the payload instead of delivering the FIFO model entry"
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
            [("leadership_state", toJson "Leader"), ("last_idx", toJson (1 : Nat))],
          observe "1"
            [("leadership_state", toJson "None"), ("last_idx", toJson (0 : Nat))]
        ])
  let genesis ← ok (lookup lexical { state := lexical.initial } "2")
  check
    ((entryAt? genesis.log 1).map (·.content)
      == some (.transaction 0 { configuration := some {2} }))
    "initial entry lost its genesis request or lexical membership"
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
      (replay invalid #[observe "2" [("leadership_state", toJson "Leader")]])
      diagnostic
  for request in [0, 2] do
    rejects
      (replay lexical
        #[act (.local "2" (.append [{ content := .transaction request {} }]))])
      "undeclared or reserved model request"
  rejects
    (replay lexical
      #[
        act (.local "2" (.append [{ content := .transaction 1 {}, flushes := [(3, 2)] }]))
      ])
    "undeclared model node 3"
  rejects
    (replay lexical #[observe "2" [("preVoteEnabled", .bool false)]])
    "unsupported observation field"
  let _ ←
    ok
      (replay lexical
        #[
          act (.local "2" (.append [{ content := .transaction 1 {} }])),
          observe "2" [("last_idx", toJson (2 : Nat))]
        ])
  let appended ←
    ok
      (runInstruction lexical { state := lexical.initial }
        (act (.local "2" (.append [{ content := .transaction 1 {} }]))))
  let node ← ok (lookup lexical appended "2")
  check ((entryAt? node.log 2).map (·.content) == some (.transaction 1 {}))
    "append changed the declared request identifier"

def main : IO UInt32 := do
  let _ ← parserTests
  parsecInfrastructureTests
  reductionRuleTests
  nodeStateObservationTests
  packetFieldTests
  receiveFifoTests
  identityTests
  IO.println "Lean replay rejection and observation checks passed."
  return 0
