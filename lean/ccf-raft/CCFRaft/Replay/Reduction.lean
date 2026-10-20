module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Records

public section

/-!
Named rules for the globally ordered `raft_driver` capture. A rule consumes one
C++ operation and its synchronous callbacks, emits its one composite model
action, and checks recorded fields at their pre/post-mutation boundaries.
No rule computes protocol state or reconstructs packet payloads.
-/

namespace CCFRaft.Replay

open Lean Model.Node

private structure Cursor where
  events : Array Event
  position : Nat := 0
  instructions : Array Instruction := #[]

private abbrev Reduction := StateT Cursor (Except String)

private def peek : Reduction (Option Event) := do
  return (← get).events[(← get).position]?

private def nextIs (name : String) (anchor : Option Event := none) : Reduction Bool := do
  return (← peek).any
    fun event =>
      event.function == name && anchor.all (·.sameContext event)

private def take : Reduction Event := do
  let some event ← peek | throw "end of trace: incomplete event group"
  modify fun cursor => { cursor with position := cursor.position + 1 }
  return event

private def checked (event : Event) (condition : Bool) (message : String)
    : Reduction Unit :=
  liftM (require condition s!"{event.record.location}: {event.function}: {message}")

private def read {α : Type} (event : Event) (result : Except String α) : Reduction α :=
  liftM
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

private def emit (instruction : Instruction) : Reduction Unit :=
  modify
    fun cursor => { cursor with instructions := cursor.instructions.push instruction }

private def action (event : Event) (rule : String) (step : Step)
    (group : List Event := [])
    : Reduction Unit :=
  emit (.action step ((if group.isEmpty then [event] else group).map (·.origin rule)))

private def entry (event : Event) (index : Nat) (fields : List (String × Json))
    (rule : String := "callback-entry")
    : Reduction Unit :=
  emit (.entry event.node index (Json.mkObj fields) (event.origin rule))

/-- Unspecified fields are always checked; every intentional omission has evidence and a reason. -/
private def observe (event : Event) (rule : String) (properties : Option Json := none)
    (exclusions : List (String × String) := []) (peer : Option String := none)
    : Reduction Unit := do
  let facts ← read event (object (properties.getD event.facts))
  let mut omitted := []
  for (key, reason) in exclusions do
    let some value := facts.lookup key
    | throw s!"{event.record.location}: exclusion names unknown property '{key}'"
    checked event (!reason.trimAscii.toString.isEmpty)
      "observation exclusion requires a reason"
    omitted := omitted ++ [(key, value, reason)]
  let fields := facts.filter fun (key, _) => !(exclusions.lookup key).isSome
  let state := fields.filter (·.1 != "committableIndices")
  checked event (!state.isEmpty) s!"{rule} has no state properties to observe"
  emit (.state event.node peer (Json.mkObj state) { event.origin rule with omitted })
  if let some markers := fields.lookup "committableIndices" then
    for marker in ← read event markers.getArr? do
      entry event (← read event (natural marker)) [("kind", toJson "signature")]
        "signature-marker"

private def message (event : Event) (rule : String) (receiving : Bool)
    : Reduction Unit := do
  let other ←
    read event (string event.message (if receiving then "from_node_id" else "to_node_id"))
  let packet ← read event (field event.message "packet")
  emit
    (.message (if receiving then other else event.node)
      (if receiving then event.node else other) packet
      (if receiving then .matching else .latest) (event.origin rule))

private def proposal (event : Event) (rule : String) : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let term ← read event (nat event.state "current_view")
  emit
    (.message event.node destination
      (Json.mkObj [("msg", toJson "raft_propose_request_vote"), ("term", toJson term)])
      .latest (event.origin rule))

private def peers (event : Event) (rule : String) : Reduction Unit := do
  let mut fields := []
  for (raw, target) in [("sent_idx", "sentIndex"), ("match_idx", "matchIndex")] do
    if let some value := optional event.message raw then
      fields := fields ++ [(target, value)]
  unless fields.isEmpty do
    let peer ←
      read event
        (text
          ((optional event.message "to_node_id"
            <|> optional event.message "from_node_id").getD
            .null))
    observe event rule (some (Json.mkObj fields)) [] (some peer)

private def retirementFields : List String :=
  [
    "membershipState",
    "retirementIndex",
    "retirementCommittableIndex",
    "retiredCommittedIndex"
  ]

private def commitChanged : List String :=
  ["commitIndex", "role", "configurations"] ++ retirementFields

private def omitPresent (facts : Json) (names : List String) (reason : String)
    : List (String × String) :=
  names.filterMap
    fun name => if (optional facts name).isSome then some (name, reason) else none

/-- `commit` traces before advancing and may nominate before clearing leadership. -/
private def takeCommit (anchor : Event) : Reduction (List Event) := do
  unless ← nextIs "commit" (some anchor) do
    return []
  let commit ← take
  checked commit ((← read commit (string commit.state "leadership_state")) == "Leader")
    "internal commit outside leadership"
  unless ← nextIs "step_down_and_nominate_successor" (some commit) do
    return [commit]
  let nomination ← take
  let target ← read commit (field commit.message "args" >>= (nat · "idx"))
  checked nomination
    (optional nomination.facts "role" == some (toJson "leader")
      && optional nomination.facts "membershipState"
          == some (toJson "retirementCompleted")
      && optional nomination.facts "commitIndex" == some (toJson target)
      && optional nomination.facts "retiredCommittedIndex" == some (toJson target))
    "unexpected terminal-retirement nomination boundary"
  return [commit, nomination]

private def observeCommit (tail : List Event) : Reduction Unit := do
  let commit :: rest := tail | return
  observe commit "commit-in-action" none
    (omitPresent commit.facts commitChanged
      "commit traces before applying itself inside the atomic step; checked after commit")
  if let nomination :: _ := rest then
    let post := ["commitIndex", "retiredCommittedIndex", "committableIndices"]
    observe nomination "terminal-nomination-pre" none
      (omitPresent nomination.facts
        (["role", "membershipState", "configurations"] ++ post)
        "nomination precedes terminal role/phase assignment and configuration pruning; raw boundary checked by takeCommit")
    proposal nomination "terminal-nomination-message"
    observe nomination "terminal-nomination-post"
      (some
        (Json.mkObj
          ((← read nomination (object nomination.facts)).filter
            (fun p => post.contains p.1))))
  let target ← read commit (field commit.message "args" >>= (nat · "idx"))
  observe commit "commit-post" (some (Json.mkObj [("commitIndex", toJson target)]))

private def activePeers (event : Event) : Reduction (List String) := do
  let configurations ← read event (field event.message "configurations" >>= Json.getArr?)
  let nodes ← configurations.toList.mapM fun value => read event (configuration value)
  return (nodes.flatten.eraseDups.filter (· != event.node)).mergeSort

/-- `become_leader`: possible lone-leader commit, then one empty send per peer. -/
private def takeLeaderTail (anchor : Event) : Reduction (List Event) := do
  let commits ← takeCommit anchor
  let mut heartbeats := []
  while ← nextIs "send_append_entries" (some anchor) do
    let some event ← peek | throw "missing leadership heartbeat"
    let packet ← read event (field event.message "packet")
    let previous ← read event (nat packet "prev_idx")
    let last ← read event (nat event.state "last_idx")
    if previous != last || (← read event (nat packet "idx")) != last then break
    heartbeats := heartbeats ++ [← take]
  let destinations ←
    heartbeats.mapM fun event => read event (string event.message "to_node_id")
  checked anchor (destinations.eraseDups == destinations)
    "duplicate leadership heartbeat destination"
  checked anchor ((← activePeers anchor).all destinations.contains)
    "missing active-peer leadership heartbeat"
  return commits ++ heartbeats

private def observeLeaderTail (tail : List Event) : Reduction Unit := do
  observeCommit (tail.filter (·.function != "send_append_entries"))
  for event in tail.filter (·.function == "send_append_entries") do
    peers event "leader-heartbeat-pre"
    message event "send-post" false

/-- Self-quorum promotion is nested before the enclosing election request loop. -/
private def takeElection (head : Event)
    : Reduction (List Event × List Event × List Event) := do
  let mut nested := []
  if head.function == "become_pre_vote_candidate"
      && (← nextIs "become_candidate" (some head)) then
    nested := [← take]
  let last := nested.getLast?.getD head
  if last.function == "become_candidate" && (← nextIs "become_leader" (some head)) then
    nested := nested ++ [← take]
  let tail ←
    if let some last := nested.getLast? then
      if last.function == "become_leader" then takeLeaderTail last else pure []
    else
      pure []
  let family :=
    if head.function == "become_pre_vote_candidate" && nested.isEmpty then
      "raft_request_pre_vote"
    else
      "raft_request_vote"
  let mut sends := []
  while ← nextIs "send_request_vote" (some head) do
    let send ← take
    let packet ← read send (field send.message "packet")
    checked send ((← read send (string packet "msg")) == family)
      "wrong vote request packet"
    sends := sends ++ [send]
  let others ← activePeers head
  let destinations ← sends.mapM fun send => read send (string send.message "to_node_id")
  checked head (destinations == others) "vote requests differ from other active members"
  checked head (nested.isEmpty || others.isEmpty)
    "self-quorum promotion with other active members"
  return (nested, sends, tail)

private def observeElection (head : Event) (nested sends tail : List Event)
    (rule : String)
    : Reduction Unit := do
  let roles := head :: nested
  let last := roles.getLast!
  for event in roles.dropLast do
    let facts ← read event (object event.facts)
    observe event rule none
      (facts.filterMap
        fun (key, value) =>
          if optional last.facts key == some value then
            none
          else
            some
              (
                key,
                "synchronous self-quorum promotion changes this field in the same step"
              ))
  observe last rule none
    (if tail.any (·.function == "commit") then
        omitPresent last.facts commitChanged "become_leader precedes its internal commit"
      else
        [])
  observeLeaderTail tail
  for send in sends do
    observe send "send-post"
    message send "send-post" false

private def bootstrap : Reduction String := do
  let names := ["become_leader", "replicate", "add_configuration", "replicate", "commit"]
  let mut prelude := #[]
  for name in names do
    let event ← take
    checked event (event.function == name) "expected exact five-event bootstrap"
    prelude := prelude.push event
  let leader := prelude[0]!.node
  for event in prelude, length in [0, 0, 0, 1, 2], markers in [[], [], [], [], [2]] do
    checked event
      (event.node == leader
        && optional event.state "current_view" == some (toJson (2 : Nat))
        && optional event.state "last_idx" == some (toJson length)
        && optional event.state "commit_idx" == some (toJson (0 : Nat))
        && optional event.state "leadership_state" == some (toJson "Leader")
        && optional event.state "membership_state" == some (toJson "Active"))
      "bootstrap state differs from audited prelude"
    checked event (optional event.state "committable_indices" == some (toJson markers))
      "bootstrap committable indices"
  let config := prelude[2]!
  checked config ((← read config (configurationArg config.message)) == [leader])
    "bootstrap is not singleton"
  let configuration ←
    read config (field config.message "args" >>= (field · "configuration"))
  checked config ((← read config (nat configuration "idx")) == 1)
    "bootstrap configuration index"
  for (event, seqno, committable) in [(prelude[1]!, 1, false), (prelude[3]!, 2, true)] do
    checked event
      (optional event.message "seqno" == some (toJson seqno)
        && optional event.message "view" == some (toJson (2 : Nat))
        && optional event.message "globally_committable" == some (toJson committable))
      "bootstrap write differs from audited prelude"
  let commit := prelude[4]!
  checked commit ((← read commit (field commit.message "args" >>= (nat · "idx"))) == 2)
    "bootstrap commit target"
  observe prelude[3]! "bootstrap"
  action prelude[3]! "bootstrap" (.local leader (.append [.signature]))
    [prelude[3]!, commit]
  observeCommit [commit]
  return leader

/-- The driver's singleton BatchVector, including hooks and new-peer heartbeats. -/
private def appendRule (write : Event) : Reduction Unit := do
  checked write
    ((← read write (nat write.message "seqno"))
        == (← read write (nat write.state "last_idx")) + 1
      && (← read write (nat write.message "view"))
          == (← read write (nat write.state "current_view")))
    "write coordinates differ from the recorded state"
  let mut configurations := []
  let mut callbacks := []
  let mut metadata : TransactionMetadata String := {}
  observe write "write-pre"
  while ← nextIs "add_configuration" (some write) do
    let config ← take
    checked config metadata.configuration.isNone
      "multiple configuration callbacks for one transaction"
    let value ← read config (field config.message "args" >>= (field · "configuration"))
    checked config
      (config.state == write.state
        && (← read config (nat value "idx")) == (← read write (nat write.message "seqno"))
        && !(← read write (boolean write.message "globally_committable")))
      "configuration write pair mismatch"
    let nodes ← read config (configurationArg config.message)
    metadata := { metadata with configuration := some nodes.toFinset }
    configurations := configurations ++ [config]
    observe config "configuration-pair"
    let previous ← activePeers config
    let added := nodes.filter fun node => node != write.node && !previous.contains node
    let mut addedCallbacks := []
    for _ in added do
      checked config (← nextIs "send_append_entries" (some write))
        "missing new-peer configuration callback"
      let callback ← take
      let oldLength ← read write (nat write.state "last_idx")
      let packet ← read callback (field callback.message "packet")
      checked callback
        ((← read callback (nat callback.state "last_idx")) == oldLength
          && (← read callback (nat packet "prev_idx")) == oldLength
          && (← read callback (nat packet "idx")) == oldLength
          && (← read callback (nat callback.message "sent_idx")) == oldLength + 1
          && (← read callback (nat callback.message "match_idx")) == 0)
        "unsupported configuration callback heartbeat"
      observe callback "configuration-callback-pre" none
        (omitPresent callback.facts retirementFields
          "configuration hook changed retirement before append; checked after append")
      addedCallbacks := addedCallbacks ++ [callback]
    let destinations ←
      addedCallbacks.mapM fun event => read event (string event.message "to_node_id")
    checked config (destinations.mergeSort == added.mergeSort)
      "new-peer configuration callback destinations differ"
    callbacks := callbacks ++ addedCallbacks
  let command ← read write (string write.command.value "cmd")
  let content ←
    if ← read write (boolean write.message "globally_committable") then
      pure EntryContent.signature
    else if command.startsWith "cleanup_nodes," then do
      let nodes := command.splitOn "," |>.drop 2
      checked write (!nodes.isEmpty && nodes.all (!·.isEmpty) && nodes.eraseDups == nodes)
        "invalid retirement node set"
      checked write metadata.configuration.isNone
        "cleanup_nodes with configuration metadata"
      pure (.transaction write.record.location { retiredCommitted := nodes.toFinset })
    else
      pure (.transaction write.record.location metadata)
  let tail ← takeCommit write
  action write "atomic-append" (.local write.node (.append [content]))
    ([write] ++ configurations ++ callbacks ++ tail)
  for callback in callbacks do
    observe callback "configuration-callback-post"
      (some
        (Json.mkObj
          ((← read callback (object callback.facts)).filter
            (fun p => retirementFields.contains p.1))))
    let sent ← read callback (nat callback.message "sent_idx")
    let matched ← read callback (nat callback.message "match_idx")
    let peer ← read callback (string callback.message "to_node_id")
    -- The new-peer constructor stores next-index, unlike ordinary sends.
    observe callback "configuration-callback-peer"
      (some
        (Json.mkObj [("sentIndex", toJson (sent - 1)), ("matchIndex", toJson matched)]))
      [] (some peer)
    message callback "send-post" false
  observeCommit tail

private def receiveFamily : String → List String
  | "recv_append_entries" => ["raft_append_entries"]
  | "recv_append_entries_response" => ["raft_append_entries_response"]
  | "recv_request_vote" => ["raft_request_vote", "raft_request_pre_vote"]
  | "recv_request_vote_response" =>
      ["raft_request_vote_response", "raft_request_pre_vote_response"]
  | "recv_propose_request_vote" => ["raft_propose_request_vote"]
  | _ => []

private def appendCallbacks : List String :=
  [
    "execute_append_entries_sync",
    "add_configuration",
    "commit",
    "send_append_entries_response"
  ]

private def observeAppendCallbacks (sender : String) (callbacks : List Event)
    : Reduction Unit := do
  for callback in callbacks, position in [:callbacks.length] do
    if ["send_append_entries_response", "send_request_vote_response"].contains
        callback.function then
      checked callback
        ((← read callback (string callback.message "to_node_id")) == sender)
        "response destination mismatch"
      observe callback "receive-post"
      message callback "response-post" false
      continue
    if callback.function == "execute_append_entries_sync" then
      checked callback
        ((← read callback (string callback.message "from_node_id")) == sender)
        "execute source mismatch"
    else if callback.function == "add_configuration" then
      let value ←
        read callback (field callback.message "args" >>= (field · "configuration"))
      entry callback (← read callback (nat value "idx"))
        [
          ("kind", toJson "transaction"),
          ("configurations", toJson [← read callback (configurationArg callback.message)])
        ]
    else if callback.function == "commit" then
      entry callback (← read callback (field callback.message "args" >>= (nat · "idx")))
        [("kind", toJson "signature"), ("committed", toJson true)]
    checked callback (optional callback.facts "role" == some (toJson "follower"))
      "receive callback requires follower role"
    let pending := (callbacks.drop position).map (·.function)
    let mut exclusions :=
      [(
        "membershipState",
        "configuration hooks, signatures and commit change retirement within the atomic receive"
      )]
    if pending.contains "execute_append_entries_sync" then
      exclusions :=
        exclusions
        ++ [(
              "logLength",
              "execute traces before applying; remaining callbacks extend the log"
            )]
    if pending.contains "commit" then
      exclusions :=
        exclusions
        ++ [
          ("role", "raw follower role checked; terminal commit may clear final role"),
          (
            "commitIndex",
            "commit traces before advancing; check the already-committed signature instead"
          )
        ]
      let committed ← read callback (nat callback.facts "commitIndex")
      if committed > 0 then
        entry callback committed
          [("kind", toJson "signature"), ("committed", toJson true)]
          "callback-committed-prefix"
    for (key, writer)
        in [
          ("retirementIndex", "add_configuration"),
          ("retirementCommittableIndex", "execute_append_entries_sync"),
          ("retiredCommittedIndex", "commit")
        ] do
      if optional callback.facts key == some .null && pending.contains writer then
        exclusions :=
          exclusions
          ++ [(key, s!"absent here; pending {writer} can set it in the same receive")]
    if let some configurations := optional callback.facts "configurations" then
      exclusions :=
        exclusions
        ++ [(
              "configurations",
              "hooks insert and commit prunes; check the recorded log entries instead"
            )]
      for configuration in ← read callback configurations.getArr? do
        entry callback (← read callback (nat configuration "index"))
          [
            ("kind", toJson "transaction"),
            ("configurations", toJson [← read callback (field configuration "nodes")])
          ]
          "callback-configuration"
    observe callback "append-callback" none exclusions

/-- Receive, term adoption, promotions, commits and responses are one model step. -/
private def receiveRule (event : Event) : Reduction Unit := do
  let sender ← read event (string event.message "from_node_id")
  let packet ← read event (field event.message "packet")
  let family ← read event (string packet "msg")
  checked event ((receiveFamily event.function).contains family)
    "receive function/packet mismatch"
  observe event "receive-pre"
  peers event "receive-pre"
  message event "receive-pre" true
  let mut followers := []
  if ← nextIs "become_follower" (some event) then
    let follower ← take
    let term ← read follower (nat follower.state "current_view")
    checked follower (term == (← read event (nat packet "term")))
      "follower term differs from packet"
    checked event
      (term > (← read event (nat event.state "current_view"))
        || event.function == "recv_append_entries")
      "unexplained same-term fallback"
    followers := [follower]
  let mut callbacks := []
  let mut election : Option (Event × List Event × List Event × List Event) := none
  if event.function == "recv_append_entries" then
    while (← peek).any (fun e => appendCallbacks.contains e.function) do
      let callback ← take
      checked callback (event.sameContext callback) "interleaved receive callback"
      callbacks := callbacks ++ [callback]
      if callback.function == "send_append_entries_response" then break
  else if
    event.function == "recv_request_vote"
    && (← nextIs "send_request_vote_response" (some event)) then
    let response ← take
    let responsePacket ← read response (field response.message "packet")
    checked response
      ((← read response (string response.message "to_node_id")) == sender
        && (← read response (string responsePacket "msg")) == family ++ "_response")
      "vote response does not match request"
    callbacks := [response]
  else if
    ["recv_propose_request_vote", "recv_request_vote_response"].contains event.function
    && (← nextIs "become_candidate" (some event)) then
    let head ← take
    let (nested, sends, tail) ← takeElection head
    election := some (head, nested, sends, tail)
    callbacks := [head] ++ nested ++ tail ++ sends
  else if
    event.function == "recv_request_vote_response"
    && (← nextIs "become_leader" (some event)) then
    let head ← take
    let tail ← takeLeaderTail head
    election := some (head, [], [], tail)
    callbacks := head :: tail
  else if event.function == "recv_append_entries_response" then
    callbacks ← takeCommit event
  action event "atomic-receive" (.receive sender event.node packet)
    ([event] ++ followers ++ callbacks)
  for follower in followers do
    observe follower "receive-follower-post" none
      ((← read follower (object follower.facts)).filterMap
        fun (key, _) =>
          if ["role", "currentTerm"].contains key then
            none
          else
            some (key, "become_follower precedes the rest of the atomic receive"))
  if let some (head, nested, sends, tail) := election then
    observeElection head nested sends tail "receive-post"
  else if event.function == "recv_append_entries_response" then
    observeCommit callbacks
  else
    observeAppendCallbacks sender callbacks

structure Reduced where
  header : Header
  instructions : Array Instruction

/-- Consumes every event exactly once; an ungrouped callback is never a stutter. -/
def reduce (records : Array Record) : Except String Reduced := do
  let (events, modes) ← associate records
  let run : Reduction String := do
    let leader ← bootstrap
    while let some event ← peek do
      let _ ← take
      match event.function with
      | "replicate" => appendRule event
      | "send_append_entries" =>
          let packet ← read event (field event.message "packet")
          checked event
            ((← read event (nat packet "prev_idx"))
              == (← read event (nat event.message "sent_idx")))
            "send prev_idx differs from sent_idx"
          observe event "send-pre"
          peers event "send-pre"
          action event "atomic-send"
            (.local event.node
              (.sendEntries (← read event (string event.message "to_node_id"))
                (← read event (nat packet "idx"))))
          message event "send-post" false
      | "drop_pending_to" =>
          checked event
            ((← read event (string event.message "from_node_id")) == event.node)
            "drop sender mismatch"
          observe event "drop"
          -- Drop checks the head, unlike a send's latest packet.
          let destination ← read event (string event.message "to_node_id")
          emit
            (.message event.node destination (← read event (field event.message "packet"))
              .head (event.origin "drop"))
          action event "drop" (.drop event.node destination)
      | "become_candidate" | "become_pre_vote_candidate" =>
          checked event
            ((← read event (boolean event.state "pre_vote_enabled"))
              == (event.function == "become_pre_vote_candidate"))
            "election entry differs from pre-vote mode"
          let (nested, sends, tail) ← takeElection event
          action event "atomic-election" (.local event.node (.timeout .election))
            ([event] ++ nested ++ tail ++ sends)
          observeElection event nested sends tail "role-post"
      | "become_follower" =>
          action event "role-post" (.local event.node (.timeout .checkQuorum))
          observe event "role-post"
      | "step_down_and_nominate_successor" =>
          checked event
            ((← read event (string event.command.value "cmd")).startsWith
              "nominate_successor,")
            "nomination outside a nominate_successor command"
          observe event "nomination"
          action event "nomination" (.local event.node .nominateSuccessor)
          proposal event "nomination-message"
      | _ =>
          if !(receiveFamily event.function).isEmpty then
            receiveRule event
          else
            throw s!"{event.record.location}: ungrouped callback {event.function}"
    return leader
  let (leader, cursor) ← run.run { events }
  let configuration : Finset String := {leader}
  let header : Header :=
    {
      declared := modes.map Prod.fst
      bootstrap :=
        {
          configuration,
          leader,
          leader_mem := by simp [configuration]
          preVoteStatus :=
            fun node => if modes.lookup node == some true then .enabled else .capable
        }
    }
  return { header, instructions := cursor.instructions }

def replayRecords (records : Array Record) : Except String Result := do
  let reduced ← reduce records
  replay reduced.header reduced.instructions

end CCFRaft.Replay
