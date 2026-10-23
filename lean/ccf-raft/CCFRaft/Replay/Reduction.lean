module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Records

import Std.Internal.Parsec.Basic

public section

/-!
Named rules for the globally ordered `raft_driver` capture. A rule consumes one
C++ operation and its synchronous callbacks, emits its one composite model
action, and checks fixed pre/post boundaries and endpoint-equivalent projections.
Native operation boundaries surround zero or more such actions.
No rule computes protocol state or reconstructs packet payloads.
-/

namespace CCFRaft.Replay

open Lean Model.Node

private structure EventInput where
  events : Array Event
  position : Nat := 0

private instance : Std.Internal.Parsec.Input EventInput Nat Nat where
  pos := (·.position)
  next input := { input with position := input.position + 1 }
  curr := (·.position)
  hasNext input := input.position < input.events.size
  next' input _ := { input with position := input.position + 1 }
  curr' input _ := input.position

private abbrev EventParser := Std.Internal.Parsec EventInput

private structure ReductionState where
  header : Header
  instructions : Array Instruction := #[]

private abbrev Reduction := StateT ReductionState EventParser

private def failure {α : Type} (message : String) : Reduction α :=
  liftM (Std.Internal.Parsec.fail message : EventParser α)

private def validated {α : Type} : Except String α → Reduction α
  | .ok value => pure value
  | .error error => failure error

private def peek : Reduction (Option Event) :=
  liftM (m := EventParser)
    ((fun input =>
        match Std.Internal.Parsec.peek? input with
        | .success remaining index => .success remaining (index.bind (input.events[·]?))
        | .error remaining error => .error remaining error)
      : EventParser (Option Event))

private def nextIs (name : String) (anchor : Option Event := none) : Reduction Bool := do
  return (← peek).any
    fun event =>
      event.function == name && anchor.all (·.sameContext event)

private def take : Reduction Event := do
  let some event ← peek | failure "end of trace: incomplete event group"
  let _ ← liftM (Std.Internal.Parsec.any : EventParser Nat)
  return event

private def checked (event : Event) (condition : Bool) (message : String)
    : Reduction Unit :=
  validated (require condition s!"{event.record.location}: {event.function}: {message}")

private def read {α : Type} (event : Event) (result : Except String α) : Reduction α :=
  validated
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

private def modelNode (event : Event) (name : String) : Reduction NodeID := do
  read event ((← get).header.nodeId name)

private def modelMembers (event : Event) (names : List String)
    : Reduction (Finset NodeID) := do
  return (← names.mapM (modelNode event)).toFinset

private def requestId (event : Event) : Reduction ReqID := do
  let some index := (← get).header.requests.findIdx? (· == event.record.location)
  | failure s!"{event.record.location}: undeclared request"
  return index

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

/-- Selected boundaries check every unexcluded field; phase omissions have fixed reasons. -/
private def observe (event : Event) (rule : String) (properties : Option Json := none)
    (exclusions : List (String × String) := []) (peer : Option String := none)
    (frontier : Option Nat := none)
    : Reduction Unit := do
  let facts ← read event (object (properties.getD event.facts))
  let mut omitted := []
  for (key, reason) in exclusions do
    let some value := facts.lookup key
    | failure s!"{event.record.location}: exclusion names unknown property '{key}'"
    checked event (!reason.trimAscii.toString.isEmpty)
      "observation exclusion requires a reason"
    omitted := omitted ++ [(key, value, reason)]
  let fields := facts.filter fun (key, _) => !(exclusions.lookup key).isSome
  let state := fields.filter (·.1 != "committableIndices")
  checked event (!state.isEmpty) s!"{rule} has no state properties to observe"
  let origin := { event.origin rule with omitted }
  if let some frontier := frontier then
    checked event peer.isNone "pre-commit observation cannot select a peer"
    emit (.stateBeforeCommit event.node frontier (Json.mkObj state) origin)
  else
    emit (.state event.node peer (Json.mkObj state) origin)
  if let some markers := fields.lookup "committableIndices" then
    for marker in ← read event markers.getArr? do
      entry event (← read event (natural marker)) [("kind", toJson "signature")]
        "signature-marker"

/-- Unlike internal cache evidence, boundary fields assert complete projected equality. -/
private def observeBoundary (event : Event) : Reduction Unit := do
  let phase ← read event (string event.message "phase")
  emit (.state event.node none event.facts (event.origin s!"native-{phase}"))

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
  let confirmation ← read nomination (nat nomination.facts "retiredCommittedIndex")
  checked nomination
    (optional nomination.facts "role" == some (toJson "leader")
      && optional nomination.facts "membershipState"
          == some (toJson "retirementCompleted")
      && optional nomination.facts "commitIndex" == some (toJson target)
      && confirmation > 0
      && confirmation <= target)
    "unexpected terminal-retirement nomination boundary"
  return [commit, nomination]

private def observeCommitPre (anchor : Event) (tail : List Event) : Reduction Unit := do
  let some commit := tail.find? (·.function == "commit") | return
  let previous ← read anchor (nat anchor.facts "commitIndex")
  checked commit (optional commit.facts "commitIndex" == some (toJson previous))
    "commitIndex differs from anchored pre-frontier"
  let target ← read commit (field commit.message "args" >>= (nat · "idx"))
  checked commit (previous < target)
    "commitIndex target does not advance the pre-frontier"
  observe commit "commit-frontier-pre"
    (some
      (Json.mkObj
        [
          ("commitIndex", toJson previous),
          (
            "retiredCommittedIndex",
            ← read commit (field commit.facts "retiredCommittedIndex")
          )
        ]))

private def observeCommit (tail : List Event) : Reduction Unit := do
  let commit :: rest := tail | return
  observe commit "commit-in-action" none
    [("role", "commit traces before terminal role clearing; exact leader role audited")]
    none (some (← read commit (nat commit.facts "commitIndex")))
  if let nomination :: _ := rest then
    checked nomination
      (optional nomination.facts "configurations"
        == optional commit.facts "configurations")
      "nomination configurations differ from checked precommit cache"
    let post := ["commitIndex", "retiredCommittedIndex", "committableIndices"]
    observe nomination "terminal-nomination-pre" none
      ([
          (
            "role",
            "nomination precedes role clearing; takeCommit checks exact leader role"
          ),
          (
            "membershipState",
            "nomination precedes terminal phase assignment; takeCommit checks completed retirement"
          ),
          (
            "configurations",
            "nomination precedes pruning; cache equals the checked commit pre-cache"
          )
        ]
        ++ omitPresent nomination.facts post
            "commit already advanced at nomination; these fields are observed at the final boundary below")
    proposal nomination "terminal-nomination-message"
    observe nomination "terminal-nomination-post"
      (some
        (Json.mkObj
          ((← read nomination (object nomination.facts)).filter
            (fun p => post.contains p.1))))
  let target ← read commit (field commit.message "args" >>= (nat · "idx"))
  -- The target constrains the effect; the trace does not record a post-commit snapshot.
  observe commit "commit-target" (some (Json.mkObj [("commitIndex", toJson target)]))

private def activePeers (event : Event) : Reduction (List String) := do
  let configurations ← read event (field event.message "configurations" >>= Json.getArr?)
  let nodes ← configurations.toList.mapM fun value => read event (configuration value)
  return (nodes.flatten.eraseDups.filter (· != event.node)).mergeSort

/-- `become_leader`: possible lone-leader commit, then one empty send per peer. -/
private def takeLeaderTail (anchor : Event) : Reduction (List Event) := do
  let commits ← takeCommit anchor
  let mut heartbeats := []
  while ← nextIs "send_append_entries" (some anchor) do
    let some event ← peek | failure "missing leadership heartbeat"
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
    observe event "leader-heartbeat-post"
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
  -- Earlier promotions are internal, not observations chosen by value disagreement.
  let last := (head :: nested).getLast!
  if let some commit := tail.find? (·.function == "commit") then
    checked last (optional last.facts "role" == some (toJson "leader"))
      "pre-commit promotion role must be leader"
    observe last rule none
      [(
        "role",
        "leader snapshot precedes terminal commit role clearing; exact phase role checked locally"
      )]
      none (some (← read commit (nat commit.facts "commitIndex")))
  else
    observe last rule
  observeLeaderTail tail
  for send in sends do
    observe send "send-post"
    message send "send-post" false

private def bootstrap (initial signature : Chunk) : Reduction String := do
  checked initial.pre
    (optional initial.pre.message "operation" == some (toJson "bootstrap")
      && (← read initial.pre (string initial.pre.command.value "cmd"))
          == s!"start_node,{initial.pre.node}")
    "expected native bootstrap operation"
  let mode := ((← get).header.preVoteModes.lookup initial.pre.node).getD true
  let expected :=
    [
      ("role", toJson "none"),
      ("currentTerm", toJson (0 : Nat)),
      ("logLength", toJson (0 : Nat)),
      ("commitIndex", toJson (0 : Nat)),
      ("preVoteEnabled", toJson mode),
      ("membershipState", toJson "active"),
      ("retirementIndex", Json.null),
      ("retirementCommittableIndex", Json.null),
      ("retiredCommittedIndex", Json.null),
      ("committableIndices", toJson ([] : List Nat)),
      ("configurations", toJson ([] : List Json)),
      ("leaderActivePeerProgress", toJson ([] : List Json))
    ]
  for (key, value) in expected do
    checked initial.pre (optional initial.pre.facts key == some value)
      s!"initialization PRE {key} differs from the native constructor"
  checked initial.pre
    (optional initial.pre.message "peers" == some (toJson ([] : List Json)))
    "initialization PRE peers must be empty"
  checked signature.pre
    (optional signature.pre.message "operation" == some (toJson "replicate"))
    "expected bootstrap signature operation"
  let prelude := initial.events ++ signature.events
  let names := ["become_leader", "replicate", "add_configuration", "replicate", "commit"]
  checked initial.pre (initial.events.size == 3 && signature.events.size == 2)
    "expected exact five-event bootstrap"
  for event in prelude, name in names do
    checked event (event.function == name) "expected exact five-event bootstrap"
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
  let initialEvent := prelude[0]!
  for key in ["retirementIndex", "retirementCommittableIndex", "retiredCommittedIndex"] do
    checked initialEvent (optional initialEvent.facts key == some .null)
      s!"bootstrap {key} must be absent"
  checked initialEvent
    (optional initialEvent.facts "configurations" == some (toJson ([] : List Json)))
    "bootstrap configurations must be empty before genesis"
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
  -- Genesis is preloaded by Model.initialNodeState, not an invented transition.
  -- The real initialization POST must agree before any model action executes.
  observeBoundary initial.post
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
  let mut metadata : TransactionMetadata := {}
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
    metadata := { metadata with configuration := some (← modelMembers config nodes) }
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
      pure
        (.transaction (← requestId write)
          { retirementConfirmations := (← modelMembers write nodes) })
    else
      pure (.transaction (← requestId write) metadata)
  let tail ← takeCommit write
  observeCommitPre write tail
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
    followers := [← take]
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
  if let some (_, _, _, tail) := election then
    observeCommitPre event tail
  else if event.function == "recv_append_entries_response" then
    observeCommitPre event callbacks
  action event "atomic-receive" (.receive sender event.node packet)
    ([event] ++ followers ++ callbacks)
  -- Adoption is a full endpoint only when no later receive callback supplies one.
  if callbacks.isEmpty then
    for follower in followers do
      observe follower "receive-follower-post"
  if let some (head, nested, sends, tail) := election then
    observeElection head nested sends tail "receive-post"
  else if event.function == "recv_append_entries_response" then
    observeCommit callbacks
  else
    observeAppendCallbacks sender callbacks

structure Reduced where
  header : Header
  instructions : Array Instruction

private def headRule (operation : String) (operations functions : List String)
    : Reduction Event := do
  let some event ← peek | failure "end of trace: incomplete event group"
  unless functions.contains event.function do
    failure "operation head mismatch"
  let event ← take
  checked event (operations.contains operation)
    s!"ungrouped callback {event.function} in {operation} boundary"
  return event

private def appendOperation (operation : String) : Reduction Unit := do
  appendRule (← headRule operation ["replicate"] ["replicate"])

private def sendOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["replicate", "periodic"] ["send_append_entries"]
  let packet ← read event (field event.message "packet")
  checked event
    ((← read event (nat packet "prev_idx"))
      == (← read event (nat event.message "sent_idx")))
    "send prev_idx differs from sent_idx"
  observe event "send-pre"
  peers event "send-pre"
  action event "atomic-send"
    (.local event.node
      (.sendEntries
        (← modelNode event (← read event (string event.message "to_node_id")))
        (← read event (nat packet "idx"))))
  message event "send-post" false

private def receiveOperation (operation : String) : Reduction Unit := do
  let some event ← peek | failure "end of trace: incomplete event group"
  unless !(receiveFamily event.function).isEmpty do
    failure "operation head mismatch"
  let event ← take
  checked event (operation == "receive")
    s!"ungrouped callback {event.function} in {operation} boundary"
  receiveRule event

private def electionOperation (operation : String) : Reduction Unit := do
  let event ←
    headRule operation ["periodic"] ["become_candidate", "become_pre_vote_candidate"]
  checked event (← read event (boolean event.state "pre_vote_enabled"))
    "unsupported disabled-pre-vote timeout election: model requires pre-vote"
  checked event
    ((← read event (boolean event.state "pre_vote_enabled"))
      == (event.function == "become_pre_vote_candidate"))
    "election entry differs from pre-vote mode"
  let (nested, sends, tail) ← takeElection event
  checked event (optional event.facts "role" == some (toJson "preVoteCandidate"))
    "election boundary role must be preVoteCandidate"
  observe event "election-pre" none
    [(
      "role",
      "timeout entry follows phase-role assignment; all other fields still equal the pre-state"
    )]
  observeCommitPre event tail
  action event "atomic-election" (.local event.node (.timeout .election))
    ([event] ++ nested ++ tail ++ sends)
  observeElection event nested sends tail "role-post"

private def checkQuorumOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["periodic"] ["become_follower"]
  action event "role-post" (.local event.node (.timeout .checkQuorum))
  observe event "role-post"

private def nominationOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["nominate"] ["step_down_and_nominate_successor"]
  checked event
    ((← read event (string event.command.value "cmd")).startsWith "nominate_successor,")
    "nomination outside a nominate_successor command"
  observe event "nomination"
  action event "nomination" (.local event.node .nominateSuccessor)
  proposal event "nomination-message"

private def dropOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["drop"] ["drop_pending_to"]
  checked event ((← read event (string event.message "from_node_id")) == event.node)
    "drop sender mismatch"
  observe event "drop"
  let destination ← read event (string event.message "to_node_id")
  emit
    (.message event.node destination (← read event (field event.message "packet")) .head
      (event.origin "drop"))
  action event "drop" (.drop event.node destination)

private def operationRule (operation : String) : Reduction Unit :=
  appendOperation operation
  <|> sendOperation operation
  <|> receiveOperation operation
  <|> electionOperation operation
  <|> checkQuorumOperation operation
  <|> nominationOperation operation
  <|> dropOperation operation

private def chunkBody (header : Header) (operation : String)
    : EventParser (Array Instruction) := do
  let batches ←
    Std.Internal.Parsec.many do
      let (_, state) ← (operationRule operation).run { header }
      return state.instructions
  if let some index ← Std.Internal.Parsec.peek? then
    return ← fun input =>
              let event := input.events[index]!
              Std.Internal.Parsec.fail
                s!"{event.record.location}: {event.function}: ungrouped callback {event.function} in {operation} boundary"
                input
  Std.Internal.Parsec.eof
  return batches.foldl (· ++ ·) #[]

private def parseEvents {α : Type} (events : Array Event) (parser : EventParser α)
    : Except String α :=
  match parser { events } with
  | .success _ value => .ok value
  | .error _ error => .error (toString error)

/-- Consumes every event exactly once; an ungrouped callback is never a stutter. -/
def reduce (records : Array Record) : Except String Reduced := do
  let (events, modes) ← associate records
  let chunks ← boundaries events
  let some initial := chunks[0]? | throw "missing native bootstrap boundaries"
  let some signature := chunks[1]? | throw "missing native bootstrap signature boundaries"
  let declared := modes.map Prod.fst
  let locations :=
    (events.toList.filter (fun event => event.function == "replicate")).map
      (·.record.location)
  require (locations.eraseDups == locations) "duplicate transaction source location"
  let requests := "" :: locations
  let header : Header := { bootstrap := ∅, declared, requests, preVoteModes := modes }
  let initialization : Reduction String := do
    for chunk in chunks do
      for endpoint in [chunk.pre, chunk.post] do
        for peer in ← read endpoint (field endpoint.message "peers" >>= Json.getArr?) do
          let _ ← modelNode endpoint (← read endpoint (string peer "node_id"))
    bootstrap initial signature
  let (leader, initialState) ← parseEvents #[] (initialization.run { header })
  let mut instructions := initialState.instructions
  for chunk in chunks.toList.drop 1 do
    let boundary : Reduction String := do
      let operation ← read chunk.pre (string chunk.pre.message "operation")
      checked chunk.pre (operation != "bootstrap")
        "bootstrap operation after initialization"
      observeBoundary chunk.pre
      return operation
    let (operation, pre) ← parseEvents #[] (boundary.run { header })
    let body ← parseEvents chunk.events (chunkBody header operation)
    let (_, post) ← parseEvents #[] ((observeBoundary chunk.post).run { header })
    instructions := instructions ++ pre.instructions ++ body ++ post.instructions
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, instructions }

def replayRecords (records : Array Record) : Except String Result := do
  let reduced ← reduce records
  replay reduced.header reduced.instructions

end CCFRaft.Replay
