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

private def eventIs (name : String) (anchor : Option Event := none)
    : Reduction Event := do
  let some event ← peek | failure "end of trace: incomplete event group"
  unless event.function == name && anchor.all (·.sameContext event) do
    failure s!"expected {name}"
  take

-- Parsec's repetition is specialized to its base monad; thread reduction output too.
-- Each repeated rule below consumes an event before it can succeed.
private partial def many {α : Type} (parser : Reduction α) : Reduction (List α) :=
  (do
    let first ← parser
    return first :: (← many parser))
  <|> pure []

private def many_ (parser : Reduction Unit) : Reduction Unit :=
  discard (many parser)

private def optionalRule {α : Type} (parser : Reduction α) : Reduction (Option α) :=
  (some <$> parser) <|> pure none

private def checked (event : Event) (condition : Bool) (message : String)
    : Reduction Unit :=
  validated (require condition s!"{event.record.location}: {event.function}: {message}")

private def read {α : Type} (event : Event) (result : Except String α) : Reduction α :=
  validated
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

private def headRule (operation : String) (operations functions : List String)
    : Reduction Event := do
  let some event ← peek | failure "end of trace: incomplete event group"
  unless functions.contains event.function do
    failure "operation head mismatch"
  let event ← take
  checked event (operations.contains operation)
    s!"ungrouped callback {event.function} in {operation} boundary"
  return event

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
private def retirementNomination (commit : Event) : Reduction Event := do
  let nomination ← eventIs "step_down_and_nominate_successor" (some commit)
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
  return nomination

private def takeCommit (anchor : Event) : Reduction (List Event) :=
  (do
    let commit ← eventIs "commit" (some anchor)
    checked commit ((← read commit (string commit.state "leadership_state")) == "Leader")
      "internal commit outside leadership"
    return commit :: (← optionalRule (retirementNomination commit)).toList)
  <|> pure []

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

private def leaderHeartbeat (anchor : Event) : Reduction Event := do
  let some event ← peek | failure "missing leadership heartbeat"
  unless event.function == "send_append_entries" && anchor.sameContext event do
    failure "expected leadership heartbeat"
  let packet ← read event (field event.message "packet")
  let previous ← read event (nat packet "prev_idx")
  let last ← read event (nat event.state "last_idx")
  unless previous == last && (← read event (nat packet "idx")) == last do
    failure "not a leadership heartbeat"
  eventIs "send_append_entries" (some anchor)

/-- `become_leader`: possible lone-leader commit, then one empty send per peer. -/
private def takeLeaderTail (anchor : Event) : Reduction (List Event) := do
  let commits ← takeCommit anchor
  let heartbeats ← many (leaderHeartbeat anchor)
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

private def voteRequest (head : Event) (family : String) : Reduction Event := do
  let send ← eventIs "send_request_vote" (some head)
  let packet ← read send (field send.message "packet")
  checked send ((← read send (string packet "msg")) == family) "wrong vote request packet"
  return send

private def electionRequests (head : Event) (family : String) (nested tail : List Event)
    : Reduction (List Event × List Event × List Event) := do
  let sends ← many (voteRequest head family)
  let others ← activePeers head
  let destinations ← sends.mapM fun send => read send (string send.message "to_node_id")
  checked head (destinations == others) "vote requests differ from other active members"
  checked head (nested.isEmpty || others.isEmpty)
    "self-quorum promotion with other active members"
  return (nested, sends, tail)

private def leaderPromotion (anchor : Event) : Reduction (List Event × List Event) :=
  (do
    let leader ← eventIs "become_leader" (some anchor)
    return ([leader], ← takeLeaderTail leader))
  <|> pure ([], [])

private def candidateElection (head : Event)
    : Reduction (List Event × List Event × List Event) := do
  let (nested, tail) ← leaderPromotion head
  electionRequests head "raft_request_vote" nested tail

/-- A pre-vote either sends probes or synchronously obtains a self-quorum. -/
private def preVoteElection (head : Event)
    : Reduction (List Event × List Event × List Event) :=
  (do
    let candidate ← eventIs "become_candidate" (some head)
    let (nested, tail) ← leaderPromotion head
    electionRequests head "raft_request_vote" (candidate :: nested) tail)
  <|> electionRequests head "raft_request_pre_vote" [] []

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
  let expected :=
    [
      ("role", toJson "none"),
      ("currentTerm", toJson (0 : Nat)),
      ("logLength", toJson (0 : Nat)),
      ("commitIndex", toJson (0 : Nat)),
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
  let _ ←
    eventIs "operation_boundary"
    *> eventIs "become_leader"
    *> eventIs "replicate"
    *> eventIs "add_configuration"
    *> eventIs "operation_boundary"
  return leader

private def configurationHeartbeat (write config : Event) : Reduction Event := do
  checked config (← nextIs "send_append_entries" (some write))
    "missing new-peer configuration callback"
  let callback ← eventIs "send_append_entries" (some write)
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
  return callback

private def appendConfiguration (write : Event)
    : Reduction (Event × Finset NodeID × List Event) := do
  let config ← eventIs "add_configuration" (some write)
  let value ← read config (field config.message "args" >>= (field · "configuration"))
  checked config
    (config.state == write.state
      && (← read config (nat value "idx")) == (← read write (nat write.message "seqno"))
      && !(← read write (boolean write.message "globally_committable")))
    "configuration write pair mismatch"
  let nodes ← read config (configurationArg config.message)
  let members ← modelMembers config nodes
  observe config "configuration-pair"
  let previous ← activePeers config
  let added := nodes.filter fun node => node != write.node && !previous.contains node
  let callbacks ← added.mapM fun _ => configurationHeartbeat write config
  let destinations ←
    callbacks.mapM fun event => read event (string event.message "to_node_id")
  checked config (destinations.mergeSort == added.mergeSort)
    "new-peer configuration callback destinations differ"
  return (config, members, callbacks)

/-- The driver's singleton BatchVector, including hooks and new-peer heartbeats. -/
private def appendRule (write : Event) : Reduction Unit := do
  checked write
    ((← read write (nat write.message "seqno"))
        == (← read write (nat write.state "last_idx")) + 1
      && (← read write (nat write.message "view"))
          == (← read write (nat write.state "current_view")))
    "write coordinates differ from the recorded state"
  observe write "write-pre"
  let configuration ← optionalRule (appendConfiguration write)
  let _ ←
    optionalRule do
      let duplicate ← eventIs "add_configuration" (some write)
      checked duplicate false "multiple configuration callbacks for one transaction"
  let (configurations, metadata, callbacks) :=
    match configuration with
    | none => ([], ({} : TransactionMetadata), [])
    | some (config, members, callbacks) =>
        ([config], { configuration := some members }, callbacks)
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

/-- Check already-parsed effects against the resulting log; consume no input. -/
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

private structure Receive where
  event : Event
  sender : String
  packet : Json
  followers : List Event

private def receiveHead (operation function : String) (families : List String)
    : Reduction Receive := do
  let event ← headRule operation ["receive"] [function]
  let sender ← read event (string event.message "from_node_id")
  let packet ← read event (field event.message "packet")
  let family ← read event (string packet "msg")
  checked event (families.contains family) "receive function/packet mismatch"
  observe event "receive-pre"
  peers event "receive-pre"
  message event "receive-pre" true
  let followers ← optionalRule (eventIs "become_follower" (some event))
  return { event, sender, packet, followers := followers.toList }

private def deliver (receive : Receive) (callbacks : List Event) : Reduction Unit := do
  action receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
    ([receive.event] ++ receive.followers ++ callbacks)
  -- Adoption is a full endpoint only when no later receive callback supplies one.
  if callbacks.isEmpty then
    for follower in receive.followers do
      observe follower "receive-follower-post"

private def recvAppendEntries (operation : String) : Reduction Unit := do
  let receive ← receiveHead operation "recv_append_entries" ["raft_append_entries"]
  let applied ←
    many
      (eventIs "execute_append_entries_sync"
        <|> eventIs "add_configuration"
        <|> eventIs "commit")
  let response ← optionalRule (eventIs "send_append_entries_response")
  let callbacks := applied ++ response.toList
  for callback in callbacks do
    checked callback (receive.event.sameContext callback) "interleaved receive callback"
  deliver receive callbacks
  observeAppendCallbacks receive.sender callbacks

private def recvAppendEntriesResponse (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_append_entries_response" ["raft_append_entries_response"]
  let commits ← takeCommit receive.event
  observeCommitPre receive.event commits
  deliver receive commits
  observeCommit commits

private def voteResponse (receive : Receive) : Reduction Event := do
  let response ← eventIs "send_request_vote_response" (some receive.event)
  let packet ← read response (field response.message "packet")
  let family ← read receive.event (string receive.packet "msg")
  checked response
    ((← read response (string response.message "to_node_id")) == receive.sender
      && (← read response (string packet "msg")) == family ++ "_response")
    "vote response does not match request"
  return response

private def recvRequestVote (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_request_vote"
      ["raft_request_vote", "raft_request_pre_vote"]
  let callbacks := (← optionalRule (voteResponse receive)).toList
  deliver receive callbacks
  observeAppendCallbacks receive.sender callbacks

private abbrev Election := Event × List Event × List Event × List Event

private def becomeCandidate (anchor : Event) : Reduction Election := do
  let head ← eventIs "become_candidate" (some anchor)
  let (nested, sends, tail) ← candidateElection head
  return (head, nested, sends, tail)

private def becomeLeader (anchor : Event) : Reduction Election := do
  let head ← eventIs "become_leader" (some anchor)
  return (head, [], [], ← takeLeaderTail head)

private def receiveElection (receive : Receive) (promotion : Reduction Election)
    : Reduction Unit := do
  match ← optionalRule promotion with
  | none => deliver receive []
  | some (head, nested, sends, tail) =>
      observeCommitPre receive.event tail
      deliver receive ([head] ++ nested ++ tail ++ sends)
      observeElection head nested sends tail "receive-post"

private def recvProposeRequestVote (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_propose_request_vote" ["raft_propose_request_vote"]
  receiveElection receive (becomeCandidate receive.event)

private def recvRequestVoteResponse (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_request_vote_response"
      ["raft_request_vote_response", "raft_request_pre_vote_response"]
  receiveElection receive (becomeCandidate receive.event <|> becomeLeader receive.event)

/-- Each receive grammar contains one delivery and its synchronous effects. -/
private def receiveRule (operation : String) : Reduction Unit :=
  recvAppendEntries operation
  <|> recvProposeRequestVote operation
  <|> recvRequestVote operation
  <|> recvRequestVoteResponse operation
  <|> recvAppendEntriesResponse operation

structure Reduced where
  header : Header
  instructions : Array Instruction

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

private def electionOperation (operation : String) : Reduction Unit := do
  let event ←
    headRule operation ["periodic"] ["become_candidate", "become_pre_vote_candidate"]
  checked event (event.function == "become_pre_vote_candidate")
    "timeout election must start in the pre-vote phase"
  let (nested, sends, tail) ← preVoteElection event
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

private def tick (operation : String) : Reduction Unit :=
  electionOperation operation <|> checkQuorumOperation operation

private def reductionRules (operation : String) : Reduction Unit :=
  appendOperation operation
  <|> receiveRule operation
  <|> tick operation
  <|> sendOperation operation
  <|> nominationOperation operation
  <|> dropOperation operation

private def boundary (phase : String) : Reduction Event := do
  let event ← eventIs "operation_boundary"
  checked event (optional event.message "phase" == some (toJson phase))
    s!"expected native {phase} boundary"
  return event

private def observed : Reduction Unit := do
  let pre ← boundary "pre"
  let operation ← read pre (string pre.message "operation")
  checked pre (operation != "bootstrap") "bootstrap operation after initialization"
  let post : Reduction Unit := do
    let some event ← peek | failure "end of trace: missing required boundary POST"
    checked event (event.function == "operation_boundary")
      s!"ungrouped callback {event.function} in {operation} boundary"
    observeBoundary (← boundary "post")
  observeBoundary pre *> many_ (reductionRules operation) <* post

private def trace (initial signature : Chunk) : Reduction String :=
  bootstrap initial signature
  <* many_ observed
  <* liftM (Std.Internal.Parsec.eof : EventParser Unit)

private def parseEvents {α : Type} (events : Array Event) (parser : EventParser α)
    : Except String α :=
  match parser { events } with
  | .success _ value => .ok value
  | .error _ error => .error (toString error)

/-- Consumes every event exactly once; an ungrouped callback is never a stutter. -/
def reduce (records : Array Record) : Except String Reduced := do
  let (events, declared) ← associate records
  let chunks ← boundaries events
  let some initial := chunks[0]? | throw "missing native bootstrap boundaries"
  let some signature := chunks[1]? | throw "missing native bootstrap signature boundaries"
  let locations :=
    (events.toList.filter (fun event => event.function == "replicate")).map
      (·.record.location)
  require (locations.eraseDups == locations) "duplicate transaction source location"
  let requests := "" :: locations
  let header : Header := { bootstrap := ∅, declared, requests }
  let initialization : Reduction String := do
    for chunk in chunks do
      for endpoint in [chunk.pre, chunk.post] do
        for peer in ← read endpoint (field endpoint.message "peers" >>= Json.getArr?) do
          let _ ← modelNode endpoint (← read endpoint (string peer "node_id"))
    trace initial signature
  let (leader, state) ← parseEvents events (initialization.run { header })
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, instructions := state.instructions }

def replayRecords (records : Array Record) : Except String Result := do
  let reduced ← reduce records
  replay reduced.header reduced.instructions

end CCFRaft.Replay
