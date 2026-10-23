module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Records

import Std.Internal.Parsec.Basic

public section

/-!
Named rules for the globally ordered `raft_driver` capture. Head rules emit
model actions; callback rules emit observations as they consume events.
Native operation boundaries surround zero or more actions with complete PRE/POST
observations. The parser produces instructions, never executes protocol state,
reconstructs packet payloads, or compares snapshots using future callbacks.
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

private partial def many_ (parser : Reduction Unit) : Reduction Unit :=
  (parser *> many_ parser) <|> pure ()

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

private def emitInstruction (instruction : Instruction) : Reduction Unit :=
  modify
    fun cursor => { cursor with instructions := cursor.instructions.push instruction }

private def emitAction (event : Event) (rule : String) (step : Step) : Reduction Unit :=
  emitInstruction (.action step [event.origin rule])

private def emitEntryObservation (event : Event) (index : Nat)
    (fields : List (String × Json)) (rule : String := "callback-entry")
    : Reduction Unit :=
  emitInstruction (.entry event.node index (Json.mkObj fields) (event.origin rule))

/-- Selected boundaries check every unexcluded field; phase omissions have fixed reasons. -/
private def emitObservation (event : Event) (rule : String)
    (properties : Option Json := none) (exclusions : List (String × String) := [])
    (peer : Option String := none) (frontier : Option Nat := none)
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
    emitInstruction (.stateBeforeCommit event.node frontier (Json.mkObj state) origin)
  else
    emitInstruction (.state event.node peer (Json.mkObj state) origin)
  if let some markers := fields.lookup "committableIndices" then
    for marker in ← read event markers.getArr? do
      emitEntryObservation event (← read event (natural marker))
        [("kind", toJson "signature")] "signature-marker"

/-- Unlike internal cache evidence, boundary fields assert complete projected equality. -/
private def emitBoundaryObservation (event : Event) : Reduction Unit := do
  let phase ← read event (string event.message "phase")
  emitInstruction (.state event.node none event.facts (event.origin s!"native-{phase}"))

private def emitPacketObservation (event : Event) (rule : String)
    (selection : PacketSelection := .latest)
    : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let packet ← read event (field event.message "packet")
  emitInstruction (.message event.node destination packet selection (event.origin rule))

private def emitProposalObservation (event : Event) (rule : String) : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let term ← read event (nat event.state "current_view")
  emitInstruction
    (.message event.node destination
      (Json.mkObj [("msg", toJson "raft_propose_request_vote"), ("term", toJson term)])
      .latest (event.origin rule))

private def emitPeerObservation (event : Event) (rule : String) : Reduction Unit := do
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
    emitObservation event rule (some (Json.mkObj fields)) [] (some peer)

private def emitInternalEvidence (event : Event) : Reduction Unit := do
  emitObservation event "callback-term"
    (some (Json.mkObj [("currentTerm", ← read event (field event.facts "currentTerm"))]))
  if let some markers := optional event.facts "committableIndices" then
    for marker in ← read event markers.getArr? do
      emitEntryObservation event (← read event (natural marker))
        [("kind", toJson "signature")] "signature-marker"
  let committed ← read event (nat event.facts "commitIndex")
  if committed > 0 then
    emitEntryObservation event committed
      [("kind", toJson "signature"), ("committed", toJson true)]
      "callback-committed-prefix"
  if let some configurations := optional event.facts "configurations" then
    for configuration in ← read event configurations.getArr? do
      emitEntryObservation event (← read event (nat configuration "index"))
        [
          ("kind", toJson "transaction"),
          ("configurations", toJson [← read event (field configuration "nodes")])
        ]
        "callback-configuration"

private def optional_ (parser : Reduction Unit) : Reduction Unit :=
  discard (optionalRule parser)

private def retirementNomination (commit : Event) : Reduction Unit := do
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
  checked nomination
    (optional nomination.facts "configurations" == optional commit.facts "configurations")
    "nomination configurations differ from checked precommit cache"
  emitProposalObservation nomination "terminal-nomination-message"
  emitObservation nomination "terminal-nomination-post" none
    [
      ("role", "nomination precedes role clearing; raw leader role checked locally"),
      (
        "membershipState",
        "nomination precedes terminal phase assignment; raw completed retirement checked locally"
      ),
      ("configurations", "nomination cache equals the checked pre-pruning commit cache")
    ]

private def commitLeader (anchor : Event) : Reduction Unit := do
  let commit ← eventIs "commit" (some anchor)
  checked commit ((← read commit (string commit.state "leadership_state")) == "Leader")
    "internal commit outside leadership"
  let previous ← read anchor (nat anchor.facts "commitIndex")
  checked commit (optional commit.facts "commitIndex" == some (toJson previous))
    "commitIndex differs from anchored pre-frontier"
  let target ← read commit (field commit.message "args" >>= (nat · "idx"))
  checked commit (previous < target)
    "commitIndex target does not advance the pre-frontier"
  emitObservation commit "commit-in-action" none
    [("role", "commit traces before terminal role clearing; exact leader role audited")]
    none (some previous)
  emitObservation commit "commit-target"
    (some (Json.mkObj [("commitIndex", toJson target)]))
  optional_ (retirementNomination commit)

private def activePeers (event : Event) : Reduction (List String) := do
  let configurations ← read event (field event.message "configurations" >>= Json.getArr?)
  let nodes ← configurations.toList.mapM fun value => read event (configuration value)
  return (nodes.flatten.eraseDups.filter (· != event.node)).mergeSort

private def leaderHeartbeat (anchor : Event) : Reduction String := do
  let some event ← peek | failure "missing leadership heartbeat"
  unless event.function == "send_append_entries" && anchor.sameContext event do
    failure "expected leadership heartbeat"
  let packet ← read event (field event.message "packet")
  let previous ← read event (nat packet "prev_idx")
  let last ← read event (nat event.state "last_idx")
  unless previous == last && (← read event (nat packet "idx")) == last do
    failure "not a leadership heartbeat"
  let event ← eventIs "send_append_entries" (some anchor)
  emitObservation event "leader-heartbeat-post"
  emitPeerObservation event "leader-heartbeat-pre"
  emitPacketObservation event "send-post"
  read event (string event.message "to_node_id")

private def voteRequest (head : Event) (family : String) : Reduction String := do
  let send ← eventIs "send_request_vote" (some head)
  let packet ← read send (field send.message "packet")
  checked send ((← read send (string packet "msg")) == family) "wrong vote request packet"
  emitObservation send "send-post"
  emitPacketObservation send "send-post"
  read send (string send.message "to_node_id")

private def electionRequests (head : Event) (family : String) (selfQuorum : Bool)
    : Reduction Unit := do
  let destinations ← many (voteRequest head family)
  let others ← activePeers head
  checked head (destinations == others) "vote requests differ from other active members"
  checked head (!selfQuorum || others.isEmpty)
    "self-quorum promotion with other active members"

private def becomeLeader (anchor : Event) : Reduction Unit := do
  let leader ← eventIs "become_leader" (some anchor)
  checked leader (optional leader.facts "role" == some (toJson "leader"))
    "promotion role must be leader"
  emitInternalEvidence leader
  emitObservation leader "leader-log"
    (some (Json.mkObj [("logLength", ← read leader (field leader.facts "logLength"))]))
  optional_ (commitLeader anchor)
  let destinations ← many (leaderHeartbeat leader)
  checked leader (destinations.eraseDups == destinations)
    "duplicate leadership heartbeat destination"
  checked leader ((← activePeers leader).all destinations.contains)
    "missing active-peer leadership heartbeat"

private def becomeCandidate (anchor : Event) : Reduction Unit := do
  let candidate ← eventIs "become_candidate" (some anchor)
  let promotion ← optionalRule (becomeLeader anchor)
  electionRequests candidate "raft_request_vote" promotion.isSome

private def preVoteElection (head : Event) : Reduction Unit :=
  (eventIs "become_candidate" (some head)
    *> optional_ (becomeLeader head)
    *> electionRequests head "raft_request_vote" true)
  <|> electionRequests head "raft_request_pre_vote" false

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
  emitBoundaryObservation initial.post
  let _ ←
    eventIs "operation_boundary"
    *> eventIs "become_leader"
    *> eventIs "replicate"
    *> eventIs "add_configuration"
    *> eventIs "operation_boundary"
  return leader

private def configurationHeartbeat (write config : Event) : Reduction String := do
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
  let sent ← read callback (nat callback.message "sent_idx")
  let matched ← read callback (nat callback.message "match_idx")
  let peer ← read callback (string callback.message "to_node_id")
  emitObservation callback "configuration-callback-peer"
    (some (Json.mkObj [("sentIndex", toJson (sent - 1)), ("matchIndex", toJson matched)]))
    [] (some peer)
  emitPacketObservation callback "send-post"
  return peer

private def configurationHead (write : Event) : Reduction (Event × Finset NodeID) := do
  let config ← eventIs "add_configuration" (some write)
  let value ← read config (field config.message "args" >>= (field · "configuration"))
  checked config
    (config.state == write.state
      && (← read config (nat value "idx")) == (← read write (nat write.message "seqno"))
      && !(← read write (boolean write.message "globally_committable")))
    "configuration write pair mismatch"
  let nodes ← read config (configurationArg config.message)
  let members ← modelMembers config nodes
  return (config, members)

private def configurationEvidence (write config : Event) : Reduction Unit := do
  let nodes ← read config (configurationArg config.message)
  let index ←
    read config
      (field config.message "args" >>= (field · "configuration") >>= (nat · "idx"))
  emitEntryObservation config index
    [("kind", toJson "transaction"), ("configurations", toJson [nodes])]
  emitInternalEvidence config
  let previous ← activePeers config
  let added := nodes.filter fun node => node != write.node && !previous.contains node
  let destinations ← added.mapM fun _ => configurationHeartbeat write config
  checked config (destinations.mergeSort == added.mergeSort)
    "new-peer configuration callback destinations differ"

/-- The driver's singleton BatchVector, including hooks and new-peer heartbeats. -/
private def appendRule (write : Event) : Reduction Unit := do
  checked write
    ((← read write (nat write.message "seqno"))
        == (← read write (nat write.state "last_idx")) + 1
      && (← read write (nat write.message "view"))
          == (← read write (nat write.state "current_view")))
    "write coordinates differ from the recorded state"
  emitObservation write "write-pre"
  let configuration ← optionalRule (configurationHead write)
  let metadata : TransactionMetadata := { configuration := configuration.map (·.2) }
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
  emitAction write "atomic-append" (.local write.node (.append [content]))
  if let some (config, _) := configuration then
    configurationEvidence write config
  let _ ←
    optionalRule do
      let duplicate ← eventIs "add_configuration" (some write)
      checked duplicate false "multiple configuration callbacks for one transaction"
  optional_ (commitLeader write)

private def emitFollowerEvidence (event : Event) : Reduction Unit := do
  checked event (optional event.facts "role" == some (toJson "follower"))
    "receive callback requires follower role"
  emitInternalEvidence event

private structure Receive where
  event : Event
  sender : String
  packet : Json

private def receiveHead (operation function : String) (families : List String)
    : Reduction Receive := do
  let event ← headRule operation ["receive"] [function]
  let sender ← read event (string event.message "from_node_id")
  let packet ← read event (field event.message "packet")
  let family ← read event (string packet "msg")
  checked event (families.contains family) "receive function/packet mismatch"
  emitObservation event "receive-pre"
  emitPeerObservation event "receive-pre"
  return { event, sender, packet }

private def becomeFollower (receive : Receive) : Reduction Unit :=
  discard (eventIs "become_follower" (some receive.event))

private def executeAppendEntries (receive : Receive) : Reduction Unit := do
  let event ← eventIs "execute_append_entries_sync" (some receive.event)
  checked event ((← read event (string event.message "from_node_id")) == receive.sender)
    "execute source mismatch"
  emitFollowerEvidence event

private def addConfiguration (receive : Receive) : Reduction Unit := do
  let event ← eventIs "add_configuration" (some receive.event)
  let value ← read event (field event.message "args" >>= (field · "configuration"))
  emitEntryObservation event (← read event (nat value "idx"))
    [
      ("kind", toJson "transaction"),
      ("configurations", toJson [← read event (configurationArg event.message)])
    ]
  emitFollowerEvidence event

private def commitFollower (receive : Receive) : Reduction Unit := do
  let event ← eventIs "commit" (some receive.event)
  emitEntryObservation event (← read event (field event.message "args" >>= (nat · "idx")))
    [("kind", toJson "signature"), ("committed", toJson true)]
  emitFollowerEvidence event

private def sendAppendEntriesResponse (receive : Receive) : Reduction Unit := do
  let response ← eventIs "send_append_entries_response" (some receive.event)
  checked response
    ((← read response (string response.message "to_node_id")) == receive.sender)
    "response destination mismatch"
  emitObservation response "receive-post"
  emitPacketObservation response "response-post"

private def recvAppendEntries (operation : String) : Reduction Unit := do
  let receive ← receiveHead operation "recv_append_entries" ["raft_append_entries"]
  emitAction receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
  optional_ (becomeFollower receive)
  many_
    (executeAppendEntries receive <|> addConfiguration receive <|> commitFollower receive)
  optional_ (sendAppendEntriesResponse receive)

private def recvAppendEntriesResponse (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_append_entries_response" ["raft_append_entries_response"]
  emitAction receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
  optional_ (becomeFollower receive)
  optional_ (commitLeader receive.event)

private def sendRequestVoteResponse (receive : Receive) : Reduction Unit := do
  let response ← eventIs "send_request_vote_response" (some receive.event)
  let packet ← read response (field response.message "packet")
  let family ← read receive.event (string receive.packet "msg")
  checked response
    ((← read response (string response.message "to_node_id")) == receive.sender
      && (← read response (string packet "msg")) == family ++ "_response")
    "vote response does not match request"
  emitObservation response "receive-post"
  emitPacketObservation response "response-post"

private def recvRequestVote (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_request_vote"
      ["raft_request_vote", "raft_request_pre_vote"]
  emitAction receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
  optional_ (becomeFollower receive)
  optional_ (sendRequestVoteResponse receive)

private def recvProposeRequestVote (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_propose_request_vote" ["raft_propose_request_vote"]
  emitAction receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
  optional_ (becomeFollower receive)
  optional_ (becomeCandidate receive.event)

private def recvRequestVoteResponse (operation : String) : Reduction Unit := do
  let receive ←
    receiveHead operation "recv_request_vote_response"
      ["raft_request_vote_response", "raft_request_pre_vote_response"]
  emitAction receive.event "atomic-receive"
    (.receive receive.sender receive.event.node receive.packet)
  optional_ (becomeFollower receive)
  optional_ (becomeCandidate receive.event <|> becomeLeader receive.event)

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
  emitObservation event "send-pre"
  emitPeerObservation event "send-pre"
  emitAction event "atomic-send"
    (.local event.node
      (.sendEntries
        (← modelNode event (← read event (string event.message "to_node_id")))
        (← read event (nat packet "idx"))))
  emitPacketObservation event "send-post"

private def electionOperation (operation : String) : Reduction Unit := do
  let event ←
    headRule operation ["periodic"] ["become_candidate", "become_pre_vote_candidate"]
  checked event (event.function == "become_pre_vote_candidate")
    "timeout election must start in the pre-vote phase"
  checked event (optional event.facts "role" == some (toJson "preVoteCandidate"))
    "election boundary role must be preVoteCandidate"
  emitObservation event "election-pre" none
    [(
      "role",
      "timeout entry follows phase-role assignment; all other fields still equal the pre-state"
    )]
  emitAction event "atomic-election" (.local event.node (.timeout .election))
  preVoteElection event

private def checkQuorumOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["periodic"] ["become_follower"]
  emitAction event "role-post" (.local event.node (.timeout .checkQuorum))
  emitObservation event "role-post"

private def nominationOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["nominate"] ["step_down_and_nominate_successor"]
  checked event
    ((← read event (string event.command.value "cmd")).startsWith "nominate_successor,")
    "nomination outside a nominate_successor command"
  emitObservation event "nomination"
  emitAction event "nomination" (.local event.node .nominateSuccessor)
  emitProposalObservation event "nomination-message"

private def dropOperation (operation : String) : Reduction Unit := do
  let event ← headRule operation ["drop"] ["drop_pending_to"]
  checked event ((← read event (string event.message "from_node_id")) == event.node)
    "drop sender mismatch"
  emitObservation event "drop"
  let destination ← read event (string event.message "to_node_id")
  emitPacketObservation event "drop" .head
  emitAction event "drop" (.drop event.node destination)

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
    emitBoundaryObservation (← boundary "post")
  emitBoundaryObservation pre *> many_ (reductionRules operation) <* post

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
