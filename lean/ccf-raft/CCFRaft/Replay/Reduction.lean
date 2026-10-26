module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Records

import CCF.Parsec

public section

/-!
Named rules for the globally ordered `raft_driver` capture. Local event rules
audit trace evidence; consumption precedes explicit ordered instruction emission.
Non-consuming observations surround each reduction rule. The parser produces instructions, never executes protocol state,
reconstructs packet payloads, or compares snapshots using future events.
-/

namespace CCFRaft.Replay.Reducer

/- Consumption sketches below use x? for zero or one, x* for zero or more, x+ for one or more,
and | for alternatives. Camel-case names refer to other parser helpers. -/

open Lean Model.Node
open CCF.Parsec (failure validated peek attempt many_)

private structure ReductionState where
  header : Header
  instructions : Array Instruction := #[]

private abbrev Reduction := CCF.Parsec.ParserT Event ReductionState

/-- A failed repeated pattern leaves its Events and emissions for the enclosing rule. -/
private def many {α : Type} (rule : Reduction α) : Reduction (List α) :=
  CCF.Parsec.many (attempt rule)

private def optionalRule {α : Type} (rule : Reduction α) : Reduction (Option α) :=
  CCF.Parsec.optionalRule (attempt rule)

/-- Consume the next `name` event and audit it. A head mismatch consumes nothing. -/
private def event {α : Type} (name : String) (audit : Event → Reduction α)
    (source : Option Event := none)
    : Reduction α :=
  attempt do
    let event ←
      CCF.Parsec.satisfy
        (fun event => event.function == name && source.all (·.node == event.node))
        s!"expected {name}"
    audit event

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

private def emitInstruction (instruction : Instruction) : Reduction Unit :=
  modify
    fun cursor => { cursor with instructions := cursor.instructions.push instruction }

private def emitAction (event : Event) (rule : String) (step : Step) : Reduction Unit :=
  emitInstruction (.action step [event.origin rule])

private def emitObserveEntry (event : Event) (index : Nat)
    (fields : List (String × Json)) (rule : String := "event-entry")
    : Reduction Unit :=
  emitInstruction (.entry event.node index (Json.mkObj fields) (event.origin rule))

/-- Selected boundaries check every unexcluded field; phase omissions have fixed reasons. -/
private def emitObserve (event : Event) (rule : String)
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
      emitObserveEntry event (← read event (natural marker))
        [("kind", toJson "signature")] "signature-marker"

private def emitObservePacket (event : Event) (rule : String)
    (selection : PacketSelection := .latest)
    : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let packet ← read event (field event.message "packet")
  emitInstruction (.message event.node destination packet selection (event.origin rule))

private def emitObserveProposal (event : Event) (rule : String) : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let term ← read event (nat event.state "current_view")
  emitInstruction
    (.message event.node destination
      (Json.mkObj [("msg", toJson "raft_propose_request_vote"), ("term", toJson term)])
      .latest (event.origin rule))

private def emitObservePeerProgress (event : Event) (rule : String) : Reduction Unit := do
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
    emitObserve event rule (some (Json.mkObj fields)) [] (some peer)

private def emitObserveInternal (event : Event) : Reduction Unit := do
  emitObserve event "event-term"
    (some (Json.mkObj [("currentTerm", ← read event (field event.facts "currentTerm"))]))
  if let some markers := optional event.facts "committableIndices" then
    for marker in ← read event markers.getArr? do
      emitObserveEntry event (← read event (natural marker))
        [("kind", toJson "signature")] "signature-marker"
  let committed ← read event (nat event.facts "commitIndex")
  if committed > 0 then
    emitObserveEntry event committed
      [("kind", toJson "signature"), ("committed", toJson true)]
      "event-committed-prefix"
  if let some configurations := optional event.facts "configurations" then
    for configuration in ← read event configurations.getArr? do
      emitObserveEntry event (← read event (nat configuration "index"))
        [
          ("kind", toJson "transaction"),
          ("configurations", toJson [← read event (field configuration "nodes")])
        ]
        "event-configuration"

/-- Consumes:
step_down_and_nominate_successor
-/
private def retirementNomination (commit : Event) : Reduction Event :=
  let nomination :=
    event "step_down_and_nominate_successor" (source := some commit)
      fun e => do
        let target ← read commit (field commit.message "args" >>= (nat · "idx"))
        let confirmation ← read e (nat e.facts "retiredCommittedIndex")
        checked e
          (optional e.facts "role" == some (toJson "leader")
            && optional e.facts "membershipState" == some (toJson "retirementCompleted")
            && optional e.facts "commitIndex" == some (toJson target)
            && confirmation > 0
            && confirmation <= target)
          "unexpected terminal-retirement nomination boundary"
        checked e
          (optional e.facts "configurations" == optional commit.facts "configurations")
          "nomination configurations differ from checked precommit cache"
        return e
  nomination

private structure LeaderCommit where
  event : Event
  previous : Nat
  target : Nat
  nomination : Option Event

/-- Consumes:
commit
(step_down_and_nominate_successor)? -- for terminal retirement
-/
private def ruleLeaderCommit (anchor : Event) : Reduction LeaderCommit :=
  let commit :=
    event "commit" (source := some anchor)
      fun e => do
        checked e ((← read e (string e.state "leadership_state")) == "Leader")
          "internal commit outside leadership"
        let previous ← read anchor (nat anchor.facts "commitIndex")
        checked e (optional e.facts "commitIndex" == some (toJson previous))
          "commitIndex differs from anchored pre-frontier"
        let target ← read e (field e.message "args" >>= (nat · "idx"))
        checked e (previous < target)
          "commitIndex target does not advance the pre-frontier"
        return (e, previous, target)
  do
    let (e, previous, target) ← commit
    let nomination ← optionalRule (retirementNomination e)
    return { event := e, previous, target, nomination }

private def emitObserveLeaderCommit (evidence : LeaderCommit) : Reduction Unit := do
  let ⟨commit, previous, target, nomination⟩ := evidence
  emitObserve commit "commit-in-action" none
    [("role", "commit traces before terminal role clearing; exact leader role audited")]
    none (some previous)
  emitObserve commit "commit-target" (some (Json.mkObj [("commitIndex", toJson target)]))
  if let some nomination := nomination then
    emitObserveProposal nomination "terminal-nomination-message"
    emitObserve nomination "terminal-nomination-post" none
      [
        ("role", "nomination precedes role clearing; raw leader role checked locally"),
        (
          "membershipState",
          "nomination precedes terminal phase assignment; raw completed retirement checked locally"
        ),
        ("configurations", "nomination cache equals the checked pre-pruning commit cache")
      ]

private def activePeers (event : Event) : Reduction (List String) := do
  let configurations ← read event (field event.message "configurations" >>= Json.getArr?)
  let nodes ← configurations.toList.mapM fun value => read event (configuration value)
  return (nodes.flatten.eraseDups.filter (· != event.node)).mergeSort

/-- Consumes:
send_append_entries, with an empty packet at the local log frontier
-/
private def leaderHeartbeat (anchor : Event) : Reduction (Event × String) :=
  event "send_append_entries" (source := some anchor)
    fun e => do
      let packet ← read e (field e.message "packet")
      let previous ← read e (nat packet "prev_idx")
      let last ← read e (nat e.state "last_idx")
      checked e (previous == last && (← read e (nat packet "idx")) == last)
        "not a leadership heartbeat"
      checked e
        (optional e.state "current_view" == optional anchor.state "current_view")
        "leadership heartbeat term differs from promotion"
      let destination ← read e (string e.message "to_node_id")
      checked e (destination != e.node) "leadership heartbeat targets self"
      return (e, destination)

/-- Consumes:
send_request_vote, with the requested vote or pre-vote packet family
-/
private def voteRequest (head : Event) (family : String) : Reduction (Event × String) :=
  let request :=
    event "send_request_vote" (source := some head)
      fun e => do
        let packet ← read e (field e.message "packet")
        checked e ((← read e (string packet "msg")) == family) "wrong vote request packet"
        return (e, ← read e (string e.message "to_node_id"))
  request

/-- Consumes:
send_request_vote*, requiring destinations to equal the other active members
-/
private def electionRequests (head : Event) (family : String) (selfQuorum : Bool)
    : Reduction (List Event) := do
  let requests ← many (voteRequest head family)
  let destinations := requests.map (·.2)
  let others ← activePeers head
  checked head (destinations == others) "vote requests differ from other active members"
  checked head (!selfQuorum || others.isEmpty)
    "self-quorum promotion with other active members"
  return requests.map (·.1)

private structure Leadership where
  event : Event
  commit : Option LeaderCommit
  heartbeats : List Event

/-- Consumes:
become_leader
(ruleLeaderCommit)?
send_append_entries*, with distinct destinations covering all active peers
The next send to an already observed destination is left for a later rule.
-/
private def ruleBecomeLeader (anchor : Event) : Reduction Leadership :=
  let promotion :=
    event "become_leader" (source := some anchor)
      fun e => do
        checked e (optional e.facts "role" == some (toJson "leader"))
          "promotion role must be leader"
        return e
  do
    let leader ← promotion
    let commit ← optionalRule (ruleLeaderCommit anchor)
    let peers ← activePeers leader
    -- Native peers also include retired nodes absent from the active configurations.
    let mut heartbeats : List (Event × String) := []
    for _ in (← get).header.declared do
      let seen := heartbeats.map (·.2)
      let next ←
        optionalRule do
          let (event, destination) ← leaderHeartbeat leader
          checked event (!seen.contains destination)
            "duplicate leadership heartbeat destination"
          return (event, destination)
      let some next := next | break
      heartbeats := heartbeats ++ [next]
    let destinations := heartbeats.map (·.2)
    checked leader (peers.all destinations.contains)
      "missing active-peer leadership heartbeat"
    return { event := leader, commit, heartbeats := heartbeats.map (·.1) }

private structure Election where
  promotion : Option Leadership
  requests : List Event

/-- Consumes:
become_candidate
(ruleBecomeLeader)? -- for self quorum
send_request_vote*, with vote packets for the other active members
-/
private def becomeCandidate (anchor : Event) : Reduction Election :=
  let candidate :=
    event "become_candidate" (source := some anchor)
      fun e => do
        return e
  do
    let candidateEvent ← candidate
    let promotion ← optionalRule (ruleBecomeLeader anchor)
    let requests ← electionRequests candidateEvent "raft_request_vote" promotion.isSome
    return { promotion, requests }

-- Emit observations of promotion, commits, heartbeats and vote requests, not model actions.
private def emitObserveElection (election : Election) : Reduction Unit := do
  if let some promotion := election.promotion then
    let ⟨leader, commit, heartbeats⟩ := promotion
    emitObserveInternal leader
    emitObserve leader "leader-log"
      (some (Json.mkObj [("logLength", ← read leader (field leader.facts "logLength"))]))
    if let some commit := commit then
      emitObserveLeaderCommit commit
    for heartbeat in heartbeats do
      emitObserve heartbeat "leader-heartbeat-post"
      emitObservePeerProgress heartbeat "leader-heartbeat-pre"
      emitObservePacket heartbeat "send-post"
  for request in election.requests do
    emitObserve request "send-post"
    emitObservePacket request "send-post"

/-- Consumes:
become_leader
replicate, for genesis at index 1
add_configuration, with the singleton leader configuration
-/
private def ruleBootstrap : Reduction String :=
  -- Every genesis event happens on the forced leader in term 2 before any write lands.
  let leading (leader : String) (e : Event) : Reduction Unit :=
    checked e
      (e.node == leader
        && optional e.state "current_view" == some (toJson (2 : Nat))
        && optional e.state "last_idx" == some (toJson (0 : Nat))
        && optional e.state "commit_idx" == some (toJson (0 : Nat))
        && optional e.state "committable_indices" == some (toJson ([] : List Nat))
        && optional e.state "leadership_state" == some (toJson "Leader")
        && optional e.state "membership_state" == some (toJson "Active"))
      "bootstrap state differs from audited prelude"
  let becomeLeader :=
    event "become_leader"
      fun e => do
        checked e
          ((← read e (string e.command.value "cmd")) == s!"start_node,{e.node}")
          "expected bootstrap start_node command"
        leading e.node e
        for key
            in [
              "retirementIndex",
              "retirementCommittableIndex",
              "retiredCommittedIndex"
            ] do
          checked e (optional e.facts key == some .null)
            s!"bootstrap {key} must be absent"
        checked e (optional e.facts "configurations" == some (toJson ([] : List Json)))
          "bootstrap configurations must be empty before genesis"
        return e
  let genesisWrite (leader : String) :=
    event "replicate"
      fun e => do
        leading leader e
        checked e
          (optional e.message "seqno" == some (toJson (1 : Nat))
            && optional e.message "view" == some (toJson (2 : Nat))
            && optional e.message "globally_committable" == some (toJson false))
          "bootstrap write differs from audited prelude"
  let genesisConfiguration (leader : String) :=
    event "add_configuration"
      fun e => do
        leading leader e
        checked e ((← read e (configurationArg e.message)) == [leader])
          "bootstrap is not singleton"
        let configuration ← read e (field e.message "args" >>= (field · "configuration"))
        checked e ((← read e (nat configuration "idx")) == 1)
          "bootstrap configuration index"
        return e
  do
    -- Consumption
    let leaderEvent ← becomeLeader
    let leader := leaderEvent.node
    genesisWrite leader
    let configurationEvent ← genesisConfiguration leader
    -- Emission
    -- Genesis is preloaded by Model.initialNodeState, not an invented transition.
    emitObserveInternal leaderEvent
    emitObserveEntry configurationEvent 1
      [("kind", toJson "transaction"), ("configurations", toJson [[leader]])]
    return leader

/-- Consumes the driver's singleton BatchVector and its synchronous effects:
replicate
(add_configuration)?
send_append_entries, once per new peer if the configuration adds peers
(ruleLeaderCommit)? -- possibly including retirement nomination
-/
private def ruleAppend : Reduction Unit :=
  let write :=
    event "replicate"
      fun e => do
        checked e
          ((← read e (nat e.message "seqno")) == (← read e (nat e.state "last_idx")) + 1
            && (← read e (nat e.message "view"))
                == (← read e (nat e.state "current_view")))
          "write coordinates differ from the recorded state"
        return e
  let configuration (write : Event) :=
    event "add_configuration" (source := some write)
      fun e => do
        let value ← read e (field e.message "args" >>= (field · "configuration"))
        checked e
          (e.state == write.state
            && (← read e (nat value "idx")) == (← read write (nat write.message "seqno"))
            && !(← read write (boolean write.message "globally_committable")))
          "configuration write pair mismatch"
        let nodes ← read e (configurationArg e.message)
        return (e, ← modelMembers e nodes, nodes, ← read e (nat value "idx"))
  let content (write : Event) (metadata : TransactionMetadata)
      : Reduction EntryContent := do
    let command ← read write (string write.command.value "cmd")
    if ← read write (boolean write.message "globally_committable") then
      pure EntryContent.signature
    else if command.startsWith "cleanup_nodes," then do
      let nodes := command.splitOn "," |>.drop 2
      checked write
        (!nodes.isEmpty && nodes.all (!·.isEmpty) && nodes.eraseDups == nodes)
        "invalid retirement node set"
      checked write metadata.configuration.isNone
        "cleanup_nodes with configuration metadata"
      pure
        (.transaction (← requestId write)
          { retirementConfirmations := (← modelMembers write nodes) })
    else
      pure (.transaction (← requestId write) metadata)
  let heartbeat (write : Event) :=
    event "send_append_entries" (source := some write)
      fun e => do
        let oldLength ← read write (nat write.state "last_idx")
        let packet ← read e (field e.message "packet")
        checked e
          ((← read e (nat e.state "last_idx")) == oldLength
            && (← read e (nat packet "prev_idx")) == oldLength
            && (← read e (nat packet "idx")) == oldLength
            && (← read e (nat e.message "sent_idx")) == oldLength + 1
            && (← read e (nat e.message "match_idx")) == 0)
          "unsupported configuration event heartbeat"
        return (
          e,
          ← read e (string e.message "to_node_id"),
          ← read e (nat e.message "sent_idx"),
          ← read e (nat e.message "match_idx")
        )
  let newPeerHeartbeats (write config : Event) (nodes : List String) := do
    let previous ← activePeers config
    let added := nodes.filter fun node => node != write.node && !previous.contains node
    let heartbeats ← added.mapM fun _ => heartbeat write
    checked config ((heartbeats.map (·.2.1)).mergeSort == added.mergeSort)
      "new-peer configuration event destinations differ"
    pure heartbeats
  do
    -- Consumption
    let writeEvent ← write
    let configurationEvent ← optionalRule (configuration writeEvent)
    let metadata : TransactionMetadata :=
      { configuration := configurationEvent.map (·.2.1) }
    let content ← content writeEvent metadata
    let heartbeats ←
      match configurationEvent with
      | none => pure []
      | some (config, _, nodes, _) => newPeerHeartbeats writeEvent config nodes
    let commit ← optionalRule (ruleLeaderCommit writeEvent)
    -- Emission
    emitObserve writeEvent "write-pre"
    emitAction writeEvent "atomic-append" (.local writeEvent.node (.append [content]))
    if let some (config, _, nodes, index) := configurationEvent then
      emitObserveEntry config index
        [("kind", toJson "transaction"), ("configurations", toJson [nodes])]
      emitObserveInternal config
    for (event, peer, sent, matched) in heartbeats do
      emitObserve event "configuration-event-peer"
        (some
          (Json.mkObj [("sentIndex", toJson (sent - 1)), ("matchIndex", toJson matched)]))
        [] (some peer)
      emitObservePacket event "send-post"
    if let some commit := commit then
      emitObserveLeaderCommit commit

private structure Receive where
  event : Event
  sender : String
  packet : Json

private def readReceive (e : Event) (families : List String) : Reduction Receive := do
  let sender ← read e (string e.message "from_node_id")
  let packet ← read e (field e.message "packet")
  let family ← read e (string packet "msg")
  checked e (families.contains family) "receive function/packet mismatch"
  return { event := e, sender, packet }

/-- Consumes:
become_follower, only when this receive can cause term adoption or same-term demotion
-/
private def becomeFollower (receive : Receive) : Reduction Event := do
  let current ← read receive.event (nat receive.event.state "current_view")
  let term ← read receive.event (nat receive.packet "term")
  let role ← read receive.event (string receive.event.state "leadership_state")
  let family ← read receive.event (string receive.packet "msg")
  let adopts :=
    match family with
    | "raft_append_entries" =>
        current < term
        || (current == term && ["Candidate", "PreVoteCandidate"].contains role)
    | "raft_append_entries_response" => role == "Leader" && current < term
    | "raft_request_vote"
    | "raft_request_pre_vote"
    | "raft_request_vote_response"
    | "raft_request_pre_vote_response" => current < term
    | _ => false
  unless adopts do
    failure "receive cannot cause a follower transition"
  let follower :=
    event "become_follower" (source := some receive.event)
      fun e => do
        checked e
          (optional e.facts "role" == some (toJson "follower")
            && optional e.state "current_view" == some (toJson term))
          "term adoption does not match received packet"
        return e
  follower

-- The rest of an AppendEntries receive may change the role, but not the adopted term.
private def emitObserveTermAdoption (event : Event) : Reduction Unit := do
  emitObserve event "receive-term-adoption"
    (some (Json.mkObj [("currentTerm", ← read event (field event.facts "currentTerm"))]))

private structure FollowerEvidence where
  event : Event
  entry : Option (Nat × List (String × Json)) := none

/-- Consumes:
recv_append_entries
(become_follower)?
(execute_append_entries_sync | add_configuration | commit)*
(send_append_entries_response)? -- to the sender
-/
private def ruleRecvAppendEntries : Reduction Unit :=
  let followerRole (e : Event) : Reduction Unit :=
    checked e (optional e.facts "role" == some (toJson "follower"))
      "receive event requires follower role"
  let head :=
    event "recv_append_entries"
      fun e =>
        readReceive e ["raft_append_entries"]
  let executeAppendEntries (receive : Receive) :=
    event "execute_append_entries_sync" (source := some receive.event)
      fun e => do
        checked e ((← read e (string e.message "from_node_id")) == receive.sender)
          "execute source mismatch"
        followerRole e
        return { event := e : FollowerEvidence }
  let addConfiguration (receive : Receive) :=
    event "add_configuration" (source := some receive.event)
      fun e => do
        let value ← read e (field e.message "args" >>= (field · "configuration"))
        let index ← read e (nat value "idx")
        let nodes ← read e (configurationArg e.message)
        followerRole e
        return {
          event := e,
          entry :=
            some
              (
                index,
                [("kind", toJson "transaction"), ("configurations", toJson [nodes])]
              ) : FollowerEvidence
        }
  let commitFollower (receive : Receive) :=
    event "commit" (source := some receive.event)
      fun e => do
        let index ← read e (field e.message "args" >>= (nat · "idx"))
        followerRole e
        return {
          event := e,
          entry :=
            some (index, [("kind", toJson "signature"), ("committed", toJson true)]) : FollowerEvidence
        }
  let response (receive : Receive) :=
    event "send_append_entries_response" (source := some receive.event)
      fun e => do
        checked e ((← read e (string e.message "to_node_id")) == receive.sender)
          "response destination mismatch"
        return e
  do
    -- Consumption
    let receive ← head
    let follower ← optionalRule (becomeFollower receive)
    let events ←
      many
        (executeAppendEntries receive
          <|> addConfiguration receive
          <|> commitFollower receive)
    let responseEvent ← optionalRule (response receive)
    -- Emission
    emitObserve receive.event "receive-pre"
    -- The effects of this are evident in the next event after receive
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveTermAdoption follower
    for evidence in events do
      if let some (index, fields) := evidence.entry then
        emitObserveEntry evidence.event index fields
      emitObserveInternal evidence.event
    if let some responseEvent := responseEvent then
      emitObserve responseEvent "receive-post"
      emitObservePacket responseEvent "response-post"

/-- Consumes:
recv_append_entries_response
(become_follower)?
(ruleLeaderCommit)?
-/
private def ruleRecvAppendEntriesResponse : Reduction Unit :=
  let head :=
    event "recv_append_entries_response"
      fun e =>
        readReceive e ["raft_append_entries_response"]
  do
    -- Consumption
    let receive ← head
    let follower ← optionalRule (becomeFollower receive)
    let commit ← optionalRule (ruleLeaderCommit receive.event)
    -- Emission
    emitObserve receive.event "receive-pre"
    emitObservePeerProgress receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveTermAdoption follower
    if let some commit := commit then
      emitObserveLeaderCommit commit

/-- Consumes:
recv_request_vote, carrying a vote or pre-vote request
(become_follower)?
(send_request_vote_response)? -- matching the request family and sender
-/
private def ruleRecvRequestVote : Reduction Unit :=
  let response (receive : Receive) :=
    event "send_request_vote_response" (source := some receive.event)
      fun e => do
        let packet ← read e (field e.message "packet")
        let family ← read receive.event (string receive.packet "msg")
        checked e
          ((← read e (string e.message "to_node_id")) == receive.sender
            && (← read e (string packet "msg")) == family ++ "_response")
          "vote response does not match request"
        return e
  let head :=
    event "recv_request_vote"
      fun e =>
        readReceive e ["raft_request_vote", "raft_request_pre_vote"]
  do
    -- Consumption
    let receive ← head
    let follower ← optionalRule (becomeFollower receive)
    let responseEvent ← optionalRule (response receive)
    -- Emission
    emitObserve receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveTermAdoption follower
    if let some responseEvent := responseEvent then
      emitObserve responseEvent "receive-post"
      emitObservePacket responseEvent "response-post"

/-- Consumes:
recv_propose_request_vote
(become_follower)?
(becomeCandidate)?
-/
private def ruleRecvProposeRequestVote : Reduction Unit :=
  let head :=
    event "recv_propose_request_vote"
      fun e =>
        readReceive e ["raft_propose_request_vote"]
  do
    -- Consumption
    let receive ← head
    let follower ← optionalRule (becomeFollower receive)
    let election ← optionalRule (becomeCandidate receive.event)
    -- Emission
    emitObserve receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveTermAdoption follower
    if let some election := election then
      emitObserveElection election

/-- Consumes:
recv_request_vote_response, carrying a vote or pre-vote response
(become_follower)?
(becomeCandidate | ruleBecomeLeader)?
-/
private def ruleRecvRequestVoteResponse : Reduction Unit :=
  let head :=
    event "recv_request_vote_response"
      fun e =>
        readReceive e ["raft_request_vote_response", "raft_request_pre_vote_response"]
  let promotion (receive : Receive) := do
    let promotion ← ruleBecomeLeader receive.event
    return { promotion := some promotion, requests := [] : Election }
  do
    -- Consumption
    let receive ← head
    let follower ← optionalRule (becomeFollower receive)
    let election ← optionalRule (becomeCandidate receive.event <|> promotion receive)
    -- Emission
    emitObserve receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveTermAdoption follower
    if let some election := election then
      emitObserveElection election

/-- Consumes:
become_pre_vote_candidate
(
  become_candidate (ruleBecomeLeader)? send_request_vote* -- for self quorum
  | send_request_vote* -- pre-vote packets for the other active members
)
-/
private def ruleElectionTimeout : Reduction Unit :=
  let preCandidate :=
    event "become_pre_vote_candidate"
      fun e => do
        checked e (optional e.facts "role" == some (toJson "preVoteCandidate"))
          "election boundary role must be preVoteCandidate"
        return e
  let selfQuorum (head : Event) := do
    event "become_candidate" (source := some head) fun _ => pure ()
    let promotion ← optionalRule (ruleBecomeLeader head)
    let requests ← electionRequests head "raft_request_vote" true
    return { promotion, requests : Election }
  let requests (head : Event) := do
    let requests ← electionRequests head "raft_request_pre_vote" false
    return { promotion := none, requests : Election }
  do
    -- Consumption
    let head ← preCandidate
    let election ← selfQuorum head <|> requests head
    -- Emission
    emitObserve head "election-pre" none
      [("role", "event follows role assignment; the reduction checks the transition")]
    emitAction head "atomic-election" (.local head.node (.timeout .election))
    emitObserveElection election

/-- Consumes:
become_follower
-/
private def ruleCheckQuorumTimeout : Reduction Unit :=
  let follower :=
    event "become_follower"
      fun e => do
        return e
  do
    -- Consumption
    let head ← follower
    -- Emission
    emitObserve head "check-quorum-pre" none
      [("role", "event follows role assignment; the reduction checks the transition")]
    emitAction head "role-post" (.local head.node (.timeout .checkQuorum))
    emitObserve head "role-post"

/-- Consumes:
send_append_entries, with packet prev_idx equal to recorded sent_idx
-/
private def ruleSend : Reduction Unit :=
  let send :=
    event "send_append_entries"
      fun e => do
        let packet ← read e (field e.message "packet")
        checked e
          ((← read e (nat packet "prev_idx")) == (← read e (nat e.message "sent_idx")))
          "send prev_idx differs from sent_idx"
        let destination ← modelNode e (← read e (string e.message "to_node_id"))
        return (e, destination, ← read e (nat packet "idx"))
  do
    -- Consumption
    let (head, destination, last) ← send
    -- Emission
    emitObserve head "send-pre"
    emitObservePeerProgress head "send-pre"
    emitAction head "atomic-send" (.local head.node (.sendEntries destination last))
    emitObservePacket head "send-post"

/-- Consumes:
step_down_and_nominate_successor, from a nominate_successor command
-/
private def ruleNomination : Reduction Unit :=
  let nomination :=
    event "step_down_and_nominate_successor"
      fun e => do
        checked e
          ((← read e (string e.command.value "cmd")).startsWith "nominate_successor,")
          "nomination outside a nominate_successor command"
        return e
  do
    -- Consumption
    let head ← nomination
    -- Emission
    emitObserve head "nomination"
    emitAction head "nomination" (.local head.node .nominateSuccessor)
    emitObserveProposal head "nomination-message"

/-- Consumes:
drop_pending_to
-/
private def ruleDrop : Reduction Unit :=
  let drop :=
    event "drop_pending_to"
      fun e => do
        checked e ((← read e (string e.message "from_node_id")) == e.node)
          "drop sender mismatch"
        return (e, ← read e (string e.message "to_node_id"))
  do
    -- Consumption
    let (head, destination) ← drop
    -- Emission
    emitObserve head "drop"
    emitObservePacket head "drop" .head
    emitAction head "drop" (.drop head.node destination)

private def reductionRules : Reduction Unit :=
  attempt ruleAppend
  -- Receive rules
  <|> attempt ruleRecvAppendEntries
  <|> attempt ruleRecvAppendEntriesResponse
  <|> attempt ruleRecvRequestVote
  <|> attempt ruleRecvProposeRequestVote
  <|> attempt ruleRecvRequestVoteResponse
  -- Async rules
  <|> attempt ruleElectionTimeout
  <|> attempt ruleCheckQuorumTimeout
  <|> attempt ruleSend
  <|> attempt ruleNomination
  <|> attempt ruleDrop

private def trace : Reduction String := do
  let leader ← ruleBootstrap
  many_ reductionRules
  if let some event ← peek then
    failure s!"{event.record.location}: ungrouped event {event.function}"
  return leader

/-- Consumes every event exactly once; an ungrouped event is never a stutter. -/
def reduce (events : Array Event) (header : Header)
    : Except String (String × Array Instruction) := do
  let (leader, state) ← CCF.Parsec.run events (trace.run { header })
  return (leader, state.instructions)

end CCFRaft.Replay.Reducer
