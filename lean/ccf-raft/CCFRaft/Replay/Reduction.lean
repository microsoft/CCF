module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Input

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
  emitInstruction (.action step (event.origin rule))

private def emitObserveEntry (event : Event) (index : Nat)
    (fields : List (String × Json)) (rule : String := "event-entry")
    : Reduction Unit := do
  emitInstruction
    (.observe (observeEntry (← get).header event.node index (Json.mkObj fields))
      (event.origin rule))

private def emitObserveState (event : Event) (rule : String)
    (fields : List (String × Json))
    (peer : Option String := none) (frontier : Option Nat := none)
    : Reduction Unit := do
  let origin := event.origin rule
  if let some frontier := frontier then
    checked event peer.isNone "pre-commit observation cannot select a peer"
    emitInstruction
      (.observe
        (observeBeforeCommit (← get).header event.node frontier (Json.mkObj fields))
        origin)
  else
    emitInstruction
      (.observe (observeState (← get).header event.node peer (Json.mkObj fields)) origin)

/-- Check every supported snapshot field except explicit native-phase exclusions. -/
private def emitObserveSnapshot (event : Event) (rule : String)
    (exclusions : List String := []) (frontier : Option Nat := none)
    (withPeer : Bool := false)
    : Reduction Unit := do
  let mut fields := []
  for key
      in [
        "leadership_state",
        "current_view",
        "last_idx",
        "commit_idx",
        "membership_state"
      ] do
    unless exclusions.contains key do
      fields := fields ++ [(key, ← read event (field event.state key))]
  for key
      in [
        "retirement_phase",
        "retirement_idx",
        "retirement_committable_idx",
        "retired_committed_idx"
      ] do
    fields := fields ++ [(key, (optional event.state key).getD .null)]
  if let some markers := optional event.state "committable_indices" then
    fields := fields ++ [("committable_indices", markers)]
  if let some configurations := optional event.message "configurations" then
    fields := fields ++ [("configurations", configurations)]
  let peer ←
    if withPeer then
      read event do
        if let some value := optional event.message "to_node_id" then
          some <$> text value
        else
          some <$> string event.message "from_node_id"
    else
      pure none
  if withPeer then
    for key in ["sent_idx", "match_idx"] do
      unless exclusions.contains key do
        fields := fields ++ [(key, ← read event (field event.message key))]
  emitObserveState event rule (fields.filter fun (key, _) => !exclusions.contains key)
    peer frontier

private def emitObservePacket (event : Event) (rule : String)
    (selection : PacketSelection := .latest) (expected : Option Json := none)
    : Reduction Unit := do
  let destination ← read event (string event.message "to_node_id")
  let packet ←
    match expected with
    | some packet => pure packet
    | none => read event (field event.message "packet")
  emitInstruction
    (.observe (observeMessage (← get).header event.node destination packet selection)
      (event.origin rule))

private def emitObserveProposal (event : Event) (rule : String) : Reduction Unit := do
  let term ← read event (nat event.state "current_view")
  emitObservePacket event rule
    (expected :=
      some
        (Json.mkObj [("msg", toJson "raft_propose_request_vote"), ("term", toJson term)]))

/-- Entry facts survive the rest of a receive even when its caches and frontier change. -/
private def emitObserveEntryEvidence (event : Event) : Reduction Unit := do
  if let some markers := optional event.state "committable_indices" then
    for marker in ← read event markers.getArr? do
      emitObserveEntry event (← read event (natural marker))
        [("kind", toJson "signature")] "signature-marker"
  let committed ← read event (nat event.state "commit_idx")
  if committed > 0 then
    emitObserveEntry event committed
      [("kind", toJson "signature"), ("committed", toJson true)]
      "event-committed-prefix"
  if let some configurations := optional event.message "configurations" then
    for value in ← read event configurations.getArr? do
      emitObserveEntry event (← read event (nat value "idx"))
        [
          ("kind", toJson "transaction"),
          ("configurations", toJson [← read event (configuration value)])
        ]
        "event-configuration"

/-- Consumes:
step_down_and_nominate_successor
-/
private def retirementNomination (commit : Event) : Reduction Event :=
  let nomination :=
    event "step_down_and_nominate_successor" (source := some commit)
      fun e => do
        let target ← read commit (nat commit.message "idx")
        let confirmation ← read e (nat e.state "retired_committed_idx")
        checked e
          (optional e.state "leadership_state" == some (toJson "Leader")
            && optional e.state "membership_state" == some (toJson "Retired")
            && optional e.state "retirement_phase" == some (toJson "Completed")
            && optional e.state "commit_idx" == some (toJson target)
            && confirmation > 0
            && confirmation <= target)
          "unexpected terminal-retirement nomination boundary"
        let configurations (event : Event) :=
          read event do
            match optional event.message "configurations" with
            | none => pure none
            | some values =>
                some
                <$> (← values.getArr?).toList.mapM
                      fun value => do
                        return (← nat value "idx", ← configuration value)
        checked e
          ((← configurations e) == (← configurations commit))
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
        let previous ← read anchor (nat anchor.state "commit_idx")
        let target ← read e (nat e.message "idx")
        return (e, previous, target)
  do
    let (e, previous, target) ← commit
    let nomination ← optionalRule (retirementNomination e)
    return { event := e, previous, target, nomination }

private def emitObserveLeaderCommit (evidence : LeaderCommit) : Reduction Unit := do
  let ⟨commit, previous, target, nomination⟩ := evidence
  -- The callback precedes terminal role clearing; the grammar checks its leader role.
  emitObserveSnapshot commit "commit-in-action" ["leadership_state"]
    (frontier := some previous)
  -- The callback's target is an output coordinate, not a post-commit node snapshot.
  emitObserveState commit "commit-target" [("commit_idx", toJson target)]
  if let some nomination := nomination then
    emitObserveProposal nomination "terminal-nomination-message"
    -- The grammar checks the pre-clearing role/phase and pre-pruning cache.
    emitObserveSnapshot nomination "terminal-nomination-post"
      ["leadership_state", "membership_state", "retirement_phase", "configurations"]

private def activePeers (event : Event) : Reduction (List String) := do
  let configurations ← read event (field event.message "configurations" >>= Json.getArr?)
  let nodes ← configurations.toList.mapM fun value => read event (configuration value)
  return (nodes.flatten.eraseDups.filter (· != event.node)).mergeSort

/-- Consumes:
send_request_vote, with the requested vote or pre-vote packet family
-/
private def voteRequest (head : Event) (family : String) : Reduction Event :=
  let request :=
    event "send_request_vote" (source := some head)
      fun e => do
        let packet ← read e (field e.message "packet")
        checked e ((← read e (string packet "msg")) == family) "wrong vote request packet"
        return e
  request

/-- Consumes:
send_request_vote*, with the requested vote or pre-vote packet family
-/
private def electionRequests (head : Event) (family : String) (selfQuorum : Bool)
    : Reduction (List Event) := do
  let requests ← many (voteRequest head family)
  if selfQuorum then
    checked head (← activePeers head).isEmpty
      "self-quorum promotion with other active members"
  return requests

private structure Leadership where
  event : Event
  commit : Option LeaderCommit
  heartbeats : List Event

/-- Consumes:
become_leader
(ruleLeaderCommit)?
send_append_entries*, with distinct destinations
The next send to an already observed destination is left for a later rule.
-/
private def ruleBecomeLeader (anchor : Event) : Reduction Leadership :=
  let promotion :=
    event "become_leader" (source := some anchor)
      fun e => do
        checked e (optional e.state "leadership_state" == some (toJson "Leader"))
          "promotion role must be leader"
        return e
  let heartbeat (leader : Event) :=
    event "send_append_entries" (source := some leader)
      fun e => do
        let packet ← read e (field e.message "packet")
        let previous ← read e (nat packet "prev_idx")
        let last ← read e (nat e.state "last_idx")
        checked e (previous == last && (← read e (nat packet "idx")) == last)
          "not a leadership heartbeat"
        let destination ← read e (string e.message "to_node_id")
        return (e, destination)
  do
    let leader ← promotion
    let commit ← optionalRule (ruleLeaderCommit anchor)
    -- Native peers also include retired nodes absent from the active configurations.
    let mut heartbeats : List (Event × String) := []
    for _ in (← get).header.declared do
      let seen := heartbeats.map (·.2)
      let next ←
        optionalRule do
          let (event, destination) ← heartbeat leader
          checked event (!seen.contains destination)
            "duplicate leadership heartbeat destination"
          return (event, destination)
      let some next := next | break
      heartbeats := heartbeats ++ [next]
    return { event := leader, commit, heartbeats := heartbeats.map (·.1) }

private structure Election where
  candidate : Option Event := none
  promotion : Option Leadership
  requests : List Event

/-- Consumes:
become_candidate
(ruleBecomeLeader)? -- for self quorum
send_request_vote*, with vote packets
-/
private def becomeCandidate (anchor : Event) : Reduction Election :=
  let candidate :=
    event "become_candidate" (source := some anchor)
      fun e => do
        checked e (optional e.state "leadership_state" == some (toJson "Candidate"))
          "candidate role must be candidate"
        return e
  do
    let candidateEvent ← candidate
    let promotion ← optionalRule (ruleBecomeLeader anchor)
    let requests ← electionRequests candidateEvent "raft_request_vote" promotion.isSome
    return { candidate := some candidateEvent, promotion, requests }

-- Emit observations of promotion, commits, heartbeats and vote requests, not model actions.
private def emitObserveElection (election : Election) : Reduction Unit := do
  if let some candidate := election.candidate then
    match election.promotion with
    | none => emitObserveSnapshot candidate "candidate-post"
    | some promotion =>
        -- Promotion changes role and truncates unsigned entries, which may contain
        -- configurations or an unsigned retirement. Signatures survive truncation;
        -- a synchronous commit is observed at its independently checked old frontier.
        emitObserveSnapshot candidate "candidate-in-election"
          [
            "leadership_state",
            "last_idx",
            "configurations",
            "membership_state",
            "retirement_phase",
            "retirement_idx"
          ] (frontier := promotion.commit.map (·.previous))
  if let some promotion := election.promotion then
    let ⟨leader, commit, heartbeats⟩ := promotion
    -- Promotion is post-rollback but pre-commit. Only a subsequent commit can
    -- clear its recorded leader role; the grammar checks that intermediate phase.
    emitObserveSnapshot leader "leader-post"
      (if commit.isSome then ["leadership_state"] else [])
      (frontier := commit.map (·.previous))
    if let some commit := commit then
      emitObserveLeaderCommit commit
    for heartbeat in heartbeats do
      emitObserveSnapshot heartbeat "leader-heartbeat-post" (withPeer := true)
      emitObservePacket heartbeat "send-post"
  for request in election.requests do
    emitObserveSnapshot request "send-post"
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
          ((← read e (field e.command.value "msg" >>= (string · "cmd")))
            == s!"start_node,{e.node}")
          "expected bootstrap start_node command"
        leading e.node e
        for key
            in [
              "retirement_idx",
              "retirement_committable_idx",
              "retired_committed_idx"
            ] do
          checked e ((optional e.state key).getD .null == .null)
            s!"bootstrap {key} must be absent"
        checked e (optional e.message "configurations" == some (toJson ([] : List Json)))
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
        return e
  let genesisConfiguration (leader : String) :=
    event "add_configuration"
      fun e => do
        leading leader e
        checked e ((← read e (configuration e.message)) == [leader])
          "bootstrap is not singleton"
        checked e ((← read e (nat e.message "idx")) == 1) "bootstrap configuration index"
        return e
  do
    -- Consumption
    let leaderEvent ← becomeLeader
    let leader := leaderEvent.node
    let writeEvent ← genesisWrite leader
    let configurationEvent ← genesisConfiguration leader
    -- Emission
    -- Genesis is preloaded, so the recorded empty log and pre-genesis configuration
    -- cache cannot match it. Every other state field is unchanged by initialization.
    for event in [leaderEvent, writeEvent, configurationEvent] do
      emitObserveSnapshot event "bootstrap-state" ["last_idx", "configurations"]
    emitObserveEntry configurationEvent 1
      [("kind", toJson "transaction"), ("configurations", toJson [[leader]])]
    return leader

/-- Consumes the driver's singleton BatchVector and its synchronous effects:
replicate
(add_configuration)?
send_append_entries*, for observed new-peer constructor heartbeats
(ruleLeaderCommit)? -- possibly including retirement nomination
-/
private def ruleAppend : Reduction Unit :=
  let write := event "replicate" fun e => pure e
  let configuration (write : Event) :=
    event "add_configuration" (source := some write)
      fun e => do
        checked e
          ((← read e (nat e.message "idx")) == (← read write (nat write.message "seqno"))
            && !(← read write (boolean write.message "globally_committable")))
          "configuration write pair mismatch"
        let nodes ← read e (configuration e.message)
        return (e, ← modelMembers e nodes, nodes, ← read e (nat e.message "idx"))
  let content (write : Event) (metadata : TransactionMetadata)
      : Reduction EntryContent := do
    let command ← read write (field write.command.value "msg" >>= (string · "cmd"))
    if ← read write (boolean write.message "globally_committable") then
      pure EntryContent.signature
    else if command.startsWith "cleanup_nodes," then do
      let nodes := command.splitOn "," |>.drop 2
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
      | some _ => many (heartbeat writeEvent)
    let commit ← optionalRule (ruleLeaderCommit writeEvent)
    -- Emission
    emitObserveSnapshot writeEvent "write-pre"
    if let some (config, _, _, _) := configurationEvent then
      emitObserveSnapshot config "configuration-pre"
    emitAction writeEvent "atomic-append" (.local writeEvent.node (.append [content]))
    -- The snapshot is pre-append; only these output coordinates describe the new log.
    emitObserveState writeEvent "write-post"
      [
        ("last_idx", ← read writeEvent (field writeEvent.message "seqno")),
        ("current_view", ← read writeEvent (field writeEvent.message "view"))
      ]
    if let some (config, _, nodes, index) := configurationEvent then
      -- Configuration arguments describe the new entry, not a post-append snapshot.
      emitObserveEntry config index
        [("kind", toJson "transaction"), ("configurations", toJson [nodes])]
    for (event, peer, sent, matched) in heartbeats do
      -- The hook has applied the configuration but not appended its log entry.
      -- A later commit may clear leadership; observe the remaining fields before it.
      emitObserveSnapshot event "configuration-event-state"
        ("last_idx" :: if commit.isSome then ["leadership_state"] else [])
        (frontier := commit.map (·.previous))
      -- Native constructor progress uses a next-index sentinel, not a sent frontier.
      emitObserveState event "configuration-event-peer"
        [("sent_idx", toJson (sent - 1)), ("match_idx", toJson matched)] (some peer)
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
          (optional e.state "leadership_state" == some (toJson "Follower")
            && optional e.state "current_view" == some (toJson term))
          "term adoption does not match received packet"
        return e
  follower

private def emitObserveAppendEntriesState (receive : Receive) (event : Event)
    : Reduction Unit := do
  let previous ← read receive.event (nat receive.event.state "commit_idx")
  -- Only supplied coordinates justify stronger checks. The preceding delivery
  -- checks the packet against the model; malformed coordinates still fail there.
  let last := (receive.packet.getObjValAs? Nat "idx").toOption
  let logUnchanged :=
    match last, (receive.packet.getObjValAs? Nat "prev_idx").toOption with
    | some last, some previous => last == previous
    | _, _ => false
  if logUnchanged && event.function == "commit" then
    -- With no entries to apply, this is the only commit and its old frontier
    -- comes from the checked receive head. Only committing can clear the role.
    emitObserveSnapshot event "receive-internal" ["leadership_state"]
      (frontier := some previous)
    emitObserveState event "receive-commit-target"
      [("commit_idx", ← read event (field event.message "idx"))]
    return
  let commitUnchanged :=
    match last, (receive.packet.getObjValAs? Nat "leader_commit_idx").toOption with
    | some last, some leaderCommit => min last leaderCommit <= previous
    | _, _ => false
  -- Commit can clear the role and latch retirement confirmation. Log changes
  -- affect length and removal coordinates; caches and phase depend on both.
  let exclusions :=
    (if commitUnchanged then
        []
      else
        ["leadership_state", "commit_idx", "retired_committed_idx"])
    ++ (if logUnchanged then
          []
        else
          [
            "last_idx",
            "membership_state",
            "retirement_idx",
            "retirement_committable_idx"
          ])
    ++ (if logUnchanged && commitUnchanged then
          []
        else
          ["committable_indices", "configurations", "retirement_phase"])
  emitObserveSnapshot event "receive-internal" exclusions

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
    checked e (optional e.state "leadership_state" == some (toJson "Follower"))
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
        let index ← read e (nat e.message "idx")
        let nodes ← read e (configuration e.message)
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
        let index ← read e (nat e.message "idx")
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
    emitObserveSnapshot receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveAppendEntriesState receive follower
    for evidence in events do
      if let some (index, fields) := evidence.entry then
        emitObserveEntry evidence.event index fields
      emitObserveAppendEntriesState receive evidence.event
      emitObserveEntryEvidence evidence.event
    if let some responseEvent := responseEvent then
      emitObserveSnapshot responseEvent "receive-post"
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
    emitObserveSnapshot receive.event "receive-pre" (withPeer := true)
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveSnapshot follower "receive-term-adoption"
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
    emitObserveSnapshot receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveSnapshot follower "receive-term-adoption"
    if let some responseEvent := responseEvent then
      emitObserveSnapshot responseEvent "receive-post"
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
    emitObserveSnapshot receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveSnapshot follower "receive-term-adoption"
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
    emitObserveSnapshot receive.event "receive-pre"
    emitAction receive.event "atomic-receive"
      (.receive receive.sender receive.event.node receive.packet)
    if let some follower := follower then
      emitObserveSnapshot follower "receive-term-adoption"
    if let some election := election then
      emitObserveElection election

/-- Consumes:
become_pre_vote_candidate
(
  become_candidate (ruleBecomeLeader)? send_request_vote* -- for self quorum
  | send_request_vote* -- pre-vote packets
)
-/
private def ruleElectionTimeout : Reduction Unit :=
  let preCandidate :=
    event "become_pre_vote_candidate"
      fun e => do
        checked e
          (optional e.state "leadership_state" == some (toJson "PreVoteCandidate"))
          "election boundary role must be preVoteCandidate"
        return e
  let selfQuorum (head : Event) := do
    let election ← becomeCandidate head
    checked head (← activePeers head).isEmpty
      "self-quorum promotion with other active members"
    return election
  let requests (head : Event) := do
    let requests ← electionRequests head "raft_request_pre_vote" false
    return { promotion := none, requests : Election }
  do
    -- Consumption
    let head ← preCandidate
    let election ← selfQuorum head <|> requests head
    -- Emission
    -- The callback follows role assignment; the grammar checks the transition.
    emitObserveSnapshot head "election-pre" ["leadership_state"]
    emitAction head "atomic-election" (.local head.node (.timeout .election))
    -- With other active members, the self-vote cannot advance beyond pre-vote.
    -- This depends on the checked configuration, not the presence of later telemetry.
    unless (← activePeers head).isEmpty do
      emitObserveSnapshot head "election-post"
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
    -- The callback follows role assignment; the grammar checks the transition.
    emitObserveSnapshot head "check-quorum-pre" ["leadership_state"]
    emitAction head "role-post" (.local head.node (.timeout .checkQuorum))
    emitObserveSnapshot head "role-post"

/-- Consumes:
send_append_entries
-/
private def ruleSend : Reduction Unit :=
  let send :=
    event "send_append_entries"
      fun e => do
        let packet ← read e (field e.message "packet")
        let destination ← modelNode e (← read e (string e.message "to_node_id"))
        return (e, destination, ← read e (nat packet "idx"))
  do
    -- Consumption
    let (head, destination, last) ← send
    -- Emission
    emitObserveSnapshot head "send-pre" (withPeer := true)
    emitAction head "atomic-send" (.local head.node (.sendEntries destination last))
    -- Sending changes only this peer's sent index, not the other recorded fields.
    emitObserveSnapshot head "send-post-state" ["sent_idx"] (withPeer := true)
    emitObservePacket head "send-post"

/-- Consumes:
step_down_and_nominate_successor, from a nominate_successor command
-/
private def ruleNomination : Reduction Unit :=
  let nomination :=
    event "step_down_and_nominate_successor"
      fun e => do
        checked e
          ((← read e (field e.command.value "msg" >>= (string · "cmd"))).startsWith
            "nominate_successor,")
          "nomination outside a nominate_successor command"
        return e
  do
    -- Consumption
    let head ← nomination
    -- Emission
    emitObserveSnapshot head "nomination"
    emitAction head "nomination" (.local head.node .nominateSuccessor)
    -- Sending the proposal leaves the recorded node state unchanged.
    emitObserveSnapshot head "nomination-post"
    emitObserveProposal head "nomination-message"

/-- Consumes:
drop_pending_to
-/
private def ruleDrop : Reduction Unit :=
  let drop :=
    event "drop_pending_to"
      fun e => do
        return (e, ← read e (string e.message "to_node_id"))
  do
    -- Consumption
    let (head, destination) ← drop
    -- Emission
    let sender ← read head (string head.message "from_node_id")
    emitInstruction
      (.observe (fun _ => require (sender == head.node) "drop sender mismatch")
        (head.origin "drop-sender"))
    emitObserveSnapshot head "drop"
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

namespace CCFRaft.Replay

/-- Prepared initialization and instructions for direct model replay. -/
structure Reduced where
  header : Header
  instructions : Array Instruction

/-- Prepare replay identities and reduce the associated event stream. -/
def reduce (events : Array Event) (declared : List String) : Except String Reduced := do
  let locations :=
    (events.toList.filter (fun event => event.function == "replicate")).map
      (·.record.location)
  require (locations.eraseDups == locations) "duplicate transaction source location"
  let requests := "" :: locations
  let header : Header := { bootstrap := ∅, declared, requests }
  let (leader, instructions) ← Reducer.reduce events header
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, instructions }

end CCFRaft.Replay
