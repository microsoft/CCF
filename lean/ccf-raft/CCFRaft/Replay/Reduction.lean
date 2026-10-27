module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Input

import CCF.Parsec

public section

/-!
Rules peek action arguments, consume named events, and emit direct model actions.
Explicit native boundaries distinguish callbacks from subsequent actions.
The dispatcher observes each native group's starting snapshot; individual rules only emit actions.
Reduction never executes or repairs model state.
-/

namespace CCFRaft.Replay.Reducer

open Lean Model.Node
open CCF.Parsec (failure validated attempt many_ optional_)

private structure ReductionState where
  header : Header
  instructions : Array Instruction := #[]

private abbrev Reduction := CCF.Parsec.ParserT Event ReductionState

private def liftExcept {α : Type} (event : Event) (result : Except String α)
    : Reduction α :=
  validated
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

private def readJson {α : Type} (event : Event) (value : Json)
    (decode : Json → Except String α)
    : Reduction α :=
  liftExcept event (decode value)

private def peek : Reduction Event := do
  let some event ← CCF.Parsec.peek | failure "unexpected end of input"
  return event

private def event (source : Event) (name : String) : Reduction Unit := do
  let next ← peek
  unless next.function == name do
    failure s!"{next.record.location}: expected {name}, got {next.function}"
  discard CCF.Parsec.take
  liftExcept next do
    require (next.node == source.node) s!"expected event on node {source.node}"
    require (next.command.location == source.command.location)
      "event group crosses a command boundary"

private def modelNode (event : Event) (name : String) : Reduction NodeID := do
  liftExcept event ((← get).header.nodeId name)

private def modelMembers (event : Event) (names : List String)
    : Reduction (Finset NodeID) := do
  return (← names.mapM (modelNode event)).toFinset

private def requestId (event : Event) : Reduction ReqID := do
  let some index := (← get).header.requests.findIdx? (· == event.record.location)
  | failure s!"{event.record.location}: undeclared request"
  return index

private def appendInstruction (instr : Instruction) : Reduction Unit :=
  modify fun s => { s with instructions := s.instructions.push instr }

private def emitAction (event : Event) (rule : String) (step : Step) : Reduction Unit :=
  appendInstruction (.action step (event.origin rule))

private def emitObserve (event : Event) (rule : String) : Reduction Unit :=
  appendInstruction (.observeNodeState event.node event.state (event.origin rule))

private def ruleBootstrap : Reduction String := do
  let head ← peek
  -- consume
  event head "become_leader"
  event head "replicate"
  let config ← peek
  liftExcept config do
    require ((← configuration config.message) == [head.node]) "bootstrap is not singleton"
  event head "add_configuration"
  return head.node

private def sendChoice (head : Event) (header : Header)
    : Except String (NodeID × Nat) := do
  let packet ← field head.message "packet"
  let destination ← header.nodeId (← string head.message "to_node_id")
  let last ← nat packet "idx"
  return (destination, last)

private def ruleAppend : Reduction Unit := do
  let head ← peek
  let signature ← readJson head head.message (boolean · "globally_committable")
  -- consume
  event head "replicate"
  let next ← CCF.Parsec.peek
  let configuration ←
    match next with
    | some config =>
        if config.function == "add_configuration" then do
          liftExcept config do
            require
              (!signature && (← nat config.message "idx") == (← nat head.message "seqno"))
              "configuration write pair mismatch"
          some <$> modelMembers config (← readJson config config.message configuration)
        else
          pure none
    | none => pure none
  let content ←
    if signature then
      pure EntryContent.signature
    else do
      let command ←
        readJson head head.command.value
          (fun value => field value "msg" >>= (string · "cmd"))
      let metadata ←
        if command.startsWith "cleanup_nodes," then do
          liftExcept head
            (require configuration.isNone "cleanup_nodes with configuration metadata")
          let nodes ← modelMembers head (command.splitOn "," |>.drop 2)
          pure { retirementConfirmations := nodes : TransactionMetadata }
        else
          pure { configuration : TransactionMetadata }
      pure (.transaction (← requestId head) metadata)

  optional_ do
    event head "add_configuration"
    many_ (event head "send_append_entries")
  let flushes ←
    CCF.Parsec.optionalRule do
      event head "batch_flush"
      CCF.Parsec.many do
        let next ← peek
        let choice := sendChoice next (← get).header
        event head "send_append_entries"
        liftExcept next choice
  optional_ do
    event head "commit"
    optional_ (event head "step_down_and_nominate_successor")
  -- emit
  emitAction head "atomic-append"
    (.local head.node (.append [{ content, flushes := flushes.getD [] }]))

private def readReceive (head : Event) (families : List String) : Reduction Step := do
  let sender ← readJson head head.message (string · "from_node_id")
  let packet ← readJson head head.message (field · "packet")
  let family ← readJson head packet (string · "msg")
  liftExcept head (require (families.contains family) "receive function/packet mismatch")
  return .receive sender head.node packet

private def ruleRecvAppendEntries : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_append_entries"]
  -- consume
  event head "recv_append_entries"
  optional_ (event head "become_follower")
  many_
    (event head "execute_append_entries_sync"
      <|> (do
            event head "add_configuration"
            many_ (event head "send_append_entries"))
      <|> (do
            event head "commit"
            optional_ (event head "step_down_and_nominate_successor")))
  optional_ (event head "send_append_entries_response")
  -- emit
  emitAction head "atomic-receive" action

private def ruleRecvAppendEntriesResponse : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_append_entries_response"]
  -- consume
  event head "recv_append_entries_response"
  optional_ (event head "become_follower")
  optional_ do
    event head "commit"
    optional_ (event head "step_down_and_nominate_successor")
  -- emit
  emitAction head "atomic-receive" action

private def ruleRecvRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_request_vote", "raft_request_pre_vote"]
  -- consume
  event head "recv_request_vote"
  optional_ (event head "become_follower")
  optional_ (event head "send_request_vote_response")
  -- emit
  emitAction head "atomic-receive" action

private def ruleRecvProposeRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_propose_request_vote"]
  -- consume
  event head "recv_propose_request_vote"
  optional_ do
    event head "become_candidate"
    optional_ do
      event head "become_leader"
      optional_ do
        event head "commit"
        optional_ (event head "step_down_and_nominate_successor")
      many_ (event head "send_append_entries")
    many_ (event head "send_request_vote")
  -- emit
  emitAction head "atomic-receive" action

private def ruleRecvRequestVoteResponse : Reduction Unit := do
  let head ← peek
  let action ←
    readReceive head ["raft_request_vote_response", "raft_request_pre_vote_response"]
  -- consume
  event head "recv_request_vote_response"
  optional_
    (event head "become_follower"
      <|> (do
            event head "become_candidate"
            optional_ do
              event head "become_leader"
              optional_ do
                event head "commit"
                optional_ (event head "step_down_and_nominate_successor")
              many_ (event head "send_append_entries")
            many_ (event head "send_request_vote"))
      <|> (do
            event head "become_leader"
            optional_ do
              event head "commit"
              optional_ (event head "step_down_and_nominate_successor")
            many_ (event head "send_append_entries")))
  -- emit
  emitAction head "atomic-receive" action

private def ruleTick : Reduction Unit := do
  let head ← peek
  -- consume
  event head "tick"
  let election ← CCF.Parsec.optionalRule (event head "become_pre_vote_candidate")
  if election.isSome then
    optional_ do
      event head "become_candidate"
      optional_ do
        event head "become_leader"
        optional_ do
          event head "commit"
          optional_ (event head "step_down_and_nominate_successor")
        many_ (event head "send_append_entries")
      many_ (event head "send_request_vote")
    many_ (event head "send_request_vote")
    -- emit
    emitAction head "atomic-election" (.local head.node (.timeout .election))
  else
    let sends ←
      CCF.Parsec.many do
        let next ← peek
        let choice := sendChoice next (← get).header
        event head "send_append_entries"
        return (next, ← liftExcept next choice)
    let demoted ← CCF.Parsec.optionalRule (event head "become_follower")
    -- emit
    for (source, destination, last) in sends do
      emitAction source "atomic-send" (.local head.node (.sendEntries destination last))
    if demoted.isSome then
      emitAction head "check-quorum" (.local head.node (.timeout .checkQuorum))

private def ruleNomination : Reduction Unit := do
  let head ← peek
  -- consume
  event head "nomination"
  let nominated ← CCF.Parsec.optionalRule (event head "step_down_and_nominate_successor")
  -- emit
  if nominated.isSome then
    emitAction head "nomination" (.local head.node .nominateSuccessor)

private def ruleDrop : Reduction Unit := do
  let head ← peek
  let destination ← readJson head head.message (string · "to_node_id")
  let sender ← readJson head head.message (string · "from_node_id")
  liftExcept head (require (sender == head.node) "drop sender mismatch")
  -- consume
  event head "drop_pending_to"
  -- emit
  emitAction head "drop" (.drop head.node destination)

private def ruleStep : Reduction Unit := do
  let head ← peek
  emitObserve head "step"
  -- Recv rules
  attempt ruleRecvAppendEntries
  <|> attempt ruleRecvAppendEntriesResponse
  <|> attempt ruleRecvRequestVote
  <|> attempt ruleRecvProposeRequestVote
  <|> attempt ruleRecvRequestVoteResponse
  -- Async rules
  <|> attempt ruleAppend
  <|> attempt ruleTick
  <|> attempt ruleNomination
  <|> attempt ruleDrop

private def ruleTrace : Reduction String := do
  let leader ← ruleBootstrap
  many_ ruleStep
  if let some event ← CCF.Parsec.peek then
    failure s!"{event.record.location}: ungrouped event {event.function}"
  return leader

/-- Consume every event exactly once; an ungrouped event is never a stutter. -/
def reduce (events : Array Event) (header : Header)
    : Except String (String × Array Instruction) := do
  let (leader, state) ← CCF.Parsec.run events (ruleTrace.run { header })
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
