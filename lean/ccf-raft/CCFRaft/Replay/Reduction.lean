module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Replay.Input

import CCF.Parsec

public section

/-!
Rules peek action arguments, consume named events, and emit direct model actions.
Explicit native boundaries distinguish callbacks from subsequent actions.
After bootstrap, each rule observes its native group's starting snapshot before emitting actions.
Reduction never executes or repairs model state.
-/

namespace CCFRaft.Replay.Reducer

open Lean Model.Node
open CCF.Parsec (failure validated attempt many_ optional_)

private structure ReductionState where
  header : Header
  nextRequestId : ReqID := 1
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

private def modelNode (event : Event) (name : String) : Reduction NodeID := do
  liftExcept event ((← get).header.nodeId name)

private def modelMembers (event : Event) (names : List String)
    : Reduction (Finset NodeID) := do
  return (← names.mapM (modelNode event)).toFinset

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
  event head "add_configuration"
  return head.node

private def ruleCommit (head : Event) : Reduction Unit := do
  let commit ← peek
  event head "commit"
  let index ← readJson commit commit.message (nat · "idx")
  let retirements ←
    CCF.Parsec.many do
      let hook ← peek
      event head "retired_committed"
      let seqno ← readJson hook hook.message (nat · "seqno")
      let names ←
        readJson hook hook.message
          fun message => do
            (← (← field message "node_ids").getArr?).toList.mapM text
      let nodes ← names.mapM (modelNode hook)
      liftExcept hook do
        require ((← nat hook.state "commit_idx") == index)
          "retirement hook must observe the advanced commit index"
      optional_ (event head "step_down_and_nominate_successor")
      pure { commitIndex := index, seqno, nodes : RetirementObservation }
  -- Enqueue retirement inputs separately rather than adding the possibility
  -- of retirement to every action's arguments.
  unless retirements.isEmpty do
    emitAction commit "commit-retirements"
      (.local head.node (.retirementObservations retirements))

private def readAppendContent (head : Event) (config : Option Event)
    : Reduction EntryContent := do
  let signature ← readJson head head.message (boolean · "globally_committable")
  let configuration ←
    match config with
    | some config => do
        liftExcept config do
          require
            (!signature && (← nat config.message "idx") == (← nat head.message "seqno"))
            "configuration write pair mismatch"
        some <$> modelMembers config (← readJson config config.message configuration)
    | none => pure none
  if signature then
    return .signature
  else
    let request := (← get).nextRequestId
    modify fun s => { s with nextRequestId := request + 1 }
    return .transaction request { configuration }

private def ruleAppend : Reduction Unit := do
  let head ← peek
  -- consume
  event head "replicate"
  let config ←
    CCF.Parsec.optionalRule do
      let config ← peek
      event head "add_configuration"
      many_ (event head "send_append_entries")
      return config
  let flushes ←
    CCF.Parsec.optionalRule do
      event head "batch_flush"
      CCF.Parsec.many do
        let next ← peek
        event head "send_append_entries"
        let packet ← readJson next next.message (field · "packet")
        let destination ←
          modelNode next (← readJson next next.message (string · "to_node_id"))
        let last ← readJson next packet (nat · "idx")
        return (destination, last)
  optional_ (ruleCommit head)
  -- emit
  emitObserve head "append"
  emitAction head "append"
    (.local head.node
      (.append
        [{ content := (← readAppendContent head config), flushes := flushes.getD [] }]))

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
      <|> ruleCommit head)
  optional_ (event head "send_append_entries_response")
  -- emit
  emitObserve head "recv-append-entries"
  emitAction head "recv-append-entries" action

private def ruleRecvAppendEntriesResponse : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_append_entries_response"]
  -- consume
  event head "recv_append_entries_response"
  optional_ (event head "become_follower")
  optional_ (ruleCommit head)
  -- emit
  emitObserve head "recv-append-entries-response"
  emitAction head "recv-append-entries-response" action

private def ruleRecvRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_request_vote", "raft_request_pre_vote"]
  -- consume
  event head "recv_request_vote"
  optional_ (event head "become_follower")
  optional_ (event head "send_request_vote_response")
  -- emit
  emitObserve head "recv-request-vote"
  emitAction head "recv-request-vote" action

private def ruleRecvProposeRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["raft_propose_request_vote"]
  -- consume
  event head "recv_propose_request_vote"
  optional_ do
    event head "become_candidate"
    optional_ do
      event head "become_leader"
      optional_ (ruleCommit head)
      many_ (event head "send_append_entries")
    many_ (event head "send_request_vote")
  -- emit
  emitObserve head "recv-propose-request-vote"
  emitAction head "recv-propose-request-vote" action

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
              optional_ (ruleCommit head)
              many_ (event head "send_append_entries")
            many_ (event head "send_request_vote"))
      <|> (do
            event head "become_leader"
            optional_ (ruleCommit head)
            many_ (event head "send_append_entries")))
  -- emit
  emitObserve head "recv-request-vote-response"
  emitAction head "recv-request-vote-response" action

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
        optional_ (ruleCommit head)
        many_ (event head "send_append_entries")
      many_ (event head "send_request_vote")
    many_ (event head "send_request_vote")
    -- emit
    emitObserve head "tick-election"
    emitAction head "tick-election" (.local head.node (.timeout .election))
  else
    let sends ←
      CCF.Parsec.many do
        let next ← peek
        event head "send_append_entries"
        let packet ← readJson next next.message (field · "packet")
        let destination ←
          modelNode next (← readJson next next.message (string · "to_node_id"))
        let last ← readJson next packet (nat · "idx")
        return (next, destination, last)
    let demoted ← CCF.Parsec.optionalRule (event head "become_follower")
    -- emit
    emitObserve head "tick"
    for (source, destination, last) in sends do
      emitAction source "tick-send" (.local head.node (.sendEntries destination last))
    if demoted.isSome then
      emitAction head "tick-check-quorum" (.local head.node (.timeout .checkQuorum))

private def ruleNomination : Reduction Unit := do
  let head ← peek
  -- consume
  event head "nomination"
  let nominated ← CCF.Parsec.optionalRule (event head "step_down_and_nominate_successor")
  -- emit
  emitObserve head "nomination"
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
  emitObserve head "drop"
  emitAction head "drop" (.drop head.node destination)

private def ruleStep : Reduction Unit := do
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
  let header : Header := { bootstrap := ∅, declared }
  let (leader, instructions) ← Reducer.reduce events header
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, instructions }

end CCFRaft.Replay
