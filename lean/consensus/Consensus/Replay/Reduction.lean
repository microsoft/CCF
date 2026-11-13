module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Input

import CCF.Parsec

public section

/-!
Rules peek action arguments, consume named events, and emit direct model actions.
Explicit native boundaries distinguish related events from subsequent actions.
After bootstrap, each rule observes its native group's starting snapshot before emitting actions.
Each rule that may send checks the native sends among its events against the envelopes its
actions queued.
Reduction never executes or repairs model state.
-/

namespace Consensus.Replay.Reducer

open Lean Model.Node
open CCF (Finset)
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

/-- The cursor position, from which `extractSends` finds the events a rule consumed. -/
private def position : Reduction Nat :=
  liftM (m := CCF.Parsec.Parser Event)
    ((fun input => .success input input.position) : CCF.Parsec.Parser Event Nat)

/-- Native sends among the events consumed since `start`, and proposals nominations imply. -/
private def extractSends (start : Nat) : Reduction (List NativeSend) := do
  let events ←
    liftM (m := CCF.Parsec.Parser Event)
      ((fun input => .success input (input.events.extract start input.position))
        : CCF.Parsec.Parser Event (Array Event))
  events.toList.filterMapM
    fun event => do
      let packet ←
        if event.function.startsWith "send_" then
          some <$> readJson event event.message (field · "packet")
        else if event.function == "step_down_and_nominate_successor" then
          -- Native then sends an untraced proposal in its current view.
          let term ← readJson event event.state (nat · "current_view")
          pure
            (some
              (Json.mkObj
                [("msg", toJson "propose_request_vote"), ("term", toJson term)]))
        else
          pure none
      packet.mapM
        fun packet => do
          let target ← readJson event event.message (string · "to_node_id")
          return { target, packet, origin := event.origin event.function }

private def event (source : Event) (name : String) : Reduction Unit := do
  let next ← peek
  unless next.function == name do
    failure s!"{next.record.location}: expected {name}, got {next.function}"
  liftExcept next do
    require (next.node == source.node) s!"expected event on node {source.node}"
  discard CCF.Parsec.take

private def modelNode (event : Event) (name : String) : Reduction NodeID := do
  liftExcept event ((← get).header.nodeId name)

private def modelMembers (event : Event) (names : List String)
    : Reduction (Finset NodeID) := do
  return Finset.ofList (← names.mapM (modelNode event))

private def appendInstruction (instr : Instruction) : Reduction Unit :=
  modify fun s => { s with instructions := s.instructions.push instr }

private def emitAction (event : Event) (rule : String) (step : Step) : Reduction Unit :=
  appendInstruction (.action step (event.origin rule))

private def emitObserve (event : Event) (rule : String) : Reduction Unit :=
  appendInstruction (.observeNodeState event.node event.state (event.origin rule))

private def emitObserveSends (event : Event) (sends : List NativeSend) : Reduction Unit :=
  appendInstruction (.observeSends sends (event.origin "sends"))

private def ruleBootstrap : Reduction String := do
  let head ← peek
  -- consume
  event head "become_leader"
  event head "replicate"
  event head "replicate_entry"
  event head "add_configuration"
  return head.node

private def readAppendContent (head : Event) (config : Option Event)
    (retirements : List Event)
    : Reduction EntryContent := do
  let signature ← readJson head head.message (boolean · "globally_committable")
  if signature then
    liftExcept head (require retirements.isEmpty "retirement metadata on signature")
    if let some config := config then
      liftExcept config (throw "configuration write pair mismatch")
    return .signature
  let configuration ←
    match config with
    | some config => do
        liftExcept config do
          require
            ((← nat config.message "idx") == (← nat head.message "seqno"))
            "configuration write pair mismatch"
        some <$> modelMembers config (← readJson config config.message configuration)
    | none => pure none
  let retiredNodes ←
    retirements.mapM
      fun retirement =>
        readJson retirement retirement.message (string · "retired_node_id")
  let retirementConfirmations ← modelMembers head retiredNodes
  let request := (← get).nextRequestId
  modify fun s => { s with nextRequestId := request + 1 }
  return .transaction request { configuration, retirementConfirmations }

/-- One entry of a batch: its replicate event, retirements, configuration and flush. -/
private def readAppendEntry (head : Event) : Reduction AppendEntryInput := do
  let seqno ← readJson head head.message (nat · "seqno")
  -- consume
  event head "replicate_entry"
  let retirements ←
    CCF.Parsec.many do
      let retirement ← peek
      event head "retired_committed_tx"
      liftExcept retirement do
        let retirementSeqno ← nat retirement.message "seqno"
        require (retirementSeqno == seqno)
          s!"expected seqno {seqno}, got {retirementSeqno}"
      return retirement
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
  let content ← readAppendContent head config retirements
  return { content, flushes := flushes.getD [] }

/--
The entries after a native `replicate` event, each starting with its `replicate_entry`
event, are appended to the model as one batch, which checks commit once at the end, as
CCF does. A call rejected at its first entry traces no entries and appends nothing.
-/
private def ruleAppend : Reduction Unit := do
  let head ← peek
  -- consume
  let start ← position
  event head "replicate"
  let entries ←
    CCF.Parsec.many do
      let next ← peek
      unless next.function == "replicate_entry" && next.node == head.node do
        failure s!"{next.record.location}: not an entry of the batch"
      readAppendEntry next
  optional_ do
    event head "commit"
    optional_ (event head "step_down_and_nominate_successor")
  -- emit
  emitObserve head "append"
  unless entries.isEmpty do
    emitAction head "append" (.local head.node (.append entries))
  emitObserveSends head (← extractSends start)

private def readReceive (head : Event) (families : List String) : Reduction Step := do
  let sender ← readJson head head.message (string · "from_node_id")
  let packet ← readJson head head.message (field · "packet")
  let family ← readJson head packet (string · "msg")
  liftExcept head (require (families.contains family) "receive function/packet mismatch")
  return .receive sender head.node packet

private def ruleRecvAppendEntries : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["append_entries"]
  -- consume
  let start ← position
  event head "recv_append_entries"
  optional_ (event head "become_follower")
  many_
    ((do
      event head "execute_append_entries_sync"
      many_ (event head "retired_committed_tx"))
      <|> (do
            event head "add_configuration"
            many_ (event head "send_append_entries"))
      <|> (do
            event head "commit"
            optional_ (event head "step_down_and_nominate_successor")))
  optional_ (event head "send_append_entries_response")
  -- emit
  emitObserve head "recv-append-entries"
  emitAction head "recv-append-entries" action
  emitObserveSends head (← extractSends start)

private def ruleRecvAppendEntriesResponse : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["append_entries_response"]
  -- consume
  let start ← position
  event head "recv_append_entries_response"
  optional_ (event head "become_follower")
  optional_ do
    event head "commit"
    optional_ (event head "step_down_and_nominate_successor")
  -- emit
  emitObserve head "recv-append-entries-response"
  emitAction head "recv-append-entries-response" action
  emitObserveSends head (← extractSends start)

private def ruleRecvRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["request_vote", "request_pre_vote"]
  -- consume
  let start ← position
  event head "recv_request_vote"
  optional_ (event head "become_follower")
  optional_ (event head "send_request_vote_response")
  -- emit
  emitObserve head "recv-request-vote"
  emitAction head "recv-request-vote" action
  emitObserveSends head (← extractSends start)

private def ruleRecvProposeRequestVote : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["propose_request_vote"]
  -- consume
  let start ← position
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
  emitObserve head "recv-propose-request-vote"
  emitAction head "recv-propose-request-vote" action
  emitObserveSends head (← extractSends start)

private def ruleRecvRequestVoteResponse : Reduction Unit := do
  let head ← peek
  let action ← readReceive head ["request_vote_response", "request_pre_vote_response"]
  -- consume
  let start ← position
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
  emitObserve head "recv-request-vote-response"
  emitAction head "recv-request-vote-response" action
  emitObserveSends head (← extractSends start)

private def ruleTick : Reduction Unit := do
  let head ← peek
  -- consume
  let start ← position
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
  emitObserveSends head (← extractSends start)

private def ruleNomination : Reduction Unit := do
  let head ← peek
  -- consume
  let start ← position
  event head "nomination"
  let nominated ← CCF.Parsec.optionalRule (event head "step_down_and_nominate_successor")
  -- emit
  emitObserve head "nomination"
  if nominated.isSome then
    emitAction head "nomination" (.local head.node .nominateSuccessor)
  emitObserveSends head (← extractSends start)

/-- Dropped packets stay queued in the model network, never delivered. -/
private def ruleDrop : Reduction Unit := do
  let head ← peek
  -- consume
  event head "drop_pending_to"

/--
Snapshot installation runs ledger hooks outside the consensus lock, so bare ticks
may interleave with their events.
-/
private def ruleInitAsBackup : Reduction Unit := do
  let head ← peek
  let hooks := ["add_configuration", "retired_committed_tx"]
  unless hooks.contains head.function || head.function == "init_as_backup" do
    failure s!"{head.record.location}: expected init_as_backup, got {head.function}"
  -- consume
  many_ (hooks.foldr (fun name rest => event head name <|> rest) (event head "tick"))
  unless (← CCF.Parsec.peek).any (·.function == "init_as_backup") do
    liftExcept head
      (throw
        "not grouped with replicate_entry, execute_append_entries_sync or init_as_backup")
  let init ← peek
  event head "init_as_backup"
  event head "become_follower"
  let index ← readJson init init.message (nat · "seqno")
  let view ← readJson init init.message (nat · "view")
  -- emit
  emitObserve init "init-as-backup"
  emitAction init "init-as-backup" (.initAsBackup head.node index view)

private def ruleStep : Reduction Unit := do
  -- Recv rules
  attempt ruleRecvAppendEntries
  <|> attempt ruleRecvAppendEntriesResponse
  <|> attempt ruleRecvRequestVote
  <|> attempt ruleRecvProposeRequestVote
  <|> attempt ruleRecvRequestVoteResponse
  -- Async rules
  <|> attempt ruleInitAsBackup
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

end Consensus.Replay.Reducer

namespace Consensus.Replay

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

end Consensus.Replay
