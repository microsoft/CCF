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
Each rule returns the native sends it consumed; after the rule, replay checks them against the
envelopes its actions queued.
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

private def event (source : Event) (name : String) : Reduction Unit := do
  let next ← peek
  unless next.function == name do
    failure s!"{next.record.location}: expected {name}, got {next.function}"
  liftExcept next do
    require (next.node == source.node) s!"expected event on node {source.node}"
  discard CCF.Parsec.take

/-- Consume a send event, or a nomination with the proposal it implies. -/
private def send (source : Event) (name : String) : Reduction NativeSend := do
  let next ← peek
  event source name
  let target ← readJson next next.message (string · "to_node_id")
  let packet ←
    if name == "step_down_and_nominate_successor" then
      -- Native then sends an untraced proposal in its current view.
      let term ← readJson next next.state (nat · "current_view")
      pure (Json.mkObj [("msg", toJson "propose_request_vote"), ("term", toJson term)])
    else
      readJson next next.message (field · "packet")
  return { target, packet, origin := next.origin name }

/-- Optionally parse a rule, yielding no sends if it is absent. -/
private def optionalSends (rule : Reduction (List NativeSend))
    : Reduction (List NativeSend) :=
  (·.getD []) <$> CCF.Parsec.optionalRule rule

/-- A commit and the nomination that may follow it. -/
private def commit (source : Event) : Reduction (List NativeSend) := do
  event source "commit"
  (·.toList) <$> CCF.Parsec.optionalRule (send source "step_down_and_nominate_successor")

/-- A new primary's commit and nomination, then its heartbeats. -/
private def becomeLeader (source : Event) : Reduction (List NativeSend) := do
  event source "become_leader"
  let committed ← optionalSends (commit source)
  return committed ++ (← CCF.Parsec.many (send source "send_append_entries"))

/-- A candidate's promotion, if any, then its vote requests. -/
private def becomeCandidate (source : Event) : Reduction (List NativeSend) := do
  event source "become_candidate"
  let leader ← optionalSends (becomeLeader source)
  return leader ++ (← CCF.Parsec.many (send source "send_request_vote"))

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

private def ruleBootstrap : Reduction String := do
  let head ← peek
  -- consume
  event head "become_leader"
  event head "replicate"
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

private def ruleAppend : Reduction (List NativeSend) := do
  let head ← peek
  unless head.function == "retired_committed_tx" || head.function == "replicate" do
    failure
      s!"{head.record.location}: expected retired_committed_tx or replicate, got {head.function}"
  let seqno ← readJson head head.message (nat · "seqno")
  let nodeId := head.node
  -- consume
  let retirements ←
    CCF.Parsec.many do
      let retirement ← peek
      unless retirement.function == "retired_committed_tx" && retirement.node == nodeId do
        failure
          s!"{retirement.record.location}: expected retired_committed_tx on node {nodeId}, got {retirement.function} on node {retirement.node}"
      let retirementSeqno ← readJson retirement retirement.message (nat · "seqno")
      unless retirementSeqno == seqno do
        failure
          s!"{retirement.record.location}: expected seqno {seqno}, got {retirementSeqno}"
      discard CCF.Parsec.take
      return retirement
  -- Map hooks run before replication acceptance; rejected writes may have no matching replicate.
  if (← CCF.Parsec.peek).isNone then
    return []
  let head ← peek
  unless head.function == "replicate" && head.node == nodeId do
    return []
  let replicateSeqno ← readJson head head.message (nat · "seqno")
  unless replicateSeqno == seqno do
    return []
  event head "replicate"
  let config ←
    CCF.Parsec.optionalRule do
      let config ← peek
      event head "add_configuration"
      return (config, ← CCF.Parsec.many (send head "send_append_entries"))
  let flushes ←
    CCF.Parsec.optionalRule do
      event head "batch_flush"
      CCF.Parsec.many do
        let next ← peek
        let sent ← send head "send_append_entries"
        let destination ← modelNode next sent.target
        let last ← readJson next sent.packet (nat · "idx")
        return ((destination, last), sent)
  let committed ← optionalSends (commit head)
  let content ← readAppendContent head (config.map Prod.fst) retirements
  -- emit
  emitObserve head "append"
  emitAction head "append"
    (.local head.node (.append [{ content, flushes := (flushes.getD []).map Prod.fst }]))
  return ((config.map Prod.snd).getD []) ++ (flushes.getD []).map Prod.snd ++ committed

private def readReceive (head : Event) (families : List String) : Reduction Step := do
  let sender ← readJson head head.message (string · "from_node_id")
  let packet ← readJson head head.message (field · "packet")
  let family ← readJson head packet (string · "msg")
  liftExcept head (require (families.contains family) "receive function/packet mismatch")
  return .receive sender head.node packet

private def ruleRecvAppendEntries : Reduction (List NativeSend) := do
  let head ← peek
  let action ← readReceive head ["append_entries"]
  -- consume
  event head "recv_append_entries"
  optional_ (event head "become_follower")
  let sends ←
    CCF.Parsec.many
      ((do
        event head "execute_append_entries_sync"
        many_ (event head "retired_committed_tx")
        return [])
        <|> (do
              event head "add_configuration"
              CCF.Parsec.many (send head "send_append_entries"))
        <|> commit head)
  let response ← CCF.Parsec.optionalRule (send head "send_append_entries_response")
  -- emit
  emitObserve head "recv-append-entries"
  emitAction head "recv-append-entries" action
  return sends.flatten ++ response.toList

private def ruleRecvAppendEntriesResponse : Reduction (List NativeSend) := do
  let head ← peek
  let action ← readReceive head ["append_entries_response"]
  -- consume
  event head "recv_append_entries_response"
  optional_ (event head "become_follower")
  let sends ← optionalSends (commit head)
  -- emit
  emitObserve head "recv-append-entries-response"
  emitAction head "recv-append-entries-response" action
  return sends

private def ruleRecvRequestVote : Reduction (List NativeSend) := do
  let head ← peek
  let action ← readReceive head ["request_vote", "request_pre_vote"]
  -- consume
  event head "recv_request_vote"
  optional_ (event head "become_follower")
  let response ← CCF.Parsec.optionalRule (send head "send_request_vote_response")
  -- emit
  emitObserve head "recv-request-vote"
  emitAction head "recv-request-vote" action
  return response.toList

private def ruleRecvProposeRequestVote : Reduction (List NativeSend) := do
  let head ← peek
  let action ← readReceive head ["propose_request_vote"]
  -- consume
  event head "recv_propose_request_vote"
  let sends ← optionalSends (becomeCandidate head)
  -- emit
  emitObserve head "recv-propose-request-vote"
  emitAction head "recv-propose-request-vote" action
  return sends

private def ruleRecvRequestVoteResponse : Reduction (List NativeSend) := do
  let head ← peek
  let action ← readReceive head ["request_vote_response", "request_pre_vote_response"]
  -- consume
  event head "recv_request_vote_response"
  let sends ←
    optionalSends
      ((do
        event head "become_follower"
        return [])
        <|> becomeCandidate head
        <|> becomeLeader head)
  -- emit
  emitObserve head "recv-request-vote-response"
  emitAction head "recv-request-vote-response" action
  return sends

private def ruleTick : Reduction (List NativeSend) := do
  let head ← peek
  -- consume
  event head "tick"
  let election ← CCF.Parsec.optionalRule (event head "become_pre_vote_candidate")
  if election.isSome then
    let candidate ← optionalSends (becomeCandidate head)
    let preVotes ← CCF.Parsec.many (send head "send_request_vote")
    -- emit
    emitObserve head "tick-election"
    emitAction head "tick-election" (.local head.node (.timeout .election))
    return candidate ++ preVotes
  else
    let sends ←
      CCF.Parsec.many do
        let next ← peek
        let sent ← send head "send_append_entries"
        let destination ← modelNode next sent.target
        let last ← readJson next sent.packet (nat · "idx")
        return (next, destination, last, sent)
    let demoted ← CCF.Parsec.optionalRule (event head "become_follower")
    -- emit
    emitObserve head "tick"
    for (source, destination, last, _) in sends do
      emitAction source "tick-send" (.local head.node (.sendEntries destination last))
    if demoted.isSome then
      emitAction head "tick-check-quorum" (.local head.node (.timeout .checkQuorum))
    return sends.map fun (_, _, _, sent) => sent

private def ruleNomination : Reduction (List NativeSend) := do
  let head ← peek
  -- consume
  event head "nomination"
  let nominated ← CCF.Parsec.optionalRule (send head "step_down_and_nominate_successor")
  -- emit
  emitObserve head "nomination"
  if nominated.isSome then
    emitAction head "nomination" (.local head.node .nominateSuccessor)
  return nominated.toList

/-- Dropped packets stay queued in the model network, never delivered. -/
private def ruleDrop : Reduction (List NativeSend) := do
  let head ← peek
  -- consume
  event head "drop_pending_to"
  return []

/--
Snapshot installation runs ledger hooks outside the consensus lock, so bare ticks
may interleave with their events.
-/
private def ruleInitAsBackup : Reduction (List NativeSend) := do
  let head ← peek
  let hooks := ["add_configuration", "retired_committed_tx"]
  unless hooks.contains head.function || head.function == "init_as_backup" do
    failure s!"{head.record.location}: expected init_as_backup, got {head.function}"
  -- consume
  many_ (hooks.foldr (fun name rest => event head name <|> rest) (event head "tick"))
  let init ← peek
  event head "init_as_backup"
  event head "become_follower"
  let index ← readJson init init.message (nat · "seqno")
  let view ← readJson init init.message (nat · "view")
  -- emit
  emitObserve init "init-as-backup"
  emitAction init "init-as-backup" (.initAsBackup head.node index view)
  return []

private def ruleStep : Reduction (List NativeSend) := do
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

/-- Check the native sends a rule consumed against the envelopes its actions queued. -/
private def emitObserveSends (event : Event) (sends : List NativeSend) : Reduction Unit :=
  appendInstruction (.observeSends sends (event.origin "sends"))

private def ruleTrace : Reduction String := do
  let leader ← ruleBootstrap
  many_ do
    let head ← peek
    emitObserveSends head (← ruleStep)
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
