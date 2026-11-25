module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Input
public import CCF.Parsec

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

open Model.Node
open CCF (Finset)
open CCF.Parsec (failure validated attempt many_ optional_)

structure ReductionState where
  header : Header
  nextRequestId : ReqID := 1
  instructions : Array Instruction := #[]
  /-- The node, if its events start by bootstrapping the network. -/
  bootstrap : Option String := none

abbrev Reduction := CCF.Parsec.ParserT Event ReductionState

private def liftExcept {α : Type} (event : Event) (result : Except String α)
    : Reduction α :=
  validated
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

/-- Fail on an event whose fields are not those a rule reads. -/
private def mismatch {α : Type} (event : Event) : Reduction α :=
  liftExcept event (throw "unexpected fields")

private def peek : Reduction Event := do
  let some event ← CCF.Parsec.peek | failure "unexpected end of input"
  return event

/-- The cursor position, from which `extractSends` finds the events a rule consumed. -/
private def position : Reduction Nat :=
  liftM (m := CCF.Parsec.Parser Event)
    ((fun input => .success input input.position) : CCF.Parsec.Parser Event Nat)

/-- Native sends among the events consumed since `start`. -/
private def extractSends (start : Nat) : Reduction (List NativeSend) := do
  let events ←
    liftM (m := CCF.Parsec.Parser Event)
      ((fun input => .success input (input.events.extract start input.position))
        : CCF.Parsec.Parser Event (Array Event))
  return events.toList.filterMap
    fun event =>
      match event.body with
      | .send { to_node_id, packet, .. } =>
          some { target := to_node_id, packet, origin := event.origin event.function }
      | _ => none

private def event (source : Event) (name : String) : Reduction Unit := do
  let next ← peek
  unless next.function == name do
    failure s!"{next.record.location}: expected {name}, got {next.function}"
  liftExcept next do
    require (next.node == source.node) s!"expected event on node {source.node}"
  discard CCF.Parsec.take

/-- A leader steps down and proposes that its successor becomes candidate. -/
private def nominate (source : Event) : Reduction Unit := do
  event source "step_down_and_nominate_successor"
  event source "send_propose_request_vote"

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

/--
Genesis runs asynchronously after the first node becomes leader, so bare ticks may precede
it, as may nominations; the model starts after genesis, so they are not observed.
`replicate` flushes a genesis entry over the append entries size limit. The node has no peers
yet, so the flush sends nothing.
Only a node's first events bootstrap the network.
-/
private def ruleBootstrap : Reduction Unit := do
  let head ← peek
  unless (← position) == 0 do
    failure s!"{head.record.location}: expected the node's first event"
  -- consume
  event head "become_leader"
  many_ (event head "tick" <|> event head "nomination")
  event head "replicate"
  event head "replicate_entry"
  event head "add_configuration"
  optional_ (event head "batch_flush")
  modify fun s => { s with bootstrap := some head.node }

private def readAppendContent (head : Event) (seqno : Nat) (signature : Bool)
    (config : Option (Event × AddConfiguration)) (retiredNodes : List String)
    : Reduction EntryContent := do
  if signature then
    liftExcept head (require retiredNodes.isEmpty "retirement metadata on signature")
    if let some (config, _) := config then
      liftExcept config (throw "configuration write pair mismatch")
    return .signature
  let configuration ←
    match config with
    | some (config, fields) => do
        liftExcept config do
          require (fields.idx == some seqno) "configuration write pair mismatch"
        some <$> modelMembers config fields.nodes
    | none => pure none
  let retirementConfirmations ← modelMembers head retiredNodes
  let request := (← get).nextRequestId
  modify fun s => { s with nextRequestId := request + 1 }
  return .transaction request { configuration, retirementConfirmations }

/-- One entry of a batch: its replicate event, retirements, configuration and flush. -/
private def readReplicateEntry (head : Event) : Reduction AppendEntryInput := do
  let .replicateEntry entry := head.body | mismatch head
  let some seqno := entry.seqno | liftExcept head (throw "seqno: missing")
  -- consume
  event head "replicate_entry"
  let retiredNodes ←
    CCF.Parsec.many do
      let retirement ← peek
      event head "retired_committed_tx"
      let .retiredCommittedTx fields := retirement.body | mismatch retirement
      liftExcept retirement do
        require (fields.seqno == seqno) s!"expected seqno {seqno}, got {fields.seqno}"
      return fields.retired_node_id
  let config ←
    CCF.Parsec.optionalRule do
      let config ← peek
      event head "add_configuration"
      let .addConfiguration fields := config.body | mismatch config
      many_ (event head "send_append_entries")
      return (config, fields)
  let flushes ←
    CCF.Parsec.optionalRule do
      event head "batch_flush"
      CCF.Parsec.many do
        let next ← peek
        event head "send_append_entries"
        let .send { to_node_id, packet := .appendEntries packet, .. } := next.body
        | mismatch next
        let destination ← modelNode next to_node_id
        return (destination, packet.idx)
  let content ←
    readAppendContent head seqno entry.globally_committable config retiredNodes
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
      readReplicateEntry next
  optional_ do
    event head "commit"
    optional_ (nominate head)
  -- emit
  emitObserve head "append"
  unless entries.isEmpty do
    emitAction head "append" (.local head.node (.append entries))
  emitObserveSends head (← extractSends start)

private def readReceive (head : Event) (families : List String) : Reduction Step := do
  let .recv { from_node_id, packet, .. } := head.body | mismatch head
  liftExcept head
    (require (families.contains packet.msg) "receive function/packet mismatch")
  return .receive from_node_id head.node packet

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
            optional_ (nominate head)))
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
    optional_ (nominate head)
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
        optional_ (nominate head)
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
                optional_ (nominate head)
              many_ (event head "send_append_entries")
            many_ (event head "send_request_vote"))
      <|> (do
            event head "become_leader"
            optional_ do
              event head "commit"
              optional_ (nominate head)
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
          optional_ (nominate head)
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
        let .send { to_node_id, packet := .appendEntries packet, .. } := next.body
        | mismatch next
        let destination ← modelNode next to_node_id
        return (next, destination, packet.idx)
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
  let nominated ← CCF.Parsec.optionalRule (nominate head)
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
A tick is a lock hold of its own, as is `init_as_backup`, so the hooks emit nothing; the
node must still initialize later.
-/
private def ruleInitAsBackup : Reduction Unit := do
  let head ← peek
  let hooks := ["add_configuration", "retired_committed_tx"]
  unless hooks.contains head.function || head.function == "init_as_backup" do
    failure s!"{head.record.location}: expected init_as_backup, got {head.function}"
  -- consume
  many_ (event head "add_configuration" <|> event head "retired_committed_tx")
  let rest ←
    liftM (m := CCF.Parsec.Parser Event)
      ((fun input => .success input (input.events.extract input.position))
        : CCF.Parsec.Parser Event (Array Event))
  unless rest.any (·.function == "init_as_backup") do
    liftExcept head
      (throw
        "not grouped with replicate_entry, execute_append_entries_sync or init_as_backup")
  if hooks.contains head.function then
    return
  let init ← peek
  event head "init_as_backup"
  event head "become_follower"
  let .initAsBackup { seqno, view, .. } := init.body | mismatch init
  -- emit
  emitObserve init "init-as-backup"
  emitAction init "init-as-backup" (.initAsBackup head.node seqno view)

def ruleStep : Reduction Unit := do
  -- Recv rules
  attempt ruleRecvAppendEntries
  <|> attempt ruleRecvAppendEntriesResponse
  <|> attempt ruleRecvRequestVote
  <|> attempt ruleRecvProposeRequestVote
  <|> attempt ruleRecvRequestVoteResponse
  -- Async rules
  <|> attempt ruleBootstrap
  <|> attempt ruleInitAsBackup
  <|> attempt ruleAppend
  <|> attempt ruleTick
  <|> attempt ruleNomination
  <|> attempt ruleDrop

end Consensus.Replay.Reducer
