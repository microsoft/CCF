module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Input

import CCF.Parsec

public section

/-!
Rules peek action arguments, consume named events, and emit direct model actions.
Each node's events reduce independently into groups, one per hold of its consensus lock.
A receive or `init_as_backup` must be its group's first action, since replay decides from that
action whether the group waits.
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
  nextRequestId : ReqID
  /-- Instructions emitted by the current group. -/
  instructions : Array Instruction := #[]
  groups : Array Group := #[]
  /-- The last consumed event, to locate a group cut short by the end of its node's events. -/
  last : Option Event := none
  /-- The node has bootstrapped the network or initialized as a backup. -/
  initialized : Bool := false
  /-- A snapshot hook whose `init_as_backup` has not been seen yet. -/
  hook : Option Event := none

private abbrev Reduction := CCF.Parsec.ParserT Event ReductionState

private def liftExcept {α : Type} (event : Event) (result : Except String α)
    : Reduction α :=
  validated
    (result.mapError fun error => s!"{event.record.location}: {event.function}: {error}")

private def readJson {α : Type} (event : Event) (value : Json)
    (decode : Json → Except String α)
    : Reduction α :=
  liftExcept event (decode value)

private def peek (expected := "another event") : Reduction Event := do
  let some event ← CCF.Parsec.peek
  | match (← get).last with
    | some last =>
        failure
          s!"{last.record.location}: expected {expected}, got end of node '{last.node}' events"
    | none => failure "unexpected end of input"
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
  events.toList.filterMapM
    fun event => do
      let packet ←
        if event.function.startsWith "send_" then
          some <$> readJson event event.message (field · "packet")
        else
          pure none
      packet.mapM
        fun packet => do
          let target ← readJson event event.message (string · "to_node_id")
          return { target, packet, origin := event.origin event.function }

private def event (source : Event) (name : String) : Reduction Unit := do
  let next ← peek name
  unless next.function == name do
    failure s!"{next.record.location}: expected {name}, got {next.function}"
  liftExcept next do
    require (next.node == source.node) s!"expected event on node {source.node}"
  discard CCF.Parsec.take
  modify fun s => { s with last := some next }

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
Genesis runs asynchronously after the first node becomes leader, so bare ticks and
nominations, which name no successor yet, may precede it; the model starts after genesis,
so they are not observed.
`replicate` flushes a genesis entry over the append entries size limit. The node has no peers
yet, so the flush sends nothing.
-/
private def ruleBootstrap : Reduction String := do
  let head ← peek
  -- consume
  event head "become_leader"
  many_ (event head "tick" <|> event head "nomination")
  event head "replicate"
  event head "replicate_entry"
  event head "add_configuration"
  optional_ (event head "batch_flush")
  modify fun s => { s with initialized := true }
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
private def readReplicateEntry (head : Event) : Reduction AppendEntryInput := do
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
Snapshot installation runs ledger hooks outside the consensus lock before the node
initializes, so other groups of the node, such as ticks, may fall between a hook and its
`init_as_backup`. A hook therefore forms no group.
-/
private def ruleSnapshotHook : Reduction Unit := do
  let head ← peek
  unless ["add_configuration", "retired_committed_tx"].contains head.function do
    failure s!"{head.record.location}: expected a snapshot hook, got {head.function}"
  -- consume
  event head head.function
  liftExcept head
    (require (!(← get).initialized)
      "not grouped with replicate_entry, execute_append_entries_sync or init_as_backup")
  modify fun s => { s with hook := s.hook <|> some head }

private def ruleInitAsBackup : Reduction Unit := do
  let head ← peek
  -- consume
  event head "init_as_backup"
  event head "become_follower"
  modify fun s => { s with initialized := true, hook := none }
  let index ← readJson head head.message (nat · "seqno")
  let view ← readJson head head.message (nat · "view")
  -- emit
  emitObserve head "init-as-backup"
  emitAction head "init-as-backup" (.initAsBackup head.node index view)

private def ruleStep : Reduction Unit := do
  -- Recv rules
  attempt ruleRecvAppendEntries
  <|> attempt ruleRecvAppendEntriesResponse
  <|> attempt ruleRecvRequestVote
  <|> attempt ruleRecvProposeRequestVote
  <|> attempt ruleRecvRequestVoteResponse
  -- Async rules
  <|> attempt ruleSnapshotHook
  <|> attempt ruleInitAsBackup
  <|> attempt ruleAppend
  <|> attempt ruleTick
  <|> attempt ruleNomination
  <|> attempt ruleDrop

/-- Collect the instructions a rule emits into one group; a drop or a snapshot hook emits none. -/
private def group (rule : Reduction Unit) : Reduction Unit := do
  let head ← peek
  rule
  let state ← get
  unless state.instructions.isEmpty do
    set
      {
        state with
          instructions := #[]
          groups :=
            state.groups.push
              {
                node := head.node
                process := head.process
                time := head.time
                last := (state.last.getD head).time
                ts := head.ts
                instructions := state.instructions
              }
      }

/-- One node's events: bootstrap, if this node starts the network, then groups. -/
private def ruleNode : Reduction (Option String) := do
  let leader ← CCF.Parsec.optionalRule (attempt ruleBootstrap)
  many_ (group ruleStep)
  if let some event ← CCF.Parsec.peek then
    failure s!"{event.record.location}: ungrouped event {event.function}"
  if let some hook := (← get).hook then
    liftExcept hook
      (throw
        "not grouped with replicate_entry, execute_append_entries_sync or init_as_backup")
  return leader

/--
Consume every event exactly once; an ungrouped event is never a stutter.
Request IDs continue across nodes, so they are unique in the trace.
-/
def reduce (streams : Array (Array Event)) (header : Header)
    : Except String (String × Array (Array Group)) := do
  let mut bootstrap := none
  let mut groups := #[]
  let mut nextRequestId := 1
  for events in streams do
    let (leader, state) ← CCF.Parsec.run events (ruleNode.run { header, nextRequestId })
    if let some leader := leader then
      if let some other := bootstrap then
        throw s!"nodes '{other}' and '{leader}' both bootstrap the network"
      bootstrap := some leader
    groups := groups.push state.groups
    nextRequestId := state.nextRequestId
  let some leader := bootstrap | throw "no node bootstraps the network"
  return (leader, groups)

end Consensus.Replay.Reducer

namespace Consensus.Replay

/-- Prepared initialization and each process's groups for direct model replay. -/
structure Reduced where
  header : Header
  queues : Array (Array Group)

/--
Prepare replay identities, reduce each node's events and queue each process's groups in
`h_ts` order. A process that traces several nodes, as `cft_driver` does, runs them on one
thread, so its groups must not overlap.
-/
def reduce (streams : Array (Array Event)) (declared : List String)
    : Except String Reduced := do
  let header : Header := { bootstrap := ∅, declared }
  let (leader, streams) ← Reducer.reduce streams header
  let header := { header with bootstrap := {← header.nodeId leader} }
  let groups :=
    streams.flatten.qsort
      fun a b => a.process < b.process || (a.process == b.process && a.time < b.time)
  let queues := (groups.toList.splitBy (·.process == ·.process)).toArray.map (·.toArray)
  for queue in queues do
    for earlier in queue, group in queue.extract 1 do
      unless earlier.last < group.time do
        throw
          s!"{group.label}: starts before the group at {earlier.label} of the same process ends"
  return { header, queues }

end Consensus.Replay
