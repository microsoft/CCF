module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Reduction

public section

/-!
Runs the reduction rules over each node's events: peek the next event, run one rule from
it, and take what the rule emitted as a group. The peeked event gives the group's node and
times, so the rules track neither.
A receive or `init_as_backup` must be its rule's first action, since replay decides from
that action whether the group waits.
-/

namespace Consensus.Replay

open Reducer

/-- One rule's instructions as a group; bootstrap, a drop or a snapshot hook emits none. -/
private def group : Reduction (Option Group) := do
  let some head ← CCF.Parsec.peek | CCF.Parsec.failure "unexpected end of input"
  ruleStep
  let state ← get
  set { state with instructions := #[] }
  if state.instructions.isEmpty then return none
  return some
    {
      node := head.node,
      m_ts := head.m_ts,
      ts := head.ts,
      instructions := state.instructions
    }

/-- One node's events. Every event is consumed; an ungrouped event is never a stutter. -/
private def node : Reduction (Array Group) := do
  let groups ← CCF.Parsec.many group
  if let some event ← CCF.Parsec.peek then
    CCF.Parsec.failure s!"{event.record.location}: ungrouped event {event.function}"
  return (groups.filterMap id).toArray

/-- Prepared initialization and each node's groups for direct model replay. -/
structure Reduced where
  header : Header
  queues : Array (Array Group)

/--
Prepare replay identities and reduce each node's events into its queue of groups.
Request IDs continue across nodes, so they are unique in the trace.
-/
def reduce (streams : Array (Array Event)) (declared : List String)
    : Except String Reduced := do
  let header : Header := { bootstrap := ∅, declared }
  let mut bootstrap := none
  let mut queues := #[]
  let mut nextRequestId := 1
  for events in streams do
    let (found, state) ←
      (CCF.Parsec.run events (node.run { header, nextRequestId })).mapError
        fun error =>
          match events.back? with
          | some last =>
              if error == "unexpected end of input" then
                s!"{last.record.location}: the events of node '{last.node}' end inside a group"
              else
                error
          | none => error
    if let some leader := state.bootstrap then
      if let some other := bootstrap then
        throw s!"nodes '{other}' and '{leader}' both bootstrap the network"
      bootstrap := some leader
    queues := queues.push found
    nextRequestId := state.nextRequestId
  let some leader := bootstrap | throw "no node bootstraps the network"
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, queues }

end Consensus.Replay
