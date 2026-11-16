module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Reduction

public section

/-!
Runs the reduction rules over each node's events: peek the next event, run one rule from
it, and take what the rule emitted as a group. The peeked event gives the group's node,
process and times, so the rules track none of them.
-/

namespace Consensus.Replay

open Reducer

/-- One rule's instructions as a group; a drop or a snapshot hook emits none. -/
private def group : Reduction (Option Group) := do
  let some head ← CCF.Parsec.peek | CCF.Parsec.failure "unexpected end of input"
  ruleStep
  let last ←
    liftM (m := CCF.Parsec.Parser Event)
      ((fun input => .success input (input.events[input.position - 1]?.getD head))
        : CCF.Parsec.Parser Event Event)
  let state ← get
  set { state with instructions := #[] }
  if state.instructions.isEmpty then return none
  return some
    {
      node := head.node
      process := head.process
      time := head.time
      last := last.time
      ts := head.ts
      instructions := state.instructions
    }

/--
One node's events: bootstrap, if this node starts the network, then groups.
Every event is consumed; an ungrouped event is never a stutter.
-/
private def node : Reduction (Option String × List Group) := do
  let leader ← CCF.Parsec.optionalRule (CCF.Parsec.attempt ruleBootstrap)
  let groups ← CCF.Parsec.many group
  if let some event ← CCF.Parsec.peek then
    CCF.Parsec.failure s!"{event.record.location}: ungrouped event {event.function}"
  return (leader, groups.filterMap id)

/-- Prepared initialization and each process's groups for direct model replay. -/
structure Reduced where
  header : Header
  queues : Array (Array Group)

/--
Prepare replay identities, reduce each node's events and queue each process's groups in
`h_ts` order. Request IDs continue across nodes, so they are unique in the trace.
A process that traces several nodes, as `cft_driver` does, runs them on one thread, so its
groups must not overlap.
-/
def reduce (streams : Array (Array Event)) (declared : List String)
    : Except String Reduced := do
  let header : Header := { bootstrap := ∅, declared }
  let mut bootstrap := none
  let mut groups := #[]
  let mut nextRequestId := 1
  for events in streams do
    let ((leader, found), state) ←
      (CCF.Parsec.run events (node.run { header, nextRequestId })).mapError
        fun error =>
          match events.back? with
          | some last =>
              if error == "unexpected end of input" then
                s!"{last.record.location}: the events of node '{last.node}' end inside a group"
              else
                error
          | none => error
    if let some leader := leader then
      if let some other := bootstrap then
        throw s!"nodes '{other}' and '{leader}' both bootstrap the network"
      bootstrap := some leader
    groups := groups ++ found
    nextRequestId := state.nextRequestId
  let some leader := bootstrap | throw "no node bootstraps the network"
  let header := { header with bootstrap := {← header.nodeId leader} }
  let sorted :=
    groups.qsort
      fun a b => a.process < b.process || (a.process == b.process && a.time < b.time)
  let queues := (sorted.toList.splitBy (·.process == ·.process)).toArray.map (·.toArray)
  for queue in queues do
    for earlier in queue, group in queue.extract 1 do
      unless earlier.last < group.time do
        throw
          s!"{group.label}: starts before the group at {earlier.label} of the same process ends"
  return { header, queues }

end Consensus.Replay
