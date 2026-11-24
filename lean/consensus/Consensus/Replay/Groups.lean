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
  let start ← CCF.Parsec.position
  ruleStep
  let state ← get
  set { state with instructions := #[] }
  if state.instructions.isEmpty then return none
  return some
    {
      node := head.node,
      start,
      m_ts := head.m_ts,
      ts := head.ts,
      instructions := state.instructions
    }

/--
One node's groups and the number of its events they consume: all of them if `strict`, as
an ungrouped event is never a stutter.
-/
private def node (strict : Bool) : Reduction (Array Group × Nat) := do
  let groups ← CCF.Parsec.many group
  if strict then
    if let some event ← CCF.Parsec.peek then
      CCF.Parsec.failure s!"{event.record.location}: ungrouped event {event.function}"
  return ((groups.filterMap id).toArray, ← CCF.Parsec.position)

/-- Prepared initialization and each node's groups for direct model replay. -/
structure Reduced where
  header : Header
  queues : Array (Array Group)
  /-- Each node's events, and how many of them its groups consume. -/
  events : Array (Nat × Nat)

/--
The least fraction of a node's events that replay consumed, having run `ran` groups of
each node: 1 unless replay is not strict.
-/
def Reduced.watermark (reduced : Reduced) (ran : Array Nat) : Float :=
  ((reduced.queues.zip reduced.events).zip ran).foldl
    (fun low ((groups, total, consumed), ran) =>
      let consumed := (groups[ran]?.map (·.start)).getD consumed
      min low (consumed.toFloat / total.toFloat))
    1

/--
Prepare replay identities and reduce each node's events into its queue of groups.
Request IDs continue across nodes, so they are unique in the trace.
Unless `strict`, a node's groups end before its first event that no rule consumes.
-/
def reduce (streams : Array (Array Event)) (declared : List String) (strict := true)
    : Except String Reduced := do
  let header : Header := { bootstrap := ∅, declared }
  let mut bootstrap := none
  let mut queues := #[]
  let mut counts := #[]
  let mut nextRequestId := 1
  for events in streams do
    let ((found, consumed), state) ←
      (CCF.Parsec.run events ((node strict).run { header, nextRequestId })).mapError
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
    counts := counts.push (events.size, consumed)
    nextRequestId := state.nextRequestId
  let some leader := bootstrap | throw "no node bootstraps the network"
  let header := { header with bootstrap := {← header.nodeId leader} }
  return { header, queues, events := counts }

end Consensus.Replay
