module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.MTv.Full

@[expose] public section

/-!
# M_tv extension: the handler monad (not reviewed)

A lock hold is one run of a `cft.h` handler, written in `M`: a plain state and exception
monad over `Ctx`, with no suspension. The run consumes the hold's actions from
`Ctx.queue`, one per `trace` call, in order. The program counter is therefore the
number of actions consumed: M_tv steps an event by rerunning the handler from the
declared state at lock acquisition with one more action queued
(`Consensus.TraceValidation.MTv.Machine`).

A run that has consumed every queued action stops (`Stop.blocked`) at the first state
mutation, trace or peek after the last trace point, so the state it stops in is the
state at that trace point. In `final` mode (the release) it never stops early, and
`look` sees `none` once the queue is empty.
-/

namespace Consensus.TraceValidation.Exec

open Lean
open Consensus.Model.Node

/-- What a hold did, in clean-model vocabulary, for the diagnostic lock-step check only. -/
inductive Note where
  /-- `ext`: an independent clean `sendEntries` (heartbeat or batch flush). -/
  | sendEntries (dest : NodeId) (endIdx : Nat) (ext : Bool)
  | appendEntry (entry : Entry)
  | batchFlush
  | heartbeatTimeout
  | electionTimeout
  | checkQuorum
  | initAsBackup (index term : Nat)
deriving Inhabited

structure Ctx where
  /-- Trace-wide parameters: node names and addresses. -/
  env : Env
  vars : State
  /-- Sends, in order, with clean node ids. -/
  outbox : List (CCF.Envelope NodeID Message) := []
  /-- The actions not yet consumed. -/
  queue : List Action
  /-- The release: run to completion. -/
  final : Bool := false
  /-- The action consumed last, whose inputs `in*` reads. -/
  cur : Option Action := none
  /-- A trace point consumed an action and nothing has happened since. -/
  atPoint : Bool := false
  label : Label := []
  notes : List Note := []

inductive Stop where
  | error (msg : String)
  /-- Every queued action is consumed: the state at the last trace point. -/
  | blocked (c : Ctx)

abbrev M := StateT Ctx (Except Stop)

def fail {α} (msg : String) : M α := throw (.error msg)

/-- After a trace point: stop if no action is left (unless final), else go on. -/
def yieldAtPoint : M Unit := do
  let c ← get
  if c.atPoint then
    if c.queue.isEmpty && !c.final then throw (.blocked c)
    set { c with atPoint := false, label := [] }

def getV : M State := do
  return (← get).vars

def setV (f : State -> State) : M Unit := do
  yieldAtPoint
  modify fun c => { c with vars := f c.vars }

/-- The next action, if any; `none` at release. -/
def look : M (Option Action) := do
  yieldAtPoint
  let c ← get
  match c.queue with
  | a :: _ => return some a
  | [] => if c.final then return none else throw (.blocked c)

def lookFn : M (Option String) := do
  return (← look).map (·.point)

def curLoc : M String := do
  match (← get).cur with
  | some a => return s!"at {a.point}"
  | none => return "between trace points"

/-- Reach the trace point `fn`: it must be the next action. -/
def trace (fn : String) : M Unit := do
  yieldAtPoint
  let c ← get
  match c.queue with
  | a :: rest =>
      unless a.point == fn do
        fail s!"expected trace point {fn}, got {a.point}"
      set { c with queue := rest, cur := some a, atPoint := true, label := [] }
  | [] =>
      if c.final then
        fail s!"expected trace point {fn} before lock release"
      else
        throw (.blocked c)

/-- Label a field of the current trace point with the model's value. -/
def emit (k : String) (model : Json) : M Unit := do
  unless (← get).atPoint do
    fail s!"emit {k} outside a trace point"
  modify fun c => { c with label := c.label ++ [(k, model)] }

def emitNat (k : String) (n : Nat) : M Unit := emit k (toJson n)
def emitStr (k : String) (s : String) : M Unit := emit k (toJson s)

def liftE {α} (x : Except String α) : M α := do
  match x with
  | .ok a => return a
  | .error e => fail s!"{← curLoc}: {e}"

/-- An input field of the current action. -/
def use (k : String) : M Json := do
  let some a := (← get).cur | fail s!"no current action for input {k}"
  match a.inputs.lookup k with
  | some j => return j
  | none => fail s!"{a.point}: {k} is not an input"

def inNat (k : String) : M Nat := do
  liftE (natural (← use k))

def inStr (k : String) : M String := do
  liftE (← use k).getStr?

def inBool (k : String) : M Bool := do
  liftE (← use k).getBool?

def parseNodes (j : Json) : Except String Nodes := do
  let o ← j.getObj?
  o.toList.mapM
    fun (id, info) => do
      let addr ← (← info.getObjVal? "address").getStr?
      unless (← info.getObj?).size == 1 do
        throw s!"node {id}: unexpected node info {info.compress}"
      return (id, addr)

def note (n : Note) : M Unit := modify fun c => { c with notes := c.notes ++ [n] }

def names : M Names := do
  return (← get).env.names

/-- Send `m` to `dst`. -/
def send (dst : NodeId) (m : Message) : M Unit := do
  modify
    fun c =>
      let x : CCF.Envelope NodeID Message :=
        {
          source := c.env.names.id c.vars.nodeId,
          target := c.env.names.id dst,
          payload := m
        }
      { c with outbox := c.outbox ++ [x] }

/-- Run a handler from `vars` on `queue`. -/
def run (env : Env) (vars : State) (queue : List Action) (final : Bool) (h : M Unit)
    : Except Stop Ctx :=
  match h.run ({ env, vars, queue, final } : Ctx) with
  | .ok ((), c) => .ok c
  | .error s => .error s

end Consensus.TraceValidation.Exec
