module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model
public import Consensus.TraceValidation.Abs
public import Consensus.TraceValidation.MTv.Aft
public import Consensus.TraceValidation.MTv.Invariant
public import CCF.Sections

@[expose] public section

/-!
# M_tv as a `CCF.Sections.Machine` (not reviewed)

The local state is the reviewed declared state (`Exec.State`, at the last release) plus
`sec`, the open lock hold if any: its head event, the message it delivered, the declared
state at lock acquisition (`saved`), the hold's actions so far (the program counter), and
the handler's context at the latest trace point.

`step` runs one event: it reruns the hold's `cft.h` handler from `saved` with the event's
action appended, up to that action's trace point, and observes the event against the
declared state there (`Exec.observe`, reviewed). `close` runs the handler to completion
(the trailing code after the last trace point) and returns its sends. A joiner's
`init_as_backup` additionally takes the ledger prefix up to its snapshot from a node that
has committed it (the donor): the implementation installs a snapshot, whose entries are
not traced; until some node has committed the snapshot index, the release waits. Every
release also checks the local invariant `inv` of the declared state it releases, and
rejects the trace, naming the failed conjuncts, when it does not hold.
-/

namespace Consensus.TraceValidation

open Lean
open CCF (Finset)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State Ev Ctx Action)

/-- An open lock hold. -/
structure Sec where
  /-- The event that opened the hold. -/
  head : Ev
  /-- The message the head delivered, if any, with its sender. -/
  recv : Option (NodeID × Message)
  /-- The declared state at lock acquisition. -/
  saved : State
  /-- The hold's actions so far. -/
  actions : List Action
  /-- The handler's context at the latest trace point. -/
  ctx : Ctx

/-- M_tv's local state. -/
structure Local where
  /-- The declared state at the last release. -/
  vars : State
  /-- The open hold. -/
  sec : Option Sec := none

def Local.idle (l : Local) : Bool := l.sec.isNone

/-- The working state at the latest trace point. -/
def current (l : Local) : State :=
  match l.sec with
  | some s => s.ctx.vars
  | none => l.vars

/-- The declared state at the latest trace point, with the model's label there (none when idle). -/
def declare (l : Local) : Exec.Declared × Exec.Label :=
  match l.sec with
  | some s => (s.ctx.vars.declared, s.ctx.label)
  | none => (l.vars.declared, [])

/--
A node before its first event. Whether the host has already called `start_ticking()` is
not traced (the driver does at creation, a real node does not), so it is a parameter.
-/
def initialLocal (env : Env) (node : NodeID) (ticking : Bool) : Local :=
  { vars := { nodeId := env.names.name node, ticking } }

/--
The genesis primary before its first ledger entry: the clean model starts it already
past `force_become_primary` and the genesis `replicate`, which `cft.h` still has to run.
-/
def pristine (env : Env) (d : State) : Bool :=
  env.genesis.min? == some (env.names.id d.nodeId) && d.lastIdx == 0

/--
Whether the host has initialised the node: `init_as_backup` or `force_become_primary` made
it a follower or leader in a positive view (a retired-committed node keeps its view).
-/
def initialised (s : State) : Bool := s.currentView != 0 || s.leadership != .none

/--
What an uninitialised node may do. The host creates the consensus and initialises it in
one callback (node_state.h: the snapshot's hooks then `init_as_backup` for a joiner,
`force_become_primary` for a genesis or recovery primary), so no message is delivered to
it before; a tick finds it not ticking, and the driver may drop messages it sent.
-/
def uninitialisedHeads : List String :=
  ["add_configuration", "tick", "init_as_backup", "become_leader", "drop_pending_to"]

/--
Events that may open a hold in state `s`: lock-taking events, the out-of-lock snapshot
hook, and the `become_leader` of the genesis primary's untraced `force_become_primary`;
before the node is initialised, only those of `uninitialisedHeads`.
-/
def isHead (env : Env) (s : State) (e : Ev) : Bool :=
  (initialised s || uninitialisedHeads.contains e.function)
  && (opens e
      || Exec.outOfLock s.declared e
      || (e.function == "become_leader"
          && s.currentView == 0
          && s.leadership == .none
          && pristine env s))

def at_ {α : Type} (e : Ev) (x : Except String α) : Except String α :=
  x.mapError fun err => s!"{e.loc} h_ts={e.hts} node={e.node}: {err}"

/-- Run the handler that `head` opens from `saved` on `actions`; in `final` mode to completion. -/
def runHold (env : Env) (saved : State) (recv : Option (NodeID × Message)) (head : Ev)
    (actions : List Action) (final : Bool)
    : Except String Ctx :=
  if !isHead env saved head then
    .error s!"{head.function} is not a section head here and no section is open"
  else
    match Exec.handlerFor head.function
            (recv.map fun (n, m) => (env.names.name n, m)) with
    | none => .error s!"{head.function} cannot open a section with this delivery"
    | some h =>
        match Exec.run env saved actions final h with
        | .ok c =>
            if c.queue.isEmpty then
              .ok c
            else
              .error
                s!"event not explained by the section opened at {head.loc} h_ts={head.hts}"
        | .error (.blocked c) =>
            if final then .error "internal: blocked at release" else .ok c
        | .error (.error err) => .error err

def sameLedger (x y : Array Exec.Entry) : Bool :=
  @decide (x = y) (withPtrEqDecEq x y fun _ => inferInstance)

/-- `a = b`, cheaply when the ledger (or the whole state) is shared, as it is across most holds. -/
def sameVars (a b : State) : Bool :=
  @decide (a = b)
    (withPtrEqDecEq a b
      fun _ =>
        if h
            : sameLedger a.ledger b.ledger = true
              ∧ { a with ledger := #[] } = { b with ledger := #[] } then
          isTrue
            (by
              obtain ⟨l, r⟩ := h
              simp only [sameLedger, decide_eq_true_eq] at l
              cases a; cases b; simp_all)
        else
          isFalse (by intro e; subst e; simp [sameLedger] at h))

/-- One event. -/
def stepE (env : Env) (l : Local) (recv : Option (NodeID × Message)) (e : Ev)
    : Except String Local :=
  match Exec.actionOf e with
  | .error err => at_ e (.error err)
  | .ok a =>
      match l.sec with
      | none =>
          match runHold env l.vars recv e [a] false with
          | .error err => at_ e (.error err)
          | .ok c =>
              match Exec.observe e c.vars.declared c.label with
              | .error err => at_ e (.error err)
              | .ok () =>
                  if opens e && !sameVars c.vars l.vars then
                    at_ e (.error "the lock-taking event changed the declared state")
                  else
                    .ok
                      {
                        l with
                          sec :=
                            some
                              {
                                head := e, recv, saved := l.vars, actions := [a], ctx := c
                              }
                      }
      | some s =>
          match recv with
          | some _ => at_ e (.error "a message delivered inside a section")
          | none =>
              match runHold env s.saved s.recv s.head (s.actions ++ [a]) false with
              | .error err => at_ e (.error err)
              | .ok c =>
                  match Exec.observe e c.vars.declared c.label with
                  | .error err => at_ e (.error err)
                  | .ok () =>
                      .ok
                        {
                          l with
                            sec := some { s with actions := s.actions ++ [a], ctx := c }
                        }

/-! ## Release -/

/-- The snapshot a joiner's hold installed, from its notes. -/
def snapshotOf (c : Ctx) : Option (Nat × Nat) :=
  c.notes.findSome?
    fun
    | .initAsBackup index term => some (index, term)
    | _ => none

/--
Fill a joiner's ledger prefix up to its snapshot `index` (its `base`) from a donor: another
node whose declared state has committed `index`. The joiner does not hold the prefix
(`State.declared` drops it): it is a ghost, for the proof. The joiner does hold the view
history up to `index`, which `init_as_backup` receives with the snapshot
(`get_history_until(index)` of the node that took it) but no trace point records: it is the
donor's, up to `index`. Both nodes' histories give each index up to `index` the term of
its committed entry (`inv`'s `terms_are_views`), and their starts are positive and sorted,
so they are equal.
-/
def fillSnapshot (others : List (NodeID × Local)) (index term : Nat) (vars : State)
    : Except String State :=
  match others.find?
          fun (_, o) => index <= o.vars.commitIdx && index <= o.vars.ledger.size with
  | none => .error s!"wait: no node has committed {index} yet"
  | some (_, donor) =>
      let prefix_ := donor.vars.ledger.extract 0 index
      -- A snapshot is taken at a signature, in the snapshot's view.
      if index != 0 && !prefix_[index - 1]?.any fun e => e.sig && e.term == term then
        .error
          s!"snapshot at {index} in view {term}: the donor's entry {index} is not a signature in that view"
      -- The snapshot's hooks installed configurations of the snapshotted prefix. hooks.h
      -- installs a snapshot's configuration at the version of the snapshot's last write
      -- to the nodes table, which may follow the entry that set the membership (a node's
      -- deletion does not change it): the configuration in force at that index.
      else if !vars.configurations.all
                fun c =>
                  1 <= c.idx
                  && c.idx <= index
                  && (prefix_.extract 0 c.idx).toList.reverse.findSome? (·.config)
                      == some c.nodes then
        .error
          s!"snapshot at {index}: the configurations its hooks installed, {vars.configurations.map (·.idx)}, are not configurations of the donor's prefix"
      else if prefix_.any (·.retired.contains vars.nodeId) then
        .error
          s!"snapshot at {index}: the snapshotted prefix retires the joiner {vars.nodeId}"
      else
        .ok
          {
            vars with
              ledger := prefix_ ++ vars.ledger.extract index vars.ledger.size
              views := donor.vars.views.filter (· <= index)
          }

/-- The declared state at release: a joiner's snapshot prefix is filled from a donor. -/
def closeVars (others : List (NodeID × Local)) (head : Ev) (c : Ctx)
    : Except String State :=
  match snapshotOf c with
  | some (index, term) =>
      if head.function == "init_as_backup" then
        fillSnapshot others index term c.vars
      else
        .ok c.vars
  | none => .ok c.vars

/--
A hold from a pristine state may only bring the node to where the clean model starts it:
it receives nothing and sends nothing, and leaves the node pristine or in the clean initial
state; no other hold makes a node pristine. This is the one lifecycle check M_tv adds to
`cft.h`; it rejects a genesis node that does anything but `force_become_primary` and
replicate the genesis configuration first, or that later truncates its ledger to nothing.
-/
def genesisOk (env : Env) (s : Sec) (c : Ctx) (vars : State) : Bool :=
  if pristine env s.saved then
    s.recv.isNone
    && c.outbox.isEmpty
    && (pristine env vars
        || agrees env.names
            (Consensus.Model.initialNodeState env.genesis (env.names.id vars.nodeId))
            vars)
  else
    !pristine env vars

/--
The release check of the local invariant: `inv` of the declared state at release. A hold
that leaves the declared state as it was at acquisition, as most do, keeps `inv` without
evaluating it, because that state was itself checked at its release (or is initial).
-/
def keepsInv (names : Names) (saved vars : State) : Bool :=
  sameVars vars saved || inv names vars

/--
The snapshot base is committed, and the ledger has the snapshot's signature there, in the
snapshot view: what the declared state's relation (`Exec.Declared.agrees`) says of the
prefix the node does not hold. Checked at every release.
-/
def baseOk (d : State) : Bool :=
  d.base <= d.commitIdx
  && (d.base == 0 || d.ledger[d.base - 1]?.any fun e => e.sig && e.term == d.baseView)

/--
The hold's outcome does not depend on the ledger up to the snapshot base, which the node
does not hold: rerun from the saved declared state with placeholders there
(`Declared.expand`), it releases the same declared state and sends. Checked at every
release of a node with a base; the placeholders are in view 0, so any entry read there
and sent, or term read there, differs. Accepted by the implementation, rejected by
validation: a primary that joined from a snapshot sends a follower that lags below its
base AppendEntries below it; the host (`node_connections.h`) cannot read those entries and
drops the message, while the specification sends them.
-/
def ghostFree (env : Env) (s : Sec) (c : Ctx) : Bool :=
  s.saved.base == 0
  || match runHold env s.saved.declared.expand s.recv s.head s.actions true with
      | .ok c' => c'.vars.declared == c.vars.declared && c'.outbox == c.outbox
      | .error _ => false

/--
Release: run the hold's trailing code; the declared state at release and the sends. The
declared state at release must satisfy `inv` and `baseOk`, and the hold be `ghostFree`.
-/
def closeX (env : Env) (others : List (NodeID × Local)) (l : Local)
    : Except String (Local × List (CCF.Envelope NodeID Message) × Ctx) :=
  match l.sec with
  | none => .error "release outside a section"
  | some s =>
      let loc := s!"release of the section opened at {s.head.loc} h_ts={s.head.hts}"
      match runHold env s.saved s.recv s.head s.actions true with
      | .error err => .error s!"{loc}: {err}"
      | .ok c =>
          match closeVars others s.head c with
          | .error err =>
              .error (if err.startsWith "wait:" then err else s!"{loc}: {err}")
          | .ok vars =>
              if genesisOk env s c vars then
                if keepsInv env.names s.saved vars then
                  if baseOk vars then
                    if ghostFree env s c then
                      .ok ({ vars }, c.outbox, c)
                    else
                      .error
                        s!"{loc}: the hold's outcome depends on the ledger up to the snapshot base {s.saved.base}, which the node does not hold (if it sends AppendEntries below the base: accepted by the implementation, rejected by validation: known implementation and specification difference: the host cannot read entries below a snapshot base and drops the message, the specification sends them)"
                  else
                    .error
                      s!"{loc}: snapshot base {vars.base} in view {vars.baseView} not a committed signature"
                else
                  .error s!"{loc}: {invDiagnostic env.names vars}"
              else
                .error
                  s!"{loc}: the genesis node must first become primary and replicate the genesis configuration, alone"

/-- M_tv as an event-granular node machine. -/
def machine (env : Env) : CCF.Sections.Machine NodeID Message Local Ev where
  init node l :=
    env.names.id (env.names.name node) = node
    ∧ (node ∈ env.genesis → env.genesis.min? = some node)
    ∧ ∃ ticking, l = initialLocal env node ticking
  idle := Local.idle
  opens := opens
  step _ l recv e := (stepE env l recv e).toOption
  close others _ l := ((closeX env others l).toOption).map fun (l, sends, _) => (l, sends)

/-- The clean protocol M_tv refines. -/
abbrev protocol (env : Env) := Consensus.Model.protocol env.genesis

end Consensus.TraceValidation
