module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.MTv.Machine

@[expose] public section

/-!
# The validator (not reviewed, except through `validate_sound`)

`schedule` finds an action list for the event-granular network of M_tv: one stream per
node, ordered by `h_ts` within the node's process; any node whose next event is enabled
steps (receives and joiner releases may wait); a node releases when its next event is a
section head or its stream has ended. It never compares `h_ts` across nodes.

`restream` takes every action's event from the streams, in order per node, and requires
every stream to be used up, so the observations are the streams' events by construction.
`certify` then replays the action list with the framework's own `next` (`emitsCheck`),
which yields the observation list, and checks that the run started in an initial state
and ended with every lock released. `validate_sound` (in `Consensus.TraceValidation.Proofs.Validator`) turns
a successful `validate` into `CCF.Sections.Accepts`, whatever `schedule` did.
-/

namespace Consensus.TraceValidation

open Lean
open CCF (Envelope)
open CCF.Sections (next)
open CCF.MultiNodeTransitionSystem (nodeState)
open Consensus.Model (initialNodeState)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (Ev State Ctx)

abbrev GState := CCF.Sections.State NodeID Message Local
abbrev GAction := CCF.Sections.Action NodeID Message Ev

/-! ## Certification: the part `validate_sound` is about -/

/-- `CCF.Sections.Emits` as a function: replay the actions, collecting observations. -/
def emitsCheck (env : Env) : GState -> List GAction -> Option (GState × List Obs)
  | s, [] => some (s, [])
  | s, .event node e :: rest =>
      match next (machine env) s (.event node e) with
      | none => none
      | some s' =>
          match nodeState s' node with
          | none => none
          | some slot =>
              match emitsCheck env s' rest with
              | none => none
              | some (f, os) => some (f, ⟨node, e, declare slot.current⟩ :: os)
  | s, .deliver x e :: rest =>
      match next (machine env) s (.deliver x e) with
      | none => none
      | some s' =>
          match nodeState s' x.target with
          | none => none
          | some slot =>
              match emitsCheck env s' rest with
              | none => none
              | some (f, os) => some (f, ⟨x.target, e, declare slot.current⟩ :: os)
  | s, .release node :: rest =>
      match next (machine env) s (.release node) with
      | none => none
      | some s' => emitsCheck env s' rest

/-- The initial network over `keys`. -/
def start (env : Env) (keys : List NodeID) (ticking : NodeID -> Bool) : GState :=
  {
    nodes := keys.map fun k => (k, { current := initialLocal env k (ticking k) }),
    network := []
  }

/--
Clean ids of the trace's nodes are their positions in the name table, and a genesis member
is the genesis primary (the clean model starts the other members as followers in term 2,
which `cft.h` has no event for).
-/
def initOk (env : Env) (k : NodeID) : Bool :=
  env.names.id (env.names.name k) == k
  && (!(k ∈ env.genesis) || env.genesis.min? == some k)

/-- Replay from the initial state; the observations, if the run is a complete accepted one. -/
def certify (env : Env) (keys : List NodeID) (ticking : NodeID -> Bool)
    (actions : List GAction)
    : Option (List Obs) :=
  if keys.Nodup /\ keys.all (initOk env) = true /\ env.genesis.Nonempty then
    match emitsCheck env (start env keys ticking) actions with
    | some (f, obs) =>
        if f.nodes.all (fun e => e.2.entry.isNone)
            && obs.all (fun o => Exec.consistent o.event o.declared) then
          some obs
        else
          none
    | none => none
  else
    none

/-- Take node `k`'s next stream event, from the first stream of `k`. -/
def popEvent (k : NodeID)
    : List (NodeID × List Ev) -> Option (Ev × List (NodeID × List Ev))
  | [] => none
  | (j, evs) :: rest =>
      if j == k then
        match evs with
        | e :: es => some (e, (j, es) :: rest)
        | [] => none
      else
        (popEvent k rest).map fun (e, rest') => (e, (j, evs) :: rest')

/--
Take the events of the actions from the streams, in order per node (checking the trace
line), and require every stream to be used up: the observations are then the streams'
events by construction.
-/
def restream : List (NodeID × List Ev) -> List GAction -> Option (List GAction)
  | rest, [] => if rest.all (·.2.isEmpty) then some [] else none
  | rest, .release k :: as => (restream rest as).map (.release k :: ·)
  | rest, .event k e :: as =>
      match popEvent k rest with
      | some (e', rest') =>
          if e'.line == e.line then (restream rest' as).map (.event k e' :: ·) else none
      | none => none
  | rest, .deliver x e :: as =>
      match popEvent x.target rest with
      | some (e', rest') =>
          if e'.line == e.line then (restream rest' as).map (.deliver x e' :: ·) else none
      | none => none

/-! ## Scheduling (untrusted search for an action list) -/

/-- A release, for the diagnostic lock-step check. -/
structure Release where
  node : NodeID
  sec : Sec
  /-- The handler's context at the end of the hold. -/
  ctx : Ctx
  /-- The declared state at release. -/
  vars : State

structure World where
  st : GState
  pos : Array Nat
  actions : Array GAction := #[]
  /-- Dropped copies, still in the framework's network. -/
  dead : List (Envelope NodeID Message) := []
  /-- Drops that found no live copy: a later identical send settles each. -/
  debts : List (NodeID × NodeID × Json) := []
  sections : Nat := 0
  waits : Nat := 0
  releases : Array Release := #[]

inductive Progress where
  | moved
  | blocked (why : String)
  | done

def count (x : Envelope NodeID Message) (l : List (Envelope NodeID Message)) : Nat :=
  (l.filter (· == x)).length

def World.live (w : World) (x : Envelope NodeID Message) : Bool :=
  let inboxes := w.st.nodes.filterMap (·.2.inbox)
  count x w.st.network > count x w.dead + count x inboxes

/-- A live in-flight envelope from `source` to `target` with this packet; unique up to identity. -/
def findLive (w : World) (source target : NodeID) (packet : Json)
    : Except String (Option (Envelope NodeID Message)) := do
  let hits :=
    w.st.network.filter
      fun x =>
        x.source == source
        && x.target == target
        && Exec.packetOf x.payload == packet
        && w.live x
  match hits with
  | [] => return none
  | x :: rest =>
      unless rest.all (· == x) do
        throw
          s!"ambiguous envelope {source}->{target} {packet.compress}: in-flight copies differ"
      return some x

def apply (env : Env) (w : World) (a : GAction) (diagnose : Unit -> String)
    : Except String World :=
  match next (machine env) w.st a with
  | some st => .ok { w with st, actions := w.actions.push a }
  | none => .error (diagnose ())

def stepNode (env : Env) (streams : Array (NodeID × Array Ev)) (w : World) (i : Nat)
    : Except String (World × Progress) := do
  let (k, evs) := streams[i]!
  let some slot := nodeState w.st k | throw s!"node {k} missing"
  let next? := evs[w.pos[i]!]?
  let others := (CCF.Sections.without w.st.nodes k).map fun e => (e.1, e.2.base)
  if slot.entry.isSome then
    if next?.all (isHead env (current slot.current)) then
      let release ←
        match closeX env others slot.current with
        | .error err =>
            if err.startsWith "wait:" then
              return (
                { w with waits := w.waits + 1 },
                .blocked s!"node {env.names.name k}: {err}"
              )
            else
              throw err
        | .ok (l, _, c) =>
            match slot.current.sec with
            | some sec => pure { node := k, sec, ctx := c, vars := l.vars : Release }
            | none => throw "internal: release without a section"
      let pendingLen := w.st.network.length - (if slot.inbox.isSome then 1 else 0)
      let w ←
        apply env w (.release k) fun _ => s!"node {env.names.name k}: release refused"
      -- Sends that settle earlier drops are dead on arrival.
      let mut w2 :=
        { w with sections := w.sections + 1, releases := w.releases.push release }
      for x in w2.st.network.drop pendingLen do
        match w2.debts.findIdx?
                fun (s, t, p) =>
                  s == x.source && t == x.target && p == Exec.packetOf x.payload with
        | some j => w2 := { w2 with debts := w2.debts.eraseIdx j, dead := x :: w2.dead }
        | none => pure ()
      return (w2, .moved)
    else
      let e := next?.get!
      let w ←
        apply env w (.event k e)
          fun _ =>
            match stepE env slot.current none e with
            | .error err => err
            | .ok _ => s!"{e.loc}: lock-taking event inside a section"
      return ({ w with pos := w.pos.set! i (w.pos[i]! + 1) }, .moved)
  else
    let some e := next? | return (w, .done)
    let mut w := w
    let mut action : GAction := .event k e
    if Exec.recvHeads.contains e.function then
      let from_ ← at_ e (Exec.getStr e.msg "from_node_id")
      let packet ← at_ e (e.msg.getObjVal? "packet")
      match ← at_ e (findLive w (env.names.id from_) k packet) with
      | some x => action := .deliver x e
      | none =>
          return (
            w,
            .blocked
              s!"{e.loc} h_ts={e.hts} waits for {from_}->{e.node} {packet.compress}"
          )
    else if e.function == "drop_pending_to" then
      let to ← at_ e (Exec.getStr e.msg "to_node_id")
      let packet ← at_ e (e.msg.getObjVal? "packet")
      match ← at_ e (findLive w k (env.names.id to) packet) with
      | some x => w := { w with dead := x :: w.dead }
      | none =>
          -- Some receiver took an identical copy early; this drop owes a later identical send.
          unless env.names.known.contains to do
            throw s!"{e.loc} h_ts={e.hts}: drops a message to unknown node {to}"
          w := { w with debts := w.debts ++ [(k, env.names.id to, packet)] }
    let recv :=
      match action with
      | .deliver x _ => some (x.source, x.payload)
      | _ => none
    let w' ←
      apply env w action
        fun _ =>
          match stepE env slot.current recv e with
          | .error err => err
          | .ok _ => s!"{e.loc}: the framework refused the step"
    return ({ w' with pos := w'.pos.set! i (w'.pos[i]! + 1) }, .moved)

structure Verdict where
  keys : List NodeID
  releases : List Release
  actions : List GAction
  observations : List Obs
  sections : Nat
  waits : Nat
  inFlight : Nat

def schedule (env : Env) (ticking : NodeID -> Bool) (streams : Array (NodeID × Array Ev))
    : Except String World := do
  let keys := streams.toList.map Prod.fst
  let mut w : World := { st := start env keys ticking, pos := streams.map fun _ => 0 }
  let total := streams.foldl (fun a (_, s) => a + s.size) 0
  let mut fuel := 4 * total + 4 * streams.size + 16
  repeat
    let mut moved := false
    let mut blocked := #[]
    for i in [0:streams.size] do
      let mut go := true
      while go do
        let (w', p) ← stepNode env streams w i
        w := w'
        match p with
        | .moved => moved := true
        | .blocked why => blocked := blocked.push why; go := false
        | .done => go := false
    if !moved then
      if blocked.isEmpty then break
      throw
        s!"deadlock: every unfinished node waits:\n  {"\n  ".intercalate blocked.toList}"
    fuel := fuel - 1
    if fuel == 0 then throw "scheduler fuel exhausted"
  unless w.debts.isEmpty do
    throw
      s!"drops never settled by an identical send: {w.debts.map fun (s, t, _) => (s, t)}"
  return w

/-- Certify a scheduled action list. -/
def conclude (env : Env) (ticking : NodeID -> Bool) (streams : List (NodeID × List Ev))
    (w : World)
    : Except String Verdict :=
  let keys := streams.map Prod.fst
  match restream streams w.actions.toList with
  | none => .error "internal: the scheduled events differ from the streams"
  | some actions =>
      match certify env keys ticking actions with
      | none => .error "internal: the scheduled run does not certify"
      | some observations =>
          .ok
            {
              keys,
              releases := w.releases.toList,
              actions,
              observations,
              sections := w.sections
              waits := w.waits,
              inFlight := w.st.network.length
            }

/--
The initial `ticking` of a node: the value carried by its first event that carries one
(every write to `ticking` follows such an event in the same hold), else unobservable.
-/
def initialTicking (streams : List (NodeID × List Ev)) (k : NodeID) : Bool :=
  ((streams.lookup k).bind
    fun evs =>
      evs.findSome? fun e => (e.msg.getObjValAs? Bool "ticking").toOption).getD
    true

/-- Schedule, then certify the action list. -/
def validate (env : Env) (streams : List (NodeID × List Ev)) : Except String Verdict :=
  let ticking := initialTicking streams
  match schedule env ticking (streams.map fun (k, evs) => (k, evs.toArray)).toArray with
  | .error err => .error err
  | .ok w => conclude env ticking streams w

end Consensus.TraceValidation
