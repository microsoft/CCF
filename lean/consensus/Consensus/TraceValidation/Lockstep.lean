module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Validator
public import Consensus.TraceValidation.Invariant

@[expose] public section

/-!
# Lock-step check (diagnostic, not part of acceptance)

`lockstep` replays an accepted trace's releases, in order, against the clean model:
for each lock hold it rebuilds the clean inputs from the handler's notes, runs the clean
local steps from the node's clean state, and reports every release where the result is
not related (`Rel`) to the declared state, where a clean primary has a stale match index
for a node outside its configurations (`UnnamedUnmatched`), where a conjunct of the local
invariant `inv` fails, where the clean sends differ from the hold's, or where a send breaks `msgInv`.
It is a regression oracle for the refinement proof's invariants, run by
`consensus-replay --refine`.
-/

namespace Consensus.TraceValidation

open Lean
open CCF (Finset Capabilities)
open Consensus.Model (initialNodeState)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State Ev Ctx Note)

/-! ## Rendering, for diagnostics -/

def showEntry (e : Entry) : String :=
  match e.content with
  | .signature => s!"{e.term}s"
  | .transaction _ md =>
      let c :=
        match md.configuration with
        | some ns => s!"c{ns.sort}"
        | none => ""
      let r :=
        if md.retirementConfirmations.sort.isEmpty then
          ""
        else
          s!"r{md.retirementConfirmations.sort}"
      s!"{e.term}{c}{r}"

def showLog (l : List Entry) : String := toString (l.map showEntry)

def showRole : Role -> String
  | .none => "none"
  | .follower => "follower"
  | .preVoteCandidate => "preVoteCandidate"
  | .candidate => "candidate"
  | .primary => "primary"

def showMessage : Message -> String
  | .appendEntriesRequest r =>
      s!"AE(t{r.term} prev {r.prevLogIndex}/{r.prevLogTerm} {showLog r.entries} c{r.primaryCommit})"
  | .appendEntriesResponse r => s!"AER(t{r.term} {r.success} {r.lastLogIndex})"
  | .requestVoteRequest r =>
      s!"RV(t{r.term} {r.lastCommittableIndex}/{r.lastCommittableTerm})"
  | .requestPreVoteRequest r =>
      s!"PRV(t{r.term} {r.lastCommittableIndex}/{r.lastCommittableTerm})"
  | .requestVoteResponse r => s!"RVR(t{r.term} {r.voteGranted})"
  | .requestPreVoteResponse r => s!"PRVR(t{r.term} {r.voteGranted})"
  | .proposeRequestVoteRequest t => s!"PROPOSE(t{t})"

def eventKind : Event -> String
  | .internal (.append es) => s!"append[{es.length}]"
  | .internal (.sendEntries _ _) => "sendEntries"
  | .internal (.timeout .election) => "timeout.election"
  | .internal (.timeout .checkQuorum) => "timeout.checkQuorum"
  | .internal .nominateSuccessor => "nominateSuccessor"
  | .internal (.initAsBackup _) => "initAsBackup"
  | .receive _ m =>
      "receive."
      ++ match m with
          | .appendEntriesRequest _ => "AE"
          | .appendEntriesResponse _ => "AER"
          | .requestVoteRequest _ => "RV"
          | .requestVoteResponse _ => "RVR"
          | .requestPreVoteRequest _ => "PRV"
          | .requestPreVoteResponse _ => "PRVR"
          | .proposeRequestVoteRequest _ => "PROPOSE"

/-- The clean guard a failed clean step corresponds to, for diagnostics. -/
def guardHint : Event -> String
  | .internal (.append _) =>
      " (Node.lean's appendEntry or sendEntries does not admit an entry the host submitted or a flush cft.h made)"
  | .internal (.sendEntries _ _) => " (Node.lean's sendEntries guard)"
  | .internal (.timeout .election) => " (Node.lean's canStartElection)"
  | _ => ""

/-- Run clean local steps, accumulating sends. -/
def runClean (node : NodeID) (st : NodeState)
    : List Event -> Except String (NodeState × List (CCF.Envelope NodeID Message))
  | [] => .ok (st, [])
  | ev :: rest =>
      match (Consensus.Model.Node.step (Capabilities.record node) node st ev).run {} with
      | some (st', o) =>
          match runClean node st' rest with
          | .ok (f, s) => .ok (f, o.outgoing ++ s)
          | .error err => .error err
      | none => .error s!"clean guard failed at {eventKind ev}{guardHint ev}"

/-- The section's clean events. -/
def cleanEvents (recv : Option (NodeID × Message)) (inputs : List Input) : List Event :=
  (recv.map fun (source, m) => Event.receive source m).toList ++ inputs.map .internal

/-- The clean result of a section: its clean local steps, run from the ghost state. -/
def cleanSection (node : NodeID) (clean : NodeState) (recv : Option (NodeID × Message))
    (inputs : List Input)
    : Except String (NodeState × List (CCF.Envelope NodeID Message)) :=
  runClean node clean (cleanEvents recv inputs)

/-- Field-wise differences between a clean state and `abs` of a declared state. -/
def relatedDiff (env : Env) (c : NodeState) (d : State) : List String :=
  let a := abs env.names d
  let f (name : String) (x y : String) :=
    if x == y then [] else [s!"{name}: clean={x} declared={y}"]
  let peers := trackedPeers env.names d
  f "role" (showRole c.role) (showRole a.role)
  ++ f "currentTerm" (toString c.currentTerm) (toString a.currentTerm)
  ++ f "log" (showLog c.log) (showLog a.log)
  ++ f "commitIndex" (toString c.commitIndex) (toString a.commitIndex)
  ++ f "sentIndex" (toString (peers.map c.sentIndex)) (toString (peers.map a.sentIndex))
  ++ f "matchIndex" (toString (peers.map c.matchIndex))
      (toString (peers.map a.matchIndex))
  ++ f "isNewFollower" (toString c.isNewFollower) (toString a.isNewFollower)
  ++ f "votedFor" (toString c.votedFor) (toString a.votedFor)
  ++ f "primaryKnown" (toString c.primaryKnown) (toString a.primaryKnown)
  ++ (if a.role == .candidate then
        f "votesGranted" (toString c.votesGranted.sort) (toString a.votesGranted.sort)
      else
        [])
  ++ (if a.role == .preVoteCandidate then
        f "preVotesGranted" (toString c.preVotesGranted.sort)
          (toString a.preVotesGranted.sort)
      else
        [])
  ++ f "retiredCommittedIndex" (toString c.retiredCommittedIndex)
      (toString a.retiredCommittedIndex)

/-- The hold's clean internal inputs, from its head and the handler's notes. -/
def cleanInputs (env : Env) (others : List (NodeID × NodeState)) (pristine : Bool)
    (r : Release)
    : Except String (List Input) := do
  let s := r.sec
  if pristine then return []
  match s.head.function with
  | "become_leader" | "add_configuration" | "drop_pending_to" => return []
  -- A non-primary's nomination is traced and does nothing.
  | "nomination" =>
      return (if s.saved.leadership == .leader then [.nominateSuccessor] else [])
  | _ => pure ()
  let mut evs : Array Input := #[]
  let mut batch : Array AppendEntryInput := #[]
  let mut flushing := false
  let mut tickSends := false
  for n in r.ctx.notes do
    match n with
    | .heartbeatTimeout => tickSends := true
    | .checkQuorum => evs := evs.push (.timeout .checkQuorum)
    | .electionTimeout => evs := evs.push (.timeout .election)
    | .appendEntry e =>
        batch := batch.push { content := (absEntry env.names e).content }
        flushing := false
    | .batchFlush => flushing := true
    | .sendEntries d e true =>
        if flushing then
          let some last := batch.back? | throw "flush before any entry"
          batch :=
            batch.pop.push { last with flushes := last.flushes ++ [(env.names.id d, e)] }
        else if tickSends then
          evs := evs.push (.sendEntries (env.names.id d) e)
        else
          throw "independent send outside a heartbeat or flush"
    | .sendEntries _ _ false => pure ()
    | .initAsBackup index _ =>
        let some (_, donor) := others.find? fun (_, o) => index <= o.commitIndex
        | throw s!"no clean node has committed {index}"
        evs := evs.push (.initAsBackup (donor.log.take index))
  if !batch.isEmpty then evs := evs.push (.append batch.toList)
  return evs.toList

/--
The clean-model findings of one release, given the clean states before it. From a pristine
genesis primary (`pristine`), whose clean state is still the initial one, a hold has no
clean counterpart (`genesisOk`).
-/
def checkRelease (env : Env) (cleans : List (NodeID × NodeState)) (r : Release)
    : Except String (NodeState × List String) := do
  let node := r.node
  let loc :=
    s!"section opened at {r.sec.head.loc} h_ts={r.sec.head.hts} node={r.sec.head.node}"
  let some clean := cleans.lookup node | throw s!"{loc}: no clean state"
  let others := cleans.filter (·.1 != node)
  let preGenesis := pristine env r.sec.saved
  let inputs ← (cleanInputs env others preGenesis r).mapError fun err => s!"{loc}: {err}"
  let events := cleanEvents (if preGenesis then none else r.sec.recv) inputs
  let (clean', sends) ← (runClean node clean events).mapError fun err => s!"{loc}: {err}"
  let mut findings := []
  let failed := (invChecks env.names r.vars).filter (!·.2) |>.map (·.1)
  unless failed.isEmpty do
    findings := findings ++ [s!"{loc}: invariant fails: {failed}"]
  unless r.vars.nodeId == env.names.name node
          && env.names.id r.vars.nodeId == node
          && ((preGenesis && pristine env r.vars) || agrees env.names clean' r.vars) do
    findings := findings ++ [s!"{loc}: not related: {relatedDiff env clean' r.vars}"]
  -- `UnnamedUnmatched` (Proofs/Obligation.lean, the proof relation's clean-side conjunct),
  -- on the trace's nodes: a clean primary has match index 0 for every other node that no
  -- configuration in its log names.
  let named := configurationMembers (configurationHistory clean'.log)
  let stale :=
    if clean'.role == .primary then
      (List.range env.names.known.size).filter
        fun n => n != node && !decide (n ∈ named) && clean'.matchIndex n != 0
    else
      []
  unless stale.isEmpty do
    findings := findings ++ [s!"{loc}: stale clean match index of unnamed nodes {stale}"]
  unless r.ctx.outbox == sends do
    findings :=
      findings
      ++ [s!"{loc}: sends differ: clean {sends.map fun x => (x.target, showMessage x.payload)}, cft.h {r.ctx.outbox.map fun x => (x.target, showMessage x.payload)}"]
  for x in r.ctx.outbox do
    unless msgInv env.names x do
      findings :=
        findings ++ [s!"{loc}: message invariant fails: {showMessage x.payload}"]
  return (clean', findings)

/-- Every finding of the lock-step check over an accepted trace's releases. -/
def lockstep (env : Env) (v : Verdict) : Except String (List String) := do
  let mut cleans := v.keys.map fun k => (k, initialNodeState env.genesis k)
  let mut findings := #[]
  let mut seen : List NodeID := []
  for r in v.releases do
    -- A hold that changed nothing has the same verdict as the node's previous release.
    if seen.contains r.node
        && r.sec.recv.isNone
        && r.ctx.notes.isEmpty
        && r.ctx.outbox.isEmpty
        && sameVars r.sec.saved r.vars then
      continue
    seen := if seen.contains r.node then seen else r.node :: seen
    let (c, fs) ← checkRelease env cleans r
    cleans := cleans.map fun (k, x) => if k == r.node then (k, c) else (k, x)
    findings := findings ++ fs
  return findings.toList

end Consensus.TraceValidation
