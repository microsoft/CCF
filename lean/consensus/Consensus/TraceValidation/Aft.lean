module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Handler

@[expose] public section

/-!
# M_tv: cft.h, one trace point at a time

Each definition mirrors the cft.h function of the same name, statement by
statement, and calls `trace` exactly where cft.h calls `trace::*`. Code between
trace points runs silently on `State`. Where cft.h depends on something the trace
does not carry (timers, batch sizes, ledger flush thresholds), the handler peeks
at the node's next event (`look`) and follows the branch that event requires.
-/

namespace Consensus.TraceValidation.Exec

open Lean
open Consensus.Model.Node

/-! ## Pure helpers over `State` (cft.h-aligned, no clean-model calls) -/

namespace State

def isRetiredCommitted (v : State) : Bool :=
  v.retired && v.retirementPhase == some .retiredCommitted

/-- `ViewHistory::view_at`: number of view starts at or below `idx`. -/
def viewAt (v : State) (idx : Nat) : Nat := (v.views.toList.filter (· <= idx)).length

def startOfView (v : State) (view : Nat) : Nat :=
  if view > v.views.size || view == 0 then
    0
  else
    let tentative := v.views[view - 1]!
    if view + 1 <= v.views.size && v.views[view]! == tentative then 0 else tentative

def endOfView (v : State) (view : Nat) : Nat :=
  if v.startOfView view == 0 then
    0
  else if view >= v.views.size || view == 0 then
    0
  else
    v.views[view]! - 1

/-- `get_term_internal`. -/
def getTerm (v : State) (idx : Nat) : Nat := if idx > v.lastIdx then 0 else v.viewAt idx

def lastCommittable (v : State) : Nat := v.committable.getLast?.getD v.commitIdx

/-- `find_highest_possible_committable_index`. -/
def highestCommittableLe (v : State) (idx : Nat) : Option Nat :=
  (v.committable.filter (· <= idx)).getLast?

/-- `find_highest_possible_match`; each round moves to an earlier view. -/
def highestMatchGo (v : State) (term probe tp : Nat) : Nat -> Nat
  | 0 => probe
  | fuel + 1 =>
      if tp > term then
        let p := v.startOfView tp
        let p := if p > 0 then p - 1 else p
        highestMatchGo v term p (v.viewAt p) fuel
      else
        probe

def highestMatch (v : State) (term idx : Nat) : Nat :=
  let probe := min idx v.lastIdx
  v.highestMatchGo term probe (v.viewAt probe) (v.views.size + 1)

def otherNodesInActiveConfigs (v : State) : List NodeId :=
  (v.configurations.flatMap (·.nodes.map Prod.fst)).filter (· != v.nodeId)
  |>.mergeSort (· <= ·)
  |>.eraseDups

def peer? (v : State) (id : NodeId) : Option Peer := v.allOtherNodes.lookup id

def setPeer (v : State) (id : NodeId) (p : Peer) : State :=
  let rest := v.allOtherNodes.filter (·.1 != id)
  { v with allOtherNodes := (rest ++ [(id, p)]).mergeSort (fun a b => a.1 <= b.1) }

def selfInLatestConfig (v : State) : Bool :=
  match v.configurations.getLast? with
  | some c => c.nodes.any (·.1 == v.nodeId)
  | none => false

def quorum (n : Nat) : Nat := n / 2 + 1

/--
Whether CheckQuorum can fail for some ack timers: some active configuration has fewer
members without peer state (counted live by cft.h) than its quorum.
-/
def canLoseQuorum (v : State) : Bool :=
  v.configurations.any
    fun c =>
      (c.nodes.filter fun (n, _) => (v.peer? n).isNone).length < quorum c.nodes.length

end State

/-! ## Messages -/

def aePacket (idx prevIdx term prevTerm leaderCommit termOfIdx : Nat) : Json :=
  Json.mkObj
    [
      ("msg", "append_entries"),
      ("idx", toJson idx),
      ("prev_idx", toJson prevIdx),
      ("term", toJson term),
      ("prev_term", toJson prevTerm),
      ("leader_commit_idx", toJson leaderCommit),
      ("term_of_idx", toJson termOfIdx),
      ("contains_new_view", toJson false)
    ]

def aerPacket (term idx : Nat) (ok : Bool) : Json :=
  Json.mkObj
    [
      ("msg", "append_entries_response"),
      ("term", toJson term),
      ("last_log_idx", toJson idx),
      ("success", toJson (if ok then "OK" else "FAIL"))
    ]

def rvPacket (pre : Bool) (term lci tlci : Nat) : Json :=
  Json.mkObj
    [
      ("msg", toJson (if pre then "request_pre_vote" else "request_vote")),
      ("term", toJson term),
      ("last_committable_idx", toJson lci),
      ("term_of_last_committable_idx", toJson tlci)
    ]

def rvrPacket (pre : Bool) (term : Nat) (granted : Bool) : Json :=
  Json.mkObj
    [
      (
        "msg",
        toJson (if pre then "request_pre_vote_response" else "request_vote_response")
      ),
      ("term", toJson term),
      ("vote_granted", toJson granted)
    ]

def prvPacket (term : Nat) : Json :=
  Json.mkObj [("msg", "propose_request_vote"), ("term", toJson term)]

/-- The term of the last entry of an AppendEntries, as `term_of_idx`. -/
def aeTermOfIdx (r : AppendEntriesRequest) : Nat :=
  (r.entries.getLast?.map (·.term)).getD r.prevLogTerm

def aeIdx (r : AppendEntriesRequest) : Nat :=
  r.prevLogIndex + r.entries.length

/-- The `cft.h` packet of a message. -/
def packetOf : Message -> Json
  | .appendEntriesRequest r =>
      aePacket (aeIdx r) r.prevLogIndex r.term r.prevLogTerm r.primaryCommit
        (aeTermOfIdx r)
  | .appendEntriesResponse r => aerPacket r.term r.lastLogIndex r.success
  | .requestVoteRequest r =>
      rvPacket false r.term r.lastCommittableIndex r.lastCommittableTerm
  | .requestPreVoteRequest r =>
      rvPacket true r.term r.lastCommittableIndex r.lastCommittableTerm
  | .requestVoteResponse r => rvrPacket false r.term r.voteGranted
  | .requestPreVoteResponse r => rvrPacket true r.term r.voteGranted
  | .proposeRequestVoteRequest t => prvPacket t

def envAddr (env : Env) (id : NodeId) : String := (env.addrs.lookup id).getD ""

def envNodes (env : Env) (s : CCF.Finset NodeID) : Nodes :=
  s.sort.map
    fun i =>
      let n := env.names.name i;
      (n, envAddr env n)

/-- A received entry as the ledger and its hooks see it. -/
def toExecEntry (env : Env) (e : Consensus.Model.Node.Entry) : Entry :=
  match e.content with
  | .signature => { term := e.term, sig := true }
  | .transaction _ md =>
      {
        term := e.term,
        sig := false,
        config := md.configuration.map (envNodes env)
        retired := md.retirementConfirmations.sort.map env.names.name
      }

/-! ## Handlers -/

/-- A receive's trace point, labelled with the delivered message. -/
def traceRecv (fn : String) (from_ : NodeId) (m : Message) : M Unit := do
  trace fn
  emit "packet" (packetOf m)
  emitStr "from_node_id" from_

/-- `send_append_entries_range`, given the sub-range end chosen by the batch size. -/
def sendAppendEntriesRange (to : NodeId) (start endIdx : Nat) (ext : Bool) : M Unit := do
  let v ← getV
  let prevIdx := start - 1
  let some node := v.peer? to | fail s!"{← curLoc}: all_other_nodes.at({to}) failed"
  let packet :=
    aePacket endIdx prevIdx v.currentView (v.getTerm prevIdx) v.commitIdx
      (v.getTerm endIdx)
  emit "packet" packet
  emitStr "to_node_id" to
  let names ← names
  let entries :=
    (List.range' start (endIdx + 1 - start)).map fun i => absEntry names v.ledger[i - 1]!
  send to
    (.appendEntriesRequest
      {
        term := v.currentView,
        prevLogIndex := prevIdx,
        prevLogTerm := v.getTerm prevIdx,
        entries,
        primaryCommit := v.commitIdx
      })
  note (.sendEntries to endIdx ext)
  setV fun v => v.setPeer to { node with sentIdx := endIdx }

/--
`send_append_entries`. The batch size is not traced, so each sub-range end is
read from the next `send_append_entries` event and checked against what any
batch size allows: one size for the whole call, every non-final sub-range full.
-/
def sendAppendEntries (to : NodeId) (start : Nat) (ext : Bool := false) : M Unit := do
  let rec loop : Nat -> Nat -> Option Nat -> M Unit
    | 0, _, _ => do fail s!"{← curLoc}: send_append_entries does not terminate"
    | fuel + 1, start, batch => do
        let v ← getV
        let maxIdx :=
          match v.endOfView (v.viewAt start) with
          | 0 => v.lastIdx
          | e => e
        -- Ends that some batch size >= 1 allows: maxIdx when start > maxIdx, else [start, maxIdx].
        let skipCertain := v.isRetiredCommitted && start >= maxIdx
        let endIdx ←
          if skipCertain then
            pure maxIdx
          else do
            let next ← look
            let isOurs :=
              match next with
              | some a =>
                  a.point == "send_append_entries"
                  && a.inputs.lookup "to_node_id" == some (toJson to)
              | none => false
            if v.isRetiredCommitted && !isOurs then
              -- Only a batch size of one makes start == end, which is silently skipped.
              if batch.any (· != 1) then
                fail s!"{← curLoc}: expected send_append_entries to {to}"
              pure start
            else
              trace "send_append_entries"
              let packet ← use "packet"
              let endIdx ← liftE (getNat packet "idx")
              pure endIdx
        let ok :=
          if start > maxIdx then endIdx == maxIdx else start <= endIdx && endIdx <= maxIdx
        unless ok do
          fail
           s!"{← curLoc}: packet.idx: observed {endIdx}, model allows [{start}, {maxIdx}]"
        let size := endIdx + 1 - start
        let batch ←
          if endIdx < maxIdx then do
            if batch.any (· != size) then
              fail
                s!"{← curLoc}: packet.idx: sub-range of {size} entries after batches of {batch}"
            pure (some size)
          else do
            if batch.any (· < size) then
              fail
                s!"{← curLoc}: packet.idx: final sub-range of {size} entries exceeds batch {batch}"
            pure batch
        let skipped := v.isRetiredCommitted && start >= endIdx
        unless skipped do
          -- Re-mark the packet as checked: the remaining fields are model-computed.
          sendAppendEntriesRange to start endIdx ext
        let v ← getV
        unless endIdx == v.lastIdx do
          loop fuel (min (endIdx + 1) v.lastIdx) batch
  loop ((← getV).lastIdx + 2) start none

def otherNodesSorted : M (List NodeId) := do
  return (← getV).allOtherNodes.map Prod.fst

def becomeRetired (idx : Nat) (phase : Phase) : M Unit := do
  match phase with
  | .ordered =>
      if (← getV).retirementIdx.isSome then
        fail s!"{← curLoc}: retirement_idx already set"
      setV fun v => { v with retirementIdx := some idx }
  | .signed => setV fun v => { v with retirementCommittableIdx := some idx }
  | .retiredCommitted =>
      nominateSuccessorUnsafe
      setV fun v => { v with leaderId := none, leadership := .none }
  | .completed => pure ()
  setV fun v => { v with retired := true, retirementPhase := some phase }
where
  findSuccessor : M (Option NodeId) := do
    let v ← getV
    let mut successor := none
    let mut maxMatch := 0
    let mut reconf := 0
    for (node, st) in v.allOtherNodes do
      if st.matchIdx >= maxMatch then
        let latest :=
          (v.configurations.reverse.find? (·.nodes.any (·.1 == node))).map (·.idx)
          |>.getD 0
        if !(st.matchIdx == maxMatch && latest < reconf) then
          reconf := latest
          successor := some node
          maxMatch := st.matchIdx
    return successor
  nominateSuccessorUnsafe : M Unit := do
    let v ← getV
    unless v.leadership == .leader do
      return
    if let some s ← findSuccessor then
      trace "step_down_and_nominate_successor"
      emitStr "to_node_id" s
      send s (.proposeRequestVoteRequest v.currentView)

def nominateSuccessorUnsafe : M Unit := becomeRetired.nominateSuccessorUnsafe

def createAndRemoveNodeState : M Unit := do
  let v ← getV
  let active :=
    (v.configurations.flatMap (·.nodes.map Prod.fst)).mergeSort (· <= ·) |>.eraseDups
  for id in active do
    if id == v.nodeId then continue
    let v ← getV
    if (v.peer? id).isNone then
      let index := v.lastIdx + 1
      setV fun v => v.setPeer id { sentIdx := index, matchIdx := 0 }
      if v.leadership == .leader then sendAppendEntries id index

/--
`set_retired_committed` of the entry at `seqno` naming `ids`. `peers0` are the peers at
the start of the commit, from which the specification nominates a successor.
-/
def setRetiredCommitted (seqno : Nat) (ids : List NodeId) (peers0 : List (NodeId × Peer))
    : M Unit := do
  for id in ids do
    let v ← getV
    if id == v.nodeId then
      unless v.retired && v.retirementPhase == some .completed do
        fail
          s!"{← curLoc}: set_retired_committed({seqno}) on self while not Retired/Completed"
      -- Accepted by the implementation, rejected by validation: successor nomination.
      -- cft.h erases the peers retired-committed earlier in the same commit before it
      -- nominates; the specification nominates from the peers before the commit.
      if v.leadership == .leader then
        let actual ← becomeRetired.findSuccessor
        setV fun v => { v with allOtherNodes := peers0 }
        let specified ← becomeRetired.findSuccessor
        setV fun _ => v
        unless actual == specified do
          fail
            s!"{← curLoc}: accepted by the implementation, rejected by validation: successor nomination (known implementation and specification difference: cft.h nominates {actual} after erasing peers retired-committed in the same commit; the specification nominates {specified} from the peers before the commit)"
      setV fun v => { v with retiredCommittedIdx := some seqno }
      becomeRetired seqno .retiredCommitted
    else
      setV fun v => { v with allOtherNodes := v.allOtherNodes.filter (·.1 != id) }

/-- Driver store `compact`: emulates the global-commit hook. -/
def storeCompact (idx : Nat) : M Unit := do
  let peers0 := (← getV).allOtherNodes
  let rec go : List (Nat × List NodeId) -> M Unit
    | [] => pure ()
    | (ver, ids) :: rest =>
        if ver <= idx then do
          setRetiredCommitted ver ids peers0; go rest
        else
          pure ()
  go (← getV).rcEntries
  setV fun v => { v with rcEntries := v.rcEntries.filter (·.1 > idx) }

def commit (idx : Nat) : M Unit := do
  let v ← getV
  if idx > v.lastIdx then fail s!"{← curLoc}: commit({idx}) beyond last_idx {v.lastIdx}"
  if idx <= v.commitIdx then return
  trace "commit"
  emitNat "idx" idx
  setV fun v => { v with committable := v.committable.filter (· > idx), commitIdx := idx }
  let v ← getV
  if v.retired && v.retirementPhase == some .signed then
    if let some rci := v.retirementCommittableIdx then
      if idx >= rci then becomeRetired idx .completed
  storeCompact idx
  let cs := (← getV).configurations
  let rec pop : List Config -> List Config
    | c :: n :: rest => if idx < n.idx then c :: n :: rest else pop (n :: rest)
    | cs => cs
  let cs' := pop cs
  if cs'.length != cs.length then
    setV fun v => { v with configurations := cs' }
    createAndRemoveNodeState

/-- The match indexes of a configuration's members, the leader's own being its last index. -/
def matchIdxs (v : State) (c : Config) : Except String (List Nat) :=
  c.nodes.mapM
    fun (id, _) =>
      if id == v.nodeId then
        .ok v.lastIdx
      else
        match v.peer? id with
        | some p => .ok p.matchIdx
        | none => .error s!"all_other_nodes.at({id}) failed in highest_committable_idx"

/-- The index a majority of `c` has reached: the median of its sorted match indexes. -/
def confirmedIdx (v : State) (c : Config) : Except String Nat := do
  let sorted := (← matchIdxs v c).mergeSort
  match sorted[(sorted.length - 1) / 2]? with
  | some x => .ok x
  | none => .error s!"empty configuration {c.idx}"

/--
The loop of `highest_committable_idx` over the configurations from `first`: `lowest` is the
lowest median so far; the loop stops at a configuration it does not reach.
-/
def agreementGo (v : State)
    : Option Nat -> List Config -> Option Nat -> Except String (Option Nat)
  | _, [], agreement => .ok agreement
  | lowest, c :: rest, agreement => do
      let confirmed ← confirmedIdx v c
      let lo :=
        match lowest with
        | some l => min l confirmed
        | none => confirmed
      if lo < c.idx then return agreement
      agreementGo v (some lo) rest
        (some
          (match rest.head? with
            | some n => min lo (n.idx - 1)
            | none => lo))

/-- `highest_committable_idx(first)`, as a function of the state. -/
def highestCommittableIdxOf (v : State) (first : Nat) : Except String (Option Nat) := do
  let confs := v.configurations.drop first
  let some a ← agreementGo v none confs none | return none
  if a > v.lastIdx then throw "followers appear to have later match indices than leader"
  let some nc := v.highestCommittableLe a | return none
  if nc < (confs.head?.map (·.idx)).getD 0 then return none
  if v.getTerm nc != v.currentView then return none
  return some nc

def highestCommittableIdx (first : Nat) : M (Option Nat) := do
  liftE (highestCommittableIdxOf (← getV) first)

/-- The inner `while` of `update_commit`: skip configurations that `i` reaches. -/
def advanceFirst (cs : List Config) (i : Nat) : Nat -> Nat -> Nat
  | first, 0 => first
  | first, fuel + 1 =>
      if cs[first + 1]?.any (·.idx <= i) then
        advanceFirst cs i (first + 1) fuel
      else
        first

/-- The outer loop of `update_commit`; each round strictly raises the candidate index. -/
def updateCommitGo (first : Nat) (newCommit : Option Nat) : Nat -> M (Option Nat)
  | 0 => fail s!"update_commit does not terminate"
  | fuel + 1 => do
      match ← highestCommittableIdx first with
      | none => return newCommit
      | some i =>
          if newCommit.any (i <= ·) then return newCommit
          let cs := (← getV).configurations
          updateCommitGo (advanceFirst cs i first cs.length) (some i) fuel

def updateCommit : M Unit := do
  let v ← getV
  unless v.leadership == .leader do
    fail s!"{← curLoc}: update_commit while not leader"
  if let some i ← updateCommitGo 0 none (v.lastIdx + 2) then commit i

def commitIfPossible (idx : Nat) : M Unit := do
  let v ← getV
  if idx > v.commitIdx && v.getTerm idx <= v.currentView then
    if let some h := v.highestCommittableLe idx then commit h

def rollback (idx : Nat) : M Unit := do
  let v ← getV
  if idx < v.commitIdx then return
  setV
    fun v =>
      let v :=
        {
          v with
            rcEntries := v.rcEntries.filter (·.1 <= idx),
            ledger := v.ledger.extract 0 idx,
            lastIdx := idx,
            views := v.views.filter (· <= idx),
            committable := v.committable.filter (· <= idx)
        }
      let v :=
        if v.retired
            && v.retirementPhase == some .signed
            && v.retirementCommittableIdx.any (· > idx) then
          { v with retirementCommittableIdx := none, retirementPhase := some .ordered }
        else
          v
      if v.retired
          && v.retirementPhase == some .ordered
          && v.retirementIdx.any (· > idx) then
        { v with retirementIdx := none, retirementPhase := none, retired := false }
      else
        v
  let cs := (← getV).configurations
  let cs' := cs.filter (·.idx <= idx)
  if cs'.length != cs.length then
    setV fun v => { v with configurations := cs' }
    createAndRemoveNodeState

def resetVotesForMe : M Unit :=
  setV
    fun v =>
      {
        v with
          votesForMe :=
            v.configurations.map fun c => (c.idx, [], State.quorum c.nodes.length)
      }

def becomeFollower : M Unit := do
  setV fun v => { v with leaderId := none, leadership := .follower }
  trace "become_follower"

def becomeAwareOfNewTerm (term : Nat) : M Unit := do
  setV
    fun v =>
      {
        v with
          votedFor := if v.currentView != term then none else v.votedFor,
          currentView := term
      }
  resetVotesForMe
  becomeFollower
  setV fun v => { v with isNewFollower := true }

def sendRequestVote (pre : Bool) (to : NodeId) : M Unit := do
  let v ← getV
  let lci := v.lastCommittable
  if lci < v.commitIdx then fail s!"{← curLoc}: lci < ci"
  let packet := rvPacket pre v.currentView lci (v.getTerm lci)
  trace "send_request_vote"
  emit "packet" packet
  emitStr "to_node_id" to
  let r : RequestVoteRequest :=
    {
      term := v.currentView,
      lastCommittableTerm := v.getTerm lci,
      lastCommittableIndex := lci
    }
  send to (if pre then .requestPreVoteRequest r else .requestVoteRequest r)

def becomeLeader : M Bool := do
  let v ← getV
  if v.isRetiredCommitted then return false
  let electionIndex := v.lastCommittable
  if v.commitIdx > 0 then
    rollback electionIndex
    -- Accepted by the implementation, rejected by validation: peers kept across the
    -- election rollback. cft.h keeps in all_other_nodes (and sends AppendEntries to) a
    -- node whose only configuration the rollback removed; the specification's peers are
    -- the eligible peers of the remaining log.
    let names ← names
    let v ← getV
    let peers := v.allOtherNodes.map (names.id ·.1)
    let eligible := (eligiblePeers (abs names v) (names.id v.nodeId)).sort
    unless peers == eligible do
      fail
        s!"{← curLoc}: accepted by the implementation, rejected by validation: peers kept across rollback (known implementation and specification difference: after rolling back to {electionIndex}, cft.h keeps peers {v.allOtherNodes.map (·.1)}, the specification's eligible peers are {eligible.map names.name})"
  setV fun v => { v with leadership := .leader, leaderId := some v.nodeId }
  trace "become_leader"
  if (← getV).otherNodesInActiveConfigs.isEmpty then updateCommit
  let next := (← getV).lastIdx + 1
  for id in ← otherNodesSorted do
    setV fun v => v.setPeer id { matchIdx := 0, sentIdx := next - 1 }
    sendAppendEntries id next
  return true

/-- The vote-recording part of `add_vote_for_me`: whether the node is now elected. -/
def recordVote (from_ : NodeId) : M Bool := do
  let v ← getV
  if v.configurations.isEmpty then return false
  let mut votes := v.votesForMe
  for c in v.configurations do
    unless c.nodes.any (·.1 == from_) do
      continue
    votes :=
      match votes.find? (·.1 == c.idx) with
      | some _ =>
          votes.map
            fun (i, vs, q) =>
              if i == c.idx then
                (i, if vs.contains from_ then vs else vs ++ [from_], q)
              else
                (i, vs, q)
      | none => (votes ++ [(c.idx, [from_], 0)]).mergeSort (fun a b => a.1 <= b.1)
  setV fun v => { v with votesForMe := votes }
  return votes.all fun (_, vs, q) => vs.length >= q

def becomeCandidate : M Unit := do
  if (← getV).configurations.isEmpty then return
  setV
    fun v =>
      { v with leadership := .candidate, leaderId := none, votedFor := some v.nodeId }
  resetVotesForMe
  setV fun v => { v with currentView := v.currentView + 1 }
  trace "become_candidate"
  -- `add_vote_for_me(node_id)` as a candidate.
  if ← recordVote (← getV).nodeId then discard becomeLeader
  for id in (← getV).otherNodesInActiveConfigs do
    sendRequestVote false id

def addVoteForMe (from_ : NodeId) : M Unit := do
  let leadership := (← getV).leadership
  if ← recordVote from_ then
    match leadership with
    | .preVoteCandidate => becomeCandidate
    | .candidate => discard becomeLeader
    | _ => do fail s!"{← curLoc}: add_vote_for_me() while not a candidate"

def becomePreVoteCandidate : M Unit := do
  if (← getV).configurations.isEmpty then return
  setV fun v => { v with leadership := .preVoteCandidate, leaderId := none }
  resetVotesForMe
  trace "become_pre_vote_candidate"
  addVoteForMe (← getV).nodeId
  for id in (← getV).otherNodesInActiveConfigs do
    sendRequestVote true id

/-! ## Configuration hooks -/

/--
`add_configuration`, called by a `ConfigurationChangeHook`. On the primary the
traced `nodes` is the entry's content (input); on a follower it must equal the
configuration carried by the replicated entry.
-/
def addConfiguration (idx? : Option Nat) (expected : Option Nodes) : M Nodes := do
  trace "add_configuration"
  let v ← getV
  let idx ←
    match idx? with
    | some i => do emitNat "idx" i; pure i
    | none => inNat "idx"
  emitNat "rid" idx
  let nodes ←
    match expected with
    | some n => do emit "nodes" (nodesJson n); pure n
    | none => do liftE (parseNodes (← use "nodes"))
  if let some last := v.configurations.getLast? then
    if last.nodes.any (·.1 == v.nodeId) && !nodes.any (·.1 == v.nodeId) then
      becomeRetired idx .ordered
  let v ← getV
  if v.configurations.isEmpty
      || some nodes != (v.configurations.getLast?.map (·.nodes)) then
    setV
      fun v =>
        { v with configurations := v.configurations ++ [{ idx, nodes, rid := idx }] }
    createAndRemoveNodeState
  return nodes

def startTickingIfNecessary : M Unit :=
  setV
    fun v => if !v.ticking && v.selfInLatestConfig then { v with ticking := true } else v

/-! ## Entry points: one per section head -/

/--
Accepted by the implementation, rejected by validation: the election guard. cft.h starts
an election (on a timeout or a ProposeRequestVote) when the node is not retired-committed
and `ticking`; the clean `canStartElection` also needs a follower or candidate role and
membership of a signed active configuration (or a completed retirement). `ticking` is
sticky, so a real node can keep it after a rollback (with peers kept across it) drops it
from every signed configuration; the driver also ticks a node of role none. Validation
rejects such an election; removing this check is a one-line change (`pure ()`).
-/
def electionGuard : M Unit := do
  let names ← names
  let v ← getV
  unless decide (canStartElection (abs names v) (names.id v.nodeId)) do
    fail
      s!"{← curLoc}: accepted by the implementation, rejected by validation: election guard (known implementation and specification difference: cft.h only needs ticking, the specification also needs a role and membership of a signed configuration)"

def periodic : M Unit := do
  trace "tick"
  let v ← getV
  if v.leadership == .leader then
    -- request_timeout is not traced: it fired iff the next event is a send.
    if (← lookFn) == some "send_append_entries" then
      note .heartbeatTimeout
      for id in ← otherNodesSorted do
        let some p := (← getV).peer? id | continue
        sendAppendEntries id (p.sentIdx + 1) (ext := true)
    -- CheckQuorum depends on untraced ack timers: it fired iff become_follower follows.
    -- cft.h counts a configuration member without peer state (self, or a node erased at
    -- retired_committed) as live, so it can only step down if, in some active
    -- configuration, the other members could leave it without a quorum.
    if (← getV).canLoseQuorum && (← lookFn) == some "become_follower" then
      note .checkQuorum
      becomeFollower
  else
    if !v.isRetiredCommitted
        && v.ticking
        && (← lookFn) == some "become_pre_vote_candidate" then
      electionGuard
      note .electionTimeout
      becomePreVoteCandidate

/-- The `retired_committed_tx` hooks of the entry at `index`. -/
def retiredHooks (index : Nat) : Nat -> List NodeId -> M (List NodeId)
  | 0, _ => do fail s!"{← curLoc}: hooks do not terminate"
  | fuel + 1, acc => do
      if (← lookFn) == some "retired_committed_tx" then
        trace "retired_committed_tx"
        emitNat "seqno" index
        let id ← inStr "retired_node_id"
        retiredHooks index fuel (acc ++ [id])
      else
        return acc

def replicateEntry : M Unit := do
  trace "replicate_entry"
  let v ← getV
  let index := v.lastIdx + 1
  let sig ← inBool "globally_committable"
  -- Entry admission (Node.lean's appendEntry): the signature timer starts only after the
  -- genesis (or recovery, or join) transaction, so a ledger never starts with a signature.
  if sig && v.lastIdx == 0 then
    fail
      s!"{← curLoc}: entry admission: a signature as the first entry of an empty ledger"
  -- Hooks: the entry's content is only visible through the hooks it triggers.
  let retired ← retiredHooks index ((← get).queue.length + 1) []
  if !retired.isEmpty then
    -- Accepted by the implementation, rejected by validation: retirement confirmations.
    -- hooks.h fires retired_committed_tx on every write of a node record whose
    -- retired_committed flag is set: the default constitution's remove_node on a node
    -- already retired-committed rewrites its record and confirms it again. The
    -- specification only confirms nodes whose retirement is completed and not yet
    -- confirmed in the ledger.
    let names ← names
    let a := abs names v
    unless decide
            (names.set retired
              ⊆ a.retirementCompletedNodes \ retiredCommittedNodes a.log) do
      fail
        s!"{← curLoc}: accepted by the implementation, rejected by validation: retirement confirmation (known implementation and specification difference: hooks.h confirms {retired} again whenever their node records are rewritten; the specification only confirms nodes whose retirement is completed and not yet confirmed)"
    setV fun v => { v with rcEntries := v.rcEntries ++ [(index, retired)] }
  -- hooks.h runs the retired_committed_tx hooks, then add_configuration, for one entry.
  let mut config := none
  if (← lookFn) == some "add_configuration" then
    let nodes ← addConfiguration (some index) none
    -- The decoder reads a configuration from a JSON object, whose node ids are distinct.
    unless (nodes.map Prod.fst).eraseDups == nodes.map Prod.fst do
      fail s!"{← curLoc}: configuration {nodes.map Prod.fst} repeats a node id"
    -- Entry admission (Node.lean's appendEntry): hooks.h only calls add_configuration
    -- when the node set changed from cft.h's latest configuration, the latest ledger one.
    -- The checks read the clean log, as the specification does: the latest configuration
    -- and the removed nodes of its configuration history.
    let ids := (nodes.map Prod.fst).mergeSort (· <= ·) |>.eraseDups
    let names ← names
    let log := (abs names v).log
    -- Accepted by the implementation, rejected by validation: an empty configuration.
    -- A single node that removes itself makes hooks.h call add_configuration with no
    -- nodes; the specification requires a non-empty configuration.
    if ids.isEmpty then
      fail
        s!"{← curLoc}: accepted by the implementation, rejected by validation: empty configuration (known implementation and specification difference: hooks.h adds an empty configuration when the last node removes itself; the specification requires a non-empty configuration)"
    if decide (names.set ids = latestConfigurationMembers (configurationHistory log)) then
      fail
        s!"{← curLoc}: entry admission: configuration {ids} unchanged from the latest configuration in the ledger"
    -- Node identities are never reused: a retired node cannot be added back.
    let back := ids.filter fun i => decide (names.id i ∈ removedNodes log)
    unless back.isEmpty do
      fail
        s!"{← curLoc}: entry admission: configuration {ids} names {back}, removed by an earlier configuration"
    config := some nodes
  -- The decoder names every node id of the trace, in order (Validator.lean), so the
  -- hooks' node ids are named and the names are sorted.
  let names ← names
  let ids := (config.getD []).map Prod.fst ++ retired
  unless ids.isEmpty
          || ids.all names.known.contains
              && (names.known.toList.zip names.known.toList.tail).all
                  fun (x, y) => decide (x < y) do
    fail s!"{← curLoc}: hook node ids {ids} not among the trace's sorted node ids"
  -- Entry admission: a signature transaction writes only the signatures table, so it
  -- triggers no hook (the clean model's signature entry has no metadata).
  if sig && (!retired.isEmpty || config.isSome) then
    fail s!"{← curLoc}: entry admission: a signature entry triggers hooks"
  if sig then
    let v ← getV
    if v.retired && v.retirementPhase == some .ordered then becomeRetired index .signed
    setV fun v => { v with committable := v.committable ++ [index] }
    startTickingIfNecessary
  let entry : Entry := { term := (← getV).currentView, sig, config, retired }
  setV fun v => { v with lastIdx := index, ledger := v.ledger.push entry }
  note (.appendEntry entry)
  let v ← getV
  if v.views.back?.any (index < ·) then
    fail s!"{← curLoc}: view history moves backwards"
  setV
    fun v =>
      { v with views := v.views ++ Array.replicate (v.currentView - v.views.size) index }
  -- The flush threshold depends on untraced entry sizes.
  if (← lookFn) == some "batch_flush" then
    trace "batch_flush"
    note .batchFlush
    for id in ← otherNodesSorted do
      let some p := (← getV).peer? id | continue
      sendAppendEntries id (p.sentIdx + 1) (ext := true)

def replicateEntries : Nat -> M Unit
  | 0 => do fail s!"{← curLoc}: replicate does not terminate"
  | fuel + 1 => do
      if (← lookFn) == some "replicate_entry" then
        replicateEntry
        replicateEntries fuel

def replicate : M Unit := do
  trace "replicate"
  let v ← getV
  unless v.leadership == .leader && !v.isRetiredCommitted do
    fail s!"{← curLoc}: replicate traced while not able to replicate"
  -- A configuration in this batch may add a node; commit is decided by the nodes before it.
  let noOtherNodes := v.otherNodesInActiveConfigs.isEmpty
  replicateEntries ((← get).queue.length + 1)
  if noOtherNodes then updateCommit

def viewUpdate (idx view : Nat) : M Unit := do
  let v ← getV
  if v.views.back?.any (idx < ·) then
    fail
      s!"{← curLoc}: view_history.update({idx}, {view}) moves backwards from {v.views.back?}"
  setV fun v => { v with views := v.views ++ Array.replicate (view - v.views.size) idx }

def sendAer (to : NodeId) (term idx : Nat) (ok : Bool) : M Unit := do
  let packet := aerPacket term idx ok
  trace "send_append_entries_response"
  emit "packet" packet
  emitStr "to_node_id" to
  send to (.appendEntriesResponse { term, success := ok, lastLogIndex := idx })

def nack (to : NodeId) : M Unit := do
  let v ← getV
  sendAer to v.currentView v.lastIdx false

def nackRejected (to : NodeId) (term idx : Nat) : M Unit := do
  let v ← getV
  let i := v.highestMatch term idx
  sendAer to (v.getTerm i) i false

def recvAppendEntries (from_ : NodeId) (r : AppendEntriesRequest) : M Unit := do
  traceRecv "recv_append_entries" from_ (.appendEntriesRequest r)
  let rTerm := r.term
  let rIdx := aeIdx r
  let rPrevIdx := r.prevLogIndex
  let rPrevTerm := r.prevLogTerm
  let rLeaderCommit := r.primaryCommit
  let rTermOfIdx := aeTermOfIdx r
  let env := (← get).env
  let payload := (r.entries.map (toExecEntry env)).toArray
  let v ← getV
  if v.currentView == rTerm
      && (v.leadership == .candidate || v.leadership == .preVoteCandidate) then
    becomeAwareOfNewTerm rTerm
  else if v.currentView < rTerm then
    becomeAwareOfNewTerm rTerm
  else if v.currentView > rTerm then
    nack from_
    return
  let v ← getV
  -- Two leaders in one view violate election safety; cft.h has no guard and would
  -- overwrite leader_id, so a trace reaching this exhibits a bug.
  if v.leadership == .leader && v.currentView == rTerm then
    fail s!"{← curLoc}: AppendEntries from {from_} to a leader in its own view {rTerm}"
  let prevTerm := v.getTerm rPrevIdx
  if prevTerm != rPrevTerm then
    if prevTerm == 0 then nack from_ else nackRejected from_ rPrevTerm rPrevIdx
    return
  setV fun v => { v with leaderId := some from_ }
  let v ← getV
  if rPrevIdx < v.commitIdx then return
  if rPrevIdx > v.lastIdx then return
  let mut toApply : Array (Nat × Entry × Bool) := #[]
  for i in [rPrevIdx + 1 : rIdx + 1] do
    let entry? := payload[i - rPrevIdx - 1]?
    if entry?.isNone then
      nack from_
      return
    let entry := entry?.get!
    let v ← getV
    if i <= v.lastIdx then
      if rTermOfIdx != v.viewAt i then
        if v.isNewFollower then
          rollback (i - 1)
          setV fun v => { v with isNewFollower := false }
        else
          return
      else
        continue
    -- store->deserialize: the driver store records retired_committed entries here.
    if !entry.retired.isEmpty then
      setV fun v => { v with rcEntries := v.rcEntries ++ [(i, entry.retired)] }
    toApply := toApply.push (i, entry, entry.term == rTermOfIdx)
  -- execute_append_entries_sync
  for (i, entry, ok) in toApply do
    trace "execute_append_entries_sync"
    emitStr "from_node_id" from_
    unless ok do
      setV fun v => { v with ledger := v.ledger.extract 0 (i - 1) }
      nack from_
      return
    setV fun v => { v with lastIdx := i }
    -- hooks.h runs the retired_committed_tx hooks, then add_configuration.
    for id in entry.retired do
      trace "retired_committed_tx"
      emitNat "seqno" i
      emitStr "retired_node_id" id
    if let some nodes := entry.config then
      let _ ← addConfiguration (some i) (some nodes)
    if entry.sig then startTickingIfNecessary
    setV fun v => { v with ledger := (v.ledger.extract 0 (i - 1)).push entry }
    if entry.sig then
      let v ← getV
      if v.retired && v.retirementPhase == some .ordered then becomeRetired i .signed
      setV fun v => { v with committable := v.committable ++ [i] }
      if entry.term != 0 then
        if rTermOfIdx == 0 then
          viewUpdate 1 rTerm
        else
          viewUpdate (rPrevIdx + 1) entry.term
        commitIfPossible (min rLeaderCommit rIdx)
  -- execute_append_entries_finish
  commitIfPossible (min rLeaderCommit rIdx)
  let lci := (← getV).lastCommittable
  if rTermOfIdx == 0 then
    viewUpdate 1 rTerm
  else if rIdx > lci then
    viewUpdate (lci + 1) rTermOfIdx
  sendAer from_ (← getV).currentView rIdx true

def recvAppendEntriesResponse (from_ : NodeId) (r : AppendEntriesResponse) : M Unit := do
  let some node := (← getV).peer? from_
  | fail
      s!"recv_append_entries_response from {from_} is traced, but {from_} is not in all_other_nodes"
  traceRecv "recv_append_entries_response" from_ (.appendEntriesResponse r)
  let rTerm := r.term
  let rIdx := r.lastLogIndex
  let ok := r.success
  let v ← getV
  if v.leadership != .leader then return
  if v.currentView < rTerm then
    becomeAwareOfNewTerm rTerm
    return
  if v.currentView != rTerm then
    if ok then return
  else if rIdx < node.matchIdx then
    if ok then return
  if !ok then
    let m := v.highestMatch rTerm rIdx
    setV
      fun v =>
        v.setPeer from_ { node with sentIdx := max (min m node.sentIdx) node.matchIdx }
    return
  setV fun v => v.setPeer from_ { node with matchIdx := max node.matchIdx rIdx }
  updateCommit

def recvRequestVote (from_ : NodeId) (pre : Bool) (r : RequestVoteRequest) : M Unit := do
  traceRecv "recv_request_vote" from_
    (if pre then .requestPreVoteRequest r else .requestVoteRequest r)
  let rTerm := r.term
  let rLci := r.lastCommittableIndex
  let rTlci := r.lastCommittableTerm
  let respond (granted : Bool) : M Unit := do
    let term := (← getV).currentView
    trace "send_request_vote_response"
    emit "packet" (rvrPacket pre term granted)
    emitStr "to_node_id" from_
    let r : RequestVoteResponse := { term, voteGranted := granted }
    send from_ (if pre then .requestPreVoteResponse r else .requestVoteResponse r)
  if (← getV).currentView > rTerm then
    respond false
    return
  if (← getV).currentView < rTerm then becomeAwareOfNewTerm rTerm
  let v ← getV
  let mut grant := true
  if !pre && v.leaderId.isSome then grant := false
  if !pre && v.votedFor.any (· != from_) then grant := false
  let lci := v.lastCommittable
  let tlci := v.getTerm lci
  unless rTlci > tlci || (rTlci == tlci && rLci >= lci) do
    grant := false
  if grant && !pre then setV fun v => { v with leaderId := none, votedFor := some from_ }
  respond grant

/--
`recv_request_vote_response`. Accepted by the implementation, rejected by validation: a
granted (pre-)vote from a peer in no active configuration. cft.h records a vote only in the
configurations that name the voter, so it ignores such a vote; the clean model adds any
eligible peer, which includes a node whose retirement completed, to the votes granted. A
candidate asks only the members of its configurations, which stay fixed in its view, so
for votes this needs an implementation bug. A pre-vote candidate can ask again in the same
view: for example, pre-vote candidate n1 asks n3 in view 2, learns from the primary of
view 2 a committed configuration without n3 and steps down, and starts another pre-vote
in view 2 when n3's late grant arrives.
-/
def recvRequestVoteResponse (from_ : NodeId) (pre : Bool) (r : RequestVoteResponse)
    : M Unit := do
  traceRecv "recv_request_vote_response" from_
    (if pre then .requestPreVoteResponse r else .requestVoteResponse r)
  let rTerm := r.term
  let granted := r.voteGranted
  let v ← getV
  if (v.peer? from_).isNone then return
  if v.currentView < rTerm then
    becomeAwareOfNewTerm rTerm
    return
  if v.currentView != rTerm then return
  if v.leadership != .preVoteCandidate && v.leadership != .candidate then return
  if !pre && v.leadership != .candidate then return
  if pre && v.leadership != .preVoteCandidate then return
  if !granted then return
  unless v.configurations.any (·.nodes.any (·.1 == from_)) do
    fail
      s!"{← curLoc}: accepted by the implementation, rejected by validation: granted vote from {from_}, in no active configuration (known implementation and specification difference: cft.h ignores the vote, the specification counts the vote of any eligible peer)"
  addVoteForMe from_

/--
`recv_propose_request_vote`. Accepted by the implementation, rejected by validation: a
proposal in the node's view to a node that is not ticking but can start an election. cft.h
ignores it; the clean model starts an election. For example, a joiner named by a
configuration that a configuration without it supersedes before the next signature never
starts ticking (it is not in the latest configuration at a signature), yet is a member of
a signed active configuration, and the primary can nominate it.
-/
def recvProposeRequestVote (from_ : NodeId) (rTerm : Nat) : M Unit := do
  traceRecv "recv_propose_request_vote" from_ (.proposeRequestVoteRequest rTerm)
  let v ← getV
  if !v.isRetiredCommitted && v.ticking && rTerm == v.currentView then
    -- Only a leader proposes, in its own view: two leaders in one view violate election
    -- safety (cft.h would demote this leader to candidate).
    if v.leadership == .leader then
      fail
        s!"{← curLoc}: ProposeRequestVote from {from_} to a leader in its own view {rTerm}"
    electionGuard
    becomeCandidate
  else if !v.ticking && rTerm == v.currentView then
    let names ← names
    if decide (canStartElection (abs names v) (names.id v.nodeId)) then
      fail
        s!"{← curLoc}: accepted by the implementation, rejected by validation: ProposeRequestVote from {from_} to a node that is not ticking (known implementation and specification difference: cft.h ignores it, the specification starts an election)"

def nominateSuccessor : M Unit := do
  trace "nomination"
  nominateSuccessorUnsafe

/-- `init_as_backup(index, term, term_history)` for a joiner; `term_history` is untraced. -/
def initAsBackup : M Unit := do
  trace "init_as_backup"
  let index ← inNat "seqno"
  let term ← inNat "view"
  -- The driver initialises a joiner once, before anything else happens to it.
  let v ← getV
  unless v.leadership == .none && v.currentView == 0 && v.lastIdx == 0 do
    fail s!"{← curLoc}: init_as_backup on a node that is not fresh"
  -- A snapshot at index 0 is no snapshot, and starts in view 0; any other is in a view.
  unless (index == 0) == (term == 0) do
    fail
      s!"{← curLoc}: init_as_backup at index {index} in view {term}: index 0 iff view 0"
  note (.initAsBackup index term)
  -- From a snapshot, `term_history` is untraced: until the release, assume every entry
  -- up to `index` is in view `term`, and the snapshotted entries are opaque (no hooks); a
  -- snapshot is taken at a signature, so entry `index` is one. The node does not hold
  -- them (the ledger starts after `index`, the base); the machine replaces them at
  -- release by a ghost from a node that has committed them, and the view history up to
  -- `index` by that node's.
  let views := if index == 0 then #[] else Array.replicate term 1
  let ledger :=
    (Array.replicate index { term, sig := false }).modify (index - 1)
      ({ · with sig := true })
  -- The configurations the snapshot's hooks installed (outside the lock) are entries of it.
  let ledger :=
    (← getV).configurations.foldl (init := ledger)
      fun l c =>
        if c.idx ≥ 1 && c.idx ≤ index then
          l.modify (c.idx - 1) ({ · with config := some c.nodes })
        else
          l
  setV
    fun v =>
      {
        v with
          lastIdx := index,
          commitIdx := index,
          views,
          ledger,
          base := index,
          baseView := term
      }
  becomeAwareOfNewTerm term

/--
`add_configuration` from `ConfigurationChangeHook` while a snapshot is installed,
outside the lock, before `init_as_backup`. The configuration version is input.
-/
def outOfLockHook : M Unit := discard (addConfiguration none none)

/-- `force_become_primary()` is untraced; its `become_leader` opens the section. -/
def forceBecomePrimary : M Unit := do
  setV fun v => { v with currentView := v.currentView + 2 }
  let ok ← becomeLeader
  unless ok do
    fail "force_become_primary on a retired-committed node"

/-- The driver dropping a queued message: no lock; the dropped message is input. -/
def dropPendingTo : M Unit := do
  trace "drop_pending_to"
  emitStr "from_node_id" (← getV).nodeId

/-! ## Dispatch: the handler an event starts -/

/-- `recv_message`: dispatch on the message type. -/
def receive (from_ : NodeId) : Message -> M Unit
  | .appendEntriesRequest r => recvAppendEntries from_ r
  | .appendEntriesResponse r => recvAppendEntriesResponse from_ r
  | .requestVoteRequest r => recvRequestVote from_ false r
  | .requestPreVoteRequest r => recvRequestVote from_ true r
  | .requestVoteResponse r => recvRequestVoteResponse from_ false r
  | .requestPreVoteResponse r => recvRequestVoteResponse from_ true r
  | .proposeRequestVoteRequest t => recvProposeRequestVote from_ t

/--
The handler the event `function` starts, given the delivered message (with its sender).
`become_leader` starts `force_become_primary` (whose own code is untraced).
-/
def handlerFor (function : String) : Option (NodeId × Message) -> Option (M Unit)
  | some (from_, m) =>
      if recvHeads.contains function then some (receive from_ m) else none
  | none =>
      match function with
      | "drop_pending_to" => some dropPendingTo
      | "tick" => some periodic
      | "replicate" => some replicate
      | "nomination" => some nominateSuccessor
      | "init_as_backup" => some initAsBackup
      | "add_configuration" => some outOfLockHook
      | "become_leader" => some forceBecomePrimary
      | _ => none

end Consensus.TraceValidation.Exec
