module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteLemmas
public import Consensus.TraceValidation.Proofs.Handlers.AeHoare
public import Consensus.TraceValidation.Proofs.Handlers.ReplUpdateCommit

@[expose] public section

/-!
# `become_leader` refines the clean `becomePrimary` (not reviewed)

`becomeLeader_spec`: from a declared non-leader `d` that a clean state `c` agrees with, and
whose ledger has no entry in its current view (`LeaderPre`), M_tv's `becomeLeader` either
stops at once (the node is retired-committed, as `c` is) or ends as a leader that, if it
satisfies `inv`, the clean `primaryState c` agrees with, having sent exactly what the clean
`becomePrimary c` sends: an empty AppendEntries at the end of the log to each eligible peer,
in order.

With no entry in the current view neither side can commit at election: the clean
`highestCommittableIndex` only commits an entry of the current term, and cft.h's
`update_commit` only one in the current view. A node that has just become candidate has
incremented its view past every view of its ledger.

On the M_tv side (`becomeLeader_tv`): the election rollback to the last committable index is
the clean `primaryState`'s truncation; `create_and_remove_node_state` after it only changes
peers (the node is not leader yet); `update_commit` commits nothing; and each
`send_append_entries` from one past the last index is one empty AppendEntries. The peers are
the clean eligible peers: after a rollback by the explicit check in `becomeLeader`, and
without one by `LeaderPre.peers` (from the `peers` conjuncts of `inv`); a node with an empty
ledger has none, by the `empty_leader_alone` conjunct of the final `inv`.
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae (Hoare)

/-! ## Clean effects that succeed and append known sends -/

/-- `x` succeeds from any outputs with result `a`, appending exactly `sends`. -/
def Emits {α : Type} (x : NodeEffect α) (a : α)
    (sends : List (CCF.Envelope NodeID Message))
    : Prop :=
  forall out : CCF.Outputs NodeID Message Notification,
    x.run out = some (a, { out with outgoing := out.outgoing ++ sends })

theorem emits_pure {α : Type} (a : α) : Emits (pure a : NodeEffect α) a [] := by
  intro out
  cases out
  simp [StateT.run, pure, StateT.pure]

theorem emits_bind {α β : Type} {x : NodeEffect α} {f : α -> NodeEffect β} {a : α} {b : β}
    {first later : List (CCF.Envelope NodeID Message)}
    (hx : Emits x a first) (hf : Emits (f a) b later)
    : Emits (x >>= f) b (first ++ later) := by
  intro out
  have := hx out
  simp only [StateT.run, bind, StateT.bind] at this ⊢
  rw [this]
  simp only [Option.bind]
  have := hf { out with outgoing := out.outgoing ++ first }
  simp only [StateT.run, List.append_assoc] at this
  exact this

theorem emits_congr {α : Type} {x : NodeEffect α} {a b : α}
    {first later : List (CCF.Envelope NodeID Message)}
    (h : Emits x a first) (same : a = b) (sends : first = later)
    : Emits x b later := by
  subst same sends
  exact h

theorem emits_send {node : NodeID} (message : Message) (target : NodeID)
    : Emits ((CCF.Capabilities.record node).send message target) ()
        [⟨node, target, message⟩] := by
  intro out
  rfl

theorem emits_forIn {node : NodeID} (peers : List NodeID) (f : NodeID -> Message)
    : Emits
        (forIn peers PUnit.unit
            fun peer _ => do
              (CCF.Capabilities.record node).send (f peer) peer
              pure (ForInStep.yield PUnit.unit)
          : NodeEffect PUnit)
        PUnit.unit (peers.map fun peer => ⟨node, peer, f peer⟩) := by
  induction peers with
  | nil => exact emits_pure _
  | cons peer rest ih =>
      rw [List.forIn_cons]
      refine emits_congr (emits_bind
        (x := do (CCF.Capabilities.record node).send (f peer) peer; pure (ForInStep.yield PUnit.unit))
        (a := ForInStep.yield PUnit.unit)
        (emits_bind (f := fun _ => pure (ForInStep.yield PUnit.unit)) (emits_send _ _)
          (emits_pure _)) ih) rfl ?_
      simp

/-! ## The clean election -/

/-- The empty AppendEntries a new primary in state `s` sends to `peer`. -/
def heartbeat (self : NodeID) (s : NodeState) (peer : NodeID)
    : CCF.Envelope NodeID Message :=
  ⟨
    self,
    peer,
    .appendEntriesRequest
      {
        term := s.currentTerm,
        prevLogIndex := s.log.length,
        prevLogTerm := termAt s.log s.log.length,
        entries := [],
        primaryCommit := s.commitIndex
      }
  ⟩

theorem foldl_stuck {f : Nat -> Nat -> Nat} (h : forall a i, f a i = a) (l : List Nat)
    (init : Nat)
    : l.foldl f init = init := by
  induction l generalizing init with
  | nil => rfl
  | cons x xs ih => simp only [List.foldl_cons, h, ih]

theorem highestCommittableIndex_stuck {s : NodeState} (self : NodeID)
    (noTerm : forall i, termAt s.log i ≠ s.currentTerm)
    : highestCommittableIndex s self = s.commitIndex := by
  unfold highestCommittableIndex
  exact foldl_stuck (fun a i => by simp [noTerm]) _ _

/--
The clean election from `c` when no entry of the truncated log is in the current term: the
primary state, and a heartbeat to each eligible peer.
-/
theorem emits_becomePrimary (self : NodeID) (c : NodeState)
    (noTerm : forall i, termAt (primaryState c).log i ≠ c.currentTerm)
    : Emits (becomePrimary (CCF.Capabilities.record self) self c) (primaryState c)
        (((eligiblePeers (primaryState c) self).sort).map
          (heartbeat self (primaryState c))) := by
  unfold becomePrimary
  have stuck : highestCommittableIndex (primaryState c) self = (primaryState c).commitIndex :=
    highestCommittableIndex_stuck self noTerm
  have adv : advanceCommit (CCF.Capabilities.record self) (primaryState c) self
      = pure (primaryState c) := by
    unfold advanceCommit
    simp [stuck]
  simp only [adv]
  refine emits_congr (emits_bind (emits_pure _)
    (emits_bind (emits_forIn _ _) (emits_pure _))) rfl ?_
  simp only [List.nil_append, List.append_nil]
  apply List.map_congr_left
  intro peer _
  simp [heartbeat, makeAppendEntriesRequest, messageEntries, primaryState]

/-! ## `update_commit` commits nothing without an entry in the current view -/

theorem getTerm_ne_view {v : State} (h : v.views.size < v.currentView) (i : Nat)
    : v.getTerm i ≠ v.currentView := by
  have := ReplUpdateCommit.viewAt_le_size v i
  unfold State.getTerm
  split <;> omega

theorem highestCommittableIdxOf_term {v : State} {first nc : Nat}
    (h : highestCommittableIdxOf v first = .ok (some nc))
    : v.getTerm nc = v.currentView := by
  unfold highestCommittableIdxOf at h
  simp only [bind, Except.bind, pure, Except.pure] at h
  repeat' (split at h <;> try simp_all [throw, throwThe, MonadExceptOf.throw])

theorem updateCommitOf_none {v : State} (h : v.views.size < v.currentView)
    {first fuel : Nat} {r : Option Nat}
    (run : ReplUpdateCommit.updateCommitOf v first none fuel = .ok r)
    : r = none := by
  cases fuel with
  | zero => simp [ReplUpdateCommit.updateCommitOf] at run
  | succ fuel =>
      simp only [ReplUpdateCommit.updateCommitOf] at run
      split at run
      · cases run
      · cases run; rfl
      · rename_i i found
        exact absurd (highestCommittableIdxOf_term found) (getTerm_ne_view h i)

/-- A leader without an entry in its current view: `update_commit` changes nothing. -/
theorem updateCommit_noop (env : Env) {u : State} {o0 : Outbox}
    (h : u.views.size < u.currentView)
    : Hoare env (fun v o => v = u /\ o = o0) Exec.updateCommit
        (fun _ v o => v = u /\ o = o0) := by
  unfold Exec.updateCommit
  refine Ae.Hoare.getV_bind fun s => ?_
  dsimp only
  refine Ae.Hoare.ite (fun _ => ?_) (fun _ => ?_)
  · refine Ae.Hoare.bind (Ae.Hoare.of_spec (ReplUpdateCommit.updateCommitGo_spec _ _ _)
      (Q := fun r v o => v = u /\ o = o0 /\ r = none)
      fun v o r v' o' ⟨⟨hv, ho⟩, hs⟩ ⟨e1, e2, run⟩ => ?_) fun r => ?_
    · subst hv hs e1 e2 ho
      exact ⟨rfl, rfl, updateCommitOf_none h run⟩
    · split
      · exact Ae.Hoare.false_pre fun _ _ ⟨_, _, e⟩ => by cases e
      · exact Ae.Hoare.pure _ fun _ _ ⟨hv, ho, _⟩ => ⟨hv, ho⟩
  · exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
      Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _) fun _ =>
        Ae.Hoare.false_pre fun _ _ f => f

/-! ## Peer bookkeeping on a non-leader -/

/-- The outbox is `o0` and the state is `v0` up to its peers. -/
def PeersOnly (v0 : State) (o0 : Outbox) (v : State) (o : Outbox) : Prop :=
  o = o0 /\ exists p, v = { v0 with allOtherNodes := p }

theorem createAndRemove_peers (env : Env) {v0 : State} {o0 : Outbox}
    (nl : v0.leadership ≠ .leader)
    : Hoare env (PeersOnly v0 o0) Exec.createAndRemoveNodeState
        (fun _ => PeersOnly v0 o0) := by
  unfold Exec.createAndRemoveNodeState
  refine Ae.Hoare.getV_bind fun s => ?_
  dsimp only
  refine Ae.Hoare.bind
    (Ae.Hoare.pre
      (Ae.Hoare.forIn_list _ _ _ (fun _ _ => PeersOnly v0 o0)
        (fun _ => PeersOnly v0 o0) ?_ fun _ _ _ p => p)
      fun _ _ p => p.1)
    fun _ => Ae.Hoare.pure _ fun _ _ p => p
  intro pre id rest b _
  split
  · exact Ae.Hoare.pure _ fun _ _ p => p
  · refine Ae.Hoare.getV_bind fun s' => ?_
    split
    · refine Ae.Hoare.bind (R := fun _ v o => PeersOnly v0 o0 v o /\ s'.leadership = v0.leadership)
        (Ae.Hoare.setV _ ?_) fun _ => ?_
      · rintro v o ⟨⟨ho, p, rfl⟩, rfl⟩
        exact ⟨⟨ho, _, rfl⟩, rfl⟩
      · split
        · rename_i hl
          exact Ae.Hoare.false_pre fun _ _ ⟨_, e⟩ => nl (by rw [← e]; simpa using hl)
        · exact Ae.Hoare.pure _ fun _ _ p => p.1
    · exact Ae.Hoare.pure _ fun _ _ p => p.1

/-! ## The election rollback -/

/--
`v` is `d` rolled back to `e`: the ledger, view history, committable indexes and pending
retired-committed records are cut at `e`; configurations are a subset of `d`'s; peers and
retirement phases other than retired-committed may change.
-/
def RolledTo (e : Nat) (d v : State) : Prop :=
  exists (cfg : List Config) (p : List (NodeId × Peer)) (rt : Bool) (rp
                                                                      : Option Phase) (rci ri
                                                                                        : Option
                                                                                            Nat),
    v
      = {
        d with
          rcEntries := d.rcEntries.filter (·.1 <= e),
          ledger := d.ledger.extract 0 e,
          lastIdx := e,
          views := d.views.filter (· <= e),
          committable := d.committable.filter (· <= e),
          configurations := cfg,
          allOtherNodes := p,
          retired := rt,
          retirementPhase := rp,
          retirementCommittableIdx := rci,
          retirementIdx := ri
      }
    /\ (forall x, x ∈ cfg -> x ∈ d.configurations)
    /\ (rt && rp == some .retiredCommitted) = false

theorem rollback_spec (env : Env) {d : State} {o0 : Outbox} {e : Nat}
    (nl : d.leadership ≠ .leader) (ce : d.commitIdx <= e)
    (nrc : d.isRetiredCommitted = false)
    : Hoare env (fun v o => v = d /\ o = o0) (Exec.rollback e)
        (fun _ v o => o = o0 /\ RolledTo e d v) := by
  unfold Exec.rollback
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.ite (fun lt => Ae.Hoare.false_pre fun v o ⟨⟨hv, _⟩, hs⟩ => ?_)
    fun _ => ?_
  · subst hv hs; omega
  refine Ae.Hoare.bind
    (R := fun _ v o => o = o0 /\ RolledTo e d v /\ v.leadership = d.leadership)
    (Ae.Hoare.setV _ ?_) fun _ => ?_
  · rintro v o ⟨⟨rfl, rfl⟩, -⟩
    simp only [State.isRetiredCommitted, Bool.and_eq_false_iff] at nrc
    refine ⟨rfl, ?_, ?_⟩
    · dsimp only
      split <;> split
      all_goals exact ⟨_, _, _, _, _, _, rfl, fun _ h => h, by
        first | (simp_all; done) | (simp_all; intro h; cases nrc <;> simp_all)⟩
    · dsimp only
      split <;> split <;> rfl
  refine Ae.Hoare.getV_bind fun w => ?_
  dsimp only
  refine Ae.Hoare.ite (fun _ => ?_) fun _ => Ae.Hoare.pure _ fun _ _ p => ⟨p.1.1, p.1.2.1⟩
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨ho, rt, hl⟩, hw⟩ => ?_
  subst ho hw
  refine Ae.Hoare.bind
    (R := fun _ v o => PeersOnly
      { v1 with configurations := v1.configurations.filter (fun c => c.idx <= e) } o1 v o)
    (Ae.Hoare.setV _ ?_) fun _ => ?_
  · rintro v o ⟨rfl, rfl⟩
    exact ⟨rfl, _, rfl⟩
  refine Ae.Hoare.post (Ae.Hoare.pre (createAndRemove_peers env ?_) fun _ _ p => p) ?_
  · simpa using hl ▸ nl
  · obtain ⟨cfg, p, rt', rp, rci, ri, rfl, hcfg, hrc⟩ := rt
    rintro _ v o ⟨rfl, p', rfl⟩
    exact ⟨rfl, _, p', rt', rp, rci, ri, rfl,
      fun x h => hcfg x (List.mem_filter.1 h).1, hrc⟩

/-! ## The election heartbeat -/

/-- Step over an operation that keeps the state and outbox. -/
macro "keep_step" : tactic =>
  `(tactic| first
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.trace _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.emit _ _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.emitStr _ _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps Spec.look fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.use _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.liftE _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps (Spec.note _) fun _ _ _ p => p) fun _ => ?_
    | refine Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ => ?_)

/-- The empty `AppendEntries` a new leader sends each peer from its ledger end. -/
def hbMsg (w : State) : Message :=
  .appendEntriesRequest
    {
      term := w.currentView,
      prevLogIndex := w.lastIdx,
      prevLogTerm := w.getTerm w.lastIdx,
      entries := [],
      primaryCommit := w.commitIdx
    }

theorem viewAt_end {w : State} (h : forall x, x ∈ w.views.toList -> x <= w.lastIdx + 1)
    : w.viewAt (w.lastIdx + 1) = w.views.size := by
  simp only [State.viewAt]
  rw [List.filter_eq_self.2 (by simpa using h), Array.length_toList]

theorem sendRange_hb (env : Env) {w : State} {o1 : Outbox} (id : NodeId)
    : Hoare env (fun v o => v = w /\ o = o1)
        (Exec.sendAppendEntriesRange id (w.lastIdx + 1) w.lastIdx false)
        (fun _ v o =>
          exists p : Peer,
            w.peer? id = some p
            /\ v = w.setPeer id { p with sentIdx := w.lastIdx }
            /\ o
                = o1
                  ++ [CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id)
                        (hbMsg w)]) := by
  unfold Exec.sendAppendEntriesRange
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o2 ⟨⟨h1, h2⟩, h3⟩ => ?_
  subst h1 h2 h3
  dsimp only
  split
  rotate_left
  · exact Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ => Ae.Hoare.fail _
  rename_i node hnode
  keep_step
  keep_step
  refine Ae.Hoare.bind (Ae.Hoare.of_spec Spec.names
    (Q := fun a v o => a = env.names /\ v = v1 /\ o = o2)
    fun v o a v' o' p ⟨ha, hv, ho⟩ => ⟨ha, hv ▸ p.1, ho ▸ p.2⟩) fun nm => ?_
  refine Ae.Hoare.lift fun hn => ?_
  subst hn
  refine Ae.Hoare.bind
    (Ae.Hoare.send _ _
      (Q :=
        fun _ v o =>
          v = v1
          /\ o
              = o2
                ++ [CCF.Envelope.mk (env.names.id v1.nodeId) (env.names.id id)
                      (hbMsg v1)])
      fun v o ⟨hv, ho⟩ => ⟨hv, by subst hv ho; simp [hbMsg]⟩)
    fun _ => ?_
  keep_step
  exact Ae.Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨node, hv ▸ hnode, by subst hv; rfl, ho⟩

theorem sendHeartbeat (env : Env) {w : State} {o1 : Outbox} (id : NodeId)
    (nrc : w.isRetiredCommitted = false)
    (vle : forall x, x ∈ w.views.toList -> x <= w.lastIdx + 1)
    : Hoare env (fun v o => v = w /\ o = o1) (Exec.sendAppendEntries id (w.lastIdx + 1))
        (fun _ v o =>
          exists p : Peer,
            w.peer? id = some p
            /\ v = w.setPeer id { p with sentIdx := w.lastIdx }
            /\ o
                = o1
                  ++ [CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id)
                        (hbMsg w)]) := by
  unfold Exec.sendAppendEntries
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v0 o0' ⟨⟨h1, h2⟩, h3⟩ => ?_
  subst h1 h2 h3
  rw [Exec.sendAppendEntries.loop]
  refine Ae.Hoare.getV_bind fun s => ?_
  have h0 : v0.endOfView (v0.viewAt (v0.lastIdx + 1)) = 0 := by
    rw [viewAt_end vle]
    simp [State.endOfView]
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨h1, h2⟩, h3⟩ => ?_
  subst h1 h2 h3
  dsimp only
  simp only [h0, nrc, Bool.false_and, Bool.false_eq_true, ↓reduceIte, Option.any_none,
    Nat.lt_add_one, gt_iff_lt]
  keep_step
  keep_step
  keep_step
  keep_step
  refine Ae.Hoare.bind (R := fun _ v o => v = v1 /\ o = o1)
    (Ae.Hoare.pure _ fun _ _ p => p) fun e => ?_
  refine Ae.Hoare.ite (fun he => ?_) fun _ =>
    Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
      Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _) fun _ =>
        Ae.Hoare.false_pre fun _ _ f => f
  obtain rfl : e = v1.lastIdx := by simpa using he
  refine Ae.Hoare.ite (fun he => absurd he (Nat.lt_irrefl _)) fun _ => ?_
  refine Ae.Hoare.bind (R := fun _ v o => v = v1 /\ o = o1)
    (Ae.Hoare.pure _ fun _ _ p => p) fun _ => ?_
  refine Ae.Hoare.bind (sendRange_hb env id) fun _ => ?_
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.ite (fun _ => Ae.Hoare.pure _ fun _ _ p => p.1) fun hn => ?_
  refine Ae.Hoare.false_pre fun v o ⟨⟨p, _, hv, _⟩, hs⟩ => hn ?_
  subst hs hv
  simp [State.setPeer]

/-! ## Peer resets -/

/-- Every peer is in `L`, and those that `S` selects are reset to `P`. -/
def PeerInv (L : List NodeId) (P : Peer) (S : NodeId -> Prop) (ps : List (NodeId × Peer))
    : Prop :=
  forall x, x ∈ ps -> x.1 ∈ L /\ (S x.1 -> x.2 = P)

theorem mem_setPeer {v : State} {id : NodeId} {P : Peer} {x : NodeId × Peer}
    (h : x ∈ (v.setPeer id P).allOtherNodes)
    : (x ∈ v.allOtherNodes /\ x.1 ≠ id) \/ x = (id, P) := by
  simp only [State.setPeer, List.mem_mergeSort, List.mem_append, List.mem_filter,
    List.mem_singleton, bne_iff_ne, ne_eq] at h
  exact h

theorem peerInv_setPeer {L : List NodeId} {P : Peer} {S S' : NodeId -> Prop} {v : State}
    {id : NodeId} (h : PeerInv L P S v.allOtherNodes) (hid : id ∈ L)
    (hS : forall y, S' y -> S y \/ y = id)
    : PeerInv L P S' (v.setPeer id P).allOtherNodes := by
  intro x hx
  rcases mem_setPeer hx with ⟨hx, hne⟩ | rfl
  · exact ⟨(h x hx).1, fun s => (h x hx).2 ((hS _ s).resolve_right hne)⟩
  · exact ⟨hid, fun _ => rfl⟩

/-- Every id of `L` has an entry in `ps`. -/
def Covers (L : List NodeId) (ps : List (NodeId × Peer)) : Prop :=
  forall y, y ∈ L -> exists q, (y, q) ∈ ps

theorem covers_setPeer {L : List NodeId} {v : State} {id : NodeId} (P : Peer)
    (h : Covers L v.allOtherNodes)
    : Covers (L ++ [id]) (v.setPeer id P).allOtherNodes := by
  intro y hy
  simp only [State.setPeer, List.mem_mergeSort, List.mem_append, List.mem_filter,
    List.mem_singleton, bne_iff_ne, ne_eq]
  by_cases hyi : y = id
  · exact ⟨P, Or.inr (by rw [hyi])⟩
  · obtain ⟨q, hq⟩ := h y (by simpa [hyi] using hy)
    exact ⟨q, Or.inl ⟨hq, hyi⟩⟩

theorem covers_mono {L L' : List NodeId} {ps : List (NodeId × Peer)} (h : Covers L ps)
    (sub : forall y, y ∈ L' -> y ∈ L)
    : Covers L' ps :=
  fun y hy => h y (sub y hy)

theorem peer_setPeer (v : State) (id : NodeId) (P : Peer)
    : (v.setPeer id P).peer? id = some P := by
  cases h : (v.setPeer id P).peer? id with
  | none =>
      simp only [State.peer?, List.lookup_eq_none_iff] at h
      exact absurd (h (id, P) (by simp [State.setPeer])) (by simp)
  | some b =>
      obtain ⟨l1, l2, hl, -⟩ := List.lookup_eq_some_iff.mp h
      have hm : (id, b) ∈ (v.setPeer id P).allOtherNodes := by rw [hl]; simp
      rcases mem_setPeer hm with ⟨-, hne⟩ | he
      · exact absurd rfl hne
      · cases he; rfl

/-! ## `become_leader` on M_tv -/

/-- `becomeLeader` after the election rollback: verbatim, so that it unfolds to the same term. -/
def leaderTail : M Bool := do
  setV fun v => { v with leadership := .leader, leaderId := some v.nodeId }
  trace "become_leader"
  if (← getV).otherNodesInActiveConfigs.isEmpty then updateCommit
  let next := (← getV).lastIdx + 1
  for id in ← otherNodesSorted do
    setV fun v => v.setPeer id { matchIdx := 0, sentIdx := next - 1 }
    sendAppendEntries id next
  return true

/-- The new leader's sends: one heartbeat to each peer of `w`, in order. -/
def hbs (names : Names) (w : State) : Outbox :=
  w.allOtherNodes.map
    fun x => CCF.Envelope.mk (names.id w.nodeId) (names.id x.1) (hbMsg w)

/-- A peer reset by the new leader. -/
def resetPeer (w : State) : Peer := { sentIdx := w.lastIdx, matchIdx := 0 }

theorem leaderLoop (env : Env) {w : State} {o1 : Outbox}
    (nrc : w.isRetiredCommitted = false)
    (vle : forall x, x ∈ w.views.toList -> x <= w.lastIdx + 1)
    : let u : State := { w with leadership := .leader, leaderId := some w.nodeId }
      Hoare env (fun v o => v = u /\ o = o1)
        (do
          let l ← otherNodesSorted
          forIn l PUnit.unit
            fun id _ => do
              setV fun v => v.setPeer id { sentIdx := u.lastIdx + 1 - 1, matchIdx := 0 }
              sendAppendEntries id (u.lastIdx + 1)
              pure (ForInStep.yield PUnit.unit)
          pure true)
        (fun b v o =>
          b = true
          /\ exists peers,
              v
                = {
                  w with
                    leadership := .leader,
                    leaderId := some w.nodeId,
                    allOtherNodes := peers
                }
              /\ PeerInv (w.allOtherNodes.map Prod.fst) (resetPeer w) (fun _ => True)
                  peers
              /\ Covers (w.allOtherNodes.map Prod.fst) peers
              /\ o = o1 ++ hbs env.names w) := by
  intro u
  let L := w.allOtherNodes.map Prod.fst
  let f : NodeId -> CCF.Envelope NodeID Message :=
    fun id => CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id) (hbMsg w)
  refine Ae.Hoare.bind (R := fun l v o => l = L /\ v = u /\ o = o1) ?_ fun l => ?_
  · unfold Exec.otherNodesSorted
    exact Ae.Hoare.getV_bind fun s =>
      Ae.Hoare.pure _ fun v o ⟨⟨hv, ho⟩, hs⟩ => ⟨by subst hs hv; rfl, hv, ho⟩
  refine Ae.Hoare.pin fun v3 o3 ⟨hl, hv, ho⟩ => ?_
  subst l v3 o3
  refine Ae.Hoare.bind (Ae.Hoare.pre (Ae.Hoare.forIn_list _ _ _
    (fun pre _ v o => exists ps, v = { u with allOtherNodes := ps }
      /\ PeerInv L (resetPeer w) (· ∈ pre) ps /\ Covers pre ps /\ o = o1 ++ pre.map f)
    (fun _ v o => exists ps, v = { u with allOtherNodes := ps }
      /\ PeerInv L (resetPeer w) (· ∈ L) ps /\ Covers L ps /\ o = o1 ++ L.map f) ?_
      fun _ _ _ p => p)
    fun v o ⟨hv, ho⟩ => ⟨w.allOtherNodes, hv, fun x hx => ⟨List.mem_map_of_mem hx, by simp⟩,
      fun _ h => by simp at h, by simp [ho]⟩) fun _ => Ae.Hoare.pure _
        fun v o ⟨ps, hv, hinv, hcov, ho⟩ =>
        ⟨rfl, ps, hv, fun x hx => ⟨(hinv x hx).1, fun _ => (hinv x hx).2 (hinv x hx).1⟩, hcov,
          by rw [ho]; simp [hbs, L, f]⟩
  intro pre id rest _ hl
  have hid : id ∈ L := by rw [hl]; simp
  refine Ae.Hoare.pin fun v4 o4 ⟨ps, hv, hinv, hcov, ho⟩ => ?_
  subst hv ho
  let X1 := ({ u with allOtherNodes := ps } : State).setPeer id (resetPeer w)
  refine Ae.Hoare.bind (R := fun _ v o => v = X1 /\ o = o1 ++ pre.map f)
    (Ae.Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨by subst hv; rfl, ho⟩) fun _ => ?_
  refine Ae.Hoare.bind
    (Ae.Hoare.pre (sendHeartbeat env (w := X1) id nrc vle) fun _ _ p => p)
    fun _ => Ae.Hoare.pure _ fun v o ⟨p, hp, hv, ho⟩ => ?_
  rw [peer_setPeer] at hp
  cases hp
  refine ⟨(X1.setPeer id (resetPeer w)).allOtherNodes, by rw [hv]; rfl, ?_, ?_, ?_⟩
  · refine peerInv_setPeer (peerInv_setPeer hinv hid fun y h => ?_) hid fun y h => Or.inl h
    simpa using h
  · exact covers_mono (covers_setPeer (L := pre ++ [id]) (id := id) _
      (covers_setPeer (v := { u with allOtherNodes := ps }) _ hcov)) fun y hy => by simp_all
  · rw [ho]; simp only [List.map_append, List.map_cons, List.map_nil, List.append_assoc]; rfl

theorem leaderTail_spec (env : Env) {w : State} {o1 : Outbox}
    (nrc : w.isRetiredCommitted = false) (vlt : w.views.size < w.currentView)
    (vle : forall x, x ∈ w.views.toList -> x <= w.lastIdx + 1)
    : Hoare env (fun v o => v = w /\ o = o1) leaderTail
        (fun b v o =>
          b = true
          /\ exists peers,
              v
                = {
                  w with
                    leadership := .leader,
                    leaderId := some w.nodeId,
                    allOtherNodes := peers
                }
              /\ PeerInv (w.allOtherNodes.map Prod.fst) (resetPeer w) (fun _ => True)
                  peers
              /\ Covers (w.allOtherNodes.map Prod.fst) peers
              /\ o = o1 ++ hbs env.names w) := by
  unfold leaderTail
  let u : State := { w with leadership := .leader, leaderId := some w.nodeId }
  refine Ae.Hoare.bind (R := fun _ v o => v = u /\ o = o1)
    (Ae.Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨by subst hv; rfl, ho⟩) fun _ => ?_
  keep_step
  refine Ae.Hoare.getV_bind fun s => ?_
  dsimp only
  refine Ae.Hoare.ite
    (fun _ =>
      Ae.Hoare.bind (Ae.Hoare.pre (updateCommit_noop env (u := u) vlt) fun _ _ p => p.1)
        fun _ => ?_)
    fun _ => Ae.Hoare.pre ?_ fun _ _ p => p.1
  all_goals
    refine Ae.Hoare.getV_bind fun s => ?_
    refine Ae.Hoare.pin fun v2 o2 ⟨⟨h1, h2⟩, h3⟩ => ?_
    subst h1 h2 h3
    exact leaderLoop env nrc vle

/-- What `becomeLeader` needs of the declared state it starts from. -/
structure TvPre (d : State) : Prop where
  notLeader : d.leadership ≠ .leader
  viewsLt : d.views.size < d.currentView
  viewsLe : forall x, x ∈ d.views.toList -> x <= d.lastIdx + 1
  commitLe : d.commitIdx <= d.lastCommittable

/-- The state after the election rollback, which only happens with a positive commit index. -/
def Rolled (d w : State) : Prop :=
  if 0 < d.commitIdx then RolledTo d.lastCommittable d w else w = d

theorem becomeLeader_tv (env : Env) {d : State} {o0 : Outbox} (pre : TvPre d)
    : Hoare env (fun v o => v = d /\ o = o0) Exec.becomeLeader
        (fun b v o =>
          (d.isRetiredCommitted = true /\ b = false /\ v = d /\ o = o0)
          \/ (d.isRetiredCommitted = false
              /\ b = true
              /\ exists w peers,
                  Rolled d w
                  /\ (0 < d.commitIdx
                      -> w.allOtherNodes.map (fun x => env.names.id x.1)
                          = (eligiblePeers (abs env.names w)
                              (env.names.id w.nodeId)).sort)
                  /\ v
                      = {
                        w with
                          leadership := .leader,
                          leaderId := some w.nodeId,
                          allOtherNodes := peers
                      }
                  /\ PeerInv (w.allOtherNodes.map Prod.fst) (resetPeer w) (fun _ => True)
                      peers
                  /\ Covers (w.allOtherNodes.map Prod.fst) peers
                  /\ o = o0 ++ hbs env.names w)) := by
  unfold Exec.becomeLeader
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨h1, h2⟩, h3⟩ => ?_
  subst h1 h2 h3
  refine Ae.Hoare.ite
    (fun hr => Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => Or.inl ⟨hr, rfl, hv, ho⟩) fun hr => ?_
  simp only [Bool.not_eq_true] at hr
  dsimp only
  refine Ae.Hoare.ite (fun hc => ?_) fun hc => ?_
  · refine Ae.Hoare.bind (rollback_spec env pre.notLeader pre.commitLe hr) fun _ => ?_
    refine Ae.Hoare.bind (Ae.Hoare.of_spec Spec.names
      (Q := fun a v o => a = env.names /\ o = o1 /\ RolledTo v1.lastCommittable v1 v)
      fun v o a v' o' p ⟨ha, hv, ho⟩ => ⟨ha, ho ▸ p.1, hv ▸ p.2⟩) fun nm => ?_
    refine Ae.Hoare.lift fun hn => ?_
    subst hn
    refine Ae.Hoare.getV_bind fun w => ?_
    refine Ae.Hoare.pin fun v2 o2 ⟨⟨ho, rt⟩, hw⟩ => ?_
    subst hw ho
    have rt' := rt
    obtain ⟨cfg, p, rtd, rp, rci, ri, hv2, -, hrc⟩ := rt'
    have nrc : v2.isRetiredCommitted = false := by rw [hv2]; exact hrc
    have vlt : v2.views.size < v2.currentView := by
      rw [hv2]; exact Nat.lt_of_le_of_lt Array.size_filter_le pre.viewsLt
    have vle : forall x, x ∈ v2.views.toList -> x <= v2.lastIdx + 1 := by
      rw [hv2]; intro x hx; simp only [Array.toList_filter, List.mem_filter,
        decide_eq_true_eq] at hx
      show x <= v1.lastCommittable + 1
      omega
    refine Ae.Hoare.ite (fun hp => ?_) fun _ =>
      Ae.Hoare.bind (Ae.Hoare.keeps Spec.curLoc fun _ _ _ p => p) fun _ =>
        Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _) fun _ =>
          Ae.Hoare.false_pre fun _ _ f => f
    refine Ae.Hoare.post (leaderTail_spec env (w := v2) (o1 := o2) nrc vlt vle)
      fun b v o ⟨hb, peers, hv, hinv, hcov, ho⟩ =>
        Or.inr ⟨hr, hb, v2, peers, ?_, fun _ => ?_, hv, hinv, hcov, ho⟩
    · simpa [Rolled, hc] using rt
    · simpa using hp
  · refine Ae.Hoare.post (leaderTail_spec env (w := v1) (o1 := o1) hr pre.viewsLt pre.viewsLe)
      fun b v o ⟨hb, peers, hv, hinv, hcov, ho⟩ =>
        Or.inr ⟨hr, hb, v1, peers, by simp [Rolled, hc], fun h => absurd h hc, hv, hinv, hcov, ho⟩

/-! ## The clean side of the election -/

theorem retirement_congr {a b : NodeState} (hl : a.log = b.log)
    (hc : a.commitIndex = b.commitIndex)
    (hr : a.retiredCommittedIndex = b.retiredCommittedIndex) (n : NodeID)
    : a.retirement n = b.retirement n := by
  simp only [NodeState.retirement, hl, hc, hr]

theorem termAt_take_le (l : List Model.Node.Entry) (n i : Nat)
    : termAt (l.take n) i <= termAt l i := by
  unfold termAt entryAt?
  split
  · simp
  · rw [List.getElem?_take]
    split <;> simp

theorem lastCommittable_bounds {d : State} (h2 : d.commitIdx <= d.lastIdx)
    (h3 : d.committable = signaturesIn d d.commitIdx d.lastIdx)
    : d.commitIdx <= d.lastCommittable /\ d.lastCommittable <= d.lastIdx := by
  unfold State.lastCommittable
  cases hl : d.committable.getLast? with
  | none => exact ⟨Nat.le_refl _, h2⟩
  | some x =>
      have hx := List.mem_of_getLast? hl
      rw [h3] at hx
      simp only [signaturesIn, List.mem_filter, List.mem_range'] at hx
      obtain ⟨⟨k, hk, rfl⟩, -⟩ := hx
      simp only [Option.getD_some]
      omega

theorem abs_log_rolled {names : Names} {e : Nat} {d w : State} (h : RolledTo e d w)
    (he : e <= d.lastIdx)
    : (abs names w).log = (abs names d).log.take e := by
  obtain ⟨cfg, p, rt, rp, rci, ri, rfl, -, -⟩ := h
  simp only [abs, Array.toList_extract, List.extract, List.drop_zero, List.take_take,
    List.map_take, Nat.min_eq_left he, Nat.sub_zero, Nat.min_self]

theorem eligiblePeers_empty {s : NodeState} (hl : s.log = []) (hc : s.commitIndex = 0)
    (self : NodeID)
    : (eligiblePeers s self).sort = [] := by
  unfold eligiblePeers NodeState.activeMembers NodeState.retirementCompletedNodes
    NodeState.activeConfigurations NodeState.committedLog
  rw [hl, hc]
  rfl

theorem agrees_frame {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c.currentTerm = d.currentView
      /\ c.log = (abs names d).log
      /\ c.commitIndex = d.commitIdx
      /\ c.isNewFollower = d.isNewFollower
      /\ c.votedFor = d.votedFor.map names.id
      /\ c.retiredCommittedIndex = d.retiredCommittedIdx := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨-, h2⟩, h3⟩, h4⟩, -⟩, h6⟩, h7⟩, -⟩, -⟩, -⟩, h11⟩ := h
  exact ⟨h2, h3, h4, h6, h7, h11⟩

/-- What the clean election needs of the declared state `becomeLeader` starts from. -/
structure LeaderPre (names : Names) (d : State) : Prop where
  notLeader : d.leadership ≠ .leader
  /-- No ledger entry is in the current view. -/
  viewsLt : d.views.size < d.currentView
  viewsLe : forall x, x ∈ d.views.toList -> x <= d.lastIdx + 1
  size : d.ledger.size = d.lastIdx
  commitLe : d.commitIdx <= d.lastIdx
  committable : d.committable = signaturesIn d d.commitIdx d.lastIdx
  commitSig : d.commitIdx = 0 \/ d.ledger[d.commitIdx - 1]?.any (·.sig) = true
  terms
    : forall i,
        1 <= i -> i <= d.lastIdx -> d.ledger[i - 1]?.map (·.term) = some (d.viewAt i)
  retired
    : d.isRetiredCommitted = decide ((abs names d).isRetiredCommitted (names.id d.nodeId))
  /-- The peers are the clean eligible peers (the `peers` conjuncts of `inv`). -/
  peers
    : d.lastIdx = 0
      \/ d.allOtherNodes.map (fun x => names.id x.1)
          = (eligiblePeers (abs names d) (names.id d.nodeId)).sort

theorem LeaderPre.tv {names : Names} {d : State} (pre : LeaderPre names d) : TvPre d :=
  ⟨
    pre.notLeader,
    pre.viewsLt,
    pre.viewsLe,
    (lastCommittable_bounds pre.commitLe pre.committable).1
  ⟩

/-- The new leader's state after `becomeLeader`, with the peers it reset. -/
def leaderState (w : State) (peers : List (NodeId × Peer)) : State :=
  { w with leadership := .leader, leaderId := some w.nodeId, allOtherNodes := peers }

/-- What the election rollback keeps. -/
theorem rolled_frame {d w : State} (rolled : Rolled d w)
    : w.nodeId = d.nodeId
      /\ w.currentView = d.currentView
      /\ w.commitIdx = d.commitIdx
      /\ w.isNewFollower = d.isNewFollower
      /\ w.votedFor = d.votedFor
      /\ w.retiredCommittedIdx = d.retiredCommittedIdx
      /\ (forall x, x ∈ w.configurations -> x ∈ d.configurations) := by
  unfold Rolled at rolled
  split at rolled
  · obtain ⟨cfg, p, rt, rp, rci, ri, rfl, sub, -⟩ := rolled
    exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, sub⟩
  · subst rolled; exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ h => h⟩

theorem leader_clean {names : Names} {c : NodeState} {d w : State}
    {peers : List (NodeId × Peer)}
    (pre : LeaderPre names d) (ag : agrees names c d = true) (rolled : Rolled d w)
    (chk
      : 0 < d.commitIdx
        -> w.allOtherNodes.map (fun x => names.id x.1)
            = (eligiblePeers (abs names w) (names.id w.nodeId)).sort)
    (pinv : PeerInv (w.allOtherNodes.map Prod.fst) (resetPeer w) (fun _ => True) peers)
    (cov : Covers (w.allOtherNodes.map Prod.fst) peers)
    (hinv : inv names (leaderState w peers) = true)
    : Emits
        (becomePrimary (CCF.Capabilities.record (names.id d.nodeId)) (names.id d.nodeId)
          c)
        (primaryState c) (hbs names w)
      /\ agrees names (primaryState c) (leaderState w peers) = true
      /\ forall e, e ∈ hbs names w -> msgInv names e = true := by
  obtain ⟨ht, hl, hcm, hnf, hvf, hrc⟩ := agrees_frame ag
  have bounds := lastCommittable_bounds pre.commitLe pre.committable
  obtain ⟨wn, wv, wc, wnf, wvf, wrc, -⟩ := rolled_frame rolled
  obtain ⟨f1, -, -, -, f5, -, -⟩ := inv_parts hinv
  have hlogw : (abs names w).log = (primaryState c).log := by
    unfold Rolled at rolled
    split at rolled
    · rename_i hc
      rw [abs_log_rolled rolled bounds.2]
      have hlc : lastCommittableIndex c = d.lastCommittable := by
        unfold lastCommittableIndex
        rw [hl, ← lastCommittable_eq_of pre.size pre.committable pre.commitSig, hcm]
        exact Nat.max_eq_right bounds.1
      simp only [primaryState, hcm, hc, ite_true, hlc, hl]
    · rename_i hc
      subst rolled
      simp only [primaryState, hcm, gt_iff_lt, hc, ite_false, hl]
  have hlen : (primaryState c).log.length = w.lastIdx := by
    rw [← hlogw]
    simp only [abs, List.length_map, List.length_take, Array.length_toList]
    exact Nat.min_eq_left (Nat.le_of_eq f1.symm)
  have htl : termAt (primaryState c).log w.lastIdx = w.getTerm w.lastIdx := by
    rw [← hlogw]
    exact (getTerm_eq hinv w.lastIdx).symm
  have peersEq : w.allOtherNodes.map (fun x => names.id x.1)
      = (eligiblePeers (primaryState c) (names.id d.nodeId)).sort := by
    rw [eligiblePeers_congr (b := abs names w) hlogw.symm
      (by simp only [primaryState, abs, hcm, wc])]
    by_cases hc : 0 < d.commitIdx
    · rw [← wn]; exact chk hc
    · have hw : w = d := by simpa [Rolled, hc] using rolled
      subst hw
      rcases pre.peers with h0 | h
      · have hemp : peers = [] := by
          have e := hinv
          have : (w.lastIdx != 0 || (Leadership.leader != .leader) || peers.isEmpty) = true := by
            inv_conj e "empty_leader_alone"
          simpa [h0] using this
        have hw0 : w.allOtherNodes = [] := by
          cases hw : w.allOtherNodes with
          | nil => rfl
          | cons x xs =>
              obtain ⟨q, hq⟩ := cov x.1 (by simp [hw])
              simp [hemp] at hq
        rw [hw0, eligiblePeers_empty (by simp [abs, h0]) (by simp only [abs]; omega)]
        rfl
      · exact h
  have noTerm : forall i, termAt (primaryState c).log i ≠ (primaryState c).currentTerm := by
    intro i
    have h1 : termAt (primaryState c).log i <= termAt c.log i := by
      simp only [primaryState]
      split
      · exact termAt_take_le _ _ _
      · exact Nat.le_refl _
    have h2 : termAt c.log i < c.currentTerm := by
      rw [hl, termAt_abs pre.size, ht]
      have vl := pre.viewsLt
      split
      · omega
      · by_cases hi : i <= d.lastIdx
        · rw [pre.terms i (by omega) hi]
          have := ReplUpdateCommit.viewAt_le_size d i
          simp only [Option.getD_some]
          omega
        · have hn : d.ledger[i - 1]? = none := by
            simp only [Array.getElem?_eq_none_iff, pre.size]; omega
          simp only [hn, Option.map_none, Option.getD_none]
          omega
    have : (primaryState c).currentTerm = c.currentTerm := rfl
    omega
  refine ⟨emits_congr (emits_becomePrimary _ c noTerm) rfl ?_, ?_, ?_⟩
  · rw [← peersEq]
    simp only [hbs, List.map_map]
    apply List.map_congr_left
    intro x _
    simp only [Function.comp, heartbeat, hbMsg, hlen, htl, wn]
    simp only [primaryState, ht, wv, hcm, wc]
  · simp only [agrees, Bool.and_eq_true, beq_iff_eq]
    refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨rfl, ?_⟩, hlogw.symm⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, rfl⟩, rfl⟩, rfl⟩, ?_⟩
    · show c.currentTerm = w.currentView
      rw [ht, wv]
    · show c.commitIndex = w.commitIdx
      rw [hcm, wc]
    · rw [List.all_eq_true]
      intro n hn
      simp only [trackedPeers, leaderState, BEq.rfl, ite_true, List.mem_map] at hn
      obtain ⟨x, hx, rfl⟩ := hn
      simp only [abs, leaderState, Bool.and_eq_true, beq_iff_eq]
      split
      · rename_i y q hf
        have hy := List.mem_of_find?_eq_some hf
        have hq := (pinv _ hy).2 trivial
        simp only at hq
        subst hq
        exact ⟨hlen, rfl⟩
      · rename_i hf
        have := List.find?_eq_none.mp hf x hx
        simp at this
    · show c.isNewFollower = w.isNewFollower
      rw [hnf, wnf]
    · show c.votedFor = w.votedFor.map names.id
      rw [hvf, wvf]
    · show c.retiredCommittedIndex = w.retiredCommittedIdx
      rw [hrc, wrc]
  · intro e he
    simp only [hbs, List.mem_map] at he
    obtain ⟨x, hx, rfl⟩ := he
    have sn : (names.name (names.id w.nodeId) == w.nodeId) = true := by
      have e := hinv
      inv_conj e "self_named"
    have pt : (leaderState w peers).ledger.all (0 < ·.term) = true := by
      have e := hinv
      inv_conj e "positive_terms"
    have hm : names.id x.1 ∈ (eligiblePeers (primaryState c) (names.id d.nodeId)).sort := by
      rw [← peersEq]; exact List.mem_map_of_mem hx
    simp only [eligiblePeers, CCF.Finset.erase, CCF.Finset.filter, CCF.Finset.sort,
      List.mem_filter, decide_eq_true_eq] at hm
    have hpos : w.lastIdx = 0 \/ 0 < w.getTerm w.lastIdx := by
      by_cases h0 : w.lastIdx = 0
      · exact Or.inl h0
      · right
        have := f5 w.lastIdx (by omega) (Nat.le_refl _)
        change Option.map (·.term) w.ledger[w.lastIdx - 1]? = some (w.viewAt w.lastIdx) at this
        simp only [leaderState] at pt
        cases hg : w.ledger[w.lastIdx - 1]? with
        | none => simp [hg] at this
        | some en =>
            simp only [hg, Option.map_some, Option.some.injEq] at this
            have hp := (Array.all_eq_true_iff_forall_mem.mp pt) en (Array.mem_of_getElem? hg)
            simp only [decide_eq_true_eq] at hp
            simp only [State.getTerm, gt_iff_lt, Nat.lt_irrefl, ite_false]
            omega
    simp only [beq_iff_eq] at sn
    have hne : names.id w.nodeId ≠ names.id x.1 := by rw [wn]; exact fun h => hm.2 h.symm
    simp only [msgInv, hbMsg, List.all_nil, Bool.and_true, sn]
    rcases hpos with h | h <;> simp [h, hne]

theorem unmatched_primaryState (node : NodeID) (c : NodeState)
    : UnnamedUnmatched node (primaryState c) :=
  fun _ _ _ _ => rfl

/--
`becomeLeader` from a declared state `d` that `c` agrees with: it stops at once if and only
if `c` is retired-committed; otherwise it ends as a leader that, if it satisfies `inv`, the
clean `primaryState c` agrees with, having sent exactly what the clean `becomePrimary` sends.
-/
theorem becomeLeader_spec (env : Env) {c : NodeState} {d : State} {o0 : Outbox}
    (pre : LeaderPre env.names d) (ag : agrees env.names c d = true)
    : Hoare env (fun v o => v = d /\ o = o0) Exec.becomeLeader
        (fun b v o =>
          (c.isRetiredCommitted (env.names.id d.nodeId) /\ b = false /\ v = d /\ o = o0)
          \/ (Not (c.isRetiredCommitted (env.names.id d.nodeId))
              /\ b = true
              /\ exists sends,
                  o = o0 ++ sends
                  /\ v.nodeId = d.nodeId
                  /\ v.currentView = d.currentView
                  /\ v.leadership = .leader
                  /\ (forall x, x ∈ v.configurations -> x ∈ d.configurations)
                  /\ (inv env.names v = true
                      -> Emits
                            (becomePrimary
                              (CCF.Capabilities.record (env.names.id d.nodeId))
                              (env.names.id d.nodeId) c)
                            (primaryState c) sends
                          /\ agrees env.names (primaryState c) v = true
                          /\ forall e, e ∈ sends -> msgInv env.names e = true))) := by
  obtain ⟨-, hl, hcm, -, -, hrc⟩ := agrees_frame ag
  have hret : d.isRetiredCommitted = decide (c.isRetiredCommitted (env.names.id d.nodeId)) := by
    have := retirement_congr (b := abs env.names d) hl hcm hrc (env.names.id d.nodeId)
    rw [pre.retired]
    simp only [NodeState.isRetiredCommitted, this]
  refine Ae.Hoare.post (becomeLeader_tv env pre.tv) fun b v o h => ?_
  rcases h with ⟨hr, hb, hv, ho⟩ | ⟨hr, hb, w, peers, rolled, chk, hv, pinv, cov, ho⟩
  · exact Or.inl ⟨of_decide_eq_true (hret ▸ hr), hb, hv, ho⟩
  · obtain ⟨wn, wv, -, -, -, -, sub⟩ := rolled_frame rolled
    refine Or.inr ⟨fun h => ?_, hb, hbs env.names w, ho, ?_, ?_, ?_, ?_, fun hinv => ?_⟩
    · rw [hret] at hr; simp [h] at hr
    all_goals subst hv
    · exact wn
    · exact wv
    · rfl
    · exact sub
    · exact leader_clean pre ag rolled chk pinv cov hinv

end Consensus.TraceValidation.Proofs.Vote
