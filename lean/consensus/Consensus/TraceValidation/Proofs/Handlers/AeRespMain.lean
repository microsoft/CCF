module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespStep

@[expose] public section

/-!
# The AppendEntries response: facts from `inv` (not reviewed)

What `inv` gives of a leader's peers (`PeerCtx`), the hypotheses of `handler_spec`
(`cover_of_inv`, `rcRetired_of_inv`), a leader's unlatched retirement confirmation
(`leader_rci_none`), and agreement and `UnnamedUnmatched` after a peer's indexes change.
-/

namespace Consensus.TraceValidation.Proofs.AeResp
open Consensus.Model.Node
open Consensus.TraceValidation (Names Env abs absRole agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (absConfig Named named_inj Hyps)

theorem lookup_mem {l : List (Exec.NodeId × Peer)} {k : Exec.NodeId} {b : Peer}
    (h : l.lookup k = some b)
    : (k, b) ∈ l := by
  obtain ⟨l1, l2, rfl, -⟩ := List.lookup_eq_some_iff.mp h
  simp

theorem abs_sentIndex_of_sorted {names : Names} {v : State}
    (sorted : v.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1)) {p}
    (mem : p ∈ v.allOtherNodes)
    : (abs names v).sentIndex (names.id p.1) = p.2.sentIdx := by
  simp only [abs]
  rw [find_sorted names _ sorted p mem]

theorem leader_nonempty {names : Names} {v : State} (h : inv names v = true)
    (lead : v.leadership = .leader) {q : Exec.NodeId × Peer} (mem : q ∈ v.allOtherNodes)
    : v.lastIdx ≠ 0 := by
  intro L0
  have e : (v.lastIdx != 0 || v.leadership != .leader || v.allOtherNodes.isEmpty) = true := by
    inv_conj h "empty_leader_alone"
  simp [L0, lead] at e
  rw [e] at mem
  cases mem

/-- What `inv` says of the peers of a leader with a nonempty ledger. -/
structure PeerCtx (names : Names) (v : State) : Prop where
  peersEq
    : v.allOtherNodes.map (fun p => names.id p.1)
      = (eligiblePeers (abs names v) (names.id v.nodeId)).sort
  sortedId : v.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1)
  sortedStr : v.allOtherNodes.Pairwise (fun p q => p.1 < q.1)

theorem peerCtx {names : Names} {v : State} (h : inv names v = true)
    (lead : v.leadership = .leader) (L0 : v.lastIdx ≠ 0)
    : PeerCtx names v := by
  have peersEq : v.allOtherNodes.map (fun p => names.id p.1)
      = (eligiblePeers (abs names v) (names.id v.nodeId)).sort := by
    have e := ReplUpdateCommit.inv_conjunct h "peers"
    simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at e
    simpa [L0, lead] using e
  have sortedId : v.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1) := by
    have := (eligiblePeers (abs names v) (names.id v.nodeId)).sorted
    rw [← CCF.Finset.sort, ← peersEq, List.pairwise_map] at this
    exact this
  have sortedStr : v.allOtherNodes.Pairwise (fun p q => p.1 < q.1) := by
    have e : ((v.allOtherNodes.zip v.allOtherNodes.tail).all
        fun (x : (Exec.NodeId × Peer) × (Exec.NodeId × Peer)) => decide (x.1.1 < x.2.1)) = true := by
      inv_conj h "peers_sorted"
    exact pairwise_of_zip_tail (r := fun p q : Exec.NodeId × Peer => p.1 < q.1)
      (fun a b => String.lt_trans a b) _ e
  exact ⟨peersEq, sortedId, sortedStr⟩

/-- A clean id is an eligible peer of a leader iff it is the id of one of its peers. -/
theorem PeerCtx.eligible_iff {names : Names} {v : State} (pc : PeerCtx names v)
    {n : NodeID}
    : n ∈ eligiblePeers (abs names v) (names.id v.nodeId)
      <-> exists p, p ∈ v.allOtherNodes /\ names.id p.1 = n := by
  rw [← CCF.Finset.mem_sort, ← pc.peersEq, List.mem_map]

theorem PeerCtx.inj {names : Names} {v : State} (pc : PeerCtx names v)
    {x y : Exec.NodeId × Peer} (hx : x ∈ v.allOtherNodes) (hy : y ∈ v.allOtherNodes)
    (e : names.id x.1 = names.id y.1)
    : x = y :=
  pairwise_inj Nat.lt_irrefl (f := fun p : Exec.NodeId × Peer => names.id p.1) pc.sortedId
    hx hy e

/-- A leader's tracked peers include every eligible peer of an agreeing clean state. -/
theorem tracked_of_eligible {names : Names} {v : State} {st : NodeState}
    (pc : PeerCtx names v) (lead : v.leadership = .leader) (A : Agrees names st v)
    {n : NodeID} (e : n ∈ eligiblePeers st (names.id v.nodeId))
    : n ∈ trackedPeers names v := by
  rw [Ae.eligiblePeers_congr A.log A.commit, pc.eligible_iff] at e
  obtain ⟨p, mem, rfl⟩ := e
  simp only [trackedPeers, lead, beq_self_eq_true, ↓reduceIte, List.mem_map]
  exact ⟨p, mem, rfl⟩

/-- `highestCommittableIndex` of an agreeing clean state, when its eligible peers are tracked. -/
theorem hc_of_agrees {names : Names} {st : NodeState} {d : State} {self : NodeID}
    (A : Agrees names st d)
    (tracked : forall n, n ∈ eligiblePeers st self -> n ∈ trackedPeers names d)
    : highestCommittableIndex st self = highestCommittableIndex (abs names d) self :=
  hc_congr A.log A.commit A.term
    fun n mem ne =>
      A.match_ n
        (tracked n (CCF.Finset.mem_erase.mpr ⟨ne, CCF.Finset.mem_union.mpr (Or.inl mem)⟩))

theorem trackedPeers_putPeer {names : Names} {v w : State} {id : Exec.NodeId} {p : Peer}
    (hw : w.allOtherNodes = putPeer v.allOtherNodes id p)
    (hl : w.leadership = v.leadership)
    : trackedPeers names w = trackedPeers names v := by
  have keys := congrArg (List.map names.id) (putPeer_keys v.allOtherNodes id p)
  simp only [List.map_map] at keys
  simp only [trackedPeers, hw, hl]
  split
  · exact keys
  · rfl

/-- Changing a leader's peer `id` changes its clean indexes at `names.id id` only. -/
theorem agrees_setPeer {names : Names} {clean clean1 : NodeState} {saved : State}
    {id : Exec.NodeId} {nd p : Peer} (A : Agrees names clean saved)
    (pc : PeerCtx names saved) (mem : (id, nd) ∈ saved.allOtherNodes)
    (role : clean1.role = clean.role) (term : clean1.currentTerm = clean.currentTerm)
    (log : clean1.log = clean.log) (commit : clean1.commitIndex = clean.commitIndex)
    (nf : clean1.isNewFollower = clean.isNewFollower)
    (voted : clean1.votedFor = clean.votedFor)
    (known : clean1.primaryKnown = clean.primaryKnown)
    (rci : clean1.retiredCommittedIndex = clean.retiredCommittedIndex)
    (mi
      : clean1.matchIndex = CCF.Function.update clean.matchIndex (names.id id) p.matchIdx)
    (si : clean1.sentIndex = CCF.Function.update clean.sentIndex (names.id id) p.sentIdx)
    : Agrees names clean1 (saved.setPeer id p) := by
  rw [setPeer_eq saved pc.sortedStr mem]
  have inj : forall x, x ∈ saved.allOtherNodes -> names.id x.1 = names.id id -> x.1 = id :=
    fun x hx e => by rw [pc.inj hx mem e]
  have keyMem : id ∈ saved.allOtherNodes.map Prod.fst := List.mem_map.mpr ⟨_, mem, rfl⟩
  obtain ⟨hm, hs⟩ := abs_putPeer (names := names) (v := saved)
    (w := { saved with allOtherNodes := putPeer saved.allOtherNodes id p }) rfl inj keyMem
  have tr := trackedPeers_putPeer (names := names) (v := saved)
    (w := { saved with allOtherNodes := putPeer saved.allOtherNodes id p }) rfl rfl
  refine ⟨role.trans A.role, term.trans A.term, log.trans A.log, commit.trans A.commit,
    ?_, ?_, nf.trans A.newFollower, voted.trans A.voted, known.trans A.known, rci.trans A.rci⟩
  · intro n mem'
    rw [tr] at mem'
    rw [hs, si]
    by_cases e : n = names.id id
    · simp [CCF.Function.update, e]
    · simp only [CCF.Function.update, e, ↓reduceIte]
      exact A.sent n mem'
  · intro n mem'
    rw [tr] at mem'
    rw [hm, mi]
    by_cases e : n = names.id id
    · simp [CCF.Function.update, e]
    · simp only [CCF.Function.update, e, ↓reduceIte]
      exact A.match_ n mem'

/-- A leader with a peer covers every node of its configurations by a peer. -/
theorem cover_of_inv {names : Names} {v : State} (h : inv names v = true)
    (lead : v.leadership = .leader) (L0 : v.lastIdx ≠ 0)
    : Cover v := by
  have hy := Hyps.ofInv h
  have pc := peerCtx h lead L0
  intro id ⟨c, memC, a, ma, ea⟩ ne
  subst ea
  obtain ⟨D, hD, sh⟩ := hy.configs (by omega)
  obtain ⟨x', memD', nodes⟩ := ReplUpdateCommit.shifted_mem sh memC
  have named := hy.membersNamed c memC a ma
  have inAbs : names.id a.1 ∈ (absConfig names x').nodes := by
    simp only [absConfig, Names.set, CCF.Finset.mem_ofList, List.mem_map, nodes]
    exact ⟨a.1, ⟨a, ma, rfl⟩, rfl⟩
  have active : names.id a.1 ∈ (abs names v).activeMembers := by
    show names.id a.1 ∈ configurationMembers (activeConfigurations (abs names v).log v.commitIdx)
    rw [hD]
    exact ReplUpdateCommit.mem_configurationMembers (List.mem_map_of_mem memD') inAbs
  have neId : names.id a.1 ≠ names.id v.nodeId := fun e => ne (named_inj named hy.selfNamed e)
  have elig : names.id a.1 ∈ eligiblePeers (abs names v) (names.id v.nodeId) :=
    CCF.Finset.mem_erase.mpr ⟨neId, CCF.Finset.mem_union.mpr (Or.inl active)⟩
  obtain ⟨p, memP, e⟩ := pc.eligible_iff.mp elig
  exact ⟨p, memP, named_inj (hy.peersNamed p memP) named e⟩

theorem cover_setPeer {v : State} {id : Exec.NodeId} {q p : Peer}
    (sorted : v.allOtherNodes.Pairwise fun a b => a.1 < b.1)
    (mem : (id, q) ∈ v.allOtherNodes) (cover : Cover v)
    : Cover (v.setPeer id p) := by
  rw [setPeer_eq v sorted mem]
  intro n memN ne
  obtain ⟨p', memP, e⟩ := cover n memN ne
  have : n ∈ (putPeer v.allOtherNodes id p).map Prod.fst := by
    rw [putPeer_keys]
    exact List.mem_map.mpr ⟨p', memP, e⟩
  obtain ⟨p'', m, e'⟩ := List.mem_map.mp this
  exact ⟨p'', m, e'⟩

theorem rcRetired_of_inv {names : Names} {v : State} (h : inv names v = true)
    (lead : v.leadership = .leader) (i : Nat)
    : RcRetired v i := by
  have e : (v.leadership != .leader
      || v.rcEntries.all fun (x : Nat × List Exec.NodeId) =>
          x.2.all fun id => id == v.nodeId
            || !(Exec.commit.pop x.1 v.configurations).any (·.nodes.any (·.1 == id))) = true := by
    inv_conj h "rc_entries_retired"
  simp only [lead, bne_self_eq_false, Bool.false_or, List.all_eq_true, Bool.or_eq_true,
    beq_iff_eq, Bool.not_eq_true'] at e
  intro x memX _ id memId ne m
  rcases e x memX id memId with e | e
  · exact ne e
  · obtain ⟨c, memC, a, ma, ea⟩ := m
    have : ((Exec.commit.pop x.1 v.configurations).any fun c => c.nodes.any (·.1 == id)) = true := by
      simp only [List.any_eq_true, beq_iff_eq]
      exact ⟨c, memC, a, ma, ea⟩
    rw [e] at this
    cases this

/-- A leader has not latched its retirement confirmation. -/
theorem leader_rci_none {names : Names} {v : State} (h : inv names v = true)
    (lead : v.leadership = .leader)
    : v.retiredCommittedIdx = none := by
  have notRC : (v.leadership != .leader || !v.isRetiredCommitted) = true := by
    inv_conj h "leader_not_retired_committed"
  have rc : (v.isRetiredCommitted == decide ((abs names v).isRetiredCommitted (names.id v.nodeId)))
      = true := by
    inv_conj h "retired_committed"
  have ret : (v.retiredCommittedIdx.all
      fun j => (retirementIndexInLog (names.id v.nodeId) ((abs names v).log.take j)).isSome) = true := by
    inv_conj h "rci_retired"
  cases e : v.retiredCommittedIdx with
  | none => rfl
  | some j =>
      exfalso
      rw [e] at ret
      simp only [Option.all_some] at ret
      have full := Ae.rii_prefix (List.take_prefix _ _) ret
      have : (abs names v).isRetiredCommitted (names.id v.nodeId) :=
        (Ae.isRetiredCommitted_iff _ _).mpr ⟨full, by simp [abs, e]⟩
      simp only [lead, bne_self_eq_false, Bool.false_or, Bool.not_eq_true'] at notRC
      simp [notRC, this] at rc

/-- Raising the match index of a node of the log's configurations keeps `UnnamedUnmatched`. -/
theorem unmatched_update {node : NodeID} {clean st : NodeState}
    (u : UnnamedUnmatched node clean) (role : st.role = clean.role)
    (log : st.log = clean.log) {src : NodeID}
    (named : src ∈ configurationMembers (configurationHistory clean.log)) {x : Nat}
    (mi : st.matchIndex = CCF.Function.update clean.matchIndex src x)
    : UnnamedUnmatched node st := by
  intro primary n ne notMem
  rw [log] at notMem
  have : n ≠ src := fun e => notMem (e ▸ named)
  rw [mi]
  simp only [CCF.Function.update, this, ↓reduceIte]
  exact u (role ▸ primary) n ne notMem

theorem localRun_of {env : Env} {node source : NodeID} {clean clean' : NodeState}
    {r : AppendEntriesResponse} {out : CCF.Outputs NodeID Message Notification}
    (h : cleanRun node source clean r = some (clean', out))
    : CCF.Sections.LocalRun (protocol env) node clean
        (cleanActions env (some (source, .appendEntriesResponse r)) []) clean'
        out.outgoing := by
  have := CCF.Sections.LocalRun.cons (protocol := protocol env) (node := node) (state := clean)
    (middle := clean') (action := (protocol env).receive source (.appendEntriesResponse r))
    (effects := out) h (CCF.Sections.LocalRun.nil _)
  simpa [cleanActions] using this

end Consensus.TraceValidation.Proofs.AeResp
