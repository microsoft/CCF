module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickViews
public import Consensus.TraceValidation.Proofs.Handlers.TickRun

@[expose] public section

/-!
# A leader's heartbeat, one range at a time (not reviewed; `Tick` obligation)

During a heartbeat the declared state only changes in its peers' send indexes, and the
clean state only in `sentIndex`. `HbRel` relates the two throughout; `hb_step` shows that
one `send_append_entries_range` of the heartbeat is the clean `sendEntries` to that peer and
range, keeps `HbRel`, and sends an envelope satisfying `msgInv`.
-/

namespace Consensus.TraceValidation.Proofs.Tick

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv msgInv)
open ReplUpdateCommit (Named named_inj)

/-! ## Peer lists -/

theorem lookup_iff_mem {l : List (NodeId × Peer)} (nd : (l.map Prod.fst).Nodup)
    {k : NodeId} {p : Peer}
    : l.lookup k = some p <-> (k, p) ∈ l := by
  induction l with
  | nil => simp
  | cons q l ih =>
      obtain ⟨k', p'⟩ := q
      simp only [List.map_cons, List.nodup_cons] at nd
      by_cases e : k = k'
      · subst e
        simp only [List.lookup_cons_self, Option.some.injEq, List.mem_cons, Prod.mk.injEq,
          true_and]
        constructor
        · intro h
          exact Or.inl h.symm
        · rintro (h | h)
          · exact h.symm
          · exact absurd (List.mem_map_of_mem (f := Prod.fst) h) nd.1
      · have ne : (k == k') = false := by simpa using e
        simp only [List.lookup_cons, ne, List.mem_cons, Prod.mk.injEq, e, false_and, false_or]
        exact ih nd.2

theorem mem_setPeer {v : State} {id k : NodeId} {p q : Peer}
    : (k, q) ∈ (v.setPeer id p).allOtherNodes
      <-> (k = id /\ q = p) \/ (k ≠ id /\ (k, q) ∈ v.allOtherNodes) := by
  simp only [State.setPeer, List.mem_mergeSort, List.mem_append, List.mem_filter,
    List.mem_singleton, Prod.mk.injEq, bne_iff_ne, ne_eq]
  constructor
  · rintro (⟨m, n⟩ | h)
    · exact Or.inr ⟨n, m⟩
    · exact Or.inl h
  · rintro (h | ⟨n, m⟩)
    · exact Or.inr h
    · exact Or.inl ⟨m, n⟩

theorem setPeer_nodup {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup)
    (id : NodeId) (p : Peer)
    : ((v.setPeer id p).allOtherNodes.map Prod.fst).Nodup := by
  simp only [State.setPeer]
  refine (((List.mergeSort_perm _ _).map Prod.fst).nodup_iff).mpr ?_
  rw [List.map_append, List.nodup_append]
  refine ⟨((List.filter_sublist).map Prod.fst).nodup nd, by simp, ?_⟩
  intro a ha b hb
  simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
  subst hb
  obtain ⟨x, mem, rfl⟩ := List.mem_map.mp ha
  have := (List.mem_filter.mp mem).2
  simpa using this

theorem setPeer_lookup {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup)
    (id k : NodeId) (p : Peer)
    : (v.setPeer id p).peer? k = if k = id then some p else v.peer? k := by
  have nd' := setPeer_nodup nd id p
  unfold State.peer?
  split
  · rename_i e
    rw [lookup_iff_mem nd', mem_setPeer]
    exact Or.inl ⟨e, rfl⟩
  · rename_i e
    apply Option.ext
    intro q
    rw [lookup_iff_mem nd', lookup_iff_mem nd, mem_setPeer]
    constructor
    · rintro (⟨h, -⟩ | ⟨-, h⟩)
      · exact absurd h e
      · exact h
    · intro h
      exact Or.inr ⟨e, h⟩

theorem mem_keys {l : List (NodeId × Peer)} {k : NodeId}
    : k ∈ l.map Prod.fst <-> exists q, (k, q) ∈ l := by
  simp

theorem setPeer_perm {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup) {id : NodeId}
    {p0 : Peer} (found : v.peer? id = some p0) (p : Peer)
    : ((v.setPeer id p).allOtherNodes.map Prod.fst).Perm
        (v.allOtherNodes.map Prod.fst) := by
  refine (List.perm_ext_iff_of_nodup (setPeer_nodup nd id p) nd).mpr fun k => ?_
  rw [mem_keys, mem_keys]
  constructor
  · rintro ⟨q, mem⟩
    rcases mem_setPeer.mp mem with ⟨rfl, -⟩ | ⟨-, mem⟩
    · exact ⟨p0, (lookup_iff_mem nd).mp found⟩
    · exact ⟨q, mem⟩
  · rintro ⟨q, mem⟩
    by_cases e : k = id
    · exact ⟨p, mem_setPeer.mpr (Or.inl ⟨e, rfl⟩)⟩
    · exact ⟨q, mem_setPeer.mpr (Or.inr ⟨e, mem⟩)⟩

/-! ## Clean and abstract peer indexes -/

/-- The clean send index of a peer is its declared one. -/
theorem abs_sentIndex {names : Names} {v : State}
    (peersNamed : forall p, p ∈ v.allOtherNodes -> Named names p.1) {id : NodeId}
    (named : Named names id) {p : Peer} (found : v.peer? id = some p)
    : (abs names v).sentIndex (names.id id) = p.sentIdx := by
  simp only [abs]
  unfold State.peer? at found
  generalize v.allOtherNodes = l at peersNamed found
  induction l with
  | nil => simp at found
  | cons q l ih =>
      obtain ⟨k, pk⟩ := q
      by_cases same : id = k
      · subst same
        simp only [List.lookup_cons, beq_self_eq_true, Option.some.injEq] at found
        subst found
        simp
      · have ne : (names.id k == names.id id) = false := by
          simp only [beq_eq_false_iff_ne]
          intro eq
          exact same (named_inj named (peersNamed (k, pk) (by simp)) eq.symm)
        have ne' : (id == k) = false := by simpa using same
        simp only [List.lookup_cons, ne'] at found
        simp only [List.find?_cons, ne]
        exact ih (fun p mem => peersNamed p (List.mem_cons_of_mem _ mem)) found

/-- A clean state that agrees with `d` is `abs d` but for the peer indexes and votes. -/
theorem agrees_eq {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : c
      = {
        abs names d with
          sentIndex := c.sentIndex,
          matchIndex := c.matchIndex,
          votesGranted := c.votesGranted,
          preVotesGranted := c.preVotesGranted
      } := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, -⟩, h6⟩, h7⟩, h8⟩, -⟩, -⟩, h11⟩ := h
  cases c
  simp only at h1 h2 h3 h4 h6 h7 h8 h11 ⊢
  rw [h1, h2, h3, h4, h6, h7, h8, h11]

/-! ## The heartbeat relation -/

/-- What a heartbeat needs of the leader it starts from. -/
structure HbHyps (names : Names) (node : NodeID) (s0 : State) (clean0 : NodeState)
    : Prop where
  inv : inv names s0 = true
  agrees : agrees names clean0 s0 = true
  self : names.id s0.nodeId = node
  leader : s0.leadership = .leader
  notRC : s0.isRetiredCommitted = false
  nodup : (s0.allOtherNodes.map Prod.fst).Nodup
  eligible
    : forall k,
        k ∈ s0.allOtherNodes.map Prod.fst -> names.id k ∈ eligiblePeers clean0 node
  bounds : forall k p, (k, p) ∈ s0.allOtherNodes -> p.sentIdx <= s0.lastIdx

theorem HbHyps.ofInv {names : Names} {node : NodeID} {s0 : State} {clean0 : NodeState}
    (invS : Consensus.TraceValidation.inv names s0 = true)
    (ag : Consensus.TraceValidation.agrees names clean0 s0 = true)
    (self : names.id s0.nodeId = node) (leader : s0.leadership = .leader)
    : HbHyps names node s0 clean0 := by
  have notRC : (s0.leadership != .leader || !s0.isRetiredCommitted) = true := by
    inv_conj invS "leader_not_retired_committed"
  have bounds : (s0.leadership != .leader
      || s0.allOtherNodes.all fun (_, p) => p.sentIdx <= s0.lastIdx && p.matchIdx <= s0.lastIdx)
      = true := by
    inv_conj invS "peer_bounds"
  simp only [leader, bne_self_eq_false, Bool.false_or, Bool.not_eq_true'] at notRC
  simp only [leader, bne_self_eq_false, Bool.false_or, List.all_eq_true, Bool.and_eq_true,
    decide_eq_true_eq] at bounds
  have peers : forall k, k ∈ s0.allOtherNodes.map Prod.fst
      -> (s0.allOtherNodes.map Prod.fst).Nodup /\ names.id k ∈ eligiblePeers clean0 node := by
    intro k mem
    by_cases z : s0.lastIdx = 0
    · have alone : (s0.lastIdx != 0 || s0.leadership != .leader || s0.allOtherNodes.isEmpty)
          = true := by
        inv_conj invS "empty_leader_alone"
      simp only [z, leader, bne_self_eq_false, Bool.false_or, List.isEmpty_iff] at alone
      simp [alone] at mem
    · have hp : (s0.lastIdx == 0 || s0.leadership == .none
          || s0.allOtherNodes.map (fun (id, _) => names.id id)
            == (eligiblePeers (abs names s0) (names.id s0.nodeId)).sort) = true := by
        inv_conj invS "peers"
      simp only [z, leader, beq_iff_eq, Bool.or_eq_true, reduceCtorEq, false_or] at hp
      have ceq := agrees_eq ag
      have congr : eligiblePeers clean0 node = eligiblePeers (abs names s0) (names.id s0.nodeId) := by
        rw [self]
        exact Ae.eligiblePeers_congr (by rw [ceq]) (by rw [ceq]) node
      have mapEq : (s0.allOtherNodes.map Prod.fst).map names.id
          = (eligiblePeers (abs names s0) (names.id s0.nodeId)).sort := by
        rw [← hp, List.map_map]
        rfl
      refine ⟨List.Pairwise.of_map (S := fun x y : NodeID => x ≠ y) names.id
        (fun a b h e => h (e ▸ rfl)) ?_, ?_⟩
      · rw [mapEq]
        exact CCF.Finset.nodup_of_sorted (eligiblePeers _ _).sorted
      · rw [congr, ← CCF.Finset.mem_sort, ← mapEq]
        exact List.mem_map_of_mem mem
  refine ⟨invS, ag, self, leader, notRC, ?_, fun k mem => (peers k mem).2,
    fun k p mem => (bounds _ mem).1⟩
  cases h : s0.allOtherNodes with
  | nil => simp
  | cons q l =>
      exact h ▸ (peers q.1 (by simp [h])).1

/--
The clean state and the declared state during a heartbeat from `clean0` and `s0`: only the
declared peers and the clean send indexes change, the peers keep their keys and match
indexes, and every peer's clean send index is its declared one, within the ledger.
-/
def HbRel (names : Names) (s0 : State) (clean0 : NodeState) (clean : NodeState)
    (v : State)
    : Prop :=
  exists (L : List (NodeId × Peer)) (f : NodeID -> Nat),
    v = { s0 with allOtherNodes := L }
    /\ clean = { clean0 with sentIndex := f }
    /\ (L.map Prod.fst).Perm (s0.allOtherNodes.map Prod.fst)
    /\ forall k p,
        L.lookup k = some p
        -> (exists p0, s0.peer? k = some p0 /\ p0.matchIdx = p.matchIdx)
            /\ f (names.id k) = p.sentIdx
            /\ p.sentIdx <= s0.lastIdx

variable {names : Names} {node : NodeID} {s0 : State} {clean0 : NodeState}

theorem HbRel.start (H : HbHyps names node s0 clean0)
    : HbRel names s0 clean0 clean0 s0 := by
  have hy := ReplUpdateCommit.Hyps.ofInv H.inv
  refine ⟨
    s0.allOtherNodes,
    clean0.sentIndex,
    rfl,
    rfl,
    List.Perm.refl _,
    fun k p found => ?_
  ⟩
  have mem := (lookup_iff_mem H.nodup).mp found
  refine ⟨⟨p, found, rfl⟩, ?_, H.bounds k p mem⟩
  have named := hy.peersNamed _ mem
  rw [← abs_sentIndex hy.peersNamed named found]
  have ag := H.agrees
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at ag
  have tracked : names.id k ∈ Consensus.TraceValidation.trackedPeers names s0 := by
    simp only [Consensus.TraceValidation.trackedPeers, H.leader]
    simp only [beq_self_eq_true, ite_true, List.mem_map]
    exact ⟨(k, p), mem, rfl⟩
  exact (ag.1.1.1.1.1.1.2 _ tracked).1

/-! ## One range of the heartbeat -/

theorem messageEntries_abs (size : s0.ledger.size = s0.lastIdx) (prev endIdx : Nat)
    (eL : endIdx <= s0.lastIdx)
    : messageEntries (abs names s0).log prev endIdx
      = (List.range' (prev + 1) (endIdx - prev)).map
          fun i => absEntry names s0.ledger[i - 1]! := by
  unfold messageEntries
  apply List.ext_getElem
  · simp [abs, size]
    omega
  · intro j h1 h2
    simp only [List.length_map, List.length_range'] at h2
    simp only [abs, List.getElem_take, List.getElem_drop, List.getElem_map,
      List.getElem_range', Array.getElem_toList]
    congr 1
    have lt : prev + 1 + j - 1 < s0.ledger.size := by rw [size]; omega
    rw [Nat.one_mul, getElem!_pos s0.ledger _ lt]
    congr 1
    omega

/-- The AppendEntries of `send_append_entries_range` from `start` to `endIdx`. -/
def aeOf (names : Names) (v : State) (start endIdx : Nat) : AppendEntriesRequest :=
  {
    term := v.currentView,
    prevLogIndex := start - 1,
    prevLogTerm := v.getTerm (start - 1),
    entries :=
      (List.range' start (endIdx + 1 - start)).map
        fun i => absEntry names v.ledger[i - 1]!,
    primaryCommit := v.commitIdx
  }

theorem names_set_round_trip {l : List NodeId} (named : forall x, x ∈ l -> Named names x)
    : forall i, i ∈ names.set l -> names.id (names.name i) = i := by
  intro i mem
  simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map] at mem
  obtain ⟨x, mem, rfl⟩ := mem
  rw [named x mem]

/-- The entries of a range in one view. -/
theorem hb_entry {v : State} (vh : ViewHyps v) {prev endIdx : Nat}
    (eL : endIdx <= v.lastIdx)
    (same : forall i, prev < i -> i <= endIdx -> v.viewAt i = v.viewAt endIdx)
    : forall i,
        prev + 1 <= i
        -> i <= endIdx
        -> v.ledger[i - 1]! ∈ v.ledger.toList
            /\ v.ledger[i - 1]!.term = v.viewAt endIdx := by
  intro i i1 iE
  have lt : i - 1 < v.ledger.size := by rw [vh.size]; omega
  rw [getElem!_pos v.ledger _ lt]
  refine ⟨by simp, ?_⟩
  have t := vh.terms i (by omega) (by omega)
  rw [Array.getElem?_eq_getElem lt] at t
  simp only [Option.map_some, Option.some.injEq] at t
  rw [t]
  exact same i (by omega) iE

theorem msgInv_hb (H : HbHyps names node s0 clean0) {to : NodeId}
    (elig : names.id to ∈ eligiblePeers clean0 node) {prev endIdx : Nat}
    (pL : prev <= s0.lastIdx) (e1 : prev <= endIdx) (eL : endIdx <= s0.lastIdx)
    (same : forall i, prev < i -> i <= endIdx -> s0.viewAt i = s0.viewAt endIdx)
    : msgInv names
        ⟨
          names.id s0.nodeId,
          names.id to,
          .appendEntriesRequest (aeOf names s0 (prev + 1) endIdx)
        ⟩
      = true := by
  have hy := ReplUpdateCommit.Hyps.ofInv H.inv
  have vh := ViewHyps.ofInv H.inv
  have ledgerNamed : s0.ledger.all
      (fun e => ((e.config.getD []).map Prod.fst ++ e.retired).all
        fun id => names.name (names.id id) == id) = true := by
    inv_conj H.inv "ledger_names_round_trip"
  have ne : node ≠ names.id to := by
    intro e
    unfold eligiblePeers at elig
    rw [← e, CCF.Finset.mem_erase] at elig
    exact elig.1 rfl
  have entry := hb_entry vh eL same
  unfold msgInv aeOf
  simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, List.all_eq_true, List.mem_map,
    List.mem_range'_1, forall_exists_index, and_imp, decide_eq_true_eq, Bool.or_eq_true]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_, ?_⟩, ?_⟩
  · rw [hy.selfNamed]
  · rw [H.self]
    exact ne
  · intro x i i1 iE xe y mem
    subst xe
    obtain ⟨inLedger, -⟩ := entry i i1 (by omega)
    have all := (Array.all_eq_true_iff_forall_mem.mp ledgerNamed) _ (by simpa using inLedger)
    simp only [List.all_eq_true, beq_iff_eq, List.mem_append] at all
    simp only [absEntry] at mem
    split at mem
    · simp [EntryContent.metadata, CCF.Finset.notMem_empty] at mem
    · simp only [EntryContent.metadata, List.mem_append, CCF.Finset.mem_sort] at mem
      rcases mem with mem | mem
      · cases hc : s0.ledger[i - 1]!.config with
        | none => simp [hc] at mem
        | some ns =>
            simp only [hc, Option.map_some, Option.getD_some, CCF.Finset.mem_sort] at mem
            exact names_set_round_trip (fun x m => all x (Or.inl (by simpa [hc] using m)))
              y mem
      · exact names_set_round_trip (fun x m => all x (Or.inr m)) y mem
  · intro x i i1 iE xe
    subst xe
    obtain ⟨inLedger, term⟩ := entry i i1 (by omega)
    have pos := (Array.all_eq_true_iff_forall_mem.mp
      (by inv_conj H.inv "positive_terms" : s0.ledger.all (0 < ·.term) = true)) _
      (by simpa using inLedger)
    simp only [decide_eq_true_eq] at pos
    have last : endIdx + 1 - (prev + 1) = (endIdx - prev - 1) + 1 := by omega
    refine ⟨⟨?_, ?_⟩, ?_⟩
    · rw [last, List.range'_1_concat, List.map_append, List.getLast?_append]
      simp only [List.map_cons, List.map_nil, List.getLast?_singleton, Option.some_or,
        Option.map_some, absEntry, Option.some.injEq]
      rw [term, (entry _ (by omega) (by omega)).2]
    · simpa [absEntry] using pos
    · simp only [absEntry]
      rw [term]
      exact Nat.le_trans (ReplUpdateCommit.viewAt_le_size _ _) hy.viewsBounded
  · rcases Nat.eq_zero_or_pos prev with z | z
    · exact Or.inl (by simp [z])
    · refine Or.inr ?_
      simp only [Nat.add_sub_cancel, State.getTerm]
      split
      · omega
      · exact viewAt_pos vh z pL
  · intro x i _ _ xe
    subst xe
    simp only [absEntry]
    split
    · rename_i h
      split at h <;> simp_all
    · rfl

/--
One range of the heartbeat to the peer `to` is the clean `sendEntries` to it, keeps `HbRel`,
and sends an envelope satisfying `msgInv`.
-/
theorem hb_step (H : HbHyps names node s0 clean0) {clean : NodeState} {v : State}
    (R : HbRel names s0 clean0 clean v) {to : NodeId} {p : Peer}
    (found : v.peer? to = some p) {endIdx : Nat} (e1 : p.sentIdx <= endIdx)
    (eL : endIdx <= s0.lastIdx)
    (same : forall i, p.sentIdx < i -> i <= endIdx -> s0.viewAt i = s0.viewAt endIdx)
    : Emits
        (act (CCF.Capabilities.record node) node clean
          (.sendEntries (names.id to) endIdx))
        {
          clean with
            sentIndex := CCF.Function.update clean.sentIndex (names.id to) endIdx
        }
        [⟨node, names.id to, .appendEntriesRequest (aeOf names v (p.sentIdx + 1) endIdx)⟩]
      /\ HbRel names s0 clean0
          {
            clean with
              sentIndex := CCF.Function.update clean.sentIndex (names.id to) endIdx
          }
          (v.setPeer to { p with sentIdx := endIdx })
      /\ msgInv names
            ⟨
              names.id v.nodeId,
              names.id to,
              .appendEntriesRequest (aeOf names v (p.sentIdx + 1) endIdx)
            ⟩
          = true := by
  obtain ⟨L, f, rfl, rfl, perm, rel⟩ := R
  have hy := ReplUpdateCommit.Hyps.ofInv H.inv
  have vh := ViewHyps.ofInv H.inv
  have lfound : L.lookup to = some p := found
  obtain ⟨⟨p0, found0, match0⟩, fto, pL⟩ := rel to p lfound
  have ndL : (L.map Prod.fst).Nodup := perm.nodup_iff.mpr H.nodup
  have key0 : to ∈ s0.allOtherNodes.map Prod.fst :=
    perm.mem_iff.mp (mem_keys.mpr ⟨p, (lookup_iff_mem ndL).mp lfound⟩)
  have elig := H.eligible to key0
  have ceq := agrees_eq H.agrees
  have hlog : clean0.log = (abs names s0).log := by rw [ceq]
  have hrole : clean0.role = .primary := by rw [ceq]; simp [abs, H.leader, absRole]
  have hterm : clean0.currentTerm = s0.currentView := by rw [ceq]; simp [abs]
  have hcommit : clean0.commitIndex = s0.commitIdx := by rw [ceq]; simp [abs]
  have hrc : Not (clean0.isRetiredCommitted node) := by
    have rc : s0.isRetiredCommitted
        = decide ((abs names s0).isRetiredCommitted (names.id s0.nodeId)) := by
      inv_conj H.inv "retired_committed"
    rw [H.notRC, H.self] at rc
    have : Not ((abs names s0).isRetiredCommitted node) := by simpa using rc
    rw [ceq]
    exact this
  have entry := hb_entry vh eL same
  have endTerm : termAt (abs names s0).log endIdx = s0.viewAt endIdx := by
    rw [← Ae.getTerm_eq H.inv]
    unfold State.getTerm
    split
    · omega
    · rfl
  have entries : messageEntries (abs names s0).log p.sentIdx endIdx
      = (List.range' (p.sentIdx + 1) (endIdx + 1 - (p.sentIdx + 1))).map
          fun i => absEntry names s0.ledger[i - 1]! := by
    rw [messageEntries_abs vh.size _ _ eL]
    congr 2
    omega
  refine ⟨?_, ?_, ?_⟩
  · have msg : makeAppendEntriesRequest { clean0 with sentIndex := f } (names.id to) endIdx
        = aeOf names s0 (p.sentIdx + 1) endIdx := by
      simp only [makeAppendEntriesRequest, aeOf, fto, hlog, hterm, hcommit, entries,
        Nat.add_sub_cancel, Ae.getTerm_eq H.inv]
    unfold act sendEntries
    refine emits_congr
      (emits_bind (emits_guard ?_) (emits_bind (emits_send _ _) (emits_pure _))) rfl ?_
    · refine ⟨hrole, elig, by simp [fto, e1], ?_, ?_, Or.inl hrc⟩
      · show endIdx <= clean0.log.length
        rw [hlog, ReplUpdateCommit.abs_log_length vh.size]
        exact eL
      · show ((messageEntries clean0.log (f (names.id to)) endIdx).all
          fun entry => entry.term == termAt clean0.log endIdx) = true
        rw [hlog, fto, entries, endTerm]
        simp only [List.all_eq_true, List.mem_map, List.mem_range'_1, beq_iff_eq,
          forall_exists_index, and_imp]
        intro x i i1 iE xe
        subst xe
        simp only [absEntry]
        exact (entry i i1 (by omega)).2
    · simp only [List.nil_append, List.append_nil]
      rw [msg]
      rfl
  · refine ⟨(({ s0 with allOtherNodes := L } : State).setPeer to
        { p with sentIdx := endIdx }).allOtherNodes,
      CCF.Function.update f (names.id to) endIdx, rfl, rfl,
      (setPeer_perm ndL found _).trans perm, fun k q lk => ?_⟩
    have h2 : (({ s0 with allOtherNodes := L } : State).setPeer to
        { p with sentIdx := endIdx }).peer? k = some q := lk
    rw [setPeer_lookup ndL] at h2
    split at h2
    · rename_i e
      subst e
      simp only [Option.some.injEq] at h2
      subst h2
      exact ⟨⟨p0, found0, match0⟩, by simp [CCF.Function.update], eL⟩
    · rename_i e
      obtain ⟨m, fk, qL⟩ := rel k q h2
      have keyk : k ∈ s0.allOtherNodes.map Prod.fst :=
        perm.mem_iff.mp (mem_keys.mpr ⟨q, (lookup_iff_mem ndL).mp h2⟩)
      obtain ⟨qk, memk⟩ := mem_keys.mp keyk
      obtain ⟨qt, memt⟩ := mem_keys.mp key0
      have ne : names.id k ≠ names.id to := fun eq =>
        e (named_inj (hy.peersNamed _ memk) (hy.peersNamed _ memt) eq)
      refine ⟨m, ?_, qL⟩
      simp only [CCF.Function.update, ne, ↓reduceIte]
      exact fk
  · exact msgInv_hb H elig pL e1 eL same

/-- At the end of a heartbeat the clean state agrees with the declared one. -/
theorem HbRel.finish (H : HbHyps names node s0 clean0) {clean : NodeState} {v : State}
    (R : HbRel names s0 clean0 clean v)
    : agrees names clean v = true
      /\ (UnnamedUnmatched node clean0 -> UnnamedUnmatched node clean) := by
  obtain ⟨L, f, rfl, rfl, perm, rel⟩ := R
  refine ⟨?_, fun um => um⟩
  have hy := ReplUpdateCommit.Hyps.ofInv H.inv
  have ndL : (L.map Prod.fst).Nodup := perm.nodup_iff.mpr H.nodup
  have namedL : forall k, k ∈ L.map Prod.fst -> Named names k := by
    intro k mem
    obtain ⟨q, mem⟩ := mem_keys.mp (perm.mem_iff.mp mem)
    exact hy.peersNamed _ mem
  have ag := H.agrees
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at ag ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨a1, a2⟩, a3⟩, a4⟩, a5⟩, a6⟩, a7⟩, a8⟩, a9⟩, a10⟩, a11⟩ := ag
  refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨a1, a2⟩, a3⟩, a4⟩, ?_⟩, a6⟩, a7⟩, a8⟩, a9⟩, a10⟩, a11⟩
  intro n mem
  simp only [Consensus.TraceValidation.trackedPeers, H.leader, beq_self_eq_true, ite_true,
    List.mem_map] at mem
  obtain ⟨⟨k, q⟩, memL, rfl⟩ := mem
  have lk : L.lookup k = some q := (lookup_iff_mem ndL).mpr memL
  obtain ⟨⟨p0, f0, m0⟩, fk, -⟩ := rel k q lk
  have named := namedL k (mem_keys.mpr ⟨q, memL⟩)
  have peersNamedV : forall p, p ∈ L -> Named names p.1 :=
    fun p mem => namedL p.1 (List.mem_map_of_mem mem)
  have tracked : names.id k ∈ Consensus.TraceValidation.trackedPeers names s0 := by
    simp only [Consensus.TraceValidation.trackedPeers, H.leader, beq_self_eq_true, ite_true,
      List.mem_map]
    exact ⟨(k, p0), (lookup_iff_mem H.nodup).mp f0, rfl⟩
  have m := (a5 _ tracked).2
  rw [ReplUpdateCommit.abs_matchIndex hy.peersNamed named f0] at m
  refine ⟨?_, ?_⟩
  · show f (names.id k) = (abs names { s0 with allOtherNodes := L }).sentIndex (names.id k)
    rw [abs_sentIndex (v := { s0 with allOtherNodes := L }) peersNamedV named lk]
    exact fk
  · show clean0.matchIndex (names.id k)
      = (abs names { s0 with allOtherNodes := L }).matchIndex (names.id k)
    rw [ReplUpdateCommit.abs_matchIndex (v := { s0 with allOtherNodes := L }) peersNamedV named
      lk, m, m0]

end Consensus.TraceValidation.Proofs.Tick
