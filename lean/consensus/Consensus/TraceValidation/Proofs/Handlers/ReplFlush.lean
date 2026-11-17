module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplMid
public import Consensus.TraceValidation.Proofs.Handlers.ReplEmits

@[expose] public section

/-!
# One `send_append_entries_range` in a batch (not reviewed; `Replicate` obligation)

A range sent during a batch (a flush, or a new peer's heartbeat) is the clean `sendEntries`
to that peer and range from the batch's clean state, keeps `Mid`, and sends an envelope
satisfying `msgInv` (after the `Tick` proof's `hb_step` and `msgInv_hb`, with `Mid`'s facts
in place of `inv`).
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees trackedPeers inv msgInv UnnamedUnmatched)
open Consensus.TraceValidation.Proofs.Ae
open ReplUpdateCommit (Named named_inj Hyps)

variable {names : Names} {node : NodeID} {v0 : State} {cl0 : NodeState}

theorem viewAt_zero_vh {v : State} (vh : ViewHyps v) : v.viewAt 0 = 0 := by
  simp only [State.viewAt, List.length_eq_zero_iff, List.filter_eq_nil_iff]
  intro x hx
  have := vh.positive x hx
  simp only [Nat.le_zero, decide_eq_true_eq]
  omega

theorem getTerm_vh {v : State} (vh : ViewHyps v) (i : Nat)
    : v.getTerm i = termAt (abs names v).log i := by
  rw [termAt_abs vh.size]
  unfold State.getTerm
  by_cases hi : i = 0
  · subst hi; simp [viewAt_zero_vh vh]
  · by_cases hl : i > v.lastIdx
    · have : v.ledger[i - 1]? = none := by simp [vh.size]; omega
      simp [hl, hi, this]
    · simp only [hl, hi, ite_false]
      rw [vh.terms i (by omega) (by omega)]; rfl

theorem messageEntries_abs {v : State} (size : v.ledger.size = v.lastIdx)
    (prev endIdx : Nat) (eL : endIdx <= v.lastIdx)
    : messageEntries (abs names v).log prev endIdx
      = (List.range' (prev + 1) (endIdx - prev)).map
          fun i => absEntry names v.ledger[i - 1]! := by
  unfold messageEntries
  apply List.ext_getElem
  · simp [abs, size]
    omega
  · intro j h1 h2
    simp only [List.length_map, List.length_range'] at h2
    simp only [abs, List.getElem_take, List.getElem_drop, List.getElem_map,
      List.getElem_range', Array.getElem_toList]
    congr 1
    have lt : prev + 1 + j - 1 < v.ledger.size := by rw [size]; omega
    rw [Nat.one_mul, getElem!_pos v.ledger _ lt]
    congr 1
    omega

theorem names_set_round_trip {l : List NodeId} (named : forall x, x ∈ l -> Named names x)
    : forall i, i ∈ names.set l -> names.id (names.name i) = i := by
  intro i mem
  simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map] at mem
  obtain ⟨x, mem, rfl⟩ := mem
  rw [named x mem]

/-- The entries of a range in one view. -/
theorem range_entry {v : State} (vh : ViewHyps v) {prev endIdx : Nat}
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

theorem Mid.self (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : names.id v.nodeId = node := by
  rw [M.frame.nodeId, S.self]

theorem Mid.leader (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : v.leadership = .leader :=
  M.frame.leadership.trans S.leader

theorem msgInv_range (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v) {to : NodeId} (ne : node ≠ names.id to)
    {prev endIdx : Nat} (pL : prev <= v.lastIdx) (e1 : prev <= endIdx)
    (eL : endIdx <= v.lastIdx)
    (same : forall i, prev < i -> i <= endIdx -> v.viewAt i = v.viewAt endIdx)
    : msgInv names
        ⟨
          node,
          names.id to,
          .appendEntriesRequest (rangeRequest names v (prev + 1) endIdx)
        ⟩
      = true := by
  have hy := M.hy
  have vh := M.vh
  have entry := range_entry vh eL same
  unfold msgInv rangeRequest
  simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, List.all_eq_true, List.mem_map,
    List.mem_range'_1, forall_exists_index, and_imp, decide_eq_true_eq, Bool.or_eq_true]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_, ?_⟩, ?_⟩
  · rw [← M.self S, hy.selfNamed]
  · exact ne
  · intro x i i1 iE xe y mem
    subst xe
    obtain ⟨inLedger, -⟩ := entry i i1 (by omega)
    have all := M.ledgerNamed _ inLedger
    simp only [absEntry] at mem
    split at mem
    · simp [EntryContent.metadata, CCF.Finset.notMem_empty] at mem
    · simp only [EntryContent.metadata, List.mem_append, CCF.Finset.mem_sort] at mem
      rcases mem with mem | mem
      · cases hc : v.ledger[i - 1]!.config with
        | none => simp [hc] at mem
        | some ns =>
            simp only [hc, Option.map_some, Option.getD_some, CCF.Finset.mem_sort] at mem
            exact names_set_round_trip
              (fun x m => all x (List.mem_append_left _ (by simpa [hc] using m))) y mem
      · exact names_set_round_trip (fun x m => all x (List.mem_append_right _ m)) y mem
  · intro x i i1 iE xe
    subst xe
    obtain ⟨inLedger, term⟩ := entry i i1 (by omega)
    have pos := vh.posTerms _ inLedger
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

/-- `Hyps` does not read the peers but for their names. -/
theorem hyps_withPeers {v : State} (h : Hyps names v) {L : List (NodeId × Peer)}
    (named : forall p, p ∈ L -> Named names p.1)
    : Hyps names { v with allOtherNodes := L } :=
  ⟨
    h.size,
    h.commitLe,
    h.committable,
    h.terms,
    h.viewsBounded,
    h.configs,
    h.selfNamed,
    named,
    h.membersNamed,
    h.distinct
  ⟩

theorem viewHyps_withPeers {v : State} (h : ViewHyps v) (L : List (NodeId × Peer))
    : ViewHyps { v with allOtherNodes := L } :=
  ⟨h.size, h.sorted, h.positive, h.leLast, h.terms, h.posTerms⟩

theorem setPeer_eq (v : State) (id : NodeId) (p : Peer)
    : v.setPeer id p = { v with allOtherNodes := (v.setPeer id p).allOtherNodes } :=
  rfl

/--
One range to the peer `to` during the batch is the clean `sendEntries` to it, keeps `Mid`,
and sends an envelope satisfying `msgInv`.
-/
theorem range_step (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v) {to : NodeId} {p : Peer}
    (found : v.peer? to = some p) {endIdx : Nat} (e1 : p.sentIdx <= endIdx)
    (eL : endIdx <= v.lastIdx)
    (same : forall i, p.sentIdx < i -> i <= endIdx -> v.viewAt i = v.viewAt endIdx)
    : Emits (sendEntries (CCF.Capabilities.record node) node cl (names.id to) endIdx)
        { cl with sentIndex := CCF.Function.update cl.sentIndex (names.id to) endIdx }
        [⟨
          node,
          names.id to,
          .appendEntriesRequest (rangeRequest names v (p.sentIdx + 1) endIdx)
        ⟩]
      /\ Mid names node v0 cl0
          { cl with sentIndex := CCF.Function.update cl.sentIndex (names.id to) endIdx }
          (v.setPeer to { p with sentIdx := endIdx })
      /\ msgInv names
            ⟨
              node,
              names.id to,
              .appendEntriesRequest (rangeRequest names v (p.sentIdx + 1) endIdx)
            ⟩
          = true := by
  obtain ⟨f, rfl, P⟩ := M.clean
  have hy := M.hy
  have vh := M.vh
  obtain ⟨fto, pL, -⟩ := P.rel to p found
  have key : to ∈ v.allOtherNodes.map Prod.fst :=
    mem_keys.mpr ⟨p, (lookup_iff_mem P.nodup).mp found⟩
  have elig : names.id to ∈ eligiblePeers { cl0 with log := (abs names v).log, sentIndex := f }
      node := (M.eligible _).mpr ⟨to, key, rfl⟩
  have ne : node ≠ names.id to := by
    intro e
    unfold eligiblePeers at elig
    rw [← e, CCF.Finset.mem_erase] at elig
    exact elig.1 rfl
  have hrole : cl0.role = .primary := S.role
  have hterm : cl0.currentTerm = v.currentView := by
    rw [M.frame.view, S.cleanEq]; rfl
  have hcommit : cl0.commitIndex = v.commitIdx := by rw [M.frame.commit, S.commit]
  have hrc : Not (({ cl0 with log := (abs names v).log, sentIndex := f } : NodeState).isRetiredCommitted
      node) := not_rc_of_rci (c := { cl0 with log := (abs names v).log, sentIndex := f }) S.cleanRci node
  have entry := range_entry vh eL same
  have endTerm : termAt (abs names v).log endIdx = v.viewAt endIdx := by
    rw [← getTerm_vh vh]
    unfold State.getTerm
    split
    · omega
    · rfl
  have entries : messageEntries (abs names v).log p.sentIdx endIdx
      = (List.range' (p.sentIdx + 1) (endIdx + 1 - (p.sentIdx + 1))).map
          fun i => absEntry names v.ledger[i - 1]! := by
    rw [messageEntries_abs vh.size _ _ eL]
    congr 2
    omega
  refine ⟨?_, ?_, msgInv_range S M ne pL e1 eL same⟩
  · have msg : makeAppendEntriesRequest { cl0 with log := (abs names v).log, sentIndex := f }
        (names.id to) endIdx = rangeRequest names v (p.sentIdx + 1) endIdx := by
      simp only [makeAppendEntriesRequest, rangeRequest, fto, hterm, hcommit, entries,
        Nat.add_sub_cancel, getTerm_vh (names := names) vh]
    unfold sendEntries
    refine emits_congr
      (emits_bind (emits_guard ?_) (emits_bind (emits_send _ _) (emits_pure _))) rfl ?_
    · refine ⟨hrole, elig, by simp [fto, e1], ?_, ?_, Or.inl hrc⟩
      · show endIdx <= (abs names v).log.length
        rw [ReplUpdateCommit.abs_log_length vh.size]
        exact eL
      · show ((messageEntries (abs names v).log (f (names.id to)) endIdx).all
          fun entry => entry.term == termAt (abs names v).log endIdx) = true
        rw [fto, entries, endTerm]
        simp only [List.all_eq_true, List.mem_map, List.mem_range'_1, beq_iff_eq,
          forall_exists_index, and_imp]
        intro x i i1 iE xe
        subst xe
        simp only [absEntry]
        exact (entry i i1 (by omega)).2
    · simp only [List.nil_append, List.append_nil]
      rw [msg]
  · have nd' := setPeer_nodup P.nodup to { p with sentIdx := endIdx }
    have keys : forall k, k ∈ (v.setPeer to { p with sentIdx := endIdx }).allOtherNodes.map Prod.fst
        <-> k ∈ v.allOtherNodes.map Prod.fst := by
      intro k
      rw [setPeer_keys]
      constructor
      · rintro (rfl | h)
        · exact key
        · exact h
      · exact Or.inr
    have named : forall q, q ∈ (v.setPeer to { p with sentIdx := endIdx }).allOtherNodes
        -> Named names q.1 := by
      intro q mem
      obtain ⟨q', mem'⟩ := mem_keys.mp ((keys q.1).mp (List.mem_map_of_mem mem))
      exact hy.peersNamed (q.1, q') mem'
    rw [setPeer_eq]
    refine ⟨by frame_step M.frame, M.notRC, hyps_withPeers hy named, viewHyps_withPeers vh _, M.unconf,
      M.ledgerNamed,
      ⟨CCF.Function.update f (names.id to) endIdx, rfl, nd', fun k q lk => ?_⟩, ?_, M.isPrefix,
      M.rcRemoved, M.confRemoved, M.removedMono, M.cfgNew⟩
    · rw [← setPeer_eq, setPeer_lookup P.nodup] at lk
      split at lk
      · rename_i e
        subst e
        simp only [Option.some.injEq] at lk
        subst lk
        obtain ⟨-, -, m⟩ := P.rel k p found
        exact ⟨by simp [CCF.Function.update], eL, m⟩
      · rename_i e
        obtain ⟨fk, qL, m⟩ := P.rel k q lk
        have keyk : k ∈ v.allOtherNodes.map Prod.fst :=
          mem_keys.mpr ⟨q, (lookup_iff_mem P.nodup).mp lk⟩
        obtain ⟨qk, memk⟩ := mem_keys.mp keyk
        obtain ⟨qt, memt⟩ := mem_keys.mp key
        have ne : names.id k ≠ names.id to := fun eq =>
          e (named_inj (hy.peersNamed _ memk) (hy.peersNamed _ memt) eq)
        refine ⟨?_, qL, m⟩
        simp only [CCF.Function.update, ne, ↓reduceIte]
        exact fk
    · intro n
      refine (iff_of_eq (congrArg (n ∈ ·) (Ae.eligiblePeers_congr
        (b := { cl0 with log := (abs names v).log, sentIndex := f }) (by rfl) (by rfl) node))).trans
        ?_
      rw [M.eligible n, ← setPeer_eq]
      constructor
      · rintro ⟨k, mem, rfl⟩
        exact ⟨k, (keys k).mpr mem, rfl⟩
      · rintro ⟨k, mem, rfl⟩
        exact ⟨k, (keys k).mp mem, rfl⟩

end Consensus.TraceValidation.Proofs.Repl
