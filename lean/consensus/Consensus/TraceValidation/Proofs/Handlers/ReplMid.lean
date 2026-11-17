module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplPeers

@[expose] public section

/-!
# The batch relation (not reviewed; `Replicate` obligation)

During a `replicate` hold the declared state `v` and the clean state `cl` reached by the
entries seen so far are related by `Mid`: `v` keeps every field `abs` reads but the ledger
and the peers, `cl` is the starting clean state with the declared log and new send
indexes, the declared peers are the clean eligible peers, each with its clean send index
and the starting clean match index, and `v` satisfies the facts `update_commit` and
`send_append_entries` need (`Hyps`, `ViewHyps`).
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees trackedPeers inv UnnamedUnmatched)
open Consensus.TraceValidation.Proofs.Ae
open ReplUpdateCommit (Named named_inj Hyps)

/-- The declared fields `abs` reads, other than the ledger and the peers, are `v0`'s. -/
structure Frame (v0 v : State) : Prop where
  nodeId : v.nodeId = v0.nodeId
  view : v.currentView = v0.currentView
  commit : v.commitIdx = v0.commitIdx
  leadership : v.leadership = v0.leadership
  newFollower : v.isNewFollower = v0.isNewFollower
  votedFor : v.votedFor = v0.votedFor
  leaderId : v.leaderId = v0.leaderId
  votes : v.votesForMe = v0.votesForMe
  rci : v.retiredCommittedIdx = v0.retiredCommittedIdx

/-- Re-establishes `Frame` across an update that keeps its fields definitionally. -/
macro "frame_step " h:term:max : tactic =>
  `(tactic| exact ⟨($h).nodeId, ($h).view, ($h).commit, ($h).leadership, ($h).newFollower,
    ($h).votedFor, ($h).leaderId, ($h).votes, ($h).rci⟩)

/-- What the batch keeps of the starting declared and clean states. -/
structure Start (names : Names) (node : NodeID) (v0 : State) (cl0 : NodeState)
    : Prop where
  inv : inv names v0 = true
  agrees : agrees names cl0 v0 = true
  um : UnnamedUnmatched node cl0
  self : names.id v0.nodeId = node
  leader : v0.leadership = .leader
  notRC : v0.isRetiredCommitted = false
  rci : v0.retiredCommittedIdx = none

/-- The declared peers against the clean send indexes `f` and starting match indexes. -/
structure PeerRel (names : Names) (cl0 : NodeState) (f : NodeID -> Nat) (v : State)
    : Prop where
  nodup : (v.allOtherNodes.map Prod.fst).Nodup
  rel
    : forall k p,
        v.peer? k = some p
        -> f (names.id k) = p.sentIdx
            /\ p.sentIdx <= v.lastIdx
            /\ cl0.matchIndex (names.id k) = p.matchIdx

/-- The batch relation. -/
structure Mid (names : Names) (node : NodeID) (v0 : State) (cl0 : NodeState)
    (cl : NodeState) (v : State)
    : Prop where
  frame : Frame v0 v
  notRC : v.isRetiredCommitted = false
  hy : Hyps names v
  vh : ViewHyps v
  unconf : v.lastIdx = 0 -> v.configurations = []
  ledgerNamed
    : forall e,
        e ∈ v.ledger.toList
        -> forall id, id ∈ (e.config.getD []).map Prod.fst ++ e.retired -> Named names id
  clean
    : exists f,
        cl = { cl0 with log := (abs names v).log, sentIndex := f }
        /\ PeerRel names cl0 f v
  eligible
    : forall n,
        n ∈ eligiblePeers cl node
        <-> exists k, k ∈ v.allOtherNodes.map Prod.fst /\ names.id k = n
  isPrefix : cl0.log <+: (abs names v).log
  rcRemoved
    : forall e,
        e ∈ v.rcEntries
        -> forall id, id ∈ e.2 -> names.id id ∈ removedNodes (abs names v0).log
  confRemoved
    : forall j x,
        v0.commitIdx <= j
        -> (abs names v).log[j]? = some x
        -> forall n,
            n ∈ x.content.metadata.retirementConfirmations
            -> n ∈ removedNodes (abs names v0).log
  removedMono
    : forall n, n ∈ removedNodes (abs names v0).log -> n ∈ removedNodes (abs names v).log
  cfgNew
    : exists new,
        v.configurations = v0.configurations ++ new
        /\ forall c,
            c ∈ new
            -> forall a, a ∈ c.nodes -> names.id a.1 ∉ removedNodes (abs names v0).log

variable {names : Names} {node : NodeID} {v0 : State} {cl0 : NodeState}

theorem Start.cleanEq (S : Start names node v0 cl0)
    : cl0
      = {
        abs names v0 with
          sentIndex := cl0.sentIndex,
          matchIndex := cl0.matchIndex,
          votesGranted := cl0.votesGranted,
          preVotesGranted := cl0.preVotesGranted
      } :=
  agrees_eq S.agrees

theorem Start.log (S : Start names node v0 cl0) : cl0.log = (abs names v0).log := by
  rw [S.cleanEq]

theorem Start.commit (S : Start names node v0 cl0) : cl0.commitIndex = v0.commitIdx := by
  rw [S.cleanEq]; rfl

theorem Start.role (S : Start names node v0 cl0) : cl0.role = .primary := by
  rw [S.cleanEq]; simp [abs, S.leader, Consensus.TraceValidation.absRole]

theorem Start.cleanRci (S : Start names node v0 cl0)
    : cl0.retiredCommittedIndex = none := by
  rw [S.cleanEq]; simp [abs, S.rci]

/-- A clean state without a latched confirmation is not retired-committed. -/
theorem not_rc_of_rci {c : NodeState} (h : c.retiredCommittedIndex = none) (n : NodeID)
    : Not (c.isRetiredCommitted n) := by
  unfold NodeState.isRetiredCommitted NodeState.retirement
  simp only [h, Option.isSome_none, Bool.false_eq_true, ite_false]
  split
  · simp
  · repeat' split
    all_goals simp

/-- The tracked peers of a declared leader are its peers' clean ids. -/
theorem tracked_iff {v : State} (leader : v.leadership = .leader) {n : NodeID}
    : n ∈ trackedPeers names v
      <-> exists k p, (k, p) ∈ v.allOtherNodes /\ names.id k = n := by
  simp only [trackedPeers, leader, beq_self_eq_true, ite_true, List.mem_map]
  constructor
  · rintro ⟨⟨k, p⟩, mem, rfl⟩
    exact ⟨k, p, mem, rfl⟩
  · rintro ⟨k, p, mem, rfl⟩
    exact ⟨(k, p), mem, rfl⟩

theorem eligible_of_log_nil {c : NodeState} (h : c.log = []) (self n : NodeID)
    : n ∉ eligiblePeers c self := by
  intro mem
  unfold eligiblePeers NodeState.activeMembers NodeState.retirementCompletedNodes
    NodeState.activeConfigurations NodeState.committedLog at mem
  rw [h] at mem
  simp [CCF.Finset.mem_erase, CCF.Finset.mem_union, CCF.Finset.mem_sdiff, configurationHistory,
    activeConfigurations, configurationMembers, CCF.Finset.notMem_empty] at mem

theorem mem_members_iff {cs : List Configuration} {n : NodeID}
    : n ∈ configurationMembers cs <-> exists x, x ∈ cs /\ n ∈ x.nodes := by
  refine ⟨
    fun h => ?_,
    fun ⟨x, mem, member⟩ => ReplUpdateCommit.mem_configurationMembers mem member
  ⟩
  unfold configurationMembers at h
  have general : forall (cs : List Configuration) (acc : CCF.Finset NodeID),
      n ∈ cs.foldl (fun nodes configuration => nodes ∪ configuration.nodes) acc
      -> n ∈ acc \/ exists x, x ∈ cs /\ n ∈ x.nodes := by
    intro cs
    induction cs with
    | nil => exact fun _ h => Or.inl h
    | cons y ys ih =>
        intro acc h
        rcases ih _ h with h | ⟨x, mem, member⟩
        · rcases CCF.Finset.mem_union.mp h with h | h
          · exact Or.inl h
          · exact Or.inr ⟨y, List.mem_cons_self, h⟩
        · exact Or.inr ⟨x, List.mem_cons_of_mem _ mem, member⟩
  rcases general cs ∅ h with h | h
  · exact absurd h (CCF.Finset.notMem_empty _)
  · exact h

theorem history_prefix (l1 l2 : List Consensus.Model.Node.Entry)
    : configurationHistory l1 <+: configurationHistory (l1 ++ l2) := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  exact List.prefix_append _ _

theorem members_prefix {l1 l2 : List Consensus.Model.Node.Entry} (h : l1 <+: l2)
    {n : NodeID} (mem : n ∈ configurationMembers (configurationHistory l1))
    : n ∈ configurationMembers (configurationHistory l2) := by
  obtain ⟨t, rfl⟩ := h
  obtain ⟨x, mem, member⟩ := mem_members_iff.mp mem
  exact mem_members_iff.mpr ⟨x, (history_prefix l1 t).subset mem, member⟩

theorem Mid.start (S : Start names node v0 cl0) : Mid names node v0 cl0 cl0 v0 := by
  have invS := S.inv
  have hy := Hyps.ofInv invS
  have unconf : (v0.lastIdx != 0 || v0.leadership != .leader || v0.configurations.isEmpty)
      = true := by
    inv_conj invS "empty_leader_unconfigured"
  have ledgerNamed : (v0.ledger.all fun e =>
      ((e.config.getD []).map Prod.fst ++ e.retired).all
        fun id => names.name (names.id id) == id) = true := by
    inv_conj invS "ledger_names_round_trip"
  have bounds : (v0.leadership != .leader
      || v0.allOtherNodes.all fun (_, p) => p.sentIdx <= v0.lastIdx && p.matchIdx <= v0.lastIdx)
      = true := by
    inv_conj invS "peer_bounds"
  simp only [S.leader, bne_self_eq_false, Bool.false_or, Bool.or_false, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at bounds unconf
  have peers : forall k, k ∈ v0.allOtherNodes.map Prod.fst
      -> (v0.allOtherNodes.map Prod.fst).Nodup := by
    intro k mem
    by_cases z : v0.lastIdx = 0
    · have alone : (v0.lastIdx != 0 || v0.leadership != .leader || v0.allOtherNodes.isEmpty)
          = true := by
        inv_conj invS "empty_leader_alone"
      simp only [z, S.leader, bne_self_eq_false, Bool.false_or, List.isEmpty_iff] at alone
      simp [alone] at mem
    · have hp : (v0.lastIdx == 0 || v0.leadership == .none
          || v0.allOtherNodes.map (fun (id, _) => names.id id)
            == (eligiblePeers (abs names v0) (names.id v0.nodeId)).sort) = true := by
        inv_conj invS "peers"
      simp only [z, S.leader, beq_iff_eq, Bool.or_eq_true, reduceCtorEq, false_or] at hp
      have mapEq : (v0.allOtherNodes.map Prod.fst).map names.id
          = (eligiblePeers (abs names v0) (names.id v0.nodeId)).sort := by
        rw [← hp, List.map_map]
        rfl
      refine List.Pairwise.of_map (S := fun x y : NodeID => x ≠ y) names.id
        (fun a b h e => h (e ▸ rfl)) ?_
      rw [mapEq]
      exact CCF.Finset.nodup_of_sorted (eligiblePeers _ _).sorted
  have nodup : (v0.allOtherNodes.map Prod.fst).Nodup := by
    cases h : v0.allOtherNodes with
    | nil => simp
    | cons q l => exact h ▸ peers q.1 (by simp [h])
  have rcRemoved : forall e, e ∈ v0.rcEntries -> forall id, id ∈ e.2
      -> names.id id ∈ removedNodes (abs names v0).log := by
    have e : (v0.leadership != .leader
        || v0.rcEntries.all fun (x : Nat × List NodeId) => x.2.all fun id =>
          decide (names.id id ∈ removedNodes (abs names v0).log)) = true := by
      inv_conj invS "rc_entries_removed"
    simp only [S.leader, bne_self_eq_false, Bool.false_or, List.all_eq_true,
      decide_eq_true_eq] at e
    exact e
  have rcs : (v0.rcEntries
      == (List.range' (v0.commitIdx + 1) (v0.lastIdx - v0.commitIdx)).filterMap
          fun i => v0.ledger[i - 1]?.bind
            fun e => if e.retired.isEmpty then none else some (i, e.retired)) = true := by
    inv_conj invS "rc_entries"
  rw [beq_iff_eq] at rcs
  refine ⟨
    ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩,
    S.notRC,
    hy,
    ViewHyps.ofInv invS,
    fun z => by simpa [z] using unconf,
    ?_,
    ?_,
    ?_,
    by rw [S.log]; exact List.prefix_refl _,
    rcRemoved,
    ?_,
    fun _ h => h,
    ⟨[], by simp, by simp⟩
  ⟩
  · intro e mem id idMem
    have := (List.all_eq_true.mp (Array.all_eq_true_iff_forall_mem.mp ledgerNamed e
      (Array.mem_def.mpr mem))) id idMem
    simpa using this
  · refine ⟨cl0.sentIndex, ?_, nodup, fun k p found => ?_⟩
    · rw [← S.log]
    have mem := (lookup_iff_mem nodup).mp found
    refine ⟨?_, (bounds _ mem).1, ?_⟩
    · have named := hy.peersNamed _ mem
      rw [← abs_sentIndex hy.peersNamed named found]
      have ag := S.agrees
      simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at ag
      exact (ag.1.1.1.1.1.1.2 _ ((tracked_iff S.leader).mpr ⟨k, p, mem, rfl⟩)).1
    · have named := hy.peersNamed _ mem
      rw [← ReplUpdateCommit.abs_matchIndex hy.peersNamed named found]
      have ag := S.agrees
      simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at ag
      exact (ag.1.1.1.1.1.1.2 _ ((tracked_iff S.leader).mpr ⟨k, p, mem, rfl⟩)).2
  · intro n
    by_cases z : v0.lastIdx = 0
    · have alone : (v0.lastIdx != 0 || v0.leadership != .leader || v0.allOtherNodes.isEmpty)
          = true := by
        inv_conj invS "empty_leader_alone"
      simp only [z, S.leader, bne_self_eq_false, Bool.false_or, List.isEmpty_iff] at alone
      have logNil : cl0.log = [] := by
        rw [S.log]
        simp [abs, z]
      simp only [alone, List.map_nil, List.not_mem_nil, false_and, exists_false, iff_false]
      exact eligible_of_log_nil logNil _ _
    · have hp : (v0.lastIdx == 0 || v0.leadership == .none
          || v0.allOtherNodes.map (fun (id, _) => names.id id)
            == (eligiblePeers (abs names v0) (names.id v0.nodeId)).sort) = true := by
        inv_conj invS "peers"
      simp only [z, S.leader, beq_iff_eq, Bool.or_eq_true, reduceCtorEq, false_or] at hp
      have congr : eligiblePeers cl0 node = eligiblePeers (abs names v0) (names.id v0.nodeId) := by
        rw [S.self]
        exact Ae.eligiblePeers_congr S.log S.commit node
      have mapEq : (v0.allOtherNodes.map Prod.fst).map names.id
          = (eligiblePeers (abs names v0) (names.id v0.nodeId)).sort := by
        rw [← hp, List.map_map]
        rfl
      rw [congr, ← CCF.Finset.mem_sort, ← mapEq, List.mem_map]
  · intro j x cj hx n mem
    simp only [abs, List.getElem?_map, List.getElem?_take, Option.map_eq_some_iff] at hx
    split at hx
    · rename_i jL
      obtain ⟨e, he, rfl⟩ := hx
      have he' : v0.ledger[j]? = some e := by simpa using he
      cases hs : e.sig with
      | true => simp [absEntry, hs, EntryContent.metadata, CCF.Finset.notMem_empty] at mem
      | false =>
          simp only [absEntry, hs, Bool.false_eq_true, ite_false, EntryContent.metadata,
            Names.set, CCF.Finset.mem_ofList, List.mem_map] at mem
          obtain ⟨id, mid, rfl⟩ := mem
          have ne : e.retired.isEmpty = false := by
            cases h : e.retired with
            | nil => rw [h] at mid; cases mid
            | cons _ _ => rfl
          refine rcRemoved (j + 1, e.retired) ?_ id mid
          rw [rcs, List.mem_filterMap]
          refine ⟨j + 1, List.mem_range'_1.mpr ⟨by omega, by omega⟩, ?_⟩
          have ne' : ¬e.retired = [] := fun z => by rw [z] at ne; cases ne
          simp [he', ne']
    · obtain ⟨_, h, _⟩ := hx
      cases h

/-- At the end of the batch the clean state agrees with the declared one. -/
theorem Mid.finish (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : agrees names cl v = true /\ UnnamedUnmatched node cl := by
  obtain ⟨f, rfl, P⟩ := M.clean
  have F := M.frame
  refine ⟨?_, ?_⟩
  · have ag := S.agrees
    have leader : v.leadership = .leader := F.leadership.trans S.leader
    simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at ag ⊢
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨a1, a2⟩, a3⟩, a4⟩, -⟩, a6⟩, a7⟩, a8⟩, -⟩, -⟩, a11⟩ := ag
    have r1 : (abs names v).role = (abs names v0).role := by simp [abs, F.leadership]
    refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨?_, ?_⟩, trivial⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩, ?_⟩
    · rw [r1]; exact a1
    · show cl0.currentTerm = v.currentView
      rw [F.view]; exact a2
    · show cl0.commitIndex = v.commitIdx
      rw [F.commit]; exact a4
    · intro n mem
      obtain ⟨k, p, memK, rfl⟩ := (tracked_iff leader).mp mem
      have found := (lookup_iff_mem P.nodup).mpr memK
      obtain ⟨fk, -, mk⟩ := P.rel k p found
      have named := M.hy.peersNamed _ memK
      refine ⟨?_, ?_⟩
      · show f (names.id k) = _
        rw [abs_sentIndex M.hy.peersNamed named found, fk]
      · show cl0.matchIndex (names.id k) = _
        rw [ReplUpdateCommit.abs_matchIndex M.hy.peersNamed named found, mk]
    · show cl0.isNewFollower = v.isNewFollower
      rw [F.newFollower]; exact a6
    · show cl0.votedFor = v.votedFor.map names.id
      rw [F.votedFor]; exact a7
    · show cl0.primaryKnown = v.leaderId.isSome
      rw [F.leaderId]; exact a8
    · simp [abs, leader, Consensus.TraceValidation.absRole]
    · simp [abs, leader, Consensus.TraceValidation.absRole]
    · show cl0.retiredCommittedIndex = v.retiredCommittedIdx
      rw [F.rci]; exact a11
  · intro role n ne notMem
    exact S.um S.role n ne fun mem => notMem (members_prefix M.isPrefix mem)

end Consensus.TraceValidation.Proofs.Repl
