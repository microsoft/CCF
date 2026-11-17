module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespPeers
public import Consensus.TraceValidation.Proofs.Handlers.AeClean

@[expose] public section

/-!
# Clean-side facts for the AppendEntries response (not reviewed)

`highestCommittableIndex` reads the match indexes of the active members other than the node
only (`hc_congr`); every eligible peer is a member of a configuration of the log
(`eligible_mem_history`); and `agrees` unpacked into its fields (`Agrees`).
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open Consensus.Model.Node
open Consensus.TraceValidation (Names abs absRole agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)

theorem mem_configurationMembers_iff {cs : List Configuration} {n : NodeID}
    : n ∈ configurationMembers cs <-> exists x, x ∈ cs /\ n ∈ x.nodes := by
  constructor
  · unfold configurationMembers
    have general : forall (cs : List Configuration) (acc : CCF.Finset NodeID),
        n ∈ cs.foldl (fun nodes configuration => nodes ∪ configuration.nodes) acc
        -> n ∈ acc \/ exists x, x ∈ cs /\ n ∈ x.nodes := by
      intro cs
      induction cs with
      | nil => intro acc h; exact Or.inl h
      | cons y cs ih =>
          intro acc h
          rcases ih _ h with h | ⟨x, mem, member⟩
          · rcases CCF.Finset.mem_union.mp h with h | h
            · exact Or.inl h
            · exact Or.inr ⟨y, List.mem_cons_self, h⟩
          · exact Or.inr ⟨x, List.mem_cons_of_mem _ mem, member⟩
    intro h
    rcases general cs ∅ h with h | h
    · exact absurd h (CCF.Finset.notMem_empty _)
    · exact h
  · rintro ⟨x, mem, member⟩
    exact ReplUpdateCommit.mem_configurationMembers mem member

/-- Every eligible peer is a member of a configuration of the log. -/
theorem eligible_mem_history {st : NodeState} {self n : NodeID}
    (h : n ∈ eligiblePeers st self)
    : n ∈ configurationMembers (configurationHistory st.log) := by
  unfold eligiblePeers at h
  rcases CCF.Finset.mem_union.mp (CCF.Finset.mem_erase.mp h).2 with h | h
  · obtain ⟨x, mem, member⟩ := mem_configurationMembers_iff.mp h
    exact mem_configurationMembers_iff.mpr ⟨x, List.mem_of_mem_drop mem, member⟩
  · unfold NodeState.retirementCompletedNodes at h
    have h := (CCF.Finset.mem_sdiff.mp (CCF.Finset.mem_sdiff.mp h).1).1
    obtain ⟨x, mem, member⟩ := mem_configurationMembers_iff.mp h
    refine mem_configurationMembers_iff.mpr ⟨x, ?_, member⟩
    exact (Ae.configurationHistory_prefix (List.take_prefix _ _)).subset mem

/--
`highestCommittableIndex` depends on the match indexes of the active members other than the
node only.
-/
theorem hc_congr {a b : NodeState} {self : NodeID} (hl : a.log = b.log)
    (hc : a.commitIndex = b.commitIndex) (ht : a.currentTerm = b.currentTerm)
    (hm : forall n, n ∈ a.activeMembers -> n ≠ self -> a.matchIndex n = b.matchIndex n)
    : highestCommittableIndex a self = highestCommittableIndex b self := by
  have members : a.activeMembers = b.activeMembers := by
    unfold NodeState.activeMembers NodeState.activeConfigurations
    rw [hl, hc]
  have rep : forall index : Nat,
      a.activeMembers.filter (fun node => node = self \/ a.matchIndex node >= index)
        = b.activeMembers.filter (fun node => node = self \/ b.matchIndex node >= index) := by
    intro index
    apply CCF.Finset.ext
    intro n
    rw [CCF.Finset.mem_filter, CCF.Finset.mem_filter, ← members]
    constructor
    · rintro ⟨mem, h⟩
      refine ⟨mem, ?_⟩
      by_cases e : n = self
      · exact Or.inl e
      · rw [← hm n mem e]; exact h
    · rintro ⟨mem, h⟩
      refine ⟨mem, ?_⟩
      by_cases e : n = self
      · exact Or.inl e
      · rw [hm n mem e]; exact h
  unfold highestCommittableIndex
  simp only [rep, hl, hc, ht]

/-- `agrees`, field by field. -/
structure Agrees (names : Names) (c : NodeState) (d : State) : Prop where
  role : c.role = absRole d.leadership
  term : c.currentTerm = d.currentView
  log : c.log = (abs names d).log
  commit : c.commitIndex = d.commitIdx
  sent : forall n, n ∈ trackedPeers names d -> c.sentIndex n = (abs names d).sentIndex n
  match_
    : forall n, n ∈ trackedPeers names d -> c.matchIndex n = (abs names d).matchIndex n
  newFollower : c.isNewFollower = d.isNewFollower
  voted : c.votedFor = d.votedFor.map names.id
  known : c.primaryKnown = d.leaderId.isSome
  rci : c.retiredCommittedIndex = d.retiredCommittedIdx

theorem Agrees.of {names : Names} {c : NodeState} {d : State}
    (h : agrees names c d = true)
    : Agrees names c d := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, -⟩, -⟩, h11⟩ := h
  exact ⟨h1, h2, h3, h4, fun n m => (h5 n m).1, fun n m => (h5 n m).2, h6, h7, h8, h11⟩

theorem Agrees.to {names : Names} {c : NodeState} {d : State} (h : Agrees names c d)
    (nc : d.leadership ≠ .candidate /\ d.leadership ≠ .preVoteCandidate)
    : agrees names c d = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h11⟩ := h
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, List.all_eq_true]
  refine ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, fun n m => by simp [h5 n m, h6 n m]⟩, h7⟩, h8⟩, h9⟩,
    ?_⟩, ?_⟩, h11⟩ <;>
    cases hl : d.leadership <;> simp_all [abs, absRole]

end Consensus.TraceValidation.Proofs.AeResp
