module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.LifeNotes

@[expose] public section

/-!
# Obligation: `init_as_backup` (not reviewed)

A joiner initialising from a snapshot. The handler (`init_hold`) records the snapshot's
index and view in a note, sizes the ledger to the index and makes the node a follower in
the snapshot's view. The release (`joinFinish`) fills the ledger with a donor's committed
prefix (`fillSnapshot`), so the clean `initAsBackup` input is the abstraction of that
prefix: the donor's clean state has committed it (`admit`), and `fillSnapshot`'s checks give
the clean guard (the prefix ends at a signature) and the clean view (every entry of the
prefix is in the snapshot's view).
-/

namespace Consensus.TraceValidation.Proofs.Life

open Consensus.Model.Node (NodeID)
open Consensus.TraceValidation.Exec

/-- A joiner's `init_as_backup` hold, from `saved`, at its end. -/
def InitPost (saved : State) (_ : Unit) (v : State) (o : Outbox) (n : List Note) : Prop :=
  exists index term,
    n = [.initAsBackup index term]
    /\ o = []
    /\ saved.leadership = .none
    /\ saved.currentView = 0
    /\ saved.lastIdx = 0
    /\ ((index == 0) == (term == 0)) = true
    /\ v.nodeId = saved.nodeId
    /\ v.currentView = term
    /\ v.lastIdx = index
    /\ v.commitIdx = index
    /\ v.ledger.size = index
    /\ v.leadership = .follower
    /\ v.leaderId = none
    /\ v.isNewFollower = true
    /\ v.votedFor = (if term = 0 then saved.votedFor else none)
    /\ v.retiredCommittedIdx = saved.retiredCommittedIdx

/-- Setting configurations keeps the ledger's size. -/
theorem size_foldl {α : Type} (cs : List α) (f : Array Entry -> α -> Array Entry)
    (keeps : forall l c, (f l c).size = l.size) (l : Array Entry)
    : (cs.foldl f l).size = l.size := by
  induction cs generalizing l with
  | nil => rfl
  | cons c rest ih => rw [List.foldl_cons, ih, keeps]

/-- The `init_as_backup` handler, run to the end. -/
theorem init_hold (env : Env) (saved : State)
    : TriN env (fun v o n => v = saved /\ o = [] /\ n = []) Exec.initAsBackup
        (InitPost saved) := by
  unfold Exec.initAsBackup Exec.becomeAwareOfNewTerm Exec.resetVotesForMe Exec.becomeFollower
  repeat' (first | trin_step | dsimp only)
  rename_i _ index term v fresh iff _ _ _ _ _ _ vEnd o n h
  obtain ⟨w, ⟨w1, ⟨w2, ⟨w3, ⟨⟨m, ⟨⟨e1, e2, e3⟩, e4⟩, e5⟩, e6⟩, e7⟩, e8⟩, e9⟩, e10⟩ := h
  subst_vars
  simp only [Bool.and_eq_true, beq_iff_eq] at fresh
  obtain ⟨⟨l, cv⟩, li⟩ := fresh
  refine ⟨
    index,
    term,
    by simp,
    rfl,
    l,
    cv,
    li,
    iff,
    rfl,
    rfl,
    rfl,
    rfl,
    ?_,
    rfl,
    rfl,
    rfl,
    ?_,
    rfl
  ⟩
  · rw [size_foldl _ _ (fun l c => by split <;> simp)]
    simp
  · by_cases t : term = 0
    · simp [t, cv]
    · simp [t, cv, Ne.symm t]

/-- A related entry of a keyed table. -/
theorem keyed_mem {Node A B : Type} {R : Node -> A -> B -> Prop}
    : forall {lefts : List (Node × A)} {rights : List (Node × B)},
        CCF.Sections.Keyed R lefts rights
        -> forall {k : Node} {a : A},
            (k, a) ∈ lefts -> exists b, (k, b) ∈ rights /\ R k a b
  | [], [], .nil, _, _, member => by cases member
  | _ :: _, _ :: _, .cons holds rest, _, _, member => by
      rcases List.mem_cons.mp member with head | tail
      · cases head
        exact ⟨_, List.mem_cons_self, holds⟩
      · obtain ⟨b, found, related⟩ := keyed_mem rest tail
        exact ⟨b, List.mem_cons_of_mem _ found, related⟩

/-- What a successful `fillSnapshot` checked. -/
theorem fill_ok {others : List (NodeID × Local)} {index term : Nat} {vars vars' : State}
    (filled : fillSnapshot others index term vars = .ok vars')
    : exists k donor,
        (k, donor) ∈ others
        /\ index <= donor.vars.commitIdx
        /\ index <= donor.vars.ledger.size
        /\ (forall e, e ∈ donor.vars.ledger.extract 0 index -> e.term = term)
        /\ (index != 0
            -> ((donor.vars.ledger.extract 0 index)[index - 1]?.any (·.sig)) = true)
        /\ vars'
            = {
              vars with
                ledger :=
                  donor.vars.ledger.extract 0 index
                  ++ vars.ledger.extract index vars.ledger.size
            } := by
  unfold fillSnapshot at filled
  split at filled
  · cases filled
  rename_i k donor found
  have member := List.mem_of_find?_eq_some found
  have chosen := List.find?_some found
  simp only [Bool.and_eq_true, decide_eq_true_eq] at chosen
  dsimp only at filled
  split at filled
  · cases filled
  rename_i terms
  split at filled
  · cases filled
  rename_i sig
  split at filled
  · cases filled
  split at filled
  · cases filled
  cases filled
  refine ⟨k, donor, member, chosen.1, chosen.2, ?_, ?_, rfl⟩
  · intro e member
    have all : (donor.vars.ledger.extract 0 index).all (·.term == term) = true := by
      cases hx : (donor.vars.ledger.extract 0 index).all (·.term == term)
      · rw [hx] at terms
        exact absurd rfl terms
      · rfl
    simpa using Array.all_eq_true_iff_forall_mem.mp all e member
  · intro nonzero
    simpa [nonzero] using sig

end Consensus.TraceValidation.Proofs.Life

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.Model.Node

/--
The clean step is `initAsBackup` of the donor's prefix: the joiner is fresh, the prefix ends
at a signature, its last entry is in the snapshot's view, and the donor has committed it.
-/
theorem initAsBackupSound (env : Env) : InitAsBackupSound env := by
  intro node saved actions c vars others cleanOthers _ _ invSaved _ keyed ran _ finished _
  obtain ⟨index, term, notes, outbox, none_, view0, last0, iff, nodeId, view, lastIdx, commitIdx,
    size, role, leader, newFollower, votedFor, retired⟩ :=
    Life.TriN.run (Life.init_hold env saved) ⟨rfl, rfl, rfl⟩ ran
  have snap : snapshotOf c = some (index, term) := by simp [snapshotOf, notes]
  simp only [joinFinish, snap] at finished
  obtain ⟨k, donor, member, committed, enough, terms, sig, filled⟩ := Life.fill_ok finished
  subst filled
  have commit0 : saved.commitIdx = 0 := by
    simp only [inv, invChecks, List.all_cons, Bool.and_eq_true] at invSaved
    obtain ⟨_, le, _⟩ := invSaved
    simp only [decide_eq_true_eq, last0] at le
    omega
  generalize hpre : donor.vars.ledger.extract 0 index = pre at terms sig
  have preSize : pre.size = index := by
    rw [← hpre, Array.size_extract]
    omega
  have ledger : c.vars.ledger.extract index c.vars.ledger.size = #[] := by
    simp [size]
  rw [ledger, Array.append_empty]
  refine ⟨nodeId, fun clean notPristine agreed _ => ?_⟩
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, and_assoc] at agreed
  obtain ⟨cRole, cTerm, cLog, cCommit, _, _, cVoted, _, _, _, cRetired⟩ := agreed
  simp only [abs, absRole, none_, view0, last0, commit0, List.take_zero, List.map_nil]
    at cRole cTerm cLog cCommit cVoted cRetired
  have takeAll : pre.toList.take index = pre.toList := by
    apply List.take_of_length_le
    simp [preSize]
  generalize hentries : pre.toList.map (absEntry env.names) = entries
  have entriesLen : entries.length = index := by
    rw [← hentries]
    simp [preSize]
  have atEnd : index ≠ 0 -> exists e, entries[index - 1]? = some (absEntry env.names e)
      /\ e.term = term /\ e.sig = true := by
    intro nonzero
    have within : index - 1 < pre.size := by omega
    refine ⟨pre[index - 1], ?_, terms _ (Array.getElem_mem within), ?_⟩
    · rw [← hentries]
      simp [within]
    · have := sig (by simpa using nonzero)
      simpa [within] using this
  have endTerm : termAt entries index = term := by
    by_cases nonzero : index = 0
    · simp only [nonzero, beq_self_eq_true, beq_iff_eq] at iff
      have t0 : term = 0 := beq_iff_eq.mp iff.symm
      simp [termAt, entryAt?, nonzero, t0]
    · obtain ⟨e, found, eTerm, _⟩ := atEnd nonzero
      simp [termAt, entryAt?, nonzero, found, absEntry, eTerm]
  have sigOk : entries = [] \/ isSignatureAt entries entries.length = true := by
    by_cases nonzero : index = 0
    · left
      rw [← List.length_eq_zero_iff, entriesLen, nonzero]
    · right
      obtain ⟨e, found, _, eSig⟩ := atEnd nonzero
      simp [isSignatureAt, entryAt?, entriesLen, nonzero, found, absEntry, eSig,
        EntryContent.isSignature]
  refine ⟨[.initAsBackup entries],
    becomeAwareOfNewTerm { clean with log := entries, commitIndex := index } term,
    ?_, ?_, ?_, ?_, ?_⟩
  · have step := LocalRun.cons (protocol := protocol env) (node := node) (state := clean)
      (middle := becomeAwareOfNewTerm { clean with log := entries, commitIndex := index } term)
      (action := (protocol env).internal (.initAsBackup entries)) (effects := {}) ?_
      (LocalRun.nil _)
    · simpa [cleanActions, outbox] using step
    · rw [entriesLen] at sigOk
      simp [protocol, Consensus.Model.protocol, Consensus.Model.Node.step, act, initAsBackup,
        guard, NodeState.isFresh, cRole, cTerm, cLog, cCommit, sigOk, entriesLen, endTerm]
  · by_cases t : term = 0
    · simp [agrees, abs, absRole, trackedPeers, becomeAwareOfNewTerm, role, view, lastIdx,
        commitIdx, newFollower, leader, votedFor, retired, cVoted, cRetired, cTerm, t, takeAll,
        hentries]
    · simp [agrees, abs, absRole, trackedPeers, becomeAwareOfNewTerm, role, view, lastIdx,
        commitIdx, newFollower, leader, votedFor, retired, cRetired, cTerm, t, Ne.symm t,
        takeAll, hentries]
  · intro primary
    simp [becomeAwareOfNewTerm] at primary
  · intro input inputMember
    simp only [List.mem_singleton] at inputMember
    subst inputMember
    obtain ⟨cd, cdMember, _, _, invDonor, agreeOrPristine, _⟩ := Life.keyed_mem keyed member
    simp only [inv, invChecks, List.all_cons, Bool.and_eq_true] at invDonor
    obtain ⟨_, le, _⟩ := invDonor
    simp only [decide_eq_true_eq] at le
    simp only [admit, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
    refine ⟨(k, cd), cdMember, ?_⟩
    rcases agreeOrPristine with ⟨_, agreedDonor⟩ | ⟨pristineDonor, _⟩
    · simp only [agrees, Bool.and_eq_true, beq_iff_eq, and_assoc] at agreedDonor
      obtain ⟨_, _, dLog, dCommit, _⟩ := agreedDonor
      refine ⟨by rw [entriesLen, dCommit]; exact committed, ?_⟩
      rw [entriesLen, dLog, ← hentries, ← hpre]
      simp only [abs]
      rw [← List.map_take, List.take_take, Nat.min_eq_left (by omega)]
      simp
    · simp only [pristine, Bool.and_eq_true, beq_iff_eq] at pristineDonor
      have nil : entries = [] := by
        rw [← List.length_eq_zero_iff, entriesLen]
        omega
      simp [nil]
  · intro envelope envelopeMember
    rw [outbox] at envelopeMember
    cases envelopeMember

end Consensus.TraceValidation.Proofs
