module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplBatch
public import Consensus.TraceValidation.Proofs.Handlers.ReplCreate
public import Consensus.TraceValidation.Proofs.Handlers.ReplClean

@[expose] public section

/-!
# Appending one entry: the clean log

How the clean configurations and eligible peers change when an entry is appended above the
commit index.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open CCF (Finset)

/-- The configuration an entry at `index` carries, as a list. -/
def entryConfig (x : Entry) (index : Nat) : List Configuration :=
  (x.content.metadata.configuration.map
    fun nodes => ({ index, nodes } : Configuration)).toList

theorem history_snoc (log : List Entry) (x : Entry)
    : configurationHistory (log ++ [x])
      = configurationHistory log ++ entryConfig x (log.length + 1) := by
  unfold configurationHistory entryConfig
  rw [List.zipIdx_append, List.filterMap_append]
  cases h : x.content.metadata.configuration <;> simp [h, Nat.add_comm]

theorem history_index_le (log : List Entry)
    : forall c, c ∈ configurationHistory log -> c.index <= log.length := by
  intro c mem
  unfold configurationHistory at mem
  obtain ⟨⟨e, i⟩, memZ, found⟩ := List.mem_filterMap.mp mem
  have := List.mem_zipIdx memZ
  cases h : e.content.metadata.configuration with
  | none => simp [h] at found
  | some nodes =>
      simp only [h, Option.map_some, Option.some.injEq] at found
      subst found
      simp only
      omega

theorem active_snoc (log : List Entry) (x : Entry) {ci : Nat} (h : ci <= log.length)
    : activeConfigurations (log ++ [x]) ci
      = activeConfigurations log ci ++ entryConfig x (log.length + 1) := by
  unfold activeConfigurations
  dsimp only
  rw [history_snoc, List.filter_append]
  have none : (entryConfig x (log.length + 1)).filter (fun c => decide (c.index <= ci)) = [] := by
    unfold entryConfig
    cases x.content.metadata.configuration <;> simp; omega
  rw [none, List.append_nil, List.drop_append_of_le_length]
  have := List.length_filter_le (fun c : Configuration => decide (c.index <= ci))
    (configurationHistory log)
  omega

theorem committedLog_snoc {cl : NodeState} (x : Entry)
    (h : cl.commitIndex <= cl.log.length)
    : ({ cl with log := cl.log ++ [x] } : NodeState).committedLog = cl.committedLog := by
  unfold NodeState.committedLog
  exact List.take_append_of_le_length h

theorem members_append (a b : List Configuration) {n : NodeID}
    : n ∈ configurationMembers (a ++ b)
      <-> n ∈ configurationMembers a \/ n ∈ configurationMembers b := by
  simp only [Repl.mem_members_iff, List.mem_append]
  constructor
  · rintro ⟨x, mem | mem, h⟩
    · exact Or.inl ⟨x, mem, h⟩
    · exact Or.inr ⟨x, mem, h⟩
  · rintro (⟨x, mem, h⟩ | ⟨x, mem, h⟩)
    · exact ⟨x, Or.inl mem, h⟩
    · exact ⟨x, Or.inr mem, h⟩

/-- The eligible peers after appending an entry above the commit index. -/
theorem eligible_snoc {cl : NodeState} (x : Entry) (h : cl.commitIndex <= cl.log.length)
    (self n : NodeID)
    : n ∈ eligiblePeers { cl with log := cl.log ++ [x] } self
      <-> n ∈ eligiblePeers cl self
          \/ (n ≠ self
              /\ exists nodes,
                  x.content.metadata.configuration = some nodes /\ n ∈ nodes) := by
  have rcn : ({ cl with log := cl.log ++ [x] } : NodeState).retirementCompletedNodes
      = cl.retirementCompletedNodes := by
    unfold NodeState.retirementCompletedNodes
    rw [committedLog_snoc x h]
  unfold eligiblePeers
  rw [rcn]
  simp only [CCF.Finset.mem_erase, CCF.Finset.mem_union, NodeState.activeMembers,
    NodeState.activeConfigurations]
  rw [show cl.log ++ [x] = (cl.log ++ [x]) from rfl, active_snoc cl.log x h, members_append]
  unfold entryConfig
  cases hc : x.content.metadata.configuration with
  | none => simp [configurationMembers]
  | some nodes =>
      simp only [Option.map_some, Option.toList_some, Repl.mem_members_iff, List.mem_singleton,
        exists_eq_left, Option.some.injEq]
      constructor
      · rintro ⟨ne, (a | b) | c⟩
        · exact Or.inl ⟨ne, Or.inl a⟩
        · exact Or.inr ⟨ne, nodes, rfl, b⟩
        · exact Or.inl ⟨ne, Or.inr c⟩
      · rintro (⟨ne, a | c⟩ | ⟨ne, _, rfl, b⟩)
        · exact ⟨ne, Or.inl (Or.inl a)⟩
        · exact ⟨ne, Or.inr c⟩
        · exact ⟨ne, Or.inl (Or.inr b)⟩

/-! ## The batch relation's clean state -/

section Declared

open Consensus.TraceValidation (Names abs)
open Consensus.TraceValidation.Exec
open ReplUpdateCommit (Named named_inj Hyps shifted_mem absConfig)

variable {names : Names} {node : NodeID} {v0 : State} {cl0 : NodeState}

theorem Mid.cleanLog {cl : NodeState} {v : State} (M : Mid names node v0 cl0 cl v)
    : cl.log = (abs names v).log := by
  obtain ⟨f, rfl, -⟩ := M.clean
  rfl

theorem Mid.cleanCommit (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : cl.commitIndex = v.commitIdx := by
  obtain ⟨f, rfl, -⟩ := M.clean
  exact S.commit.trans M.frame.commit.symm

theorem Mid.cleanTerm (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : cl.currentTerm = v.currentView := by
  obtain ⟨f, rfl, -⟩ := M.clean
  rw [M.frame.view, S.cleanEq]
  rfl

theorem Mid.pos {cl : NodeState} {v : State} (M : Mid names node v0 cl0 cl v)
    (ne : v.configurations ≠ [])
    : 0 < v.lastIdx := by
  refine Nat.pos_of_ne_zero fun z => ne (M.unconf z)

/-- A member of a declared configuration is the node itself or one of its peers. -/
theorem Mid.member (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v) {x : Config} (mem : x ∈ v.configurations)
    {a : NodeId × String} (ma : a ∈ x.nodes)
    : a.1 = v.nodeId \/ a.1 ∈ v.allOtherNodes.map Prod.fst := by
  have L0 := M.pos (List.ne_nil_of_mem mem)
  obtain ⟨D, hD, sh⟩ := M.hy.configs L0
  obtain ⟨x', memD, nodes⟩ := shifted_mem sh mem
  have named : Named names a.1 := M.hy.membersNamed x mem a ma
  have act : names.id a.1 ∈ cl.activeMembers := by
    unfold NodeState.activeMembers NodeState.activeConfigurations
    rw [M.cleanLog, M.cleanCommit S, hD]
    refine ReplUpdateCommit.mem_configurationMembers (List.mem_map_of_mem memD) ?_
    simp only [absConfig, nodes, Names.set, CCF.Finset.mem_ofList, List.mem_map]
    exact ⟨a.1, ⟨a, ma, rfl⟩, rfl⟩
  by_cases eq : names.id a.1 = node
  · exact Or.inl (named_inj named M.hy.selfNamed (eq.trans (M.self S).symm))
  · obtain ⟨k, memK, idk⟩ := (M.eligible _).mp
      (CCF.Finset.mem_erase.mpr ⟨eq, CCF.Finset.mem_union.mpr (Or.inl act)⟩)
    obtain ⟨q, memQ⟩ := mem_keys.mp memK
    have := named_inj (M.hy.peersNamed _ memQ) named idk
    exact Or.inr (this ▸ memK)

end Declared

end Consensus.TraceValidation.Proofs.Repl
