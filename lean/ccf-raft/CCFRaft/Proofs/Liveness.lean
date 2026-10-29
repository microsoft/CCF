module

public import CCFRaft.Proofs.Liveness.Admissible
public import CCFRaft.Proofs.Liveness.Delay
public import CCFRaft.Proofs.Liveness.Network
public import CCFRaft.Proofs.Liveness.Timers

@[expose] public section

/-!
# Liveness proof base

Admissible executions, the packet ledger, bounded delay and election deadlines,
imported from `Proofs/Liveness/`, plus the primary's commit scan.
-/

namespace CCFRaft.Proofs.Liveness

open Model.Node
open CCFRaft.Liveness

private theorem foldMax_acc (predicate : Nat -> Prop) [DecidablePred predicate]
    (values : List Nat) (initial : Nat)
    : initial
      <= values.foldl (fun best value => if predicate value then max best value else best)
          initial := by
  induction values generalizing initial with
  | nil => simp
  | cons value values ih =>
      simp only [List.foldl_cons]
      exact le_trans (by split <;> omega) (ih _)

private theorem foldMax_mem (predicate : Nat -> Prop) [DecidablePred predicate]
    (values : List Nat) (initial value : Nat) (member : value ∈ values)
    (accepted : predicate value)
    : value
      <= values.foldl (fun best value => if predicate value then max best value else best)
          initial := by
  induction values generalizing initial with
  | nil => simp at member
  | cons head values ih =>
      simp only [List.foldl_cons]
      rcases List.mem_cons.mp member with equal | member
      · subst head
        simpa [accepted]
          using le_trans (Nat.le_max_right initial value) (foldMax_acc predicate values _)
      · exact ih _ member

/-- The executable scan includes every ready signature beyond the current frontier. -/
theorem highestCommittableIndex_ge (state : NodeState) (self : NodeID) (index : Nat)
    (ready : SignatureReady state self index) (uncommitted : state.commitIndex < index)
    : index <= highestCommittableIndex state self := by
  obtain ⟨inLog, signature, currentTerm, quorum⟩ := ready
  apply foldMax_mem
  · exact List.mem_range.mpr (by omega)
  · exact ⟨uncommitted, signature, currentTerm, quorum⟩

/-- Successful advancement preserves the selected commit frontier through retirement handling. -/
private theorem advanceCommit_frontier (state : NodeState) (self : NodeID)
    (after : NodeState) (effects : CCF.Outputs NodeID Message Notification)
    (executed
      : (advanceCommit (CCF.Capabilities.record self) state self).run {}
        = some (after, effects))
    : after.commitIndex = max state.commitIndex (highestCommittableIndex state self) := by
  have recorded :
      (state.recordCommit self (highestCommittableIndex state self)).commitIndex
        = highestCommittableIndex state self := by
    dsimp only [NodeState.recordCommit]
    split_ifs <;> rfl
  dsimp only [advanceCommit] at executed
  split_ifs at executed <;>
    cases successor : findSuccessor state self <;>
    simp_all [nominateSuccessor, CCF.Capabilities.record, StateT.run]
  all_goals (cases executed; grind)

/-- Recording outputs cannot disable commit advancement, including successor nomination. -/
private theorem advanceCommit_enabled (state : NodeState) (self : NodeID)
    : ((advanceCommit (CCF.Capabilities.record self) state self).run {}).isSome
      = true := by
  dsimp only [advanceCommit]
  split_ifs <;>
    cases successor : findSuccessor state self <;>
    simp_all [nominateSuccessor, CCF.Capabilities.record, StateT.run] <;> rfl

/-- The actual commit operation commits a current-term signature acknowledged by a
quorum. This is the final protocol step, not a fairness assumption about collecting
acknowledgements. -/
theorem acknowledged_signature_commits (state : NodeState) (self : NodeID) (index : Nat)
    (ready : SignatureReady state self index)
    : exists after effects,
        (advanceCommit (CCF.Capabilities.record self) state self).run {}
          = some (after, effects)
        /\ index <= after.commitIndex := by
  have enabled := advanceCommit_enabled state self
  cases executed : (advanceCommit (CCF.Capabilities.record self) state self).run {} with
  | none => simp [executed] at enabled
  | some result =>
      obtain ⟨after, effects⟩ := result
      refine ⟨after, effects, rfl, ?_⟩
      have frontier := advanceCommit_frontier state self after effects executed
      by_cases committed : index <= state.commitIndex
      · grind
      · have := highestCommittableIndex_ge state self index ready (by omega)
        grind

end CCFRaft.Proofs.Liveness
