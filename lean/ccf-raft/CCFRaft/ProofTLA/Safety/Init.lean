module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Safety.Derived

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The invariant holds initially

The initial history has one state and no records besides the bootstrap leader.
-/

namespace CCFRaft.ProofTLA.Safety

open CCF
open Model.Node

variable [Model.ModelConfig]

section Initial

variable {nodes : List NodeID} {initial : Model.State}
  (initialized : (Model.transitionSystem (inferInstance) nodes).init initial)
include initialized

theorem initial_state {node : NodeID} {state : NodeState}
    (member : (node, state) ∈ initial.nodes)
    : state = Model.initialNodeState (inferInstance) node :=
  initialized.2.2.2.2.2 _ member

theorem initial_seen {node : NodeID} {state : NodeState}
    (seen : Seen [initial] node state)
    : state = Model.initialNodeState (inferInstance) node := by
  obtain ⟨current, member, mem⟩ := seen
  rw [List.mem_singleton.mp member] at mem
  exact initial_state initialized mem

omit initialized in
theorem not_elected_single {current : Model.State} {node : NodeID}
    {term commit : Nat} {log : List (Entry)}
    : Not (Elected [current] node term log commit) := by
  rintro ⟨after, before, rest, suffix, -⟩
  have := suffix.length_le
  simp at this

omit initialized in
theorem led_single {current : Model.State} {node : NodeID} {term : Nat}
    (led : Led [current] node term)
    : term = Model.BOOTSTRAP_TERM
      /\ node = ((inferInstance : Model.ModelConfig).primary : NodeID) := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact bootstrap
  · exact absurd elected not_elected_single

theorem initial_canon {term : Nat} {log : List (Entry)} (canon : Canon [initial] term log)
    : term = Model.BOOTSTRAP_TERM
      /\ log
          = (Model.initialNodeState (inferInstance)
                ((inferInstance : Model.ModelConfig).primary : NodeID)
              : NodeState).log := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, -, led⟩, rfl⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · obtain ⟨bootstrap, rfl⟩ := led_single led
    exact ⟨bootstrap, by rw [initial_state initialized now]⟩
  · rw [List.eq_nil_of_suffix_nil inner] at now
    exact absurd now id

theorem inv_initial : Inv [initial] := by
  have leaderMem := ((inferInstance : Model.ModelConfig).primary).2
  have stateOf : forall {node : NodeID} {state : NodeState},
      Now [initial] node state -> state = Model.initialNodeState (inferInstance) node :=
    fun now => initial_state initialized now
  constructor
  · intro node state now entry member
    rw [stateOf now] at member ⊢
    by_cases leader : node = ((inferInstance : Model.ModelConfig).primary : NodeID)
    · subst leader
      simp_all [Model.initialNodeState]
    · simp [Model.initialNodeState, leader] at member
  · intro node state now
    rw [stateOf now]
    unfold Model.initialNodeState
    split <;> simp
  · intro node state now active
    rw [stateOf now] at active ⊢
    simp only [Model.initialNodeState] at active ⊢
    split_ifs at active ⊢ <;> simp_all [Model.BOOTSTRAP_TERM]
  · intro node state earlier now seen
    rw [stateOf now, initial_seen initialized seen]
  · intro node state earlier candidate now seen voted
    rw [initial_seen initialized seen] at voted
    simp [Model.initialNodeState] at voted
  · intro node state term now led
    obtain ⟨rfl, rfl⟩ := led_single led
    rw [stateOf now]
    right
    simp [Model.initialNodeState, leaderMem]
  · intro node state now leader
    left
    rw [stateOf now] at leader ⊢
    by_cases isLeader : node = ((inferInstance : Model.ModelConfig).primary : NodeID)
    · subst isLeader
      simp [Model.initialNodeState, leaderMem]
    · simp only [Model.initialNodeState, isLeader, ite_false] at leader
      split at leader <;> cases leader
  · intro node state now candidate
    rw [stateOf now] at candidate
    simp only [Model.initialNodeState] at candidate
    split_ifs at candidate
  · intro after before rest node term log commit suffix
    have := suffix.length_le
    simp at this
  · intro node other term left right
    rw [(led_single left).2, (led_single right).2]
  · intro node state now _ led
    obtain ⟨-, rfl⟩ := led_single led
    refine ⟨fun log canon => ?_, fun log commit elected => absurd elected not_elected_single⟩
    rw [(initial_canon initialized canon).2, stateOf now]
  · intro node state index now positive bound
    rw [stateOf now] at bound ⊢
    by_cases isLeader : node = ((inferInstance : Model.ModelConfig).primary : NodeID)
    · subst isLeader
      have one : index = 1 := by
        simp [Model.initialNodeState] at bound
        omega
      subst one
      refine ⟨_, ⟨[initial], List.suffix_refl _, _, _,
        ⟨now, ?_, ?_, Or.inl ⟨?_, rfl⟩⟩, rfl⟩, ?_, ?_⟩
      · rw [stateOf now]
        simp [Model.initialNodeState, leaderMem, Model.BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        simp [Model.initialNodeState]
      · simp [Model.initialNodeState, Model.BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        exact bound
      · rw [stateOf now]
    · simp [Model.initialNodeState, isLeader] at bound
      omega
  · intro term part node later log commit _ elected
    exact absurd elected not_elected_single
  · intro node state now
    left
    rw [stateOf now]
    rfl
  · intro node state earlier index now seen _
    left
    rw [stateOf now, initial_seen initialized seen]
    exact List.take_prefix _ _
  · intro node state peer now _ _ positive
    rw [stateOf now] at positive
    simp [Model.initialNodeState] at positive
  · intro envelope pending
    simp [Pending, initialized.2.2.2.2.1] at pending
  · intro envelope pending
    simp [Pending, initialized.2.2.2.2.1] at pending
  · intro node state now
    rw [stateOf now]
    by_cases isLeader : node = ((inferInstance : Model.ModelConfig).primary : NodeID)
    · subst isLeader
      simp [Model.initialNodeState, genesisEntry]
    · simp only [Model.initialNodeState, isLeader, ite_false]
      refine ⟨by simp, ?_⟩
      split <;> simp

end Initial

end CCFRaft.ProofTLA.Safety
