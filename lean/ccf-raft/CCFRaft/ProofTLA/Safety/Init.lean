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

variable [Initial]

omit [Initial] in
theorem primary_mem {configuration : Finset NodeID} {node : NodeID}
    (primary : configuration.min = (node : WithTop NodeID))
    : node ∈ configuration :=
  Finset.mem_of_min (a := node) primary

theorem initial_primary {node : NodeID}
    (primary : Initial.configuration.min = (node : WithTop NodeID))
    : Model.initialNodeState Initial.configuration node
      = {
        role := .primary
        currentTerm := Model.BOOTSTRAP_TERM
        log := [genesisEntry]
        commitIndex := 0
        sentIndex := fun _ => 0
        matchIndex := fun _ => 0
        isNewFollower := false
        votedFor := none
        primaryKnown := true
        votesGranted := ∅
      } := by
  simp [Model.initialNodeState, primary, primary_mem primary, genesisEntry]

theorem initial_secondary {node : NodeID}
    (secondary : Not (Initial.configuration.min = (node : WithTop NodeID)))
    : Model.initialNodeState Initial.configuration node
      = {
        role := if node ∈ Initial.configuration then .follower else .none
        currentTerm := if node ∈ Initial.configuration then Model.BOOTSTRAP_TERM else 0
        log := []
        commitIndex := 0
        sentIndex := fun _ => 0
        matchIndex := fun _ => 0
        isNewFollower := false
        votedFor := none
        primaryKnown := false
        votesGranted := ∅
      } := by
  simp [Model.initialNodeState, secondary]

section Initial

variable {nodes : List NodeID} {initial : Model.State}
  (initialized : (Model.transitionSystem Initial.configuration nodes).init initial)
include initialized

theorem initial_state {node : NodeID} {state : NodeState}
    (member : (node, state) ∈ initial.nodes)
    : state = Model.initialNodeState Initial.configuration node :=
  initialized.2.2.2.2 _ member

theorem initial_seen {node : NodeID} {state : NodeState}
    (seen : Seen [initial] node state)
    : state = Model.initialNodeState Initial.configuration node := by
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
      /\ Initial.configuration.min = (node : WithTop NodeID) := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact bootstrap
  · exact absurd elected not_elected_single

theorem initial_canon {term : Nat} {log : List (Entry)} (canon : Canon [initial] term log)
    : term = Model.BOOTSTRAP_TERM /\ log = [genesisEntry] := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, -, led⟩, rfl⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · obtain ⟨bootstrap, primary⟩ := led_single led
    refine ⟨bootstrap, ?_⟩
    rw [initial_state initialized now, initial_primary primary]
  · rw [List.eq_nil_of_suffix_nil inner] at now
    exact absurd now id

theorem inv_initial : Inv [initial] := by
  have stateOf : forall {node : NodeID} {state : NodeState},
      Now [initial] node state -> state = Model.initialNodeState Initial.configuration node :=
    fun now => initial_state initialized now
  constructor
  · intro node state now entry member
    rw [stateOf now] at member ⊢
    by_cases leader : Initial.configuration.min = (node : WithTop NodeID)
    · rw [initial_primary leader] at member ⊢
      simp_all [genesisEntry]
    · simp [initial_secondary leader] at member
  · intro node state now
    rw [stateOf now]
    by_cases leader : Initial.configuration.min = (node : WithTop NodeID)
    · simp [initial_primary leader]
    · simp [initial_secondary leader]
  · intro node state now active
    rw [stateOf now] at active ⊢
    by_cases leader : Initial.configuration.min = (node : WithTop NodeID)
    · simp_all [initial_primary leader, Model.BOOTSTRAP_TERM]
    · rw [initial_secondary leader] at active ⊢
      split_ifs at active ⊢ <;> simp_all [Model.BOOTSTRAP_TERM]
  · intro node state earlier now seen
    rw [stateOf now, initial_seen initialized seen]
  · intro node state earlier candidate now seen voted
    rw [initial_seen initialized seen] at voted
    simp [Model.initialNodeState] at voted
  · intro node state term now led
    obtain ⟨rfl, primary⟩ := led_single led
    rw [stateOf now, initial_primary primary]
    right
    simp
  · intro node state now leader
    left
    rw [stateOf now] at leader ⊢
    by_cases isLeader : Initial.configuration.min = (node : WithTop NodeID)
    · exact ⟨by simp [initial_primary isLeader], isLeader⟩
    · rw [initial_secondary isLeader] at leader
      split at leader <;> cases leader
  · intro node state now candidate
    rw [stateOf now] at candidate
    by_cases isLeader : Initial.configuration.min = (node : WithTop NodeID)
    · rw [initial_primary isLeader] at candidate
      cases candidate
    · rw [initial_secondary isLeader] at candidate
      split at candidate <;> cases candidate
  · intro after before rest node term log commit suffix
    have := suffix.length_le
    simp at this
  · intro node other term left right
    exact WithTop.coe_injective ((led_single left).2.symm.trans (led_single right).2)
  · intro node state now _ led
    obtain ⟨-, primary⟩ := led_single led
    refine ⟨fun log canon => ?_, fun log commit elected => absurd elected not_elected_single⟩
    rw [(initial_canon initialized canon).2, stateOf now, initial_primary primary]
  · intro node state index now positive bound
    rw [stateOf now] at bound ⊢
    by_cases isLeader : Initial.configuration.min = (node : WithTop NodeID)
    · have one : index = 1 := by
        simp [initial_primary isLeader] at bound
        omega
      subst one
      refine ⟨_, ⟨[initial], List.suffix_refl _, _, _,
        ⟨now, ?_, ?_, Or.inl ⟨?_, isLeader⟩⟩, rfl⟩, ?_, ?_⟩
      · rw [stateOf now, initial_primary isLeader]
        simp [genesisEntry, Model.BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now, initial_primary isLeader]
        simp
      · simp [initial_primary isLeader, genesisEntry, Model.BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        exact bound
      · rw [stateOf now]
    · simp [initial_secondary isLeader] at bound
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
    simp [Pending, initialized.2.2.2.1] at pending
  · intro envelope pending
    simp [Pending, initialized.2.2.2.1] at pending
  · intro node state now
    rw [stateOf now]
    by_cases isLeader : Initial.configuration.min = (node : WithTop NodeID)
    · simp [initial_primary isLeader]
    · simp only [initial_secondary isLeader]
      split <;> simp

end Initial

end CCFRaft.ProofTLA.Safety
