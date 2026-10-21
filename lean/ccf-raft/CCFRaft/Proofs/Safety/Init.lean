module

public import CCFRaft.Proofs.Safety.Derived

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The invariant holds initially

The initial history has one state and no records besides the bootstrap leader.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)

variable [Config.InitialConfiguration]

section Initial

/-- The model's initial node state, with the bootstrap primary named directly. -/
def initialLocal (node : NodeID) : NodeState where
  role :=
    if node = INITIAL_PRIMARY then
      .primary
    else if node ∈ INITIAL_CONFIGURATION then
      .follower
    else
      .none
  currentTerm := if node ∈ INITIAL_CONFIGURATION then BOOTSTRAP_TERM else 0
  log := if node = INITIAL_PRIMARY then [GENESIS] else []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  primaryKnown := node = INITIAL_PRIMARY
  votesGranted := ∅

theorem initialNodeState_eq (nonempty : INITIAL_CONFIGURATION.Nonempty) (node : NodeID)
    : initialNodeState INITIAL_CONFIGURATION node = initialLocal node := by
  simp only [initialNodeState, initialLocal, initial_primary_iff nonempty]

variable {nodes : List NodeID} {initial : Model.State}
  (initialized : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
include initialized

theorem initial_state {node : NodeID} {state : NodeState}
    (member : (node, state) ∈ initial.nodes)
    : state = initialLocal node := by
  rw [← initialNodeState_eq initialized.1]
  exact initialized.2.2.2.2 _ member

theorem initial_seen {node : NodeID} {state : NodeState}
    (seen : Seen [initial] node state)
    : state = initialLocal node := by
  obtain ⟨current, member, mem⟩ := seen
  rw [List.mem_singleton.mp member] at mem
  exact initial_state initialized mem

omit initialized in
theorem not_elected_single {current : Model.State} {node : NodeID}
    {term commit : Nat} {log : List Entry}
    : Not (Elected [current] node term log commit) := by
  rintro ⟨after, before, rest, suffix, -⟩
  have := suffix.length_le
  simp at this

omit initialized in
theorem led_single {current : Model.State} {node : NodeID} {term : Nat}
    (led : Led [current] node term)
    : term = BOOTSTRAP_TERM /\ node = INITIAL_PRIMARY := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact bootstrap
  · exact absurd elected not_elected_single

theorem initial_canon {term : Nat} {log : List Entry} (canon : Canon [initial] term log)
    : term = BOOTSTRAP_TERM /\ log = (initialLocal INITIAL_PRIMARY).log := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, -, led⟩, rfl⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · obtain ⟨bootstrap, rfl⟩ := led_single led
    exact ⟨bootstrap, by rw [initial_state initialized now]⟩
  · rw [List.eq_nil_of_suffix_nil inner] at now
    exact absurd now id

theorem inv_initial : Inv [initial] := by
  have leaderMem := INITIAL_PRIMARY_mem initialized.1
  have stateOf : forall {node : NodeID} {state : NodeState},
      Now [initial] node state -> state = initialLocal node :=
    fun now => initial_state initialized now
  constructor
  · intro node state now entry member
    rw [stateOf now] at member ⊢
    by_cases leader : node = INITIAL_PRIMARY
    · subst leader
      simp_all [initialLocal]
    · simp [initialLocal, leader] at member
  · intro node state now
    rw [stateOf now]
    unfold initialLocal
    split <;> simp
  · intro node state now active
    rw [stateOf now] at active ⊢
    simp only [initialLocal] at active ⊢
    split_ifs at active ⊢ <;> simp_all [BOOTSTRAP_TERM]
  · intro node state earlier now seen
    rw [stateOf now, initial_seen initialized seen]
  · intro node state earlier candidate now seen voted
    rw [initial_seen initialized seen] at voted
    simp [initialLocal] at voted
  · intro node state term now led
    obtain ⟨rfl, rfl⟩ := led_single led
    rw [stateOf now]
    right
    simp [initialLocal, leaderMem]
  · intro node state now leader
    left
    rw [stateOf now] at leader ⊢
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      simp [initialLocal, leaderMem]
    · simp only [initialLocal, isLeader, ite_false] at leader
      split at leader <;> cases leader
  · intro node state now candidate
    rw [stateOf now] at candidate
    simp only [initialLocal] at candidate
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
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      have one : index = 1 := by
        simp [initialLocal] at bound
        omega
      subst one
      refine ⟨_, ⟨[initial], List.suffix_refl _, _, _,
        ⟨now, ?_, ?_, Or.inl ⟨?_, rfl⟩⟩, rfl⟩, ?_, ?_⟩
      · rw [stateOf now]
        simp [initialLocal, leaderMem, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        simp [initialLocal]
      · simp [initialLocal, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        exact bound
      · rw [stateOf now]
    · simp [initialLocal, isLeader] at bound
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
    simp [initialLocal] at positive
  · intro envelope pending
    simp [Pending, initialized.2.2.2.1] at pending
  · intro envelope pending
    simp [Pending, initialized.2.2.2.1] at pending
  · intro node state now
    rw [stateOf now]
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      exact Or.inr (by simp [initialLocal])
    · exact Or.inl (by simp [initialLocal, isLeader])
  · intro node state now leader
    rw [stateOf now] at leader ⊢
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      simp [initialLocal]
    · simp only [initialLocal, isLeader, ite_false] at leader
      split at leader <;> cases leader

end Initial

end CCFRaft.Proofs.Safety
