module

public import CCFRaft.Proofs.Replication.Eligible
public import CCFRaft.Proofs.Liveness

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Owed retirement confirmations

A primary whose commit scan has just run cannot hold an uncommitted signature
that it alone makes committable, unless that scan retired the other members of
the configurations before the signature. Those members then owe retirement
confirmations, provided none was in the log while they were active.
-/

open CCF
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety

namespace CCFRaft.Proofs.Replication

/-- An uncommitted current-term signature, every active configuration at or
before which is the primary alone. -/
def AloneReady (state : NodeState) (self : NodeID) (signature : Nat) : Prop :=
  state.commitIndex < signature
  /\ isSignatureAt state.log signature = true
  /\ termAt state.log signature = state.currentTerm
  /\ (exists configuration,
        configuration ∈ state.activeConfigurations /\ configuration.index <= signature)
  /\ forall configuration,
      configuration ∈ state.activeConfigurations
      -> configuration.index <= signature
      -> configuration.nodes = {self}

/-- Some retirement is complete but not yet confirmed anywhere in the log. -/
def Owed (state : NodeState) : Prop :=
  (state.retirementCompletedNodes \ retiredCommittedNodes state.log).Nonempty

/-- No member of an active configuration has a confirmation that remains in
force in any prefix covering that configuration. -/
def Fresh (state : NodeState) : Prop :=
  forall configuration,
    configuration ∈ state.activeConfigurations
    -> forall node,
        node ∈ configuration.nodes
        -> forall bound,
            configuration.index <= bound
            -> node ∉ retiredCommittedNodes (state.log.take bound)

/-- A higher commit index leaves a suffix of the active configurations. -/
theorem activeConfigurations_suffix (log : List Entry) {small large : Nat}
    (le : small <= large)
    : activeConfigurations log large <:+ activeConfigurations log small := by
  unfold activeConfigurations
  have mono := length_filter_index_mono (configurationHistory log) le
  have eq
      : (configurationHistory log).drop
          (((configurationHistory log).filter
              fun configuration => configuration.index <= large).length - 1)
        = ((configurationHistory log).drop
            (((configurationHistory log).filter
                fun configuration => configuration.index <= small).length - 1)).drop
          (((configurationHistory log).filter
              fun configuration => configuration.index <= large).length - 1
            - (((configurationHistory log).filter
                fun configuration => configuration.index <= small).length - 1)) := by
    rw [List.drop_drop]
    congr 1
    omega
  rw [eq]
  exact List.drop_suffix _ _

theorem signature_le_length {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  by_contra beyond
  have none : log[index - 1]? = none := List.getElem?_eq_none (by omega)
  simp [isSignatureAt, entryAt?, none] at signature

/-- A configuration dropped by a commit scan that left the primary alone has a
member other than the primary, whose retirement is then complete. -/
theorem popped_owed {self : NodeID} {middle state : NodeState}
    (logEq : state.log = middle.log)
    (fresh : Fresh middle)
    {signature : Nat} (below : state.commitIndex < signature)
    (single
      : forall configuration,
          configuration ∈ state.activeConfigurations
          -> configuration.index <= signature
          -> configuration.nodes = {self})
    {configuration : Configuration}
    (inMiddle : configuration ∈ middle.activeConfigurations)
    (dropped : configuration ∉ state.activeConfigurations)
    {node : NodeID} (inNodes : node ∈ configuration.nodes) (other : Not (node = self))
    : Owed state := by
  obtain ⟨rest, split, later⟩ :=
    configurationHistory_split state.log state.commitIndex
  have inside
      : forall configuration,
          configuration ∈ configurationHistory (state.log.take state.commitIndex)
          -> configuration.index <= state.commitIndex := by
    intro configuration member
    have := configurationHistory_index_le _ member
    simp only [List.length_take] at this
    omega
  have activeEq
      : state.activeConfigurations
        = (configurationHistory (state.log.take state.commitIndex)).drop
            ((configurationHistory (state.log.take state.commitIndex)).length - 1)
          ++ rest := by
    unfold NodeState.activeConfigurations activeConfigurations
    dsimp only
    rw [split, filter_index_split inside later]
    rw [List.drop_append_of_le_length (by omega)]
  have historyEq : configurationHistory middle.log
      = configurationHistory (state.log.take state.commitIndex) ++ rest := by
    rw [← logEq]
    exact split
  have inHistory : configuration ∈ configurationHistory middle.log :=
    (activeConfigurations_sublist _ _).subset inMiddle
  rw [historyEq] at inHistory
  rcases List.mem_append.mp inHistory with committed | pending
  swap
  · exact absurd (by rw [activeEq]; exact List.mem_append_right _ pending) dropped
  have nonempty : configurationHistory (state.log.take state.commitIndex) ≠ [] :=
    List.ne_nil_of_mem committed
  have lastEq
      : (configurationHistory (state.log.take state.commitIndex)).drop
          ((configurationHistory (state.log.take state.commitIndex)).length - 1)
        = [(configurationHistory (state.log.take state.commitIndex)).getLast nonempty] :=
    List.drop_length_sub_one nonempty
  have lastActive
      : (configurationHistory (state.log.take state.commitIndex)).getLast nonempty
        ∈ state.activeConfigurations := by
    rw [activeEq, lastEq]
    exact List.mem_append_left _ (List.mem_singleton_self _)
  have lastSingle :=
    single _ lastActive
      (by
        have := inside _ (List.getLast_mem nonempty)
        omega)
  have unconfirmed : node ∉ retiredCommittedNodes state.log := by
    have := fresh configuration inMiddle node inNodes middle.log.length
      (configurationHistory_index_le _ ((activeConfigurations_sublist _ _).subset inMiddle))
    rwa [List.take_length, ← logEq] at this
  refine ⟨node, Finset.mem_sdiff.mpr ⟨?_, unconfirmed⟩⟩
  unfold NodeState.retirementCompletedNodes NodeState.committedLog
  refine Finset.mem_sdiff.mpr ⟨Finset.mem_sdiff.mpr ⟨?_, ?_⟩, ?_⟩
  · exact mem_configurationMembers_iff.mpr ⟨configuration, committed, inNodes⟩
  · simp only [latestConfigurationMembers, List.getLast?_eq_some_getLast nonempty, Option.map_some,
      Option.getD_some, lastSingle, Finset.mem_singleton]
    exact other
  · have := fresh configuration inMiddle node inNodes state.commitIndex
      (inside _ committed)
    rwa [← logEq] at this

/-- Right after a commit scan, a signature that the primary alone makes
committable means that some retirement confirmation is owed. -/
theorem advance_owed {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    (fresh : Fresh middle)
    {signature : Nat} (alone : AloneReady state self signature)
    : Owed state := by
  obtain ⟨below, isSignature, termEq, ⟨first, firstIn, firstLe⟩, single⟩ := alone
  have logEq := advance.log
  have currentEq := advance.term
  have commitLe := advance.commit_le
  by_contra notOwed
  have suffix : state.activeConfigurations <:+ middle.activeConfigurations := by
    unfold NodeState.activeConfigurations
    rw [logEq]
    exact activeConfigurations_suffix _ commitLe
  have allAlone
      : forall configuration,
          configuration ∈ middle.activeConfigurations
          -> configuration.index <= signature
          -> configuration.nodes = {self} := by
    intro configuration member le
    by_cases kept : configuration ∈ state.activeConfigurations
    · exact single configuration kept le
    rcases advance with ⟨rfl, _⟩ | ⟨_, _, _, _, _, _, ahead, commitEq, _⟩
    · exact absurd member kept
    have spec := highestCommittableIndex_spec middle self (by rw [← commitEq]; exact ahead)
    rw [← commitEq] at spec
    have dropped : configuration.index <= state.commitIndex := by
      by_contra beyond
      apply kept
      obtain ⟨rest, split, later⟩ := configurationHistory_split state.log state.commitIndex
      have inHistory : configuration ∈ configurationHistory state.log := by
        rw [logEq]
        exact (activeConfigurations_sublist _ _).subset member
      rw [split] at inHistory
      rcases List.mem_append.mp inHistory with committed | pending
      · have := configurationHistory_index_le _ committed
        simp only [List.length_take] at this
        omega
      · have inside
            : forall configuration,
                configuration ∈ configurationHistory (state.log.take state.commitIndex)
                -> configuration.index <= state.commitIndex := by
          intro configuration member
          have := configurationHistory_index_le _ member
          simp only [List.length_take] at this
          omega
        unfold NodeState.activeConfigurations activeConfigurations
        dsimp only
        rw [split, filter_index_split inside later,
          List.drop_append_of_le_length (by omega)]
        exact List.mem_append_right _ pending
    have majority :=
      hasQuorum_majority spec.2.2.2 (List.mem_filter.mpr ⟨member, decide_eq_true dropped⟩)
    have positive : configuration.nodes.Nonempty := by
      by_contra empty
      rw [Finset.not_nonempty_iff_eq_empty] at empty
      simp [hasConfigurationMajority, empty] at majority
    have sub : configuration.nodes ⊆ {self} := by
      intro node inNodes
      by_contra other
      exact notOwed
        (popped_owed logEq fresh below single member kept inNodes
          fun eq => other (Finset.mem_singleton.mpr eq))
    exact (Finset.Nonempty.subset_singleton_iff positive).mp sub
  have ready : SignatureReady middle self signature := by
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [← logEq]
      exact signature_le_length isSignature
    · rw [← logEq]
      exact isSignature
    · rw [← logEq, ← currentEq]
      exact termEq
    · refine ⟨?_, List.all_eq_true.mpr fun configuration member => ?_⟩
      · exact List.ne_nil_of_mem
          (List.mem_filter.mpr ⟨suffix.subset firstIn, decide_eq_true firstLe⟩)
      · obtain ⟨inActive, le⟩ := List.mem_filter.mp member
        have nodesEq := allAlone configuration inActive (of_decide_eq_true le)
        have selfIn
            : self ∈ middle.activeMembers.filter
                fun node => node = self \/ middle.matchIndex node >= signature :=
          Finset.mem_filter.mpr
            ⟨mem_configurationMembers_iff.mpr
              ⟨configuration, inActive, by rw [nodesEq]; exact Finset.mem_singleton_self _⟩,
              Or.inl rfl⟩
        simp only [hasConfigurationMajority, decide_eq_true_eq, nodesEq,
          Finset.inter_singleton_of_mem selfIn, Finset.card_singleton]
        omega
  have high := CCFRaft.Proofs.Liveness.highestCommittableIndex_ge middle self signature ready
  rcases advance with ⟨rfl, le⟩ | ⟨_, _, _, _, _, _, _, commitEq, _⟩
  · have := high below
    omega
  · have := high (by omega)
    omega

end CCFRaft.Proofs.Replication
