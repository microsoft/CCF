module

public import CCFRaft.Proofs.Replication.Peer
public import CCFRaft.Proofs.Replication.Owing

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Configurations and signatures for commitment

Facts the commit argument uses about a signature in the primary's log: its active configurations only grow as the log is extended, a set covering a quorum's members in each configuration is a quorum, and a majority other than the primary alone includes another node.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)
open HasProtocol (proto)

namespace CCFRaft.Proofs.Replication

theorem mem_configurationMembers {configurations : List Configuration}
    {configuration : Configuration} (member : configuration ∈ configurations)
    {node : NodeID} (inNodes : node ∈ configuration.nodes)
    : node ∈ configurationMembers configurations := by
  unfold configurationMembers
  suffices general
      : forall (acc : Finset NodeID) (configurations : List Configuration),
          (forall other, other ∈ acc
            -> other ∈ configurations.foldl (fun nodes next => nodes ∪ next.nodes) acc)
          /\ (configuration ∈ configurations
            -> node ∈ configurations.foldl (fun nodes next => nodes ∪ next.nodes) acc) from
    (general ∅ configurations).2 member
  intro acc configurations
  induction configurations generalizing acc with
  | nil => simp
  | cons head tail ih =>
      simp only [List.foldl_cons, List.mem_cons]
      refine ⟨fun other inAcc => (ih _).1 _ (Finset.mem_union_left _ inAcc), ?_⟩
      rintro (rfl | inTail)
      · exact (ih _).1 _ (Finset.mem_union_right _ inNodes)
      · exact (ih _).2 inTail

theorem le_length_of_isSignatureAt {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index /\ index <= log.length := by
  constructor
  · by_contra zero
    simp [isSignatureAt, entryAt?, show index = 0 by omega] at signature
  · by_contra beyond
    have none : log[index - 1]? = none := List.getElem?_eq_none (by omega)
    simp [isSignatureAt, entryAt?, none] at signature

theorem isSignatureAt_of_prefix {small large : List Entry} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : isSignatureAt large index = isSignatureAt small index := by
  have same : entryAt? large index = entryAt? small index := by
    obtain ⟨rest, rfl⟩ := sub
    unfold entryAt?
    split
    · rfl
    · rw [List.getElem?_append_left (by omega)]
  unfold isSignatureAt
  rw [same]

theorem hasQuorum_of_cover {configurations : List Configuration}
    {small large : Finset NodeID} (quorum : hasQuorum configurations small)
    (cover
      : forall configuration,
          configuration ∈ configurations
          -> forall node, node ∈ small -> node ∈ configuration.nodes -> node ∈ large)
    : hasQuorum configurations large := by
  refine ⟨quorum.1, List.all_eq_true.mpr fun configuration member => ?_⟩
  have majority := hasQuorum_majority quorum member
  simp only [hasConfigurationMajority, decide_eq_true_eq] at majority ⊢
  have sub : small ∩ configuration.nodes ⊆ large ∩ configuration.nodes := by
    intro node inter
    rw [Finset.mem_inter] at inter ⊢
    exact ⟨cover configuration member node inter.1 inter.2, inter.2⟩
  have := Finset.card_le_card sub
  omega

/-! ## Appends rerun the commit scan -/

section Append

open CCFRaft.Proofs.Direct

/-- `activeConfigurations_append`, with the appended configurations beyond the old log. -/
theorem activeConfigurations_extend {log : List Entry} {commit : Nat}
    (frontier : commit <= log.length) (extra : List Entry)
    : exists rest,
        activeConfigurations (log ++ extra) commit
          = activeConfigurations log commit ++ rest
        /\ forall configuration,
            configuration ∈ rest -> log.length < configuration.index := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split (log ++ extra) log.length
  rw [List.take_left' rfl] at split
  refine ⟨rest, ?_, later⟩
  unfold activeConfigurations
  have bound := length_filter_le (configurationHistory log) commit
  simp only [split, filter_index_append frontier later]
  rw [List.drop_append_of_le_length (by omega)]

end Append

/-- A majority of a configuration other than the primary alone includes another node. -/
theorem other_member {support : Finset NodeID} {configuration : Configuration}
    {leader : NodeID} (majority : hasConfigurationMajority support configuration)
    (notAlone : Not (configuration.nodes = {leader}))
    : exists node,
        node ∈ support /\ node ∈ configuration.nodes /\ Not (node = leader) := by
  unfold hasConfigurationMajority at majority
  generalize configuration.nodes = nodes at majority notAlone ⊢
  by_contra none
  simp only [not_exists, not_and, not_not] at none
  have sub : support ∩ nodes ⊆ {leader} := by
    intro node member
    rw [Finset.mem_inter] at member
    exact Finset.mem_singleton.mpr (none node member.1 member.2)
  have small := Finset.card_le_card sub
  rw [Finset.card_singleton] at small
  obtain ⟨node, member⟩ := Finset.card_pos.mp (show 0 < (support ∩ nodes).card by omega)
  have same := Finset.mem_singleton.mp (sub member)
  rw [same] at member
  apply notAlone
  symm
  apply Finset.eq_of_subset_of_card_le
  · intro other inSingleton
    rw [Finset.mem_singleton.mp inSingleton]
    exact (Finset.mem_inter.mp member).2
  · rw [Finset.card_singleton]
    have := Finset.card_le_card (Finset.inter_subset_right (s₁ := support) (s₂ := nodes))
    omega

end CCFRaft.Proofs.Replication
