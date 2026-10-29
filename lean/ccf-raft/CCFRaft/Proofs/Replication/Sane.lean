module

public import CCFRaft.Proofs.Replication.Confirm
public import CCFRaft.Proofs.Safety.Follower

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Retirement confirmations and rejoins follow committed history

Every retirement confirmation in a node's log follows a removal of its node that
the node has committed, and no configuration names that node from the removal to
the confirmation. Every configuration that re-adds a node follows a confirmation
of it that the node has committed, and no configuration names the node in
between. A primary appends both only when its own commit index covers them; a
follower receives them with its sender's commit index, or with a signature after
them, which its commit scan then covers.
-/

open CCF
open CCFRaft.Model.Node
open CCFRaft.Proofs.Safety

namespace CCFRaft.Proofs.Replication

variable [Config.InitialConfiguration]

/-! ## Logs -/

theorem mem_history_take {log : List Entry} {count : Nat} {configuration : Configuration}
    : configuration ∈ configurationHistory (log.take count)
      <-> configuration ∈ configurationHistory log /\ configuration.index <= count := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split log count
  constructor
  · intro member
    refine ⟨by rw [split]; exact List.mem_append_left _ member, ?_⟩
    have := configurationHistory_index_le _ member
    simp only [List.length_take] at this
    omega
  · rintro ⟨member, le⟩
    rw [split] at member
    rcases List.mem_append.mp member with done | pending
    · exact done
    · have := later _ pending
      omega

theorem history_index_pos {log : List Entry} {configuration : Configuration}
    (member : configuration ∈ configurationHistory log)
    : 0 < configuration.index := by
  unfold configurationHistory at member
  have := mem_history_filterMap member
  omega

theorem take_agree_of_prefix {small large : List Entry} (sub : small <+: large)
    {count : Nat} (le : count <= small.length)
    : small.take count = large.take count := by
  rw [List.prefix_iff_eq_take.mp sub, List.take_take, Nat.min_eq_left le]

theorem isSignatureAt_agree {log log' : List Entry} {count index : Nat}
    (same : log.take count = log'.take count) (le : index <= count)
    (signature : isSignatureAt log index = true)
    : isSignatureAt log' index = true := by
  have taken := Ledger.isSignatureAt_take_of_le le signature
  rw [same] at taken
  exact Ledger.isSignatureAt_of_prefix (List.take_prefix _ _) taken

theorem le_maxCommittableIndexUpTo {log : List Entry} {index bound : Nat}
    (signature : isSignatureAt log index = true) (le : index <= bound)
    : index <= maxCommittableIndexUpTo log bound := by
  unfold maxCommittableIndexUpTo
  exact Ledger.signatureIndex_le_maxCommittableIndex (Ledger.isSignatureAt_take_of_le le signature)

/-- The last element of a list sorted by index has the largest index. -/
theorem index_lt_getLast {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    (nonempty : configurations ≠ []) {configuration : Configuration}
    (member : configuration ∈ configurations)
    (different : Not (configuration = configurations.getLast nonempty))
    : configuration.index < (configurations.getLast nonempty).index := by
  have split := List.dropLast_append_getLast nonempty
  rw [← split] at sorted member
  rw [List.pairwise_append] at sorted
  rcases List.mem_append.mp member with front | last
  · exact sorted.2.2 _ front _ (List.mem_singleton_self _)
  · exact absurd (List.mem_singleton.mp last) different

theorem getElem_agree {log log' : List Entry} {count position : Nat}
    (same : log.take count = log'.take count) (lt : position < count)
    (bound : position < log.length) (bound' : position < log'.length)
    : log[position]'bound = log'[position]'bound' := by
  have := congrArg (fun l : List Entry => l[position]?) same
  simp only [List.getElem?_take, lt, ite_true, List.getElem?_eq_getElem bound,
    List.getElem?_eq_getElem bound', Option.some.injEq] at this
  exact this

theorem history_index_inj {log : List Entry} {first second : Configuration}
    (inFirst : first ∈ configurationHistory log)
    (inSecond : second ∈ configurationHistory log) (same : first.index = second.index)
    : first = second := by
  have nodup : ((configurationHistory log).map Configuration.index).Nodup :=
    (List.pairwise_map.mpr (configurationHistory_sorted log)).imp fun lt => ne_of_lt lt
  exact List.inj_on_of_nodup_map nodup inFirst inSecond same

theorem configurationHistory_append_single (log : List Entry) (entry : Entry)
    : configurationHistory (log ++ [entry])
      = configurationHistory log
        ++ (entry.content.metadata.configuration.map
              fun nodes =>
                ({ index := log.length + 1, nodes } : Configuration)).toList := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  cases configured : entry.content.metadata.configuration <;> simp [configured, Nat.add_comm]

theorem mem_history_append_single {log : List Entry} {entry : Entry}
    {configuration : Configuration}
    : configuration ∈ configurationHistory (log ++ [entry])
      <-> configuration ∈ configurationHistory log
          \/ (configuration.index = log.length + 1
              /\ entry.content.metadata.configuration = some configuration.nodes) := by
  rw [configurationHistory_append_single, List.mem_append]
  cases entry.content.metadata.configuration with
  | none => simp
  | some nodes =>
      simp only [Option.map_some, Option.toList_some, List.mem_singleton, Option.some.injEq]
      constructor
      · rintro (old | rfl)
        · exact Or.inl old
        · exact Or.inr ⟨rfl, rfl⟩
      · rintro (old | ⟨index, nodesEq⟩)
        · exact Or.inl old
        · right
          cases configuration
          simp_all

/-- The last committed configuration, followed by later ones. -/
theorem activeConfigurations_last {log : List Entry} {commit : Nat}
    (nonempty : configurationHistory (log.take commit) ≠ [])
    : exists rest,
        activeConfigurations log commit
          = [(configurationHistory (log.take commit)).getLast nonempty] ++ rest
        /\ forall configuration,
            configuration ∈ rest -> commit < configuration.index := by
  obtain ⟨rest, split, beyond⟩ := configurationHistory_split log commit
  have inside
      : forall configuration,
          configuration ∈ configurationHistory (log.take commit)
          -> configuration.index <= commit :=
    fun configuration member => (mem_history_take.mp member).2
  refine ⟨rest, ?_, beyond⟩
  unfold activeConfigurations
  dsimp only
  rw [split, filter_index_split inside beyond,
    List.drop_append_of_le_length (by omega), List.drop_length_sub_one nonempty]

/-- Every active configuration is at or after every committed configuration. -/
theorem active_index_ge {log : List Entry} {commit : Nat}
    {committed configuration : Configuration}
    (inHistory : committed ∈ configurationHistory log) (le : committed.index <= commit)
    (active : configuration ∈ activeConfigurations log commit)
    : committed.index <= configuration.index := by
  have taken := mem_history_take.mpr ⟨inHistory, le⟩
  have nonempty := List.ne_nil_of_mem taken
  obtain ⟨rest, activeEq, beyond⟩ := activeConfigurations_last nonempty
  rw [activeEq] at active
  rcases List.mem_append.mp active with last | pending
  · rw [List.mem_singleton.mp last]
    by_cases same : committed = (configurationHistory (log.take commit)).getLast nonempty
    · rw [← same]
    · exact (index_lt_getLast (configurationHistory_sorted _) nonempty taken same).le
  · have := beyond configuration pending
    omega

/-! ## Confirmed and rejoined nodes -/

/-- No configuration with index in `(after, upto]` names `node`. -/
def Absent (log : List Entry) (node : NodeID) (after upto : Nat) : Prop :=
  forall configuration,
    configuration ∈ configurationHistory log
    -> after < configuration.index
    -> configuration.index <= upto
    -> node ∉ configuration.nodes

/-- The confirmation of `node` at `position` follows a removal at or before
`bound`, and no configuration names `node` from the removal up to and including
the confirmation. -/
def Settled (log : List Entry) (node : NodeID) (position bound : Nat) : Prop :=
  exists removal,
    removal ∈ configurationHistory log
    /\ removal.index <= position
    /\ removal.index <= bound
    /\ node ∉ removal.nodes
    /\ Absent log node removal.index (position + 1)

/-- `rejoin` names `node` again after a configuration without it. -/
def Rejoins (log : List Entry) (node : NodeID) (rejoin : Configuration) : Prop :=
  rejoin ∈ configurationHistory log
  /\ node ∈ rejoin.nodes
  /\ node ∈ configurationMembers (configurationHistory (log.take (rejoin.index - 1)))
  /\ node
      ∉ latestConfigurationMembers (configurationHistory (log.take (rejoin.index - 1)))

/-- A confirmation of `node` before `bound` and before index `upto`, after which
no configuration names `node` before `upto`. -/
def Justified (log : List Entry) (node : NodeID) (upto bound : Nat) : Prop :=
  exists position,
  exists inLog : position < log.length,
    node ∈ (log[position]'inLog).content.metadata.retirementConfirmations
    /\ position < bound
    /\ position + 1 < upto
    /\ Absent log node (position + 1) (upto - 1)

/-- Confirmations and rejoins each follow a signature after what justifies them. -/
def ConfShape (log : List Entry) : Prop :=
  (forall position node (inLog : position < log.length),
    node ∈ (log[position]'inLog).content.metadata.retirementConfirmations
    -> exists signature,
        signature <= position
        /\ isSignatureAt log signature = true
        /\ Settled log node position signature)
  /\ forall node rejoin,
      Rejoins log node rejoin
      -> exists signature,
          signature < rejoin.index
          /\ isSignatureAt log signature = true
          /\ Justified log node rejoin.index signature

/-- Confirmations and rejoins are justified by the committed prefix. -/
def ConfSane (state : NodeState) : Prop :=
  ConfShape state.log
  /\ (forall position node (inLog : position < state.log.length),
        node ∈ (state.log[position]'inLog).content.metadata.retirementConfirmations
        -> Settled state.log node position state.commitIndex)
  /\ forall node rejoin,
      Rejoins state.log node rejoin
      -> Justified state.log node rejoin.index state.commitIndex

/-! ## Agreeing logs -/

section Agree

variable {log log' : List Entry} {count : Nat} (same : log.take count = log'.take count)

include same

theorem history_agree {configuration : Configuration}
    (member : configuration ∈ configurationHistory log)
    (le : configuration.index <= count)
    : configuration ∈ configurationHistory log' := by
  have taken := mem_history_take.mpr ⟨member, le⟩
  rw [same] at taken
  exact (mem_history_take.mp taken).1

theorem Absent.agree {node : NodeID} {after upto : Nat}
    (absent : Absent log node after upto) (le : upto <= count)
    : Absent log' node after upto :=
  fun configuration member lt bounded =>
    absent configuration (history_agree same.symm member (by omega)) lt bounded

theorem Settled.agree {node : NodeID} {position bound : Nat}
    (settled : Settled log node position bound) (le : position + 1 <= count)
    : Settled log' node position bound := by
  obtain ⟨removal, inHistory, before, within, absent, after⟩ := settled
  exact ⟨
    removal,
    history_agree same inHistory (by omega),
    before,
    within,
    absent,
    after.agree same le
  ⟩

theorem length_agree {position : Nat} (lt : position < count)
    (inLog : position < log.length)
    : position < log'.length := by
  have lengths := congrArg List.length same
  simp only [List.length_take] at lengths
  omega

theorem Justified.agree {node : NodeID} {upto bound : Nat}
    (justified : Justified log node upto bound) (le : upto <= count)
    : Justified log' node upto bound := by
  obtain ⟨position, inLog, member, below, before, absent⟩ := justified
  have inLog' := length_agree same (by omega) inLog
  refine ⟨position, inLog', ?_, below, before, absent.agree same (by omega)⟩
  rw [← getElem_agree same (by omega) inLog inLog']
  exact member

theorem Rejoins.agree {node : NodeID} {rejoin : Configuration}
    (rejoins : Rejoins log node rejoin) (le : rejoin.index <= count)
    : Rejoins log' node rejoin := by
  obtain ⟨inHistory, member, earlier, notLatest⟩ := rejoins
  have prefixEq : log.take (rejoin.index - 1) = log'.take (rejoin.index - 1) := by
    have := congrArg (List.take (rejoin.index - 1)) same
    simpa [List.take_take, Nat.min_eq_left (show rejoin.index - 1 <= count by omega)]
      using this
  exact ⟨
    history_agree same inHistory le,
    member,
    prefixEq ▸ earlier,
    prefixEq ▸ notLatest
  ⟩

theorem ConfShape.agree_confirmation (shape : ConfShape log) {position : Nat}
    {node : NodeID} (lt : position < count) (inLog : position < log'.length)
    (member : node ∈ (log'[position]'inLog).content.metadata.retirementConfirmations)
    : exists signature,
        signature <= position
        /\ isSignatureAt log' signature = true
        /\ Settled log' node position signature := by
  have inLog' := length_agree same.symm lt inLog
  rw [← getElem_agree same lt inLog' inLog] at member
  obtain ⟨signature, le, isSignature, settled⟩ := shape.1 position node inLog' member
  exact ⟨
    signature,
    le,
    isSignatureAt_agree same (by omega) isSignature,
    settled.agree same (by omega)
  ⟩

theorem ConfShape.agree_rejoin (shape : ConfShape log) {node : NodeID}
    {rejoin : Configuration} (rejoins : Rejoins log' node rejoin)
    (le : rejoin.index <= count)
    : exists signature,
        signature < rejoin.index
        /\ isSignatureAt log' signature = true
        /\ Justified log' node rejoin.index signature := by
  obtain ⟨signature, lt, isSignature, justified⟩ := shape.2 node rejoin (rejoins.agree same.symm le)
  exact ⟨
    signature,
    lt,
    isSignatureAt_agree same (by omega) isSignature,
    justified.agree same le
  ⟩

end Agree

theorem Settled.mono {log : List Entry} {node : NodeID} {position bound bound' : Nat}
    (settled : Settled log node position bound) (le : bound <= bound')
    : Settled log node position bound' := by
  obtain ⟨removal, inHistory, before, within, absent, after⟩ := settled
  exact ⟨removal, inHistory, before, within.trans le, absent, after⟩

theorem Justified.mono {log : List Entry} {node : NodeID} {upto bound bound' : Nat}
    (justified : Justified log node upto bound) (le : bound <= bound')
    : Justified log node upto bound' := by
  obtain ⟨position, inLog, member, below, before, absent⟩ := justified
  exact ⟨position, inLog, member, by omega, before, absent⟩

theorem Rejoins.index_le {log : List Entry} {node : NodeID} {rejoin : Configuration}
    (rejoins : Rejoins log node rejoin)
    : rejoin.index <= log.length :=
  configurationHistory_index_le _ rejoins.1

theorem ConfShape.of_prefix {small large : List Entry} (shape : ConfShape large)
    (sub : small <+: large)
    : ConfShape small := by
  have same := (take_agree_of_prefix sub (le_refl small.length)).symm
  rw [List.take_length] at same
  have same' : large.take small.length = small.take small.length := by
    rw [List.take_length]
    exact same
  exact ⟨fun position node inLog member =>
      shape.agree_confirmation same' inLog inLog member,
    fun node rejoin rejoins => shape.agree_rejoin same' rejoins rejoins.index_le⟩

/-- A prefix that keeps the committed prefix keeps `ConfSane`. -/
theorem ConfSane.of_prefix {state after : NodeState} (sane : ConfSane state)
    (sub : after.log <+: state.log)
    (commitLe : state.commitIndex <= after.commitIndex)
    : ConfSane after := by
  have same : state.log.take after.log.length = after.log.take after.log.length := by
    rw [List.take_length]
    exact (List.prefix_iff_eq_take.mp sub).symm
  refine ⟨sane.1.of_prefix sub, fun position node inLog member => ?_,
    fun node rejoin rejoins => ?_⟩
  · have inLog' := length_agree same.symm inLog inLog
    rw [← getElem_agree same inLog inLog' inLog] at member
    exact ((sane.2.1 position node inLog' member).agree same inLog).mono commitLe
  · exact ((sane.2.2 node rejoin (rejoins.agree same.symm rejoins.index_le)).agree same
      rejoins.index_le).mono commitLe

theorem ConfSane.of_log {state after : NodeState} (sane : ConfSane state)
    (logEq : after.log = state.log) (commitLe : state.commitIndex <= after.commitIndex)
    : ConfSane after :=
  sane.of_prefix (logEq ▸ List.prefix_refl _) commitLe

/-! ## Confirmations in force -/

theorem retiredCommittedNodes_append_single (log : List Entry) (entry : Entry)
    : retiredCommittedNodes (log ++ [entry])
      = (retiredCommittedNodes log \ entry.content.metadata.configuration.getD ∅)
        ∪ entry.content.metadata.retirementConfirmations := by
  simp [retiredCommittedNodes, List.foldl_append]

theorem absent_append_single {log : List Entry} {entry : Entry} {node : NodeID}
    {after : Nat} (le : after <= log.length)
    : Absent (log ++ [entry]) node after (log.length + 1)
      <-> Absent log node after log.length
          /\ node ∉ entry.content.metadata.configuration.getD ∅ := by
  constructor
  · intro absent
    refine ⟨
      fun configuration member lt bounded =>
        absent configuration (mem_history_append_single.mpr (Or.inl member)) lt
          (by omega),
      ?_
    ⟩
    cases configured : entry.content.metadata.configuration with
    | none => simp
    | some nodes =>
        simp only [Option.getD_some]
        exact absent { index := log.length + 1, nodes }
          (mem_history_append_single.mpr (Or.inr ⟨rfl, configured⟩)) (by simp; omega)
          le_rfl
  · rintro ⟨absent, fresh⟩ configuration member lt bounded
    rcases mem_history_append_single.mp member with old | ⟨index, configured⟩
    · exact absent configuration old lt (configurationHistory_index_le _ old)
    · rw [configured, Option.getD_some] at fresh
      exact fresh

/-- A node is confirmed when some confirmation of it is not followed by a
configuration naming it. -/
theorem mem_retiredCommittedNodes {log : List Entry} {node : NodeID}
    : node ∈ retiredCommittedNodes log
      <-> exists position,
      exists inLog : position < log.length,
        node ∈ (log[position]'inLog).content.metadata.retirementConfirmations
        /\ Absent log node (position + 1) log.length := by
  induction log using List.reverseRecOn with
  | nil => simp [retiredCommittedNodes]
  | append_singleton log entry ih =>
      rw [retiredCommittedNodes_append_single, Finset.mem_union, Finset.mem_sdiff, ih]
      simp only [List.length_append, List.length_singleton]
      constructor
      · rintro (⟨⟨position, inLog, member, absent⟩, fresh⟩ | member)
        · refine ⟨position, by omega, ?_, ?_⟩
          · rw [List.getElem_append_left inLog]
            exact member
          · exact (absent_append_single (by omega)).mpr
              ⟨fun configuration inHistory lt bounded =>
                absent configuration inHistory lt bounded, fresh⟩
        · refine ⟨log.length, by omega, ?_, fun _ _ lt bounded => absurd bounded (by omega)⟩
          rw [List.getElem_append_right (le_refl _)]
          simpa using member
      · rintro ⟨position, inLog, member, absent⟩
        by_cases old : position < log.length
        · rw [List.getElem_append_left old] at member
          obtain ⟨absent', fresh⟩ := (absent_append_single (by omega)).mp absent
          exact Or.inl ⟨⟨position, old, member, absent'⟩, fresh⟩
        · have last : position = log.length := by omega
          subst last
          rw [List.getElem_append_right (le_refl _)] at member
          right
          simpa using member

/-- No member of an active configuration has a confirmation in force. -/
theorem fresh_of_sane {state : NodeState} (sane : ConfSane state) : Fresh state := by
  intro configuration active node inNodes bound le confirmed
  obtain ⟨position, inTake, member, absent⟩ := mem_retiredCommittedNodes.mp confirmed
  have inLog : position < state.log.length := by
    simp only [List.length_take] at inTake
    omega
  rw [List.getElem_take] at member
  obtain ⟨removal, inHistory, before, committed, notRemoved, after⟩ :=
    sane.2.1 position node inLog member
  have inActive : configuration ∈ configurationHistory state.log :=
    (activeConfigurations_sublist _ _).subset active
  have ge := active_index_ge inHistory committed active
  rcases Nat.lt_or_ge removal.index configuration.index with later | same
  · by_cases early : configuration.index <= position + 1
    · exact after configuration inActive later early inNodes
    · have bounded : configuration.index <= (state.log.take bound).length := by
        simp only [List.length_take]
        have := configurationHistory_index_le _ inActive
        omega
      exact absent configuration (mem_history_take.mpr ⟨inActive, le⟩) (by omega) bounded
        inNodes
  · have := history_index_inj inHistory inActive (by omega)
    rw [this] at notRemoved
    exact notRemoved inNodes

/-! ## Appending guarded entries -/

theorem not_latest_of_absent {log : List Entry} {node : NodeID} {removal : Configuration}
    (inHistory : removal ∈ configurationHistory log) (notRemoved : node ∉ removal.nodes)
    (absent : Absent log node removal.index log.length)
    : node ∉ latestConfigurationMembers (configurationHistory log) := by
  have nonempty := List.ne_nil_of_mem inHistory
  simp only [latestConfigurationMembers, List.getLast?_eq_some_getLast nonempty,
    Option.map_some, Option.getD_some]
  by_cases same : removal = (configurationHistory log).getLast nonempty
  · rw [← same]
    exact notRemoved
  · exact absent _ (List.getLast_mem nonempty)
      (index_lt_getLast (configurationHistory_sorted _) nonempty inHistory same)
      (configurationHistory_index_le _ (List.getLast_mem nonempty))

/-- A node with complete retirement is not named by any configuration after the
last committed one, which removed it. -/
theorem completed_absent {state : NodeState} (sane : ConfSane state) {node : NodeID}
    (completed : node ∈ state.retirementCompletedNodes)
    : exists removal,
        removal ∈ configurationHistory state.log
        /\ removal.index <= state.commitIndex
        /\ node ∉ removal.nodes
        /\ Absent state.log node removal.index state.log.length
        /\ node ∈ configurationMembers (configurationHistory state.log) := by
  unfold NodeState.retirementCompletedNodes NodeState.committedLog at completed
  obtain ⟨⟨wasMember, notLatest⟩, notConfirmed⟩ :=
    And.intro (Finset.mem_sdiff.mp (Finset.mem_sdiff.mp completed).1)
      (Finset.mem_sdiff.mp completed).2
  obtain ⟨earlier, inEarlier, inNodes⟩ := mem_configurationMembers_iff.mp wasMember
  have nonempty := List.ne_nil_of_mem inEarlier
  simp only [latestConfigurationMembers, List.getLast?_eq_some_getLast nonempty,
    Option.map_some, Option.getD_some] at notLatest
  have lastIn := mem_history_take.mp (List.getLast_mem nonempty)
  have earlierIn := mem_history_take.mp inEarlier
  refine ⟨_, lastIn.1, lastIn.2, notLatest, ?_,
    mem_configurationMembers_iff.mpr ⟨earlier, earlierIn.1, inNodes⟩⟩
  intro configuration inHistory lt _ named
  classical
  have exists_named
      : exists index, exists configuration,
          configuration ∈ configurationHistory state.log
          /\ configuration.index = index
          /\ ((configurationHistory (state.log.take state.commitIndex)).getLast
                nonempty).index < index
          /\ node ∈ configuration.nodes :=
    ⟨_, configuration, inHistory, rfl, lt, named⟩
  obtain ⟨rejoin, rejoinIn, rejoinIndex, rejoinAfter, rejoinNamed⟩ := Nat.find_spec exists_named
  have pending : state.commitIndex < rejoin.index := by
    by_contra committed
    have taken :=
      mem_history_take.mpr ⟨rejoinIn, (by omega : rejoin.index <= state.commitIndex)⟩
    by_cases same
        : rejoin = (configurationHistory (state.log.take state.commitIndex)).getLast nonempty
    · rw [same] at rejoinIndex
      omega
    · have := index_lt_getLast (configurationHistory_sorted _) nonempty taken same
      omega
  have rejoins : Rejoins state.log node rejoin := by
    refine ⟨rejoinIn, rejoinNamed, ?_, ?_⟩
    · exact mem_configurationMembers_iff.mpr
        ⟨earlier, mem_history_take.mpr ⟨earlierIn.1, by omega⟩, inNodes⟩
    · have lastBefore :=
        (mem_history_take (count := rejoin.index - 1)).mpr ⟨lastIn.1, by omega⟩
      have previous := List.ne_nil_of_mem lastBefore
      simp only [latestConfigurationMembers, List.getLast?_eq_some_getLast previous,
        Option.map_some, Option.getD_some]
      have beforeIn := mem_history_take.mp (List.getLast_mem previous)
      by_cases same
          : (configurationHistory (state.log.take state.commitIndex)).getLast nonempty
            = (configurationHistory (state.log.take (rejoin.index - 1))).getLast previous
      · rw [← same]
        exact notLatest
      · have lt' := index_lt_getLast (configurationHistory_sorted _) previous lastBefore same
        intro beforeNamed
        exact Nat.find_min exists_named (show _ < Nat.find exists_named by omega)
          ⟨_, beforeIn.1, rfl, lt', beforeNamed⟩
  obtain ⟨position, inLog, member, below, _, absent⟩ := sane.2.2 node rejoin rejoins
  apply notConfirmed
  refine mem_retiredCommittedNodes.mpr ⟨position, by simp; omega, ?_, ?_⟩
  · rw [List.getElem_take]
    exact member
  · intro other otherIn otherAfter otherBounded
    have otherTaken := mem_history_take.mp otherIn
    simp only [List.length_take] at otherBounded
    exact absent other otherTaken.1 otherAfter (by omega)

theorem ConfSane.extend {state : NodeState} (sane : ConfSane state)
    (frontier : Direct.CommitFrontier state) {content : EntryContent}
    (guarded : Guarded state content) (term : Nat)
    : ConfSane
        {
          state with
            log := state.log ++ [({ term := term, content := content } : Entry)]
        } := by
  obtain ⟨confirmations, rejoinGuard⟩ := guarded
  have frontierLe := frontier.1
  have same : state.log.take state.log.length
      = (state.log ++ [({ term := term, content := content } : Entry)]).take state.log.length := by
    rw [List.take_left' rfl, List.take_length]
  have settledNew
      : forall node,
          node ∈ content.metadata.retirementConfirmations
          -> 0 < state.commitIndex
            /\ Settled (state.log ++ [({ term := term, content := content } : Entry)]) node state.log.length
                state.commitIndex := by
    intro node member
    obtain ⟨completed, unconfirmed⟩ := Finset.mem_sdiff.mp (confirmations member)
    obtain ⟨removal, inHistory, committed, notRemoved, absent, wasMember⟩ :=
      completed_absent sane completed
    have positive := history_index_pos inHistory
    refine ⟨
      by omega,
      removal,
      mem_history_append_single.mpr (Or.inl inHistory),
      by omega,
      committed,
      notRemoved,
      ?_
    ⟩
    refine (absent_append_single (by omega)).mpr ⟨absent, ?_⟩
    cases configured : content.metadata.configuration with
    | none => simp
    | some nodes =>
        simp only [Option.getD_some]
        intro named
        exact unconfirmed (Finset.mem_inter.mp (rejoinGuard nodes configured
          (Finset.mem_sdiff.mpr ⟨Finset.mem_inter.mpr ⟨named, wasMember⟩,
            not_latest_of_absent inHistory notRemoved absent⟩))).2
  have justifiedNew
      : forall node nodes,
          content.metadata.configuration = some nodes
          -> node ∈ nodes
          -> node ∈ configurationMembers (configurationHistory state.log)
          -> node ∉ latestConfigurationMembers (configurationHistory state.log)
          -> 0 < state.commitIndex
            /\ Justified (state.log ++ [({ term := term, content := content } : Entry)]) node (state.log.length + 1)
                state.commitIndex := by
    intro node nodes configured named wasMember notLatest
    obtain ⟨committedConfirmed, confirmed⟩ :=
      Finset.mem_inter.mp (rejoinGuard nodes configured
        (Finset.mem_sdiff.mpr ⟨Finset.mem_inter.mpr ⟨named, wasMember⟩, notLatest⟩))
    unfold NodeState.committedLog at committedConfirmed
    obtain ⟨position, inTake, member, absentTake⟩ :=
      mem_retiredCommittedNodes.mp committedConfirmed
    obtain ⟨position', inLog', member', absent'⟩ := mem_retiredCommittedNodes.mp confirmed
    obtain ⟨removal, _, _, committed, _, after⟩ := sane.2.1 position' node inLog' member'
    simp only [List.length_take] at inTake
    have inLog : position < state.log.length := by omega
    refine ⟨by omega, position, by simp; omega, ?_, by omega, by omega, ?_⟩
    · rw [List.getElem_append_left inLog]
      rw [List.getElem_take] at member
      exact member
    · intro configuration inHistory lt bounded
      have old : configuration ∈ configurationHistory state.log := by
        rcases mem_history_append_single.mp inHistory with old | ⟨index, _⟩
        · exact old
        · omega
      by_cases committedConfiguration : configuration.index <= state.commitIndex
      · exact absentTake configuration (mem_history_take.mpr ⟨old, committedConfiguration⟩)
          lt (by
            simp only [List.length_take]
            have := configurationHistory_index_le _ old
            omega)
      · by_cases early : configuration.index <= position' + 1
        · exact after configuration old (by omega) early
        · exact absent' configuration old (by omega) (configurationHistory_index_le _ old)
  have newRejoin
      : forall node rejoin,
          Rejoins (state.log ++ [({ term := term, content := content } : Entry)]) node rejoin
          -> Not (rejoin.index <= state.log.length)
          -> rejoin.index = state.log.length + 1
            /\ 0 < state.commitIndex
            /\ Justified (state.log ++ [({ term := term, content := content } : Entry)]) node (state.log.length + 1)
                state.commitIndex := by
    intro node rejoin rejoins beyond
    obtain ⟨inHistory, named, wasMember, notLatest⟩ := rejoins
    rcases mem_history_append_single.mp inHistory with old | ⟨index, configured⟩
    · exact absurd (configurationHistory_index_le _ old) beyond
    have takeEq : (state.log ++ [({ term := term, content := content } : Entry)]).take (rejoin.index - 1) = state.log := by
      rw [index, Nat.add_sub_cancel]
      exact List.take_left' rfl
    rw [takeEq] at wasMember notLatest
    exact ⟨index, justifiedNew node rejoin.nodes configured named wasMember notLatest⟩
  refine ⟨⟨fun position node inLog member => ?_, fun node rejoin rejoins => ?_⟩,
    fun position node inLog member => ?_, fun node rejoin rejoins => ?_⟩
  · by_cases old : position < state.log.length
    · exact sane.1.agree_confirmation same old inLog member
    · have last : position = state.log.length := by
        simp only [List.length_append, List.length_singleton] at inLog
        omega
      subst last
      rw [List.getElem_append_right (le_refl _)] at member
      simp only [Nat.sub_self, List.getElem_singleton] at member
      obtain ⟨positive, settled⟩ := settledNew node member
      exact ⟨state.commitIndex, frontierLe,
        Ledger.isSignatureAt_of_prefix (List.prefix_append _ _) (frontier.2 positive), settled⟩
  · by_cases old : rejoin.index <= state.log.length
    · exact sane.1.agree_rejoin same rejoins old
    · obtain ⟨index, positive, justified⟩ := newRejoin node rejoin rejoins old
      rw [index]
      exact ⟨state.commitIndex, by omega,
        Ledger.isSignatureAt_of_prefix (List.prefix_append _ _) (frontier.2 positive),
        justified⟩
  · by_cases old : position < state.log.length
    · have inLog' := length_agree same.symm old inLog
      rw [← getElem_agree same old inLog' inLog] at member
      exact (sane.2.1 position node inLog' member).agree same old
    · have last : position = state.log.length := by
        simp only [List.length_append, List.length_singleton] at inLog
        omega
      subst last
      rw [List.getElem_append_right (le_refl _)] at member
      simp only [Nat.sub_self, List.getElem_singleton] at member
      exact (settledNew node member).2
  · by_cases old : rejoin.index <= state.log.length
    · exact (sane.2.2 node rejoin (rejoins.agree same.symm old)).agree same old
    · obtain ⟨index, _, justified⟩ := newRejoin node rejoin rejoins old
      rw [index]
      exact justified

/-- Appending a batch of guarded entries keeps `ConfSane`. -/
theorem ConfSane.batch {before : NodeState} (sane : ConfSane before)
    (frontier : Direct.CommitFrontier before)
    : forall {entries : List Entry},
        AppendGuarded before entries
        -> ConfSane { before with log := before.log ++ entries } := by
  intro entries
  induction entries using List.reverseRecOn with
  | nil => exact fun _ => sane.of_log (by simp) le_rfl
  | append_singleton entries entry ih =>
      intro guarded
      have prefixGuarded : AppendGuarded before entries := by
        intro position bound
        have := guarded position (by simp; omega)
        rwa [List.take_append_of_le_length bound.le, List.getElem_append_left bound] at this
      have lastGuarded
          : Guarded { before with log := before.log ++ entries } entry.content := by
        have := guarded entries.length (by simp)
        rw [List.take_left' rfl, List.getElem_append_right (le_refl _)] at this
        simpa using this
      have extended :=
        (ih prefixGuarded).extend (frontier.extend (List.prefix_append _ _)) lastGuarded
          entry.term
      exact extended.of_log (by simp) le_rfl

theorem initial_sane (node : NodeID)
    : ConfSane (Model.initialNodeState Config.INITIAL_CONFIGURATION node) := by
  have empty
      : forall entry,
          entry ∈ (Model.initialNodeState Config.INITIAL_CONFIGURATION node).log
          -> entry.content.metadata.retirementConfirmations = ∅ := by
    intro entry member
    simp only [Model.initialNodeState] at member
    split at member
    · simp at member
      subst member
      rfl
    · simp at member
  have short : (Model.initialNodeState Config.INITIAL_CONFIGURATION node).log.length <= 1 := by
    simp only [Model.initialNodeState]
    split <;> simp
  have noRejoin
      : forall other rejoin,
          Not (Rejoins (Model.initialNodeState Config.INITIAL_CONFIGURATION node).log other
            rejoin) := by
    rintro other rejoin ⟨inHistory, _, wasMember, _⟩
    have := configurationHistory_index_le _ inHistory
    rw [show rejoin.index - 1 = 0 by omega, List.take_zero] at wasMember
    simp [configurationHistory, configurationMembers] at wasMember
  refine ⟨⟨fun position other inLog member => ?_, fun other rejoin rejoins => ?_⟩,
    fun position other inLog member => ?_, fun other rejoin rejoins => ?_⟩
  · rw [empty _ (List.getElem_mem inLog)] at member
    simp at member
  · exact absurd rejoins (noRejoin other rejoin)
  · rw [empty _ (List.getElem_mem inLog)] at member
    simp at member
  · exact absurd rejoins (noRejoin other rejoin)

/-! ## Steps -/

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest)

include c

theorem sane_post
    (sane : forall node state, Seen (before :: rest) node state -> ConfSane state)
    : ConfSane c.post := by
  have pre := sane c.actor c.pre c.pre_seen
  have preFrontier := c.pre_seen.frontier c.prior
  cases Summary.kind c.sum with
  | same log commit => exact pre.of_log log commit.ge
  | ack _ _ _ _ _ _ advance => exact pre.of_log advance.log advance.commit_le
  | elect wins =>
      obtain ⟨candidate, campaign, _, logEq, _, _, _, _, commitLe⟩ := Wins.facts wins
      obtain ⟨_, candidateLog, candidateCommit, _⟩ := campaign
      have sub : c.post.log <+: c.pre.log := by
        rw [logEq, ← candidateLog]
        exact primaryState_log_prefix _
      exact pre.of_prefix sub (candidateCommit ▸ commitLe)
  | append entries sent _ _ guarded advance =>
      exact (pre.batch preFrontier guarded).of_log advance.log advance.commit_le
  | accept source request eq accepted =>
      obtain ⟨earlier, sender, suffix, canon, aeok, batchBound, _, shape, prevAgree⟩ :=
        c.accept_shape eq accepted
      have senderSeen : Seen (before :: rest) source sender := canon.1.seen.mono suffix
      have senderSane := sane source sender senderSeen
      have senderFrontier := senderSeen.frontier c.prior
      obtain ⟨_, _, commitPrev, _, _, _, commitEq⟩ := accepted
      have commitLe : c.pre.commitIndex <= c.post.commitIndex := by
        rw [commitEq]
        exact le_max_left _ _
      rcases shape with same | ⟨postEq, _⟩
      · exact pre.of_log same commitLe
      have postShape : ConfShape c.post.log := by
        rw [postEq]
        exact senderSane.1.of_prefix (List.take_prefix _ _)
      have postLength
          : c.post.log.length = request.prevLogIndex + request.entries.length := by
        rw [postEq, List.length_take]
        omega
      have senderAgree
          : sender.log.take (request.prevLogIndex + request.entries.length)
            = c.post.log.take (request.prevLogIndex + request.entries.length) := by
        rw [postEq, List.take_take, Nat.min_self]
      have prevPost
          : c.pre.log.take request.prevLogIndex = c.post.log.take request.prevLogIndex := by
        rw [prevAgree, postEq, List.take_take, Nat.min_eq_left (by omega)]
      have scanned
          : forall index, isSignatureAt c.post.log index = true
            -> index <= request.primaryCommit
            -> index <= c.post.commitIndex := by
        intro index signed below
        have := le_maxCommittableIndexUpTo signed
          (bound := min request.primaryCommit
            (request.prevLogIndex + request.entries.length))
          (le_min below (by have := signature_le_length signed; omega))
        rw [commitEq]
        exact le_max_of_le_right this
      have senderCovered
          : request.entries ≠ []
            -> 0 < request.primaryCommit
            -> request.primaryCommit <= request.prevLogIndex + request.entries.length
            -> request.primaryCommit <= c.post.commitIndex := by
        intro nonempty positive within
        have commitExact := aeok.2.2.2.2.2.2 nonempty
        have signed := isSignatureAt_agree senderAgree within
          (commitExact ▸ senderFrontier.2 (commitExact ▸ positive))
        exact scanned _ signed le_rfl
      refine ⟨
        postShape,
        fun position node inLog member => ?_,
        fun node rejoin rejoins => ?_
      ⟩
      · by_cases early : position < request.prevLogIndex
        · have preBound := length_agree prevPost.symm early inLog
          rw [← getElem_agree prevPost early preBound inLog] at member
          exact ((pre.2.1 position node preBound member).agree prevPost (by omega)).mono
            commitLe
        · have nonempty : request.entries ≠ [] := by
            intro empty
            rw [empty] at postLength
            simp at postLength
            omega
          obtain ⟨signature, le, isSignature, settled⟩ := postShape.1 position node inLog member
          by_cases covered : signature <= request.primaryCommit
          · exact settled.mono (scanned signature isSignature covered)
          · have senderBound : position < sender.log.length := by omega
            rw [← getElem_agree senderAgree (by omega) senderBound inLog] at member
            have commitExact := aeok.2.2.2.2.2.2 nonempty
            have senderSettled := senderSane.2.1 position node senderBound member
            rw [← commitExact] at senderSettled
            have moved := senderSettled.agree senderAgree (by omega)
            obtain ⟨removal, inHistory, _, committed, _, _⟩ := senderSettled
            have positive := history_index_pos inHistory
            exact moved.mono (senderCovered nonempty (by omega) (by omega))
      · have bound := rejoins.index_le
        by_cases early : rejoin.index <= request.prevLogIndex
        · exact ((pre.2.2 node rejoin (rejoins.agree prevPost.symm early)).agree prevPost
            early).mono commitLe
        · have nonempty : request.entries ≠ [] := by
            intro empty
            rw [empty] at postLength
            simp at postLength
            omega
          obtain ⟨signature, lt, isSignature, justified⟩ := postShape.2 node rejoin rejoins
          by_cases covered : signature <= request.primaryCommit
          · exact justified.mono (scanned signature isSignature covered)
          · have commitExact := aeok.2.2.2.2.2.2 nonempty
            have senderJustified :=
              senderSane.2.2 node rejoin (rejoins.agree senderAgree.symm (by omega))
            rw [← commitExact] at senderJustified
            have moved := senderJustified.agree senderAgree (by omega)
            obtain ⟨position, _, _, below, _, _⟩ := senderJustified
            exact moved.mono (senderCovered nonempty (by omega) (by omega))

end Ctx

/-- Every state of every execution satisfies `ConfSane`. -/
theorem sane_of_exec {nodes : List NodeID} {history : History} (exec : Exec nodes history)
    : forall node state, Seen history node state -> ConfSane state := by
  induction exec with
  | @initial current initialized =>
      intro node state seen
      obtain ⟨_, member, mem⟩ := seen
      simp only [List.mem_singleton] at member
      subst member
      have initial : state = Model.initialNodeState Config.INITIAL_CONFIGURATION node :=
        initialized.2.2.2.2 (node, state) mem
      rw [initial]
      exact initial_sane node
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, good_of_exec prior⟩
      intro node state seen
      rcases seen.cons with now | old
      · rcases c.now_after now with ⟨_, rfl⟩ | ⟨_, old⟩
        · exact Ctx.sane_post c ih
        · exact ih node state old.seen
      · exact ih node state old

end CCFRaft.Proofs.Replication
