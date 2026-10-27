module

public import CCFRaft.Proofs.Leadership.AnchorWindow
public import CCFRaft.Proofs.Liveness.MinimalGood
public import CCFRaft.Proofs.Replication.Run

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Logs stay in sync from a minimal start

While the term stays quiet among all nodes and no configuration is appended,
every node stays in the term and its log extends the primary's starting log by
entries naming no configuration. The configuration history therefore stays the
starting one, so no node the start keeps from retiring retires, and the primary's
reconfiguration stays settled.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Leadership
open CCFRaft.Proofs.StablePrimary (Acts)
open HasProtocol (proto)

variable [Config.InitialConfiguration]

/-- `log` extends `base` by entries naming no configuration. -/
def ExtendsPlain (base log : List Entry) : Prop :=
  base <+: log
  /\ forall entry,
      entry ∈ log.drop base.length -> entry.content.metadata.configuration = none

/-- Every node is in `term`, and its log extends `base` by entries naming no
configuration. -/
def Synced (base : List Entry) (term : Nat) (state : Model.State) : Prop :=
  forall node local_,
    (node, local_) ∈ state.nodes
    -> local_.currentTerm = term /\ ExtendsPlain base local_.log

/-! ## Plain extensions -/

theorem ExtendsPlain.refl (base : List Entry) : ExtendsPlain base base :=
  ⟨List.prefix_refl _, fun entry member => by simp at member⟩

/-- A plain extension keeps the configuration history. -/
theorem ExtendsPlain.history {base log : List Entry} (extended : ExtendsPlain base log)
    : configurationHistory log = configurationHistory base := by
  obtain ⟨⟨extra, rfl⟩, plain⟩ := extended
  refine configurationHistory_append_none fun entry member => plain entry ?_
  simpa using member

theorem ExtendsPlain.append {base log : List Entry} (extended : ExtendsPlain base log)
    {extra : List Entry}
    (plain : forall entry, entry ∈ extra -> entry.content.metadata.configuration = none)
    : ExtendsPlain base (log ++ extra) := by
  obtain ⟨prefix_, old⟩ := extended
  refine ⟨prefix_.trans (List.prefix_append _ _), fun entry member => ?_⟩
  rw [List.drop_append_of_le_length prefix_.length_le, List.mem_append] at member
  rcases member with member | member
  · exact old entry member
  · exact plain entry member

/-- A prefix of a plain extension on which another plain extension differs is
itself a plain extension. -/
theorem ExtendsPlain.take {base log other : List Entry} (extended : ExtendsPlain base log)
    (otherExtended : ExtendsPlain base other) {count : Nat}
    (differ : Not (log.take count = other.take count))
    : ExtendsPlain base (other.take count) := by
  obtain ⟨prefix_, plain⟩ := otherExtended
  by_cases short : count <= base.length
  · exfalso
    apply differ
    have agree
        : forall {longer : List Entry}, base <+: longer
            -> longer.take count = base.take count := by
      intro longer sub
      conv_rhs => rw [List.prefix_iff_eq_take.mp sub]
      rw [List.take_take, Nat.min_eq_left short]
    rw [agree extended.1, agree prefix_]
  · refine ⟨List.prefix_take_iff.mpr ⟨prefix_, by omega⟩, fun entry member => ?_⟩
    rw [List.drop_take] at member
    exact plain entry (List.mem_of_mem_take member)

/-- A node whose log keeps the configuration history of a log in which it is never
removed has not retired. -/
theorem not_retired_of_history {local_ : NodeState} {node : NodeID} {base : List Entry}
    (history : configurationHistory local_.log = configurationHistory base)
    (never : retirementIndexInLog node base = none)
    : Not (local_.isRetiredCommitted node) := by
  have unretired : retirementIndexInLog node local_.log = none := by
    unfold retirementIndexInLog at never ⊢
    rw [history]
    exact never
  simp [NodeState.isRetiredCommitted, NodeState.retirement, unretired]

/-! ## Settled reconfiguration -/

/-- The configurations of a log prefix are those of the log up to its length. -/
theorem history_take (log : List Entry) (count : Nat)
    : configurationHistory (log.take count)
      = (configurationHistory log).filter
          fun configuration => configuration.index <= count := by
  obtain ⟨rest, split, later⟩ := configurationHistory_split log count
  rw [split, List.filter_append]
  have dropped : (rest.filter fun configuration => configuration.index <= count) = [] :=
    List.filter_eq_nil_iff.mpr fun configuration member => by
      have := later configuration member
      simp
      omega
  rw [dropped, List.append_nil, eq_comm, List.filter_eq_self]
  intro configuration member
  have := configurationHistory_index_le _ member
  have := List.length_take_le count log
  simp
  omega

/-- Entries past every configuration name none. -/
theorem plain_after {log : List Entry} {count : Nat}
    (bound
      : forall configuration,
          configuration ∈ configurationHistory log -> configuration.index <= count)
    : forall entry,
        entry ∈ log.drop count -> entry.content.metadata.configuration = none := by
  intro entry member
  obtain ⟨position, lt, rfl⟩ := List.getElem_of_mem member
  rw [List.getElem_drop]
  have inLog : count + position < log.length := by
    simp only [List.length_drop] at lt
    omega
  cases configured : log[count + position].content.metadata.configuration with
  | none => rfl
  | some members =>
      exfalso
      have inHistory
          : ({ index := count + position + 1, nodes := members } : Configuration)
            ∈ configurationHistory log := by
        unfold configurationHistory
        refine List.mem_filterMap.mpr ⟨(log[count + position], count + position + 1), ?_, ?_⟩
        · have entryAt := List.getElem?_zipIdx (l := log) (i := 1) (j := count + position)
          rw [List.getElem?_eq_getElem inLog, Option.map_some,
            show 1 + (count + position) = count + position + 1 by omega] at entryAt
          exact List.mem_iff_getElem?.mpr ⟨_, entryAt⟩
        · simp [configured]
      have := bound _ inHistory
      simp at this

/-- Appending entries naming no configuration keeps every confirmed retirement. -/
theorem retiredCommittedNodes_plain_mono {log extra : List Entry}
    (plain : forall entry, entry ∈ extra -> entry.content.metadata.configuration = none)
    : retiredCommittedNodes log ⊆ retiredCommittedNodes (log ++ extra) := by
  induction extra using List.reverseRec with
  | nil => simp
  | append_singleton init last ih =>
      rw [← List.append_assoc, retiredCommittedNodes_append_single,
        plain last (by simp)]
      simp only [Option.getD_none, Finset.sdiff_empty]
      exact (ih fun entry member => plain entry (by simp [member])).trans
        Finset.subset_union_left

/-- At most one configuration names no node outside the latest. -/
theorem members_latest_of_short {configurations : List Configuration}
    (short : configurations.length <= 1)
    : configurationMembers configurations \ latestConfigurationMembers configurations
      = ∅ := by
  rcases configurations with _ | ⟨configuration, _ | ⟨_, _⟩⟩
  · simp [configurationMembers]
  · simp [configurationMembers, latestConfigurationMembers]
  · simp at short

/-- A settled reconfiguration stays settled as the log grows by entries naming no
configuration and the commit index grows. -/
theorem settled_of_extends {initial state : NodeState}
    (settled : ReconfigurationSettled initial)
    (extended : ExtendsPlain initial.log state.log)
    (commitLe : initial.commitIndex <= state.commitIndex)
    (frontier : initial.commitIndex <= initial.log.length)
    : ReconfigurationSettled state := by
  obtain ⟨single, completed⟩ := settled
  have history := extended.history
  have few := length_filter_index_mono (configurationHistory initial.log) commitLe
  have many := List.length_filter_le
    (fun configuration : Configuration => decide (configuration.index <= state.commitIndex))
    (configurationHistory initial.log)
  unfold NodeState.activeConfigurations activeConfigurations at single
  simp only [List.length_drop] at single
  refine ⟨?_, ?_⟩
  · unfold NodeState.activeConfigurations activeConfigurations
    simp only [List.length_drop]
    rw [history]
    omega
  · unfold NodeState.retirementCompletedNodes NodeState.committedLog at completed ⊢
    simp only at completed ⊢
    rw [history_take, history]
    rw [history_take] at completed
    by_cases all
        : forall configuration,
            configuration ∈ configurationHistory initial.log
            -> configuration.index <= initial.commitIndex
    · have keepAll
          : forall bound, initial.commitIndex <= bound
              -> ((configurationHistory initial.log).filter
                    fun configuration => configuration.index <= bound)
                = configurationHistory initial.log :=
        fun bound le => List.filter_eq_self.mpr fun configuration member => by
          have := all configuration member
          simp
          omega
      rw [keepAll _ commitLe]
      rw [keepAll _ le_rfl] at completed
      refine Finset.subset_empty.mp (completed ▸ Finset.sdiff_subset_sdiff
        (Finset.Subset.refl _) ?_)
      obtain ⟨extra, logEq⟩ := extended.1
      have split
          : state.log.take state.commitIndex
            = initial.log.take initial.commitIndex
              ++ (state.log.take state.commitIndex).drop initial.commitIndex := by
        conv_lhs =>
          rw [← List.take_append_drop initial.commitIndex
            (state.log.take state.commitIndex)]
        rw [List.take_take, Nat.min_eq_left commitLe, ← logEq,
          List.take_append_of_le_length frontier]
      rw [split]
      refine retiredCommittedNodes_plain_mono fun entry member => ?_
      rw [List.drop_take] at member
      exact plain_after
        (fun configuration member => by rw [history] at member; exact all _ member) entry
        (List.mem_of_mem_take member)
    · have notAll
          : ((configurationHistory initial.log).filter
                fun configuration => configuration.index <= initial.commitIndex).length
            < (configurationHistory initial.log).length := by
        refine lt_of_le_of_ne (List.length_filter_le _ _) fun same => all ?_
        intro configuration member
        have := List.length_filter_eq_length_iff.mp same configuration member
        simpa using this
      rw [members_latest_of_short (by omega), Finset.empty_sdiff]

/-! ## One step -/

section Step

/-- The primary of a quiet term extends its log by entries naming no configuration
when it receives only from participants and appends no configuration. -/
theorem leader_log_extends {nodes : List NodeID} {after before : Model.State}
    {rest : History} (c : Ctx nodes after before rest) {participants : Finset NodeID}
    {leader : NodeID} {term : Nat} (quiet : QuietTerm participants leader term before)
    (leaderIn : leader ∈ participants) (same : c.actor = leader)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    : exists extra,
        c.post.log = c.pre.log ++ extra
        /\ forall entry,
            entry ∈ extra -> entry.content.metadata.configuration = none := by
  obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
  have now : Now (before :: rest) c.actor local_ := by
    rw [same]
    exact lead.now
  have localEq := c.now_pre now
  have primary : c.pre.role = .primary := localEq ▸ lead.primary
  have termEq : c.pre.currentTerm = term := localEq ▸ lead.term
  have ran := c.tr.ran
  cases eventEq : c.tr.event with
  | internal input =>
      rw [eventEq] at ran
      by_cases appending : exists contents, input = .append contents
      · obtain ⟨contents, rfl⟩ := appending
        obtain ⟨log, _⟩ := CommitLiveness.append_log c.tr.actor c.tr.pre contents _ _ _ ran
        refine ⟨_, log, fun entry member => ?_⟩
        obtain ⟨content, contentIn, rfl⟩ := List.mem_map.mp member
        exact plain contents eventEq content contentIn
      · have kept := act_log c.tr.actor c.tr.pre input primary
          (fun contents eq => appending ⟨contents, eq⟩) _ _ _ ran
        exact ⟨[], by rw [List.append_nil]; exact kept, by simp⟩
  | receive source message =>
      rw [eventEq] at ran
      have kept := receive_log c.tr.actor c.tr.pre source message primary
        (fun request payloadEq => by
          obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ :=
            c.received (eventEq.trans (by rw [payloadEq]))
          have targetLeader : envelope.target = leader := targetEq.trans same
          have le := quiet.messages envelope pending
            (sourceEq ▸ isolated source message eventEq) (targetLeader ▸ leaderIn)
          rw [payload] at le
          have notTerm : Not (request.term = term) := fun current =>
            (lead.request pending payload current).2.1 targetLeader
          change request.term <= term at le
          have termEq' : c.tr.pre.currentTerm = term := termEq
          omega) _ _ _ ran
      exact ⟨[], by rw [List.append_nil]; exact kept, by simp⟩

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A node of a recorded state is listed. -/
theorem listed_of_mem {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {node : NodeID} {local_ : NodeState} (member : (node, local_) ∈ (proto point).nodes)
    : node ∈ nodes := by
  rw [← Leadership.keys_eq (admissible.reachable found)]
  exact List.mem_map.mpr ⟨_, member, rfl⟩

/-- In a good period, a participant receives only from participants. -/
theorem ctx_isolated {start : Nat} {duration : Real} {participants : Finset NodeID}
    (good : GoodBase trace start duration participants) {index : Nat}
    (within : Within trace start duration index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {rest : History}
    (c : Ctx nodes (proto step.after) (proto step.before) rest)
    (acts : Acts action c.tr.actor c.tr.event)
    : c.actor ∈ participants
      -> forall source message,
          c.event = .receive source message -> source ∈ participants := by
  intro actorIn source message eventEq
  cases action with
  | «local» node input =>
      obtain ⟨_, eventEq'⟩ := acts
      cases eventEq'.symm.trans eventEq
  | deliver envelope =>
      obtain ⟨actorEq, eventEq'⟩ := acts
      obtain ⟨sourceEq, _⟩ := Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
      rw [← sourceEq]
      exact good.isolated index step envelope within stepped (delivered_of_action selected)
        (actorEq ▸ actorIn)

/-- In a good period, no step appends a configuration. -/
theorem ctx_plain {start : Nat} {duration : Real} {participants : Finset NodeID}
    (good : GoodBase trace start duration participants) {index : Nat}
    (within : Within trace start duration index)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {rest : History}
    (c : Ctx nodes (proto step.after) (proto step.before) rest)
    (acts : Acts action c.tr.actor c.tr.event)
    : forall contents,
        c.event = .internal (.append contents)
        -> forall content, content ∈ contents -> content.metadata.configuration = none :=
  fun contents eventEq =>
    good.noReconfiguration index step c.actor contents within stepped
      (anchor_local_of_internal selected acts eventEq)

/-- A step of a good period keeps every node in the term with a plain extension of
`base`, when the term is quiet among the participants before it and no node is
past it after it. -/
theorem Synced.step {base : List Entry} {start : Nat} {duration : Real}
    {participants : Finset NodeID} {leader : NodeID} {term index : Nat}
    (good : GoodBase trace start duration participants)
    (within : Within trace start duration index) (leaderIn : leader ∈ participants)
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (quiet : QuietTerm participants leader term (proto step.before))
    (terms
      : forall node local_,
          (node, local_) ∈ (proto step.after).nodes -> local_.currentTerm <= term)
    (held : Synced base term (proto step.before))
    : Synced base term (proto step.after) := by
  rcases selected : step.action.action with _ | action
  · rw [admissible.stutter stepped selected]
    exact held
  obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
  intro node local_ member
  rcases c.now_after member with ⟨same, rfl⟩ | ⟨_, old⟩
  · subst same
    obtain ⟨preTerm, preExtended⟩ := held _ _ c.pre_now
    have postTerm : c.post.currentTerm = term := by
      have := c.term_le
      have := terms _ _ c.post_now
      omega
    refine ⟨postTerm, ?_⟩
    by_cases isLeader : c.actor = leader
    · obtain ⟨extra, log, extraPlain⟩ :=
        leader_log_extends c quiet leaderIn isLeader
          (ctx_isolated admissible good within stepped selected c acts (isLeader ▸ leaderIn))
          (ctx_plain admissible good within stepped selected c acts)
      rw [log]
      exact preExtended.append extraPlain
    by_cases unchanged : c.post.log = c.pre.log
    · rw [unchanged]
      exact preExtended
    obtain ⟨leaderState, leaderNow, primary, leaderTerm⟩ := quiet.leader
    have leaderFound := found_of_now c.prior leaderNow
    obtain ⟨_, _, leaderState', _, _, _, _, _, leaderFound', _, postLog, differ, _⟩ :=
      follower_step_of_leads admissible stepped ⟨leaderState, leaderFound, primary, leaderTerm⟩
        isLeader c.tr.found (found_of_now c.exec c.post_now) preTerm postTerm unchanged
    rw [leaderFound, Option.some.injEq] at leaderFound'
    subst leaderFound'
    rw [postLog]
    exact preExtended.take (held leader leaderState leaderNow).2 differ
  · exact held _ _ old

/-- Through a window in which the term stays quiet among all listed nodes, every
node stays in the term with a plain extension of `base`. -/
theorem synced_window {base : List Entry} {start : Nat} {duration : Real}
    {participants : Finset NodeID} {leader : NodeID} {term : Nat}
    (good : GoodBase trace start duration participants) (leaderIn : leader ∈ participants)
    (listed : forall node, node ∈ nodes -> node ∈ participants)
    (stable : Window.StableTerm trace start duration leader term participants)
    {first : W} (firstFound : trace.stateAt start = some first)
    (initial : Synced base term (proto first))
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> Synced base term (proto point) := by
  intro index point within found
  refine trace.induction (start := start)
    (motive := fun index point =>
      Within trace start duration index -> Synced base term (proto point))
    (fun point found _ => by
      rw [firstFound, Option.some.injEq] at found
      exact found ▸ initial)
    (fun index step afterStart stepped held within => ?_)
    index point within.1 found within
  have recorded := Trace.stateAt_succ_of_stepAt stepped
  have before := Trace.stateAt_of_stepAt stepped
  have inside := within_of_le admissible within recorded afterStart (Nat.le_succ index)
  exact Synced.step admissible good inside leaderIn stepped (stable index _ inside before).1
    (fun node local_ member =>
      (stable (index + 1) _ within recorded).1.terms node local_ member
        (listed node (listed_of_mem admissible recorded member)))
    (held inside)

/-- The primary's reconfiguration stays settled through a window in which its log
stays a plain extension of its log at `start`. -/
theorem settled_window {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {first : W} {leaderState : NodeState} (firstFound : trace.stateAt start = some first)
    (leaderFound : nodeState (proto first) leader = some leaderState)
    (settled : ReconfigurationSettled leaderState)
    (synced
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Synced leaderState.log term (proto point))
    : Window.ReconfigurationSettled trace start duration leader := by
  intro index point state within found stateFound
  have atStart : nodeAt trace start leader = some leaderState :=
    nodeAt_eq_some.mpr ⟨first, firstFound, leaderFound⟩
  exact settled_of_extends settled
    (synced index point within found leader state (Concrete.mem_of_nodeState stateFound)).2
    (commit_mono admissible within.1 atStart (nodeAt_eq_some.mpr ⟨point, found, stateFound⟩))
    (commit_le_length admissible atStart)

end Step

end CCFRaft.Proofs.Liveness
