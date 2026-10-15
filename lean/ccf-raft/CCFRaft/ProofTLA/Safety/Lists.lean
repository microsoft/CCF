module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.Node

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Log and configuration facts

Pure facts about logs, prefixes and active configurations used by the safety
proof: the shape of a log after accepting AppendEntries, and why two quorums
for logs agreeing on their committed prefixes intersect.
-/

namespace CCFRaft.ProofTLA.Safety

open Model.Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

/-! ## Prefixes -/

theorem take_eq_of_prefix {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (bound : n <= small.length)
    : large.take n = small.take n := by
  obtain ⟨rest, rfl⟩ := sub
  rw [List.take_append_of_le_length bound]

theorem take_prefix_take {α : Type} (list : List α) {m n : Nat} (le : m <= n)
    : list.take m <+: list.take n := by
  have := List.take_prefix m (list.take n)
  rwa [List.take_take, Nat.min_eq_left le] at this

theorem comparable_of_prefix {α : Type} {left right common : List α}
    (leftSub : left <+: common) (rightSub : right <+: common)
    : left <+: right \/ right <+: left :=
  List.prefix_or_prefix_of_prefix leftSub rightSub

theorem take_eq_take_of_comparable {α : Type} {left right : List α} {n : Nat}
    (comparable : left <+: right \/ right <+: left)
    (leftBound : n <= left.length) (rightBound : n <= right.length)
    : left.take n = right.take n := by
  rcases comparable with sub | sub
  · exact (take_eq_of_prefix sub leftBound).symm
  · exact take_eq_of_prefix sub rightBound

/-! ## Terms and signatures -/

theorem termAt_eq {log : List (Entry Node TxId)} {index : Nat} (positive : 0 < index)
    (bound : index <= log.length)
    : termAt log index = log[index - 1].term := by
  simp [termAt, entryAt?, Nat.pos_iff_ne_zero.mp positive,
    List.getElem?_eq_getElem (show index - 1 < log.length by omega)]

theorem termAt_zero (log : List (Entry Node TxId)) : termAt log 0 = 0 := by
  simp [termAt, entryAt?]

theorem termAt_take {log : List (Entry Node TxId)} {index n : Nat} (le : index <= n)
    : termAt (log.take n) index = termAt log index := by
  unfold termAt entryAt?
  split
  · rfl
  · rw [List.getElem?_take_of_lt (by omega)]

theorem termAt_of_prefix {small large : List (Entry Node TxId)} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : termAt large index = termAt small index := by
  rw [List.prefix_iff_eq_take.mp sub, termAt_take bound]

/-! ## Accepting AppendEntries -/

/-- The follower log after accepting `request` on `log`. -/
def acceptLog (log : List (Entry Node TxId)) (request : AppendEntriesRequest Node TxId)
    : List (Entry Node TxId) :=
  let kept :=
    if ((log.drop request.prevLogIndex).zip request.entries).any
        (fun (existing, incoming) => existing.term != incoming.term) then
      log.take request.prevLogIndex
    else
      log
  kept ++ request.entries.drop (kept.length - request.prevLogIndex)

/--
The accepted log is the sender's prefix up to the end of the batch, followed by
the follower's own suffix exactly when the follower already agreed with that
prefix. `aligned` is log matching between the two logs.
-/
theorem acceptLog_eq {follower sender : List (Entry Node TxId)}
    {request : AppendEntriesRequest Node TxId}
    (prevBound : request.prevLogIndex <= follower.length)
    (prevSender : request.prevLogIndex <= sender.length)
    (prevAgree : follower.take request.prevLogIndex = sender.take request.prevLogIndex)
    (entries : request.entries <+: sender.drop request.prevLogIndex)
    (aligned
      : forall j,
          0 < j
          -> j <= follower.length
          -> j <= sender.length
          -> termAt follower j = termAt sender j
          -> follower.take j = sender.take j)
    : acceptLog follower request
      = sender.take (request.prevLogIndex + request.entries.length)
        ++ (if follower.take (request.prevLogIndex + request.entries.length)
                = sender.take (request.prevLogIndex + request.entries.length) then
              follower.drop (request.prevLogIndex + request.entries.length)
            else
              []) := by
  obtain ⟨term, prev, prevTerm, batch, leaderCommit⟩ := request
  simp only at prevBound prevSender prevAgree entries ⊢
  have batchEq : batch = (sender.drop prev).take batch.length :=
    List.prefix_iff_eq_take.mp entries
  have batchBound : prev + batch.length <= sender.length := by
    have := entries.length_le
    simp at this
    omega
  have senderTake : sender.take (prev + batch.length) = sender.take prev ++ batch := by
    rw [List.take_add, ← batchEq]
  unfold acceptLog
  simp only
  split
  · -- A conflicting term: the follower keeps only the matched prefix.
    rename_i conflict
    obtain ⟨⟨existing, incoming⟩, member, different⟩ := List.any_eq_true.mp conflict
    obtain ⟨offset, lt, pairEq⟩ := List.getElem_of_mem member
    simp only [List.getElem_zip, List.length_zip, List.length_drop, Prod.mk.injEq] at lt pairEq
    obtain ⟨existingEq, incomingEq⟩ := pairEq
    have takeLength : (follower.take prev).length = prev := by simp; omega
    rw [takeLength, Nat.sub_self, List.drop_zero, prevAgree, ← senderTake]
    have differ : Not (follower.take (prev + batch.length) = sender.take (prev + batch.length)) := by
      intro same
      have := congrArg (fun list => list[prev + offset]?) same
      rw [List.getElem?_take_of_lt (by omega), List.getElem?_take_of_lt (by omega),
        List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at this
      have entryEq := Option.some.inj this
      have senderEntry : sender[prev + offset]'(by omega) = incoming := by
        rw [← incomingEq, List.getElem_of_eq batchEq]
        simp
      have followerEntry : follower[prev + offset]'(by omega) = existing := by
        rw [← existingEq]
        simp
      rw [followerEntry, senderEntry] at entryEq
      simp [entryEq] at different
    simp [differ]
  · -- No conflicting term: the overlap agrees, so the follower log is extended.
    rename_i noConflict
    simp only [Bool.not_eq_true, List.any_eq_false] at noConflict
    have overlapTerms : forall offset (lt : offset < batch.length)
        (inFollower : prev + offset < follower.length),
        follower[prev + offset].term = (sender[prev + offset]'(by omega)).term := by
      intro offset lt inFollower
      have member : (follower[prev + offset], batch[offset]) ∈ (follower.drop prev).zip batch := by
        apply List.mem_iff_getElem.mpr
        refine ⟨offset, by simp; omega, ?_⟩
        simp
      have := noConflict _ member
      simp only [bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    by_cases long : prev + batch.length <= follower.length
    · have agree : follower.take (prev + batch.length) = sender.take (prev + batch.length) := by
        rcases Nat.eq_zero_or_pos batch.length with empty | nonempty
        · simp only [empty, Nat.add_zero]
          exact prevAgree
        · apply aligned _ (by omega) long batchBound
          rw [termAt_eq (by omega) long, termAt_eq (by omega) batchBound]
          have := overlapTerms (batch.length - 1) (by omega) (by omega)
          simpa only [show prev + (batch.length - 1) = prev + batch.length - 1 by omega]
            using this
      rw [ite_eq_left agree, ← agree, List.take_append_drop,
        List.drop_eq_nil_of_le (by omega), List.append_nil]
    · have agree : follower = sender.take follower.length := by
        rcases Nat.eq_or_lt_of_le prevBound with same | ahead
        · rw [← same]
          have := prevAgree
          rwa [List.take_of_length_le (by omega)] at this
        · have := aligned follower.length (by omega) le_rfl (by omega) (by
            rw [termAt_eq (by omega) le_rfl, termAt_eq (by omega) (by omega)]
            have := overlapTerms (follower.length - 1 - prev) (by omega) (by omega)
            simpa only [show prev + (follower.length - 1 - prev) = follower.length - 1 by omega]
              using this)
          rwa [List.take_of_length_le le_rfl] at this
      have differ : Not (follower.take (prev + batch.length)
          = sender.take (prev + batch.length)) := by
        intro same
        have := congrArg List.length same
        simp at this
        omega
      rw [ite_eq_right differ, List.append_nil]
      have followerEq : follower = sender.take prev ++ batch.take (follower.length - prev) := by
        have viaTake : follower = (sender.take (prev + batch.length)).take follower.length := by
          rw [List.take_take, Nat.min_eq_left (by omega)]
          exact agree
        rw [senderTake, List.take_append, List.length_take, Nat.min_eq_left prevSender,
          List.take_of_length_le (by simp; omega)] at viaTake
        exact viaTake
      nth_rewrite 1 [followerEq]
      rw [List.append_assoc, List.take_append_drop, senderTake]

/-! ## Configurations -/

theorem mem_history_filterMap {log : List (Entry Node TxId)} {start : Nat}
    {configuration : Configuration Node}
    (member
      : configuration
        ∈ (log.zipIdx start).filterMap
            fun (entry, index) =>
              entry.content.metadata.configuration.map
                fun nodes => ({ index, nodes } : Configuration Node))
    : start <= configuration.index /\ configuration.index < start + log.length := by
  obtain ⟨⟨entry, index⟩, pairMember, configMember⟩ := List.mem_filterMap.mp member
  obtain ⟨nodes, _, rfl⟩ := Option.map_eq_some_iff.mp configMember
  have := List.mem_zipIdx pairMember
  simp only
  omega

/-- The configuration history of a log extends that of any of its prefixes by
configurations from later positions. -/
theorem configurationHistory_split (config : InitialConfig Node)
    (log : List (Entry Node TxId)) (k : Nat)
    : exists rest,
        configurationHistory config log = configurationHistory config (log.take k) ++ rest
        /\ forall configuration, configuration ∈ rest -> k < configuration.index := by
  have split : log = log.take k ++ log.drop k := (List.take_append_drop k log).symm
  refine ⟨((log.drop k).zipIdx (1 + (log.take k).length)).filterMap fun (entry, index) =>
      entry.content.metadata.configuration.map
        fun nodes => ({ index, nodes } : Configuration Node),
    ?_, ?_⟩
  · unfold configurationHistory
    conv_lhs => rw [split]
    rw [List.zipIdx_append, List.filterMap_append]
    rfl
  · intro configuration member
    have := mem_history_filterMap member
    by_cases short : log.length <= k
    · simp [List.drop_eq_nil_of_le short] at member
    · simp at this
      omega

theorem filter_index_append {front rest : List (Configuration Node)} {bound k : Nat}
    (le : bound <= k)
    (later : forall configuration, configuration ∈ rest -> k < configuration.index)
    : ((front ++ rest).filter fun configuration => configuration.index <= bound)
      = front.filter fun configuration => configuration.index <= bound := by
  have empty : (rest.filter fun configuration => configuration.index <= bound) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro configuration member
    have := later configuration member
    simp
    omega
  rw [List.filter_append, empty, List.append_nil]

theorem filter_index_pos (config : InitialConfig Node) (log : List (Entry Node TxId))
    (bound : Nat)
    : 0
      < ((configurationHistory config log).filter
          fun configuration => configuration.index <= bound).length := by
  simp [configurationHistory]

theorem length_filter_index_mono (configurations : List (Configuration Node))
    {small large : Nat} (le : small <= large)
    : (configurations.filter fun configuration => configuration.index <= small).length
      <= (configurations.filter
            fun configuration => configuration.index <= large).length := by
  apply List.Sublist.length_le
  apply List.monotone_filter_right
  intro configuration holds
  simp at holds ⊢
  omega

theorem length_filter_le (configurations : List (Configuration Node)) (bound : Nat)
    : (configurations.filter fun configuration => configuration.index <= bound).length
      <= configurations.length :=
  List.length_filter_le _ _

/--
Two logs agreeing up to `k`, with commit indices at most `k`, share an active
configuration: the last one committed by the larger commit index.
-/
theorem activeConfigurations_overlap (config : InitialConfig Node)
    {left right : List (Entry Node TxId)} {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k)
    : exists configuration,
        configuration ∈ activeConfigurations config left leftCommit
        /\ configuration ∈ activeConfigurations config right rightCommit := by
  obtain ⟨leftRest, leftEq, leftLater⟩ := configurationHistory_split config left k
  obtain ⟨rightRest, rightEq, rightLater⟩ := configurationHistory_split config right k
  rw [agree] at leftEq
  set common := configurationHistory config (right.take k)
  have count : forall {log : List (Entry Node TxId)} {rest commit},
      configurationHistory config log = common ++ rest
      -> (forall configuration, configuration ∈ rest -> k < configuration.index)
      -> commit <= k
      -> ((configurationHistory config log).filter
            fun configuration => configuration.index <= commit)
          = common.filter fun configuration => configuration.index <= commit := by
    intro log rest commit eq later le
    rw [eq]
    exact filter_index_append le later
  have commonPos : forall commit,
      0 < (common.filter fun configuration => configuration.index <= commit).length :=
    fun commit => filter_index_pos config (right.take k) commit
  have inDrop : forall {log : List (Entry Node TxId)} {rest} {m p : Nat}
      (lt : p < common.length),
      configurationHistory config log = common ++ rest -> m <= p
      -> common[p] ∈ (configurationHistory config log).drop m := by
    intro log rest m p lt eq le
    rw [eq, List.mem_iff_getElem]
    refine ⟨p - m, by simp; omega, ?_⟩
    simp only [List.getElem_drop]
    rw [List.getElem_append_left (by omega)]
    congr 1
    omega
  unfold activeConfigurations
  simp only
  rw [count leftEq leftLater leftLe, count rightEq rightLater rightLe]
  rcases Nat.le_total leftCommit rightCommit with ordered | ordered
  · have mono := length_filter_index_mono common ordered
    have bound := length_filter_le common rightCommit
    have pos := commonPos rightCommit
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq (by omega),
      inDrop (by omega) rightEq le_rfl⟩
  · have mono := length_filter_index_mono common ordered
    have bound := length_filter_le common leftCommit
    have pos := commonPos leftCommit
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq le_rfl,
      inDrop (by omega) rightEq (by omega)⟩

/-- Two strict majorities of one configuration share a member. -/
theorem majorities_intersect {configuration : Configuration Node}
    {left right : Finset Node}
    (leftMajority : hasConfigurationMajority left configuration)
    (rightMajority : hasConfigurationMajority right configuration)
    : exists node, node ∈ left /\ node ∈ right := by
  unfold hasConfigurationMajority at leftMajority rightMajority
  obtain ⟨node, member⟩ := Finset.inter_nonempty_of_card_lt_card_add_card
    (show left ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (show right ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (by omega)
  simp only [Finset.mem_inter] at member
  exact ⟨node, member.1.1, member.2.1⟩

theorem hasQuorum_majority {configurations : List (Configuration Node)}
    {voters : Finset Node} (quorum : hasQuorum configurations voters)
    {configuration : Configuration Node} (member : configuration ∈ configurations)
    : hasConfigurationMajority voters configuration := by
  have := List.all_eq_true.mp quorum configuration member
  simpa using this

/-- Quorums for two logs agreeing on both committed prefixes share a voter. -/
theorem quorums_intersect (config : InitialConfig Node)
    {left right : List (Entry Node TxId)} {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) {leftVoters rightVoters : Finset Node}
    (leftQuorum : hasQuorum (activeConfigurations config left leftCommit) leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations config right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  obtain ⟨configuration, leftMember, rightMember⟩ :=
    activeConfigurations_overlap config agree leftLe rightLe
  exact majorities_intersect (hasQuorum_majority leftQuorum leftMember)
    (hasQuorum_majority rightQuorum rightMember)

end CCFRaft.ProofTLA.Safety
