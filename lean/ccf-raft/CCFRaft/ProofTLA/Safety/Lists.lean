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

theorem termAt_eq {log : List (Entry)} {index : Nat} (positive : 0 < index)
    (bound : index <= log.length)
    : termAt log index = log[index - 1].term := by
  simp [termAt, entryAt?, Nat.pos_iff_ne_zero.mp positive,
    List.getElem?_eq_getElem (show index - 1 < log.length by omega)]

theorem termAt_zero (log : List (Entry)) : termAt log 0 = 0 := by
  simp [termAt, entryAt?]

theorem termAt_take {log : List (Entry)} {index n : Nat} (le : index <= n)
    : termAt (log.take n) index = termAt log index := by
  unfold termAt entryAt?
  split
  · rfl
  · rw [List.getElem?_take_of_lt (by omega)]

theorem termAt_of_prefix {small large : List (Entry)} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : termAt large index = termAt small index := by
  rw [List.prefix_iff_eq_take.mp sub, termAt_take bound]

/-! ## Accepting AppendEntries -/

/-- The first overlapping entry whose term differs from the request's, one-based. -/
def conflictIndex (log : List Entry) (request : AppendEntriesRequest) : Option Nat :=
  ((((log.drop request.prevLogIndex).zip request.entries).zipIdx
      (request.prevLogIndex + 1)).find?
    fun ((existing, incoming), _) => existing.term != incoming.term).map
    Prod.snd

/-- The follower log after accepting `request` on `log`. -/
def acceptLog (log : List Entry) (request : AppendEntriesRequest) : List Entry :=
  let kept :=
    match conflictIndex log request with
    | none => log
    | some index => log.take (index - 1)
  kept ++ request.entries.drop (kept.length - request.prevLogIndex)

theorem conflictIndex_some {log : List Entry} {request : AppendEntriesRequest}
    {index : Nat} (found : conflictIndex log request = some index)
    : exists offset,
        index = request.prevLogIndex + 1 + offset
        /\ exists (inLog : request.prevLogIndex + offset < log.length) (inBatch
                                                                        : offset
                                                                          < request.entries.length),
            Not (log[request.prevLogIndex + offset].term = request.entries[offset].term)
            /\ forall m (lt : m < offset),
                (log[request.prevLogIndex + m]'(by omega)).term
                = (request.entries[m]'(by omega)).term := by
  unfold conflictIndex at found
  obtain ⟨⟨⟨existing, incoming⟩, idx⟩, hit, rfl⟩ := Option.map_eq_some_iff.mp found
  obtain ⟨different, offset, lt, at_, before⟩ := List.find?_eq_some_iff_getElem.mp hit
  simp only [List.length_zipIdx, List.length_zip, List.length_drop] at lt
  rw [List.getElem_zipIdx] at at_
  simp only [List.getElem_zip, List.getElem_drop, Prod.mk.injEq] at at_
  obtain ⟨⟨existingEq, incomingEq⟩, idxEq⟩ := at_
  refine ⟨offset, idxEq.symm, by omega, by omega, ?_, fun m mLt => ?_⟩
  · simp only [bne_iff_ne, ne_eq] at different
    rw [existingEq, incomingEq]
    exact different
  · have := before m (by omega)
    rw [List.getElem_zipIdx] at this
    simpa [List.getElem_zip, List.getElem_drop] using this

theorem conflictIndex_none {log : List Entry} {request : AppendEntriesRequest}
    (found : conflictIndex log request = none) (offset : Nat)
    (inLog : request.prevLogIndex + offset < log.length)
    (inBatch : offset < request.entries.length)
    : log[request.prevLogIndex + offset].term = request.entries[offset].term := by
  unfold conflictIndex at found
  have none := List.find?_eq_none.mp (Option.map_eq_none_iff.mp found)
  have member : (((log[request.prevLogIndex + offset], request.entries[offset]),
      request.prevLogIndex + 1 + offset) : (Entry × Entry) × Nat)
      ∈ ((log.drop request.prevLogIndex).zip request.entries).zipIdx
          (request.prevLogIndex + 1) := by
    apply List.mem_iff_getElem.mpr
    refine ⟨offset, by simp; omega, ?_⟩
    rw [List.getElem_zipIdx]
    simp [List.getElem_zip, List.getElem_drop]
  simpa using none _ member

/--
The accepted log is the sender's prefix up to the end of the batch, followed by
the follower's own suffix exactly when the follower already agreed with that
prefix. `aligned` is log matching between the two logs.
-/
theorem acceptLog_eq {follower sender : List (Entry)}
    {request : AppendEntriesRequest}
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
  obtain ⟨term, prev, prevTerm, batch, primaryCommit⟩ := request
  simp only at prevBound prevSender prevAgree entries ⊢
  have batchEq : batch = (sender.drop prev).take batch.length :=
    List.prefix_iff_eq_take.mp entries
  have batchBound : prev + batch.length <= sender.length := by
    have := entries.length_le
    simp at this
    omega
  have senderTake : sender.take (prev + batch.length) = sender.take prev ++ batch := by
    rw [List.take_add, ← batchEq]
  have overlapTerms : forall offset (lt : offset < batch.length)
      (inFollower : prev + offset < follower.length),
      conflictIndex follower ⟨term, prev, prevTerm, batch, primaryCommit⟩ = none
      -> follower[prev + offset].term = (sender[prev + offset]'(by omega)).term := by
    intro offset lt inFollower none
    rw [conflictIndex_none none offset inFollower lt]
    congr 1
    simp only
    rw [List.getElem_of_eq batchEq]
    simp
  unfold acceptLog
  simp only
  split
  · -- No conflicting term: the overlap agrees, so the follower log is extended.
    rename_i noConflict
    by_cases long : prev + batch.length <= follower.length
    · have agree : follower.take (prev + batch.length) = sender.take (prev + batch.length) := by
        rcases Nat.eq_zero_or_pos batch.length with empty | nonempty
        · simp only [empty, Nat.add_zero]
          exact prevAgree
        · apply aligned _ (by omega) long batchBound
          rw [termAt_eq (by omega) long, termAt_eq (by omega) batchBound]
          have := overlapTerms (batch.length - 1) (by omega) (by omega) noConflict
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
            have := overlapTerms (follower.length - 1 - prev) (by omega) (by omega) noConflict
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
  · -- The first conflicting entry: the follower keeps the agreeing prefix before it.
    rename_i index conflict
    obtain ⟨offset, rfl, inFollower, inBatch, different, before⟩ := conflictIndex_some conflict
    dsimp only at inFollower inBatch different before
    have senderAt : forall m (lt : m < batch.length),
        (sender[prev + m]'(by omega)) = batch[m] := by
      intro m lt
      rw [List.getElem_of_eq batchEq]
      simp
    have keptAgree : follower.take (prev + offset) = sender.take (prev + offset) := by
      rcases Nat.eq_zero_or_pos offset with zero | positive
      · simpa [zero] using prevAgree
      · apply aligned _ (by omega) (by omega) (by omega)
        rw [termAt_eq (by omega) (by omega), termAt_eq (by omega) (by omega)]
        have := before (offset - 1) (by omega)
        rw [← senderAt (offset - 1) (by omega)] at this
        simpa only [show prev + (offset - 1) = prev + offset - 1 by omega] using this
    have differ
        : Not (follower.take (prev + batch.length) = sender.take (prev + batch.length)) := by
      intro same
      have := congrArg (fun list => list[prev + offset]?) same
      rw [List.getElem?_take_of_lt (by omega), List.getElem?_take_of_lt (by omega),
        List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega),
        Option.some.injEq, senderAt offset inBatch] at this
      exact different (congrArg Entry.term this)
    rw [ite_eq_right differ, List.append_nil, show prev + 1 + offset - 1 = prev + offset by omega,
      keptAgree, List.length_take, Nat.min_eq_left (by omega),
      show prev + offset - prev = offset by omega, List.take_add, List.take_add, ← batchEq,
      List.append_assoc]
    congr 1
    have : (sender.drop prev).take offset = batch.take offset := by
      rw [batchEq, List.take_take, Nat.min_eq_left (by omega)]
    rw [this, List.take_append_drop]

/-! ## Configurations -/

theorem mem_history_filterMap {log : List (Entry)} {start : Nat}
    {configuration : Configuration}
    (member
      : configuration
        ∈ (log.zipIdx start).filterMap
            fun (entry, index) =>
              entry.content.metadata.configuration.map
                fun nodes => ({ index, nodes } : Configuration))
    : start <= configuration.index /\ configuration.index < start + log.length := by
  obtain ⟨⟨entry, index⟩, pairMember, configMember⟩ := List.mem_filterMap.mp member
  obtain ⟨nodes, _, rfl⟩ := Option.map_eq_some_iff.mp configMember
  have := List.mem_zipIdx pairMember
  simp only
  omega

/-- The configuration history of a log extends that of any of its prefixes by
configurations from later positions. -/
theorem configurationHistory_split (log : List (Entry)) (k : Nat)
    : exists rest,
        configurationHistory log = configurationHistory (log.take k) ++ rest
        /\ forall configuration, configuration ∈ rest -> k < configuration.index := by
  have split : log = log.take k ++ log.drop k := (List.take_append_drop k log).symm
  refine ⟨((log.drop k).zipIdx (1 + (log.take k).length)).filterMap fun (entry, index) =>
      entry.content.metadata.configuration.map
        fun nodes => ({ index, nodes } : Configuration),
    ?_, ?_⟩
  · unfold configurationHistory
    conv_lhs => rw [split]
    rw [List.zipIdx_append, List.filterMap_append]
  · intro configuration member
    have := mem_history_filterMap member
    by_cases short : log.length <= k
    · simp [List.drop_eq_nil_of_le short] at member
    · simp at this
      omega

theorem filter_index_append {front rest : List (Configuration)} {bound k : Nat}
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

theorem length_filter_index_mono (configurations : List (Configuration))
    {small large : Nat} (le : small <= large)
    : (configurations.filter fun configuration => configuration.index <= small).length
      <= (configurations.filter
            fun configuration => configuration.index <= large).length := by
  apply List.Sublist.length_le
  apply List.monotone_filter_right
  intro configuration holds
  simp at holds ⊢
  omega

theorem length_filter_le (configurations : List (Configuration)) (bound : Nat)
    : (configurations.filter fun configuration => configuration.index <= bound).length
      <= configurations.length :=
  List.length_filter_le _ _

/--
Two logs agreeing up to `k` on a prefix naming some configuration, with commit
indices at most `k`, share an active configuration: the last one committed by
the larger commit index, or the first one if neither commits any.
-/
theorem activeConfigurations_overlap
    {left right : List (Entry)} {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (named : configurationHistory (right.take k) ≠ [])
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit := by
  obtain ⟨leftRest, leftEq, leftLater⟩ := configurationHistory_split left k
  obtain ⟨rightRest, rightEq, rightLater⟩ := configurationHistory_split right k
  rw [agree] at leftEq
  set common := configurationHistory (right.take k)
  have count : forall {log : List (Entry)} {rest commit},
      configurationHistory log = common ++ rest
      -> (forall configuration, configuration ∈ rest -> k < configuration.index)
      -> commit <= k
      -> ((configurationHistory log).filter
            fun configuration => configuration.index <= commit)
          = common.filter fun configuration => configuration.index <= commit := by
    intro log rest commit eq later le
    rw [eq]
    exact filter_index_append le later
  have commonPos : 0 < common.length := List.length_pos_of_ne_nil named
  have inDrop : forall {log : List (Entry)} {rest} {m p : Nat}
      (lt : p < common.length),
      configurationHistory log = common ++ rest -> m <= p
      -> common[p] ∈ (configurationHistory log).drop m := by
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
    have pos := commonPos
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq (by omega),
      inDrop (by omega) rightEq le_rfl⟩
  · have mono := length_filter_index_mono common ordered
    have bound := length_filter_le common leftCommit
    have pos := commonPos
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq le_rfl,
      inDrop (by omega) rightEq (by omega)⟩

/-- Two strict majorities of one configuration share a member. -/
theorem majorities_intersect {configuration : Configuration}
    {left right : Finset NodeID}
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

theorem hasQuorum_majority {configurations : List (Configuration)}
    {voters : Finset NodeID} (quorum : hasQuorum configurations voters)
    {configuration : Configuration} (member : configuration ∈ configurations)
    : hasConfigurationMajority voters configuration := by
  have := List.all_eq_true.mp quorum.2 configuration member
  simpa using this

/-- Quorums for two logs agreeing on both committed prefixes share a voter. -/
theorem quorums_intersect
    {left right : List (Entry)} {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (named : configurationHistory (right.take k) ≠ [])
    {leftVoters rightVoters : Finset NodeID}
    (leftQuorum : hasQuorum (activeConfigurations left leftCommit) leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  obtain ⟨configuration, leftMember, rightMember⟩ :=
    activeConfigurations_overlap agree leftLe rightLe named
  exact majorities_intersect (hasQuorum_majority leftQuorum leftMember)
    (hasQuorum_majority rightQuorum rightMember)

end CCFRaft.ProofTLA.Safety
