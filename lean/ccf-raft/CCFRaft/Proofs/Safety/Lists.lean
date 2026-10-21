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

namespace CCFRaft.Proofs.Safety

open Model.Node

/-! ## Prefixes -/

theorem prefix_take_of_prefix {α : Type} {small large : List α} (n : Nat)
    (sub : small <+: large)
    : small.take n <+: large.take n := by
  obtain ⟨rest, rfl⟩ := sub
  rw [List.take_append]
  exact List.prefix_append _ _

theorem take_eq_of_prefix {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (bound : n <= small.length)
    : large.take n = small.take n := by
  obtain ⟨rest, rfl⟩ := sub
  rw [List.take_append_of_le_length bound]

/-- Two lists agreeing on a common prefix of a third list. -/
theorem prefix_of_prefix_take {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (bound : small.length <= n)
    : small <+: large.take n := by
  rw [List.prefix_iff_eq_take] at sub ⊢
  rw [List.take_take, Nat.min_eq_left bound]
  exact sub

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

theorem termAt_eq {log : List Entry} {index : Nat} (positive : 0 < index)
    (bound : index <= log.length)
    : termAt log index = log[index - 1].term := by
  simp [termAt, entryAt?, Nat.pos_iff_ne_zero.mp positive,
    List.getElem?_eq_getElem (show index - 1 < log.length by omega)]

theorem termAt_zero (log : List Entry) : termAt log 0 = 0 := by
  simp [termAt, entryAt?]

theorem termAt_of_length_lt {log : List Entry} {index : Nat} (beyond : log.length < index)
    : termAt log index = 0 := by
  unfold termAt entryAt?
  split
  · rfl
  · rw [List.getElem?_eq_none (by omega)]
    rfl

theorem termAt_take {log : List Entry} {index n : Nat} (le : index <= n)
    : termAt (log.take n) index = termAt log index := by
  unfold termAt entryAt?
  split
  · rfl
  · rw [List.getElem?_take_of_lt (by omega)]

theorem termAt_of_prefix {small large : List Entry} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : termAt large index = termAt small index := by
  rw [List.prefix_iff_eq_take.mp sub, termAt_take bound]

theorem take_eq_iff_getElem {α : Type} {left right : List α} {n : Nat}
    (leftBound : n <= left.length) (rightBound : n <= right.length)
    : left.take n = right.take n
      <-> forall j (lt : j < n), left[j]'(by omega) = right[j]'(by omega) := by
  constructor
  · intro same j lt
    have := congrArg (fun list => list[j]?) same
    rw [List.getElem?_take_of_lt lt, List.getElem?_take_of_lt lt,
      List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at this
    exact Option.some.inj this
  · intro same
    apply List.ext_getElem
    · simp; omega
    · intro j leftLt _
      simp only [List.getElem_take]
      exact same j (by simp at leftLt; omega)

/-! ## Accepting AppendEntries -/

/-- The one-based index of the first overlapping entry whose term conflicts. -/
def conflictIndex (log : List Entry) (request : AppendEntriesRequest) : Option Nat :=
  ((((log.drop request.prevLogIndex).zip request.entries).zipIdx
      (request.prevLogIndex + 1)).find?
    fun ((existing, incoming), _) => existing.term != incoming.term).map
    Prod.snd

theorem firstTermConflictIndex_eq (state : NodeState) (request : AppendEntriesRequest)
    : firstTermConflictIndex state request = conflictIndex state.log request :=
  rfl

/-- The follower log after accepting `request` on `log`. -/
def acceptLog (log : List Entry) (request : AppendEntriesRequest) : List Entry :=
  let kept :=
    match conflictIndex log request with
    | some index => log.take (index - 1)
    | none => log
  kept ++ request.entries.drop (kept.length - request.prevLogIndex)

/--
The accepted log is the sender's prefix up to the end of the batch, followed by
the follower's own suffix exactly when the follower already agreed with that
prefix. `aligned` is log matching between the two logs.
-/
theorem acceptLog_eq {follower sender : List Entry}
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
  unfold acceptLog
  simp only
  split
  · -- A conflicting term: the follower keeps only the agreeing prefix.
    rename_i index conflict
    unfold conflictIndex at conflict
    obtain ⟨pair, found, indexEq⟩ := Option.map_eq_some_iff.mp conflict
    obtain ⟨different, offset, lt, pairEq, before⟩ :=
      List.find?_eq_some_iff_getElem.mp found
    simp only [List.length_zipIdx, List.length_zip, List.length_drop] at lt
    rw [List.getElem_zipIdx] at pairEq
    subst pairEq indexEq
    simp only [List.getElem_zip, List.getElem_drop, bne_iff_ne, ne_eq] at different
    have prefixTerms : forall j (jLt : j < offset),
        (follower[prev + j]'(by omega)).term = (sender[prev + j]'(by omega)).term := by
      intro j jLt
      have := before j jLt
      simp only [List.getElem_zipIdx, List.getElem_zip, List.getElem_drop,
        Bool.not_eq_true', bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    have keptEq : prev + 1 + offset - 1 = prev + offset := by omega
    simp only [keptEq]
    have keptAgree : follower.take (prev + offset) = sender.take (prev + offset) := by
      rcases Nat.eq_zero_or_pos offset with zero | positive
      · simp only [zero, Nat.add_zero]
        exact prevAgree
      · apply aligned _ (by omega) (by omega) (by omega)
        rw [termAt_eq (by omega) (by omega), termAt_eq (by omega) (by omega)]
        have := prefixTerms (offset - 1) (by omega)
        simpa only [show prev + (offset - 1) = prev + offset - 1 by omega] using this
    have takeLength : (follower.take (prev + offset)).length = prev + offset := by
      simp
      omega
    have senderOffset : sender.take (prev + offset) = sender.take prev ++ batch.take offset := by
      rw [List.take_add]
      congr 1
      conv_rhs => rw [batchEq]
      rw [List.take_take, Nat.min_eq_left (by omega)]
    rw [takeLength, show prev + offset - prev = offset by omega, keptAgree, senderOffset,
      List.append_assoc, List.take_append_drop, ← senderTake]
    have differ : Not (follower.take (prev + batch.length) = sender.take (prev + batch.length)) := by
      intro same
      have := congrArg (fun list => list[prev + offset]?) same
      rw [List.getElem?_take_of_lt (by omega), List.getElem?_take_of_lt (by omega),
        List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at this
      have entryEq := Option.some.inj this
      have senderEntry : sender[prev + offset]'(by omega) = batch[offset] := by
        rw [List.getElem_of_eq batchEq]
        simp
      rw [entryEq, senderEntry] at different
      exact different rfl
    simp [differ]
  · -- No conflicting term: the overlap agrees, so the follower log is extended.
    rename_i noConflict
    unfold conflictIndex at noConflict
    have notFound := Option.map_eq_none_iff.mp noConflict
    have overlapTerms : forall offset (lt : offset < batch.length)
        (inFollower : prev + offset < follower.length),
        follower[prev + offset].term = (sender[prev + offset]'(by omega)).term := by
      intro offset lt inFollower
      have member : ((follower[prev + offset], batch[offset]), prev + 1 + offset)
          ∈ ((follower.drop prev).zip batch).zipIdx (prev + 1) := by
        apply List.mem_iff_getElem.mpr
        refine ⟨offset, by simp; omega, ?_⟩
        simp
      have := List.find?_eq_none.mp notFound _ member
      simp only [Bool.not_eq_true, bne_eq_false_iff_eq] at this
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

theorem mem_history_filterMap {log : List Entry} {start : Nat}
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
theorem configurationHistory_split (log : List Entry) (k : Nat)
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

theorem configurationHistory_index_le (log : List Entry) {configuration : Configuration}
    (member : configuration ∈ configurationHistory log)
    : configuration.index <= log.length := by
  have := mem_history_filterMap member
  omega

/-- A log with a configuration history is nonempty. -/
theorem ne_nil_of_configurationHistory {log : List Entry}
    (nonempty : configurationHistory log ≠ [])
    : log ≠ [] := by
  rintro rfl
  exact nonempty rfl

/-- Active configurations are drawn from the configuration history. -/
theorem activeConfigurations_sublist (log : List Entry) (commit : Nat)
    : (activeConfigurations log commit).Sublist (configurationHistory log) :=
  List.drop_sublist _ _

/-- A log whose first entry is a configuration has a configuration history. -/
theorem configurationHistory_ne_nil {log : List Entry} {root : Entry}
    (head : log.take 1 = [root]) (configured : root.content.metadata.configuration.isSome)
    : configurationHistory log ≠ [] := by
  obtain ⟨rest, eq, _⟩ := configurationHistory_split log 1
  rw [eq, head]
  obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp configured
  simp [configurationHistory, some]

theorem filter_index_append {front rest : List Configuration} {bound k : Nat}
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

theorem length_filter_index_mono (configurations : List Configuration)
    {small large : Nat} (le : small <= large)
    : (configurations.filter fun configuration => configuration.index <= small).length
      <= (configurations.filter
            fun configuration => configuration.index <= large).length := by
  apply List.Sublist.length_le
  apply List.monotone_filter_right
  intro configuration holds
  simp at holds ⊢
  omega

theorem length_filter_le (configurations : List Configuration) (bound : Nat)
    : (configurations.filter fun configuration => configuration.index <= bound).length
      <= configurations.length :=
  List.length_filter_le _ _

theorem zipIdx_sorted {α : Type} (log : List α) (start : Nat)
    : (log.zipIdx start).Pairwise fun first second => first.2 < second.2 := by
  induction log generalizing start with
  | nil => simp
  | cons head tail ih =>
      rw [List.zipIdx_cons, List.pairwise_cons]
      refine ⟨fun pair member => ?_, ih (start + 1)⟩
      have := List.mem_zipIdx member
      omega

/-- Configuration histories are ordered by index. -/
theorem configurationHistory_sorted (log : List Entry)
    : (configurationHistory log).Pairwise
        fun first second => first.index < second.index := by
  unfold configurationHistory
  refine List.Pairwise.filterMap _ (fun first second lt left leftMem right rightMem => ?_)
    (zipIdx_sorted log 1)
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp leftMem
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp rightMem
  exact lt

/-- In an index-sorted list, the positions counted by an index bound hold
configurations within it. -/
theorem getElem_le_of_lt_length_filter {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    {bound i : Nat}
    (lt
      : i
        < (configurations.filter
            fun configuration => configuration.index <= bound).length)
    : (configurations[i]'(lt.trans_le (List.length_filter_le _ _))).index <= bound := by
  induction configurations generalizing i with
  | nil => simp at lt
  | cons head tail ih =>
      rw [List.pairwise_cons] at sorted
      by_cases within : head.index <= bound
      · rw [List.filter_cons_of_pos (by simpa using within)] at lt
        rcases i with _ | i
        · exact within
        · exact ih sorted.2 (by simpa using lt)
      · have empty : (tail.filter fun configuration => configuration.index <= bound) = [] := by
          refine List.filter_eq_nil_iff.mpr fun configuration member => ?_
          have := sorted.1 configuration member
          simp
          omega
        rw [List.filter_cons_of_neg (by simpa using within), empty] at lt
        simp at lt

/-- The configuration chosen by an index bound is within it, or is the first. -/
theorem chosen_bound {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    (bound : Nat) (positive : 0 < configurations.length)
    : let chosen :=
        configurations[
          (configurations.filter fun configuration => configuration.index <= bound).length
          - 1
          ]'(by
              have :=
                List.length_filter_le
                  (fun configuration : Configuration =>
                    decide (configuration.index <= bound))
                  configurations
              omega)
      chosen.index <= bound
      \/ forall other, other ∈ configurations -> chosen.index <= other.index := by
  intro chosen
  by_cases counted : 0 < (configurations.filter
      fun configuration => configuration.index <= bound).length
  · exact Or.inl (getElem_le_of_lt_length_filter sorted (by omega))
  · refine Or.inr fun other member => ?_
    rcases configurations with _ | ⟨head, tail⟩
    · simp at positive
    · simp only [chosen, Nat.eq_zero_of_not_pos counted, Nat.zero_sub, List.getElem_cons_zero]
      rcases List.mem_cons.mp member with rfl | later
      · exact le_rfl
      · exact ((List.pairwise_cons.mp sorted).1 other later).le

/--
Two logs agreeing up to `k`, with commit indices at most `k` and a configuration
among their first `k` entries, share an active configuration: the last one
committed by the larger commit index, or the first one if neither commits one.
-/
theorem activeConfigurations_overlap {left right : List Entry}
    {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (configured : configurationHistory (right.take k) ≠ [])
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ (configuration.index <= max leftCommit rightCommit
            \/ forall other,
                other ∈ configurationHistory (right.take k)
                -> configuration.index <= other.index) := by
  obtain ⟨leftRest, leftEq, leftLater⟩ := configurationHistory_split left k
  obtain ⟨rightRest, rightEq, rightLater⟩ := configurationHistory_split right k
  rw [agree] at leftEq
  set common := configurationHistory (right.take k)
  have commonPos : 0 < common.length := List.length_pos_iff.mpr configured
  have count : forall {log : List Entry} {rest commit},
      configurationHistory log = common ++ rest
      -> (forall configuration, configuration ∈ rest -> k < configuration.index)
      -> commit <= k
      -> ((configurationHistory log).filter
            fun configuration => configuration.index <= commit)
          = common.filter fun configuration => configuration.index <= commit := by
    intro log rest commit eq later le
    rw [eq]
    exact filter_index_append le later
  have inDrop : forall {log : List Entry} {rest} {m p : Nat}
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
  have leftBound := length_filter_le common leftCommit
  have rightBound := length_filter_le common rightCommit
  have sorted := configurationHistory_sorted (right.take k)
  rcases Nat.le_total leftCommit rightCommit with ordered | ordered
  · have mono := length_filter_index_mono common ordered
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq (by omega),
      inDrop (by omega) rightEq le_rfl, ?_⟩
    rcases chosen_bound sorted rightCommit commonPos with within | first
    · exact Or.inl (within.trans (Nat.le_max_right _ _))
    · exact Or.inr first
  · have mono := length_filter_index_mono common ordered
    refine ⟨common[_ - 1]'(by omega), inDrop (by omega) leftEq le_rfl,
      inDrop (by omega) rightEq (by omega), ?_⟩
    rcases chosen_bound sorted leftCommit commonPos with within | first
    · exact Or.inl (within.trans (Nat.le_max_left _ _))
    · exact Or.inr first

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

theorem hasQuorum_majority {configurations : List Configuration}
    {voters : Finset NodeID} (quorum : hasQuorum configurations voters)
    {configuration : Configuration} (member : configuration ∈ configurations)
    : hasConfigurationMajority voters configuration := by
  have := List.all_eq_true.mp quorum.2 configuration member
  simpa using this

/-- A log is empty or starts with `root`. -/
def Rooted (root : Entry) (log : List Entry) : Prop :=
  log = [] \/ log.take 1 = [root]

theorem Rooted.prefix {root : Entry} {small large : List Entry}
    (rooted : Rooted root large) (sub : small <+: large)
    : Rooted root small := by
  rcases small with _ | ⟨first, rest⟩
  · exact Or.inl rfl
  · refine Or.inr ?_
    obtain ⟨suffix, rfl⟩ := sub
    rcases rooted with empty | head
    · simp at empty
    · simpa using head

theorem Rooted.take {root : Entry} {log : List Entry} (rooted : Rooted root log) (n : Nat)
    : Rooted root (log.take n) :=
  rooted.prefix (List.take_prefix n log)

theorem Rooted.append {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ []) (entries : List Entry)
    : Rooted root (log ++ entries) := by
  rcases rooted with empty | head
  · exact absurd empty nonempty
  · refine Or.inr ?_
    have := List.length_pos_iff.mpr nonempty
    rw [List.take_append_of_le_length (by omega), head]

theorem Rooted.head {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ [])
    : log.take 1 = [root] := by
  rcases rooted with empty | head
  · exact absurd empty nonempty
  · exact head

theorem hasQuorum_nonempty {log : List Entry} {commit : Nat} {voters : Finset NodeID}
    (quorum : hasQuorum (activeConfigurations log commit) voters)
    : log ≠ [] := by
  apply ne_nil_of_configurationHistory
  intro empty
  apply quorum.1
  have := activeConfigurations_sublist log commit
  rw [empty] at this
  exact List.sublist_nil.mp this

/-- Two nonempty rooted logs agreeing on both committed prefixes share an active
configuration within both commit indices or at the root's index; a
configuration-bearing root supplies it. -/
theorem rooted_overlap {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (leftNonempty : left ≠ []) (rightNonempty : right ≠ [])
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k)
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ configuration.index <= max (max leftCommit rightCommit) 1 := by
  have leftHead := leftRooted.head leftNonempty
  have rightHead := rightRooted.head rightNonempty
  have agree' : left.take (max k 1) = right.take (max k 1) := by
    rcases Nat.eq_zero_or_pos k with zero | positive
    · subst zero
      simp [leftHead, rightHead]
    · rwa [Nat.max_eq_left positive]
  have rooted : (right.take (max k 1)).take 1 = [root] := by
    rw [List.take_take, Nat.min_eq_left (Nat.le_max_right _ _), rightHead]
  obtain ⟨configuration, leftMember, rightMember, bound⟩ :=
    activeConfigurations_overlap agree' (leftLe.trans (Nat.le_max_left _ _))
      (rightLe.trans (Nat.le_max_left _ _))
      (configurationHistory_ne_nil rooted configured)
  refine ⟨configuration, leftMember, rightMember, ?_⟩
  rcases bound with within | first
  · exact within.trans (Nat.le_max_left _ _)
  · obtain ⟨rest, eq, _⟩ := configurationHistory_split (right.take (max k 1)) 1
    obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp configured
    have genesis : ({ index := 1, nodes } : Configuration)
        ∈ configurationHistory (right.take (max k 1)) := by
      rw [eq, rooted]
      simp [configurationHistory, some]
    exact (first _ genesis).trans (Nat.le_max_right _ _)

/-- Quorums for two rooted logs agreeing on both committed prefixes share a
voter; a configuration-bearing root supplies a common configuration. -/
theorem quorums_intersect {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) {leftVoters rightVoters : Finset NodeID}
    (leftQuorum : hasQuorum (activeConfigurations left leftCommit) leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  obtain ⟨configuration, leftMember, rightMember, _⟩ :=
    rooted_overlap configured leftRooted rightRooted (hasQuorum_nonempty leftQuorum)
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  exact majorities_intersect (hasQuorum_majority leftQuorum leftMember)
    (hasQuorum_majority rightQuorum rightMember)

/-- As `quorums_intersect`, with the left quorum taken over the active
configurations no later than a positive `bound` covering both commit indices. -/
theorem quorums_intersect_bounded {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k bound : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (leftBound : leftCommit <= bound)
    (rightBound : rightCommit <= bound) (positive : 0 < bound)
    {leftVoters rightVoters : Finset NodeID}
    (leftQuorum
      : hasQuorum
          ((activeConfigurations left leftCommit).filter
            fun configuration => configuration.index <= bound)
          leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  have leftNonempty : left ≠ [] := by
    apply ne_nil_of_configurationHistory
    intro empty
    apply leftQuorum.1
    have := activeConfigurations_sublist left leftCommit
    rw [empty] at this
    rw [List.sublist_nil.mp this, List.filter_nil]
  obtain ⟨configuration, leftMember, rightMember, within⟩ :=
    rooted_overlap configured leftRooted rightRooted leftNonempty
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  have filtered : configuration
      ∈ (activeConfigurations left leftCommit).filter
          fun configuration => configuration.index <= bound := by
    refine List.mem_filter.mpr ⟨leftMember, ?_⟩
    simp only [decide_eq_true_eq]
    omega
  exact majorities_intersect (hasQuorum_majority leftQuorum filtered)
    (hasQuorum_majority rightQuorum rightMember)

end CCFRaft.Proofs.Safety
