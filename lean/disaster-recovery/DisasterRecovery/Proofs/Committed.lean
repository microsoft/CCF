import DisasterRecovery.Proofs.Predicates
import DisasterRecovery.Proofs.Quorum
import DisasterRecovery.Properties.Utils
import Mathlib.Tactic

/-!
Machine-checked proof implementations. Review the system-level statements in
`DisasterRecovery.Properties` and ghost predicates in `DisasterRecovery.Proofs.Predicates`.
-/

namespace DisasterRecovery.Proofs.Committed

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants DisasterRecovery.Proofs.Quorum

lemma prefix_refl (txid : TxID) : TxID.EarlierThan txid txid := by
  simp [TxID.EarlierThan]

lemma prefix_trans
    {first second third : TxID}
    (firstSecond : TxID.EarlierThan first second)
    (secondThird : TxID.EarlierThan second third)
    : TxID.EarlierThan first third := by
  simp [TxID.EarlierThan] at firstSecond secondThird ⊢
  omega

lemma prefix_of_score_true
    (leftName rightName : Location)
    (left right : TxID)
    (score : txScoreGreater leftName left rightName right = true)
    : TxID.EarlierThan right left := by
  simp [txScoreGreater] at score
  simp [TxID.EarlierThan]
  omega

lemma prefix_of_score_false
    (leftName rightName : Location)
    (left right : TxID)
    (score : txScoreGreater leftName left rightName right = false)
    : TxID.EarlierThan left right := by
  simp [txScoreGreater] at score
  simp [TxID.EarlierThan]
  omega

lemma current_prefix_selectMaximum (current candidate : Prod Location TxID)
    : TxID.EarlierThan current.2 (selectMaximum current candidate).2 := by
  unfold selectMaximum
  split
  · rename_i score
    exact prefix_of_score_true
      candidate.1 current.1 candidate.2 current.2 score
  · exact prefix_refl current.2

lemma candidate_prefix_selectMaximum (current candidate : Prod Location TxID)
    : TxID.EarlierThan candidate.2 (selectMaximum current candidate).2 := by
  unfold selectMaximum
  split
  · exact prefix_refl candidate.2
  · rename_i score
    exact prefix_of_score_false
      candidate.1 current.1 candidate.2 current.2
      (Bool.eq_false_iff.mpr score)

lemma foldl_selectMaximum_upper_bound
    (current member : Prod Location TxID)
    (tail : List (Prod Location TxID))
    (membership : member = current \/ member ∈ tail)
    : TxID.EarlierThan member.2 (tail.foldl selectMaximum current).2 := by
  induction tail generalizing current member with
  | nil =>
      simp at membership
      subst member
      exact prefix_refl current.2
  | cons candidate rest ih =>
      simp only [List.foldl_cons]
      rcases membership with currentMember | tailMember
      · subst member
        exact prefix_trans
          (current_prefix_selectMaximum current candidate)
          (ih (selectMaximum current candidate)
            (selectMaximum current candidate) (Or.inl rfl))
      · rw [List.mem_cons] at tailMember
        rcases tailMember with candidateMember | restMember
        · subst member
          exact prefix_trans
            (candidate_prefix_selectMaximum current candidate)
            (ih (selectMaximum current candidate)
              (selectMaximum current candidate) (Or.inl rfl))
        · exact ih (selectMaximum current candidate) member
            (Or.inr restMember)

lemma maximumGossip_upper_bound
    {gossips : List (Prod Location TxID)}
    {selected member : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected)
    (membership : member ∈ gossips)
    : TxID.EarlierThan member.2 selected.2 := by
  cases gossips with
  | nil => simp at membership
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      apply foldl_selectMaximum_upper_bound head member tail
      simpa using membership

lemma foldl_selectMaximum_mem (current : Prod Location TxID)
    (tail : List (Prod Location TxID))
    : tail.foldl selectMaximum current ∈ current :: tail := by
  induction tail generalizing current with
  | nil => simp
  | cons candidate rest ih =>
      simp only [List.foldl_cons]
      have selected :
          selectMaximum current candidate = current \/
            selectMaximum current candidate = candidate := by
        unfold selectMaximum
        split <;> simp
      have member :=
        ih (selectMaximum current candidate)
      rw [List.mem_cons] at member
      rcases member with currentMember | restMember
      · rw [currentMember]
        rcases selected with selected | selected
        · simp [selected]
        · simp [selected]
      · simp [restMember]

lemma maximumGossip_mem
    {gossips : List (Prod Location TxID)}
    {selected : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected)
    : selected ∈ gossips := by
  cases gossips with
  | nil => simp [maximumGossip] at maximum
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      exact foldl_selectMaximum_mem head tail

lemma recoveredTxID_of_mem
    {config : Config}
    {location : Location}
    {txid : TxID}
    (valid : config.Valid)
    (membership : (location, txid) ∈ config.recovered)
    : recoveredTxID config location = some txid := by
  have keysNodup : (config.recovered.map Prod.fst).Nodup := by
    rw [valid.2.2]
    exact valid.2.1
  unfold recoveredTxID
  cases found : config.recovered.find? fun entry => entry.1 == location with
  | none =>
      rw [List.find?_eq_none] at found
      exact False.elim (found (location, txid) membership (by simp))
  | some entry =>
      have foundMember : entry ∈ config.recovered :=
        List.mem_of_find?_eq_some found
      have foundLocation : entry.1 = location :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location TxID =>
              entry.1 == location) found)
      have same :
          entry = (location, txid) :=
        eq_of_key_eq keysNodup foundMember membership foundLocation
      simp [same]

lemma mem_of_recoveredTxID
    {config : Config} {location : Location} {txid : TxID}
    (recovered : recoveredTxID config location = some txid)
    : (location, txid) ∈ config.recovered := by
  obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp recovered
  have key := beq_iff_eq.mp
    (List.find?_some (p := fun entry : Location × TxID => entry.1 == location) found)
  have same : entry = (location, txid) := Prod.ext key value
  rw [← same]
  exact List.mem_of_find?_eq_some found

lemma up_to_date_with_quorum_of_voters
    {config : Config} {candidate : TxID} {voters : List Location}
    (nodup : voters.Nodup)
    (threshold : voteQuorum config.protocol <= voters.length)
    (fresh
      : forall voter,
          voter ∈ voters
          -> exists txid,
              recoveredTxID config voter = some txid /\ TxID.EarlierThan txid candidate)
    : Properties.UpToDateWithQuorum config candidate := by
  let eligible := config.recovered.filter fun (_, voter) =>
    decide (Properties.LogUpToDate candidate voter)
  have subset : voters.toFinset ⊆ (eligible.map Prod.fst).toFinset := by
    intro voter member
    obtain ⟨txid, recovered, earlier⟩ := fresh voter (List.mem_toFinset.mp member)
    apply List.mem_toFinset.mpr
    apply List.mem_map.mpr
    refine ⟨(voter, txid), List.mem_filter.mpr ⟨mem_of_recoveredTxID recovered, ?_⟩, rfl⟩
    exact decide_eq_true earlier
  have count := Finset.card_le_card subset
  rw [List.toFinset_card_of_nodup nodup] at count
  have bound := List.toFinset_card_le (eligible.map Prod.fst)
  rw [List.length_map] at bound
  exact threshold.trans (count.trans bound)

lemma up_to_date_with_quorum_of_all
    {config : Config} {candidate : TxID}
    (valid : config.Valid)
    (fresh : forall entry, entry ∈ config.recovered -> TxID.EarlierThan entry.2 candidate)
    : Properties.UpToDateWithQuorum config candidate := by
  apply up_to_date_with_quorum_of_voters valid.2.1
  · have nonempty : config.protocol.expectedLocations ≠ [] := by
      intro empty
      have configured := valid.1
      simp [Model.Local.Config.isValid, empty] at configured
    have positive := List.length_pos_iff.mpr nonempty
    unfold voteQuorum
    omega
  · intro voter member
    rw [← valid.2.2] at member
    obtain ⟨entry, present, key⟩ := List.mem_map.mp member
    subst voter
    exact ⟨entry.2, recoveredTxID_of_mem valid present, fresh entry present⟩

lemma full_gossip_selection_preserves_commit
    {config : Config}
    {state : State}
    {opener : Location}
    {committed : TxID}
    (reachable : Reachable config state)
    (full : FullGossipSelection config state opener)
    (durable : DurableCommit config committed)
    : exists recovered,
        recoveredTxID config opener = some recovered
        /\ TxID.EarlierThan committed recovered := by
  have configValid := reachable_config_valid reachable
  have wellFormed := reachable_well_formed reachable
  have invariant := reachable_quorum_invariant reachable
  rcases full with
    ⟨vote, sent, payload, target, complete⟩
  have voteState :=
    retry_vote_state (wellFormed.sentValid vote sent) payload
  rcases invariant.sentVotesSelected vote sent payload with
    ⟨selectedTarget, selectedTxID, choice, selected⟩
  have selectedTargetEq : selectedTarget = vote.target :=
    Option.some.inj (choice.symm.trans voteState.2)
  rw [selectedTargetEq, target] at selected
  rcases durable with
    ⟨durableLocation, durableTxID, durableMember, committedDurable⟩
  have durableGossip :
      (durableLocation, durableTxID) ∈ vote.sourceState.gossips :=
    (complete (durableLocation, durableTxID)).2 durableMember
  have durableMaximum :=
    maximumGossip_upper_bound selected durableGossip
  have selectedGossip :
      (opener, selectedTxID) ∈ vote.sourceState.gossips :=
    maximumGossip_mem selected
  have selectedRecovered :
      (opener, selectedTxID) ∈ config.recovered :=
    (complete (opener, selectedTxID)).1 selectedGossip
  exact ⟨
    selectedTxID,
    recoveredTxID_of_mem configValid selectedRecovered,
    prefix_trans committedDurable durableMaximum
  ⟩

end DisasterRecovery.Proofs.Committed
