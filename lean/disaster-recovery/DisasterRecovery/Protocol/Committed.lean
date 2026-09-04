import DisasterRecovery.Protocol.Quorum
import Mathlib.Tactic

namespace DisasterRecovery.Protocol

namespace TxID

def PrefixOf (left right : TxID) : Prop :=
  left.view < right.view \/
    (left.view = right.view /\ left.seqno <= right.seqno)

theorem prefix_refl (txid : TxID) : PrefixOf txid txid := by
  simp [PrefixOf]

theorem prefix_trans
    {first second third : TxID}
    (firstSecond : PrefixOf first second)
    (secondThird : PrefixOf second third) :
    PrefixOf first third := by
  simp [PrefixOf] at firstSecond secondThird ⊢
  omega

end TxID

namespace Global

theorem prefix_of_score_true
    (leftName rightName : Location)
    (left right : TxID)
    (score :
      txScoreGreater leftName left rightName right = true) :
    TxID.PrefixOf right left := by
  simp [txScoreGreater] at score
  simp [TxID.PrefixOf]
  omega

theorem prefix_of_score_false
    (leftName rightName : Location)
    (left right : TxID)
    (score :
      txScoreGreater leftName left rightName right = false) :
    TxID.PrefixOf left right := by
  simp [txScoreGreater] at score
  simp [TxID.PrefixOf]
  omega

theorem current_prefix_selectMaximum
    (current candidate : Prod Location TxID) :
    TxID.PrefixOf current.2
      (selectMaximum current candidate).2 := by
  unfold selectMaximum
  split
  · rename_i score
    exact prefix_of_score_true
      candidate.1 current.1 candidate.2 current.2 score
  · exact TxID.prefix_refl current.2

theorem candidate_prefix_selectMaximum
    (current candidate : Prod Location TxID) :
    TxID.PrefixOf candidate.2
      (selectMaximum current candidate).2 := by
  unfold selectMaximum
  split
  · exact TxID.prefix_refl candidate.2
  · rename_i score
    exact prefix_of_score_false
      candidate.1 current.1 candidate.2 current.2
      (Bool.eq_false_iff.mpr score)

theorem foldl_selectMaximum_upper_bound
    (current member : Prod Location TxID)
    (tail : List (Prod Location TxID))
    (membership : member = current \/ member ∈ tail) :
    TxID.PrefixOf member.2
      (tail.foldl selectMaximum current).2 := by
  induction tail generalizing current member with
  | nil =>
      simp at membership
      subst member
      exact TxID.prefix_refl current.2
  | cons candidate rest ih =>
      simp only [List.foldl_cons]
      rcases membership with currentMember | tailMember
      · subst member
        exact TxID.prefix_trans
          (current_prefix_selectMaximum current candidate)
          (ih (selectMaximum current candidate)
            (selectMaximum current candidate) (Or.inl rfl))
      · rw [List.mem_cons] at tailMember
        rcases tailMember with candidateMember | restMember
        · subst member
          exact TxID.prefix_trans
            (candidate_prefix_selectMaximum current candidate)
            (ih (selectMaximum current candidate)
              (selectMaximum current candidate) (Or.inl rfl))
        · exact ih (selectMaximum current candidate) member
            (Or.inr restMember)

theorem maximumGossip_upper_bound
    {gossips : List (Prod Location TxID)}
    {selected member : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected)
    (membership : member ∈ gossips) :
    TxID.PrefixOf member.2 selected.2 := by
  cases gossips with
  | nil => simp at membership
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      apply foldl_selectMaximum_upper_bound head member tail
      simpa using membership

theorem foldl_selectMaximum_mem
    (current : Prod Location TxID)
    (tail : List (Prod Location TxID)) :
    tail.foldl selectMaximum current ∈ current :: tail := by
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

theorem maximumGossip_mem
    {gossips : List (Prod Location TxID)}
    {selected : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected) :
    selected ∈ gossips := by
  cases gossips with
  | nil => simp [maximumGossip] at maximum
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      exact foldl_selectMaximum_mem head tail

theorem recoveredTxID_of_mem
    {config : Config}
    {location : Location}
    {txid : TxID}
    (valid : config.Valid)
    (membership : (location, txid) ∈ config.recovered) :
    recoveredTxID config location = some txid := by
  have keysNodup : (config.recovered.map Prod.fst).Nodup := by
    rw [valid.2.2]
    exact valid.2.1
  unfold recoveredTxID
  cases found :
      config.recovered.find? fun entry => entry.1 == location with
  | none =>
      rw [List.find?_eq_none] at found
      exact False.elim
        (found (location, txid) membership (by simp))
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

def FullGossipSelection
    (config : Config)
    (state : State)
    (opener : Location) : Prop :=
  exists vote,
    vote ∈ state.sent /\
      vote.payload = .vote /\
      vote.target = opener /\
      forall gossip,
        gossip ∈ vote.sourceState.gossips <->
          gossip ∈ config.recovered

def DurableCommit (config : Config) (committed : TxID) : Prop :=
  exists location txid,
    (location, txid) ∈ config.recovered /\
      TxID.PrefixOf committed txid

theorem full_gossip_selection_preserves_commit
    {config : Config}
    {state : State}
    {opener : Location}
    {committed : TxID}
    (reachable : Reachable config state)
    (full : FullGossipSelection config state opener)
    (durable : DurableCommit config committed) :
    exists recovered,
      recoveredTxID config opener = some recovered /\
        TxID.PrefixOf committed recovered := by
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
  exact
    ⟨selectedTxID,
      recoveredTxID_of_mem configValid selectedRecovered,
      TxID.prefix_trans committedDurable durableMaximum⟩

/--
Quorum opening scopes the result to an actual decision, while the separate
`FullGossipSelection` premise carries the completeness requirement. Quorum
opening alone does not imply complete gossip because voting may follow a
gossip timeout.
-/
theorem quorum_open_preserves_commit
    {config : Config}
    {state : State}
    {opener : Location}
    {committed : TxID}
    (reachable : Reachable config state)
    (_opened : QuorumOpened state opener)
    (full : FullGossipSelection config state opener)
    (durable : DurableCommit config committed) :
    exists recovered,
      recoveredTxID config opener = some recovered /\
        TxID.PrefixOf committed recovered :=
  full_gossip_selection_preserves_commit reachable full durable

end Global

end DisasterRecovery.Protocol
