module

public import CCFRaft.Proofs.Safety.Follower

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Step facts for liveness

Per-handler facts that the safety summary leaves out: when a node becomes a
settled follower, how a primary's replication frontiers move, and the exact
rejection a follower sends.
-/

namespace CCFRaft.Proofs.Safety

open CCFRaft.Proofs.Ledger
open CCF
open Model.Node

/-- Not campaigning, and not waiting to truncate a conflicting suffix. -/
def Settled (state : NodeState) : Prop :=
  Not (state.role = .candidate)
  /\ Not (state.role = .preVoteCandidate)
  /\ state.isNewFollower = false

/-- A step that keeps the log and ends settled started settled in the same term,
unless it won an election. -/
def Steady (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    : Prop :=
  Settled after
  -> after.log = before.log
  -> (Settled before /\ after.currentTerm = before.currentTerm)
      \/ Wins self before event after

/-- The fields `advanceCommit` may change. -/
def Committing (middle state : NodeState) : Prop :=
  exists commitIndex retiredCommittedIndex role primaryKnown,
    state = { middle with commitIndex, retiredCommittedIndex, role, primaryKnown }
    /\ (role = middle.role \/ role = .none)

/-- Truncating a conflicting suffix changes the log. -/
theorem acceptLog_ne {log : List Entry} {request : AppendEntriesRequest} {index : Nat}
    (conflict : conflictIndex log request = some index)
    : Not (acceptLog log request = log) := by
  intro eq
  unfold acceptLog at eq
  rw [conflict] at eq
  unfold conflictIndex at conflict
  obtain ⟨pair, found, indexEq⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨different, offset, lt, pairEq, -⟩ := List.find?_eq_some_iff_getElem.mp found
  simp only [List.length_zipIdx, List.length_zip, List.length_drop] at lt
  rw [List.getElem_zipIdx] at pairEq
  subst pairEq indexEq
  simp only [List.getElem_zip, List.getElem_drop, bne_iff_ne, ne_eq] at different
  have keptLength
      : (log.take (request.prevLogIndex + 1 + offset - 1)).length
        = request.prevLogIndex + offset := by
    simp only [List.length_take]
    omega
  have at_ := congrArg (fun list => list[request.prevLogIndex + offset]?) eq
  simp only at at_
  rw [List.getElem?_append_right (by omega), keptLength, List.getElem?_drop] at at_
  rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at at_
  have same : request.entries[offset] = log[request.prevLogIndex + offset] := by
    simpa using Option.some.inj at_
  exact different (by rw [same])

section Effects

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advanceCommit_committing (middle : NodeState)
    : Sends (fun state (_ : List Model.Envelope) => Committing middle state)
        (advanceCommit caps middle self) := by
  unfold advanceCommit
  dsimp only
  have keep : Committing middle middle := ⟨_, _, _, _, rfl, Or.inl rfl⟩
  obtain ⟨retired, role, known, eq, roleCase⟩ :=
    NodeState.recordCommit_eq self middle (highestCommittableIndex middle self)
  have recorded
      : Committing middle (middle.recordCommit self (highestCommittableIndex middle self)) :=
    ⟨_, retired, role, known, eq, roleCase⟩
  refine Sends.ite' (fun _ => Sends.pure' keep) fun _ => ?_
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' recorded)
    fun _ => Sends.pure' recorded
  exact Sends.bind' (nominate_sends self middle) fun _ _ _ => Sends.pure' recorded

theorem Committing.newFollower {middle state : NodeState}
    (committing : Committing middle state)
    : state.isNewFollower = middle.isNewFollower := by
  obtain ⟨_, _, _, _, rfl, _⟩ := committing
  rfl

theorem Committing.term {middle state : NodeState} (committing : Committing middle state)
    : state.currentTerm = middle.currentTerm := by
  obtain ⟨_, _, _, _, rfl, _⟩ := committing
  rfl

end Effects

/-! ## Settling -/

section Steady

variable {self : NodeID}

theorem steady_keep {before after : NodeState} {event : Event}
    (newFollower : after.isNewFollower = before.isNewFollower)
    (term : after.currentTerm = before.currentTerm)
    (role
      : (Not (before.role = .candidate) /\ Not (before.role = .preVoteCandidate))
        \/ after.role = before.role)
    : Steady self before event after := by
  intro settled _
  refine Or.inl ⟨?_, term⟩
  obtain ⟨notCandidate, notPreVote, settledFollower⟩ := settled
  rcases role with ⟨left, right⟩ | same
  · exact ⟨left, right, newFollower ▸ settledFollower⟩
  · exact ⟨same ▸ notCandidate, same ▸ notPreVote, newFollower ▸ settledFollower⟩

theorem steady_unsettled {before after : NodeState} {event : Event}
    (unsettled : Not (Settled after))
    : Steady self before event after :=
  fun settled => (unsettled settled).elim

theorem campaign_steady {before candidate after : NodeState} {event : Event}
    {sent : List Model.Envelope} (campaign : Campaign self before event candidate)
    (result : CampaignResult self before candidate after sent)
    : Steady self before event after := by
  intro settled _
  rcases result with ⟨rfl, _⟩ | ⟨quorum, advance, _⟩
  · exact (settled.1 campaign.1).elim
  · exact Or.inr ⟨candidate, campaign, quorum, advance⟩

theorem bumped_unsettled (state : NodeState) (term : Nat)
    : Not (Settled (bumpedState state term)) := by
  simp [Settled, bumpedState]

theorem steady_committing {before middle after : NodeState} {event : Event}
    (leader : before.role = .primary) (committing : Committing middle after)
    (newFollower : middle.isNewFollower = before.isNewFollower)
    (term : middle.currentTerm = before.currentTerm)
    : Steady self before event after :=
  steady_keep (committing.newFollower.trans newFollower) (committing.term.trans term)
    (Or.inl ⟨by simp [leader], by simp [leader]⟩)

end Steady

/-! ## Handling AppendEntries exactly -/

/-- The state an AppendEntries request is handled in, after a same-term
candidate learns of the primary. -/
def awareState (z : NodeState) (r : AppendEntriesRequest) : NodeState :=
  if r.term = z.currentTerm /\ (z.role = .candidate \/ z.role = .preVoteCandidate) then
    becomeAwareOfNewTerm z r.term
  else
    z

theorem awareState_term (z : NodeState) (r : AppendEntriesRequest)
    : (awareState z r).currentTerm = z.currentTerm := by
  unfold awareState
  split
  · rename_i h
    simp [becomeAwareOfNewTerm, h.1]
  · rfl

theorem awareState_log (z : NodeState) (r : AppendEntriesRequest)
    : (awareState z r).log = z.log := by
  unfold awareState
  split <;> rfl

theorem awareState_settled {z : NodeState} {r : AppendEntriesRequest}
    (settled : (awareState z r).isNewFollower = false)
    : awareState z r = z
      /\ (r.term = z.currentTerm
          -> Not (z.role = .candidate) /\ Not (z.role = .preVoteCandidate)) := by
  unfold awareState at *
  split at settled
  · simp [becomeAwareOfNewTerm] at settled
  · rename_i keep
    exact ⟨ite_eq_right_iff.mpr fun h => (keep h).elim, fun same => ⟨fun c => keep ⟨same, Or.inl c⟩, fun c => keep ⟨same, Or.inr c⟩⟩⟩

/-- The rejection sent by a node in state `w` to request `r`. -/
def nackResponse (w : NodeState) (r : AppendEntriesRequest) : AppendEntriesResponse :=
  if r.term < w.currentTerm \/ termAt w.log r.prevLogIndex = 0 then
    { term := w.currentTerm, success := false, lastLogIndex := w.log.length }
  else
    {
      term := termAt w.log (findHighestPossibleMatch w.log r.prevLogIndex r.prevLogTerm),
      success := false,
      lastLogIndex := findHighestPossibleMatch w.log r.prevLogIndex r.prevLogTerm
    }

/-- The three outcomes of handling AppendEntries request `r` in state `w`:
reject, ignore, or accept. -/
def AEStep (self source : NodeID) (w : NodeState) (r : AppendEntriesRequest)
    (after : NodeState) (sent : List Model.Envelope)
    : Prop :=
  ((r.term < w.currentTerm \/ Not (appendEntryMatchesLog w r))
    /\ after = w
    /\ sent
        = [{
            source := self,
            target := source,
            payload := .appendEntriesResponse (nackResponse w r)
          }])
  \/ (r.term = w.currentTerm
      /\ appendEntryMatchesLog w r
      /\ (r.prevLogIndex < w.commitIndex
          \/ ((conflictIndex w.log r).isSome /\ w.isNewFollower = false))
      /\ after = { w with primaryKnown := true }
      /\ sent = [])
  \/ (r.term = w.currentTerm
      /\ appendEntryMatchesLog w r
      /\ w.commitIndex <= r.prevLogIndex
      /\ ((conflictIndex w.log r).isSome -> w.isNewFollower = true)
      /\ after.currentTerm = w.currentTerm
      /\ (after.role = w.role \/ after.role = .none)
      /\ after.log = acceptLog w.log r
      /\ (conflictIndex w.log r = none -> after.isNewFollower = w.isNewFollower)
      /\ after.sentIndex = w.sentIndex
      /\ after.matchIndex = w.matchIndex
      /\ sent
          = [{
              source := self,
              target := source,
              payload :=
                .appendEntriesResponse
                  {
                    term := w.currentTerm,
                    success := true,
                    lastLogIndex := r.prevLogIndex + r.entries.length
                  }
            }])

theorem aeStep (self source : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    (le : r.term <= z.currentTerm)
    : Sends (AEStep self source (awareState z r) r)
        (handleAppendEntriesRequest (Capabilities.record self) self source z r) := by
  have wTerm := awareState_term z r
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have hw' : awareState z r = w := hw
  rw [hw'] at wTerm ⊢
  refine Sends.ite' (fun reject => ?_) fun accept => ?_
  · refine Sends.ite' (fun short => ?_) fun long => ?_ <;>
      refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' (Or.inl ⟨reject, rfl, ?_⟩) <;>
      subst eq
    · simp [nackResponse, short]
    · simp [nackResponse, long]
  have notOr := not_or.mp accept
  have same : r.term = w.currentTerm := by have := notOr.1; omega
  have matches_ : appendEntryMatchesLog w r := Classical.not_not.mp notOr.2
  have conflictEq : firstTermConflictIndex { w with primaryKnown := true } r
      = conflictIndex w.log r := rfl
  refine Sends.ite'
    (fun ignore => Sends.pure' (Or.inr (Or.inl ⟨same, matches_, ?_, rfl, rfl⟩)))
    fun go => ?_
  · rw [conflictEq] at ignore
    simpa using ignore
  rw [conflictEq] at go
  have go' : w.commitIndex <= r.prevLogIndex
      /\ ((conflictIndex w.log r).isSome -> w.isNewFollower = true) := by
    simp only [not_or, not_and, Bool.not_eq_true'] at go
    exact ⟨by omega, fun some => by simpa using go.2 some⟩
  have tail : forall v : NodeState,
      v.log
          = (match conflictIndex w.log r with
            | some index => w.log.take (index - 1)
            | none => w.log)
      -> v.currentTerm = w.currentTerm -> v.role = w.role
      -> (conflictIndex w.log r = none -> v.isNewFollower = w.isNewFollower)
      -> v.sentIndex = w.sentIndex -> v.matchIndex = w.matchIndex
      -> Sends (AEStep self source w r)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v vLog vTerm vRole vNew vSent vMatch
    have spec := fromLeader_spec self v r
    obtain ⟨_, _, _, eq, _⟩ := Ledger.handleAppendEntiresFromPrimary_eq self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    have newEq : result.isNewFollower = v.isNewFollower := by
      simpa [hres] using congrArg (fun p => p.1.isNewFollower) eq
    have sentEq : result.sentIndex = v.sentIndex := by
      simpa [hres] using congrArg (fun p => p.1.sentIndex) eq
    have matchEq : result.matchIndex = v.matchIndex := by
      simpa [hres] using congrArg (fun p => p.1.matchIndex) eq
    simp only [hres] at spec ⊢
    obtain ⟨term, _, _, _, role, log, _, response⟩ := spec
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    refine Or.inr
      (Or.inr
        ⟨
          same,
          matches_,
          go'.1,
          go'.2,
          term.trans vTerm,
          vRole ▸ role,
          ?_,
          fun none => newEq.trans (vNew none),
          sentEq.trans vSent,
          matchEq.trans vMatch,
          ?_
        ⟩)
    · rw [log, vLog]
      rfl
    · simp [response, vTerm]
  split
  · rename_i heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq]) rfl rfl (fun _ => rfl) rfl rfl
  · rename_i index heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq]) rfl rfl (fun none => by rw [heq] at none; cases none) rfl
      rfl

theorem steady_ae {self source : NodeID} {before z after : NodeState}
    {r : AppendEntriesRequest} {sent : List Model.Envelope} {event : Event}
    (step : AEStep self source (awareState z r) r after sent)
    (zLog : z.log = before.log) (zCase : z.isNewFollower = true \/ z = before)
    : Steady self before event after := by
  intro settled logEq
  have known : z.isNewFollower = false -> z = before := fun f => by
    rcases zCase with t | e
    · rw [t] at f; cases f
    · exact e
  rcases step with ⟨_, rfl, _⟩ | ⟨_, _, _, rfl, _⟩ |
      ⟨same, _, _, _, term, _, log, newFollower, _⟩
  · obtain ⟨wz, _⟩ := awareState_settled settled.2.2
    rw [wz] at settled ⊢
    obtain rfl := known settled.2.2
    exact Or.inl ⟨settled, rfl⟩
  · obtain ⟨wz, _⟩ := awareState_settled (z := z) (r := r) settled.2.2
    rw [wz] at settled ⊢
    obtain rfl := known settled.2.2
    exact Or.inl ⟨settled, rfl⟩
  · cases conflict : conflictIndex (awareState z r).log r with
    | some index =>
        exact (acceptLog_ne conflict
          (log.symm.trans (logEq.trans (zLog.symm.trans (awareState_log z r).symm)))).elim
    | none =>
        have wFresh := (newFollower conflict).symm.trans settled.2.2
        have roleOk := (awareState_settled wFresh).2 (same.trans (awareState_term z r))
        have wz := (awareState_settled wFresh).1
        rw [wz] at wFresh term
        obtain rfl := known wFresh
        exact Or.inl ⟨⟨roleOk.1, roleOk.2, wFresh⟩, term⟩

/-! ## Settling steps -/

section StepSteady

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem appendBatch_steady (before : NodeState) (contents : List EntryContent)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.internal (.append contents)) after)
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => ?_
  subst empty
  have start : BatchState self before before [] := BatchState.start self before
  refine Sends.bind' (Sends.mono (Sends.foldlM' (I := BatchState self before)
      (fun value sent' item batch => appendEntry_batch self before value sent' item batch)
      contents before [] start) fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  obtain ⟨⟨entries, sentIndex, rfl, _⟩, _⟩ := batch
  exact Sends.mono (advanceCommit_committing self _) fun after _ committing =>
    steady_committing leader committing rfl rfl

theorem sendEntries_steady (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.internal (.sendEntries destination batchEnds)) after)
        (sendEntries caps self before destination batchEnds) :=
  Sends.mono (sendEntries_pass self before destination batchEnds)
    fun _ _ pass => by
      rw [pass.state]
      exact steady_keep rfl rfl (Or.inr rfl)

theorem startElection_steady (before : NodeState)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.internal (.timeout .election)) after)
        (startElection caps before self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  have notNone : Not (before.role = .none) := by
    rcases can.1 with eq | eq | eq <;> rw [eq] <;> simp
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_result self _ before rfl) fun after sent result =>
      campaign_steady (fresh_campaign notNone rfl rfl rfl (Or.inl rfl)) result
  · exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ =>
      Sends.pure' (steady_unsettled fun settled => settled.2.1 rfl)

theorem checkQuorum_steady (before : NodeState)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.internal (.timeout .checkQuorum)) after)
        (checkQuorum before self) := by
  unfold checkQuorum
  exact Sends.bind' Sends.guard'
    fun _ _ ⟨⟨leader, _⟩, _⟩ =>
      Sends.pure' (steady_keep rfl rfl (Or.inl ⟨by simp [leader], by simp [leader]⟩))

theorem nominate_steady (before : NodeState)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.internal .nominateSuccessor) after)
        (act caps self before .nominateSuccessor) :=
  Sends.mono (nominate_sends self before)
    fun _ _ ⟨same, _, _⟩ => by
      subst same
      exact steady_keep rfl rfl (Or.inr rfl)

theorem appendEntriesRequest_steady (before : NodeState) (source : NodeID)
    (request : AppendEntriesRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.appendEntriesRequest request)) after)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · exact Sends.mono (aeStep self source _ request (le_refl _)) fun after sent step =>
      steady_ae step rfl (Or.inl rfl)
  · exact Sends.mono (aeStep self source _ request le) fun after sent step =>
      steady_ae step rfl (Or.inr rfl)

theorem appendEntriesResponse_steady (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.appendEntriesResponse response)) after)
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))) fun _ => ?_
  rcases observe_response before response with ⟨leader, bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · exact Sends.ite' (fun _ => Sends.pure' (steady_unsettled (bumped_unsettled _ _)))
      fun notFollower => absurd notFollower (by simp [bumpedState])
  · refine Sends.ite' (fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))) fun leader => ?_
    have leader : before.role = .primary := by simpa using leader
    refine Sends.ite'
      (fun _ =>
        Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl)))
      fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))
    exact Sends.mono (advanceCommit_committing self _) fun after _ committing =>
      steady_committing leader committing rfl rfl

theorem voteRequest_steady (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.requestVoteRequest request)) after)
        (receive caps self source before (.requestVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_ <;> split
  · exact steady_unsettled fun settled => by simp [Settled, bumpedState] at settled
  · exact steady_unsettled (bumped_unsettled _ _)
  · exact steady_keep rfl rfl (Or.inr rfl)
  · exact steady_keep rfl rfl (Or.inr rfl)

theorem voteResponse_steady (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.requestVoteResponse response)) after)
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))) fun _ => ?_
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · exact Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (steady_unsettled (bumped_unsettled _ _))
  · refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))
    have campaign : Campaign self before (.receive source (.requestVoteResponse response))
        { before with votesGranted := insert source before.votesGranted } := by
      refine ⟨won.1, rfl, rfl, Or.inr ⟨won.1, rfl, Or.inl rfl, fun voter member => ?_⟩⟩
      rcases Finset.mem_insert.mp member with rfl | old
      · exact Or.inr ⟨response, rfl, won.2.1, won.2.2⟩
      · exact Or.inl old
    exact Sends.mono (electIfQuorum_sends self _) fun after sent elected =>
      campaign_steady campaign (elect_result self elected)

theorem preVoteRequest_steady (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.requestPreVoteRequest request)) after)
        (receive caps self source before (.requestPreVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestPreVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
  · exact steady_unsettled (bumped_unsettled _ _)
  · exact steady_keep rfl rfl (Or.inr rfl)

theorem preVoteResponse_steady (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.requestPreVoteResponse response)) after)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))) fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · exact Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (steady_unsettled (bumped_unsettled _ _))
  · refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))
    have notNone : Not (before.role = .none) := by rw [won.1]; simp
    refine Sends.ite' (fun _ => ?_) fun _ =>
      Sends.pure' (steady_unsettled fun settled => settled.2.1 won.1)
    exact Sends.mono (becomeCandidate_result self _ before rfl) fun after sent result =>
      campaign_steady
        (fresh_campaign notNone rfl rfl rfl (Or.inr (Or.inl ⟨source, response, rfl, won.1⟩)))
        result

theorem proposeVote_steady (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          Steady self before (.receive source (.proposeRequestVoteRequest term)) after)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))) fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_)
    fun _ => Sends.pure' (steady_keep rfl rfl (Or.inr rfl))
  have notNone : Not (before.role = .none) := by
    rcases start.2.1 with eq | eq | eq <;> rw [eq] <;> simp
  exact Sends.mono (becomeCandidate_result self before before rfl)
    fun after sent result =>
      campaign_steady
        (fresh_campaign notNone rfl rfl rfl (Or.inr (Or.inr ⟨source, by rw [start.1]⟩)))
        result

/-- Every local step is `Steady`. -/
theorem steady_step (before : NodeState) (event : Event)
    : Sends (fun after (_ : List Model.Envelope) => Steady self before event after)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_steady self before contents
      | sendEntries destination batchEnds =>
          exact sendEntries_steady self before destination batchEnds
      | timeout kind =>
          cases kind with
          | election => exact startElection_steady self before
          | checkQuorum => exact checkQuorum_steady self before
      | nominateSuccessor => exact nominate_steady self before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_steady self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_steady self before source response
      | requestVoteRequest request => exact voteRequest_steady self before source request
      | requestVoteResponse response =>
          exact voteResponse_steady self before source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_steady self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_steady self before source response
      | proposeRequestVoteRequest term => exact proposeVote_steady self before source term

end StepSteady

/-! ## Settled logs follow the leader of their term -/

variable [Config.InitialConfiguration]

/-- A settled node's log is empty or a prefix of a leader log of its term. -/
def NoJunk (history : History) : Prop :=
  forall node state,
    Now history node state
    -> Settled state
    -> state.log = []
        \/ exists log, Canon history state.currentTerm log /\ state.log <+: log

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

theorem steady : Steady c.actor c.pre c.event c.post := by
  obtain ⟨_, _, holds⟩ := steady_step c.tr.actor c.tr.pre c.tr.event {} _ _ c.tr.ran
  exact holds

theorem noJunk_step (noJunk : NoJunk (before :: rest))
    : NoJunk (after :: before :: rest) := by
  intro node state now settled
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · by_cases led : Led (after :: before :: rest) c.actor c.post.currentTerm
    · exact Or.inr ⟨c.post.log, ⟨after :: before :: rest, List.suffix_refl _, c.actor, c.post,
        ⟨c.post_now, rfl, settled.1, led⟩, rfl⟩, List.prefix_refl _⟩
    rcases c.log_follow led with same | ⟨earlier, sender, n, suffix, ⟨source, canon⟩, _,
        postEq, _⟩
    · rcases c.steady settled same with ⟨preSettled, term⟩ | wins
      · rcases noJunk c.actor c.pre c.pre_now preSettled with empty | ⟨log, canon, held⟩
        · exact Or.inl (same.trans empty)
        · exact Or.inr ⟨log, by rw [term]; exact canon.mono c.suffix_tail, same ▸ held⟩
      · exact absurd (Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩)
          led
    · exact Or.inr ⟨sender.log, ⟨earlier, suffix.trans c.suffix_tail, source, sender, canon,
        rfl⟩, postEq ▸ List.take_prefix _ _⟩
  · rcases noJunk node state old settled with empty | ⟨log, canon, held⟩
    · exact Or.inl empty
    · exact Or.inr ⟨log, canon.mono c.suffix_tail, held⟩

end Ctx

theorem noJunk_of_exec {nodes : List NodeID} {history : History}
    (exec : Exec nodes history)
    : NoJunk history := by
  induction exec with
  | @initial current initialized =>
      have inv : Inv [current] :=
        good_of_exec (Exec.initial (nodes := nodes) initialized) _ (List.suffix_refl _)
          (List.cons_ne_nil _ _)
      intro node state now settled
      by_cases leader : state.role = .primary
      · exact Or.inr ⟨state.log, ⟨[current], List.suffix_refl _, node, state,
          ⟨now, rfl, by simp [leader], inv.leader_led node state now leader⟩, rfl⟩,
          List.prefix_refl _⟩
      · left
        have := initial_state initialized now
        subst this
        by_cases primary : node = Config.INITIAL_PRIMARY
        · simp [initialLocal, primary] at leader
        · simp [initialLocal, primary]
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, good_of_exec prior⟩
      exact c.noJunk_step ih

end CCFRaft.Proofs.Safety
