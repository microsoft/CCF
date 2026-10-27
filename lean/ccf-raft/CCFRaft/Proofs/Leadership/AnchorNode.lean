module

public import CCFRaft.Proofs.Leadership.Membership
public import CCFRaft.Proofs.Safety.Origin

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# What one step does to an anchor node

The node-level facts an anchor relies on. A node that knows a primary
grants no pre-vote, and keeps knowing it and keeps its role unless it times
out, fails a quorum check, sees a newer term, is asked to campaign, or has its
retirement committed. A pre-vote candidate counts only pre-votes it receives,
and a step starts a fresh campaign only with a quorum of its pre-votes.
-/

namespace CCFRaft.Proofs.Leadership

open CCF
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Ledger

/-! ## The retirement latch -/

theorem isRetiredCommitted_iff (node : NodeID) (state : NodeState)
    : state.isRetiredCommitted node
      <-> (retirementIndexInLog node state.log).isSome
          /\ state.retiredCommittedIndex.isSome := by
  unfold NodeState.isRetiredCommitted NodeState.retirement
  dsimp only
  cases retirementIndexInLog node state.log <;> dsimp only
  · simp
  · split_ifs <;> simp_all

theorem zip_tail_prefix {α : Type} (left right : List α)
    : (left.zip left.tail) <+: ((left ++ right).zip (left ++ right).tail) := by
  induction left with
  | nil => simp
  | cons head tail ih =>
      cases tail with
      | nil => simp
      | cons next rest =>
          simp only [List.tail_cons, List.cons_append, List.zip_cons_cons]
          exact List.cons_prefix_cons.mpr ⟨rfl, by simpa using ih⟩

theorem configurationHistory_append (log extra : List Entry)
    : configurationHistory log <+: configurationHistory (log ++ extra) := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  exact List.prefix_append _ _

theorem find?_prefix {α : Type} {p : α -> Bool} {left right : List α}
    (isPrefix : left <+: right) (found : (left.find? p).isSome)
    : (right.find? p).isSome := by
  obtain ⟨rest, rfl⟩ := isPrefix
  rw [List.find?_append]
  obtain ⟨x, eq⟩ := Option.isSome_iff_exists.mp found
  simp [eq]

theorem retirementIndexInLog_append {node : NodeID} {log : List Entry}
    (found : (retirementIndexInLog node log).isSome) (extra : List Entry)
    : (retirementIndexInLog node (log ++ extra)).isSome := by
  unfold retirementIndexInLog at *
  dsimp only at *
  rw [Option.isSome_map] at *
  obtain ⟨more, eq⟩ := configurationHistory_append log extra
  rw [<- eq]
  exact find?_prefix (zip_tail_prefix _ _) found

/-- A committed retirement survives appending to the log. -/
theorem retired_append {node : NodeID} {state : NodeState}
    (retired : state.isRetiredCommitted node) (extra : List Entry)
    : ({ state with log := state.log ++ extra } : NodeState).isRetiredCommitted node := by
  rw [isRetiredCommitted_iff] at *
  exact ⟨retirementIndexInLog_append retired.1 extra, retired.2⟩

/-- A committed retirement survives recording a commit. -/
theorem retired_recordCommit {node : NodeID} {state : NodeState}
    (retired : state.isRetiredCommitted node) (index : Nat)
    : (state.recordCommit node index).isRetiredCommitted node := by
  rw [isRetiredCommitted_iff] at *
  unfold NodeState.recordCommit
  dsimp only
  obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp retired.2
  split <;> exact ⟨retired.1, by simp only [hx, Option.orElse_some, Option.isSome_some]⟩

/-- Recording a commit keeps the role and primary knowledge unless it commits
the node's retirement. -/
theorem recordCommit_keep (node : NodeID) (state : NodeState) (index : Nat)
    : ((state.recordCommit node index).role = state.role
        /\ (state.recordCommit node index).primaryKnown = state.primaryKnown)
      \/ (state.recordCommit node index).isRetiredCommitted node := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · rename_i retired
    refine Or.inr ?_
    have := retired.2
    simp only [NodeState.isRetiredCommitted, NodeState.retirement] at this ⊢
    exact this
  · exact Or.inl ⟨rfl, rfl⟩

/-- Role and primary knowledge are kept, or the node's retirement is committed. -/
def Latched (self : NodeID) (before after : NodeState) : Prop :=
  (after.role = before.role /\ after.primaryKnown = before.primaryKnown)
  \/ after.isRetiredCommitted self

theorem Latched.refl (self : NodeID) (state : NodeState) : Latched self state state :=
  Or.inl ⟨rfl, rfl⟩

theorem Latched.recordCommit {self : NodeID} {before after : NodeState}
    (latched : Latched self before after) (index : Nat)
    : Latched self before (after.recordCommit self index) := by
  rcases latched with ⟨role, known⟩ | retired
  · rcases recordCommit_keep self after index with ⟨role', known'⟩ | retired
    · exact Or.inl ⟨role'.trans role, known'.trans known⟩
    · exact Or.inr retired
  · exact Or.inr (retired_recordCommit retired index)

theorem Latched.append {self : NodeID} {before after : NodeState}
    (latched : Latched self before after) (extra : List Entry)
    : Latched self before { after with log := after.log ++ extra } := by
  rcases latched with ⟨role, known⟩ | retired
  · exact Or.inl ⟨role, known⟩
  · exact Or.inr (retired_append retired extra)

theorem fromLeader_latched (self : NodeID) (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        Latched self state
          (entries.foldl
            (fun state entry =>
              let state := { state with log := state.log ++ [entry] }
              if entry.content.isSignature then
                state.recordCommit self
                  (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
              else
                state)
            state) := by
  suffices general : forall (start state : NodeState), Latched self start state
      -> Latched self start
          (entries.foldl
            (fun state entry =>
              let state := { state with log := state.log ++ [entry] }
              if entry.content.isSignature then
                state.recordCommit self
                  (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
              else
                state)
            state) from
    fun state => general state state (Latched.refl self state)
  induction entries with
  | nil => exact fun _ _ latched => latched
  | cons entry entries ih =>
      intro start state latched
      simp only [List.foldl_cons]
      apply ih
      have appended := latched.append [entry]
      split
      · exact appended.recordCommit _
      · exact appended

/-- The follower's append keeps role and primary knowledge unless it commits
the node's retirement. -/
theorem fromPrimary_latched (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Latched self state (handleAppendEntiresFromPrimary self state request).1 := by
  unfold handleAppendEntiresFromPrimary
  dsimp only
  exact (fromLeader_latched self _ _ state).recordCommit _

/-! ## One step -/

/-- The step receives a message of a newer term. -/
def Raised (before : NodeState) (event : Event) : Prop :=
  exists source message,
    event = .receive source message /\ before.currentTerm < message.term

/-- Steps that may make a node forget its primary or change its role. -/
def Exempt (before : NodeState) (event : Event) : Prop :=
  event = .internal (.timeout .election)
  \/ event = .internal (.timeout .checkQuorum)
  \/ Raised before event
  \/ exists source,
      event = .receive source (.proposeRequestVoteRequest before.currentTerm)

/-- Not a pre-vote response. -/
def NoGrant (envelope : Model.Envelope) : Prop :=
  forall response, Not (envelope.payload = .requestPreVoteResponse response)

/-- What one local step does to the facts an anchor relies on. -/
structure AnchorStep (actor : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (sent : List Model.Envelope)
    : Prop where
  /-- A primary does not time out. -/
  timeout : event = .internal (.timeout .election) -> Not (before.role = .primary)
  /-- A node that knows a primary grants no pre-vote. -/
  grants
    : forall e,
        e ∈ sent
        -> forall response,
            e.payload = .requestPreVoteResponse response
            -> response.voteGranted = true
            -> before.primaryKnown = false \/ Raised before event
  /-- A follower or primary that knows a primary keeps knowing it and keeps its
  role, unless its retirement commits or the step is exempt. -/
  keep
    : before.primaryKnown = true
      -> (before.role = .follower \/ before.role = .primary)
      -> Latched actor before after \/ Exempt before event
  /-- A pre-vote is counted only from the node itself on a timeout, or from a
  granted response of the current term. -/
  counts
    : forall voter,
        voter ∈ after.preVotesGranted
        -> (event = .internal (.timeout .election) /\ voter = actor)
            \/ (Not (event = .internal (.timeout .election))
                /\ voter ∈ before.preVotesGranted)
            \/ exists response,
                event = .receive voter (.requestPreVoteResponse response)
                /\ response.term = before.currentTerm
                /\ response.voteGranted = true
  /-- A term rises without a newer message only with a quorum of pre-votes. -/
  fresh
    : before.currentTerm < after.currentTerm -> Not (Raised before event)
      -> (event = .internal (.timeout .election)
            -> hasQuorum before.activeConfigurations {actor})
          /\ forall source response,
              event = .receive source (.requestPreVoteResponse response)
              -> response.term = before.currentTerm
                  /\ response.voteGranted = true
                  /\ hasQuorum before.activeConfigurations
                      (insert source before.preVotesGranted)

namespace AnchorStep

variable {self : NodeID} {before after : NodeState} {event : Event}
  {sent : List Model.Envelope}

theorem quiet (notTimeout : Not (event = .internal (.timeout .election)))
    (latched : Latched self before after)
    (votes : after.preVotesGranted = before.preVotesGranted)
    (term : after.currentTerm = before.currentTerm)
    (noGrant : forall e, e ∈ sent -> NoGrant e)
    : AnchorStep self before event after sent where
  timeout := fun eq => (notTimeout eq).elim
  grants := fun e member response eq _ => (noGrant e member response eq).elim
  keep := fun _ _ => Or.inl latched
  counts := fun voter member => Or.inr (Or.inl ⟨notTimeout, votes ▸ member⟩)
  fresh := fun lt => absurd lt (by omega)

theorem raised (up : Raised before event)
    (votes
      : forall voter, voter ∈ after.preVotesGranted -> voter ∈ before.preVotesGranted)
    : AnchorStep self before event after sent where
  timeout :=
    fun eq => by
      obtain ⟨_, _, eq', _⟩ := up
      rw [eq] at eq'
      cases eq'
  grants := fun _ _ _ _ _ => Or.inr up
  keep := fun _ _ => Or.inr (Or.inr (Or.inr (Or.inl up)))
  counts :=
    fun voter member =>
      Or.inr
        (Or.inl
          ⟨
            fun eq => (by
              obtain ⟨_, _, eq', _⟩ := up
              rw [eq] at eq'
              cases eq'),
            votes voter member
          ⟩)
  fresh := fun _ not => (not up).elim

end AnchorStep

theorem leaderStart_noGrant {self : NodeID} {term : Nat} {state : NodeState}
    {envelope : Model.Envelope} (start : LeaderStart self term state envelope)
    : NoGrant envelope := by
  intro response eq
  rcases start with ⟨_, payload⟩ | ⟨_, _, request, payload, _⟩ <;> rw [eq] at payload <;>
    cases payload

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem advanceCommit_latched (middle : NodeState)
    : Sends
        (fun state _ =>
          Latched self middle state
          /\ state.preVotesGranted = middle.preVotesGranted
          /\ state.currentTerm = middle.currentTerm)
        (advanceCommit caps middle self) := by
  have recorded : forall index,
      Latched self middle (middle.recordCommit self index)
      /\ (middle.recordCommit self index).preVotesGranted = middle.preVotesGranted
      /\ (middle.recordCommit self index).currentTerm = middle.currentTerm := by
    intro index
    obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq self middle index
    refine ⟨(Latched.refl self middle).recordCommit index, ?_, ?_⟩ <;> rw [eq]
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun _ => Sends.pure' ⟨Latched.refl self middle, rfl, rfl⟩)
    fun _ => ?_
  refine Sends.ite'
    (fun _ =>
      Sends.ite'
        (fun _ =>
          Sends.bind' (nominate_sends self middle) fun _ _ _ => Sends.pure' (recorded _))
        fun _ => Sends.pure' (recorded _))
    fun _ => Sends.pure' (recorded _)

theorem becomePrimary_kept (candidate : NodeState)
    : Sends
        (fun state _ =>
          state.preVotesGranted = candidate.preVotesGranted
          /\ state.currentTerm = candidate.currentTerm)
        (becomePrimary caps self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (advanceCommit_latched self _) fun _ _ ⟨_, votes, term⟩ => ?_
  refine Sends.bind' (Sends.forIn' (R := fun _ => True) fun _ _ _ => ?_)
    fun _ _ _ => Sends.pure' ⟨votes, term⟩
  exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (by simp)

theorem electIfQuorum_kept (candidate : NodeState)
    : Sends
        (fun state _ =>
          state.preVotesGranted = candidate.preVotesGranted
          /\ state.currentTerm = candidate.currentTerm)
        (electIfQuorum caps self candidate) := by
  unfold electIfQuorum
  exact Sends.ite' (fun _ => becomePrimary_kept self candidate) fun _ =>
    Sends.pure' ⟨rfl, rfl⟩

theorem becomeCandidate_kept (state : NodeState)
    : Sends
        (fun next _ =>
          next.preVotesGranted = ∅ /\ next.currentTerm = state.currentTerm + 1)
        (becomeCandidate caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_kept self _) fun _ _ kept => ?_
  exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ => Sends.pure' kept

theorem electIfQuorum_noGrant (candidate : NodeState)
    : Sends (fun _ sent => forall e, e ∈ sent -> NoGrant e)
        (electIfQuorum caps self candidate) :=
  Sends.mono (electIfQuorum_sends self candidate)
    fun _ _ result e member => by
      rcases result with ⟨_, rfl⟩ | ⟨_, _, _, started⟩
      · cases member
      · exact leaderStart_noGrant (started e member)

theorem becomeCandidate_noGrant (state : NodeState)
    : Sends (fun _ sent => forall e, e ∈ sent -> NoGrant e)
        (becomeCandidate caps state self) :=
  Sends.mono (becomeCandidate_sends self state)
    fun _ _ result e member => by
      rcases result with ⟨_, votes⟩ | ⟨_, _, started⟩
      · intro response eq
        rw [(votes e member).2] at eq
        cases eq
      · rcases started e member with start | ⟨_, vote⟩
        · exact leaderStart_noGrant start
        · intro response eq
          rw [vote] at eq
          cases eq

theorem appendBatch_anchor (before : NodeState) (contents : List EntryContent)
    : Sends
        (fun after sent =>
          AnchorStep self before (.internal (.append contents)) after sent)
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.mono
      (Sends.foldlM' (I := BatchState self before)
        (fun value sent' item batch =>
          appendEntry_batch self before value sent' item batch)
        contents before [] (BatchState.start self before))
      fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  refine Sends.mono
    (Sends.and' (advanceCommit_latched self appended) (advanceCommit_sends self appended))
    fun after later ⟨⟨latched, votes, term⟩, _, proposals⟩ => ?_
  obtain ⟨⟨entries, sentIndex, rfl, _, _⟩, beats⟩ := batch
  refine AnchorStep.quiet (fun h => by cases h) latched votes term fun e member => ?_
  rcases List.mem_append.mp (by simpa using member) with old | new
  · obtain ⟨_, _, request, payload, _⟩ := beats e old
    intro response eq
    rw [eq] at payload
    cases payload
  · intro response eq
    rw [(proposals e new).2] at eq
    cases eq

theorem sendEntries_anchor (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends
        (fun after sent =>
          AnchorStep self before (.internal (.sendEntries destination batchEnds)) after
            sent)
        (act caps self before (.sendEntries destination batchEnds)) := by
  simp only [act]
  refine Sends.mono (sendEntries_pass self before destination batchEnds)
    fun after sent pass => ?_
  rw [pass.state]
  refine AnchorStep.quiet (fun h => by cases h) (Or.inl ⟨rfl, rfl⟩) rfl rfl
    fun e member => ?_
  obtain ⟨batch, _, rfl⟩ := pass.sends e member
  intro response eq
  simp [batchEnvelope] at eq

theorem startElection_anchor (before : NodeState)
    : Sends
        (fun after sent =>
          AnchorStep self before (.internal (.timeout .election)) after sent)
        (act caps self before (.timeout .election)) := by
  simp only [act]
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ _ ⟨can, empty⟩ => ?_
  subst empty
  have role : Not (before.role = .primary) := by
    rcases can.1 with eq | eq | eq <;> rw [eq] <;> simp
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun quorum => ?_) fun _ => ?_
  · refine Sends.mono
      (Sends.and' (becomeCandidate_kept self _) (becomeCandidate_noGrant self _))
      fun after sent ⟨⟨votes, _⟩, noGrant⟩ => ?_
    exact {
      timeout := fun _ => role
      grants := fun e member response eq _ =>
        (noGrant e (by simpa using member) response eq).elim
      keep := fun _ _ => Or.inr (Or.inl rfl)
      counts := fun voter member => by
        rw [votes] at member
        simp at member
      fresh := fun _ _ => ⟨fun _ => quorum, fun _ _ eq => (by cases eq)⟩
    }
  · refine Sends.bind' (broadcast_sends self _ _) fun _ sent requests => Sends.pure' ?_
    exact {
      timeout := fun _ => role
      grants := fun e member response eq _ => by
        rw [(requests e (by simpa using member)).2.2] at eq
        cases eq
      keep := fun _ _ => Or.inr (Or.inl rfl)
      counts := fun voter member => Or.inl ⟨rfl, by simpa using member⟩
      fresh := fun lt => absurd lt (lt_irrefl _)
    }

theorem checkQuorum_anchor (before : NodeState)
    : Sends
        (fun after sent =>
          AnchorStep self before (.internal (.timeout .checkQuorum)) after sent)
        (act caps self before (.timeout .checkQuorum)) := by
  simp only [act]
  unfold checkQuorum
  refine Sends.bind' Sends.guard' fun _ _ ⟨_, empty⟩ => ?_
  subst empty
  exact Sends.pure'
    {
      timeout := fun eq => by cases eq
      grants := fun e member => by simp at member
      keep := fun _ _ => Or.inr (Or.inr (Or.inl rfl))
      counts := fun voter member => Or.inr (Or.inl ⟨fun eq => (by cases eq), member⟩)
      fresh := fun lt => absurd lt (lt_irrefl _)
    }

theorem nominate_anchor (before : NodeState)
    : Sends
        (fun after sent =>
          AnchorStep self before (.internal .nominateSuccessor) after sent)
        (act caps self before .nominateSuccessor) :=
  Sends.mono (nominate_sends self before)
    fun _ _ ⟨eq, _, proposals⟩ => by
      rw [eq]
      exact AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl
        fun e member response payload => by
          rw [(proposals e member).2] at payload
          cases payload

/-- Handling an AppendEntries request from its aware state: unchanged, or
knowing the primary with role and knowledge latched. -/
theorem ae_anchor (source : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          (after = awareState z r
            \/ Latched self { awareState z r with primaryKnown := true } after)
          /\ after.preVotesGranted = (awareState z r).preVotesGranted
          /\ after.currentTerm = (awareState z r).currentTerm
          /\ forall e, e ∈ sent -> NoGrant e)
        (handleAppendEntriesRequest caps self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have hw' : awareState z r = w := hw
  rw [hw']
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · refine Sends.ite' (fun _ => ?_) fun _ => ?_ <;>
      refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
        Sends.pure' ⟨Or.inl rfl, rfl, rfl, ?_⟩ <;>
      subst eq <;> intro e member response payload <;> simp at member <;>
      subst member <;> simp at payload
  refine Sends.ite'
    (fun _ => Sends.pure' ⟨Or.inr (Or.inl ⟨rfl, rfl⟩), rfl, rfl, by simp⟩) fun _ => ?_
  have tail : forall v : NodeState,
      v.role = w.role -> v.primaryKnown = true
      -> v.preVotesGranted = w.preVotesGranted -> v.currentTerm = w.currentTerm
      -> Sends
          (fun after sent =>
            (after = w \/ Latched self { w with primaryKnown := true } after)
            /\ after.preVotesGranted = w.preVotesGranted
            /\ after.currentTerm = w.currentTerm
            /\ forall e, e ∈ sent -> NoGrant e)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v role known votes term
    have latched := fromPrimary_latched self v r
    obtain ⟨_, _, _, eq, _⟩ := Ledger.handleAppendEntiresFromPrimary_eq self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    have votesEq : result.preVotesGranted = v.preVotesGranted := by
      simpa [hres] using congrArg (fun p => p.1.preVotesGranted) eq
    have termEq : result.currentTerm = v.currentTerm := by
      simpa [hres] using congrArg (fun p => p.1.currentTerm) eq
    rw [hres] at latched
    simp only [hres]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
      Sends.pure' ⟨Or.inr ?_, votesEq.trans votes, termEq.trans term, ?_⟩
    · rcases latched with ⟨role', known'⟩ | retired
      · exact Or.inl ⟨role'.trans role, known'.trans known⟩
      · exact Or.inr retired
    · subst eq
      intro e member response payload
      simp at member
      subst member
      simp at payload
  split
  · exact tail _ rfl rfl rfl rfl
  · exact tail _ rfl rfl rfl rfl

theorem appendEntriesRequest_anchor (before : NodeState) (source : NodeID)
    (request : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq]
  · refine Sends.mono (ae_anchor self source _ request) fun after _ ⟨_, votes, _, _⟩ =>
      AnchorStep.raised ⟨source, _, rfl, bump⟩ fun voter member => ?_
    rw [votes] at member
    simp [awareState, bumpedState] at member
  · refine Sends.mono (ae_anchor self source _ request)
      fun after sent ⟨shape, votes, term, noGrant⟩ => ?_
    have aware : awareState before request = before
        \/ ((awareState before request).preVotesGranted = ∅
            /\ (awareState before request).currentTerm = before.currentTerm
            /\ (before.role = .candidate \/ before.role = .preVoteCandidate)) := by
      unfold awareState
      split
      · rename_i h
        exact Or.inr ⟨rfl, by simp [becomeAwareOfNewTerm, h.1], h.2⟩
      · exact Or.inl rfl
    exact {
      timeout := fun eq => by cases eq
      grants := fun e member response eq _ => (noGrant e member response eq).elim
      keep := fun known role => by
        rcases aware with same | ⟨_, _, candidate⟩
        · rw [same] at shape
          rcases shape with rfl | latched
          · exact Or.inl (Latched.refl self _)
          · rcases latched with ⟨role', known'⟩ | retired
            · exact Or.inl (Or.inl ⟨role', known'.trans known.symm⟩)
            · exact Or.inl (Or.inr retired)
        · rcases role with r | r <;> rcases candidate with c | c <;> rw [r] at c <;> cases c
      counts := fun voter member => by
        rw [votes] at member
        refine Or.inr (Or.inl ⟨fun eq => (by cases eq), ?_⟩)
        rcases aware with same | ⟨empty, _⟩
        · rwa [same] at member
        · rw [empty] at member
          simp at member
      fresh := fun lt => by
        rcases aware with same | ⟨_, t, _⟩
        · rw [term, same] at lt
          exact absurd lt (lt_irrefl _)
        · rw [term, t] at lt
          exact absurd lt (lt_irrefl _)
    }

theorem appendEntriesResponse_anchor (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.appendEntriesResponse response)) after
            sent)
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
    fun _ => ?_
  rcases observe_response before response with ⟨_, bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · refine Sends.ite' (fun _ => Sends.pure' (AnchorStep.raised ⟨source, _, rfl, bump⟩
      fun voter member => by simp [bumpedState] at member)) fun notFollower => ?_
    exact (notFollower (by simp [bumpedState])).elim
  · refine Sends.ite' (fun _ => Sends.pure'
      (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
      fun _ => ?_
    refine Sends.ite'
      (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
      fun _ => Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Or.inl ⟨rfl, rfl⟩) rfl rfl (by simp))
    refine Sends.mono
      (Sends.and' (advanceCommit_latched self _) (advanceCommit_sends self _))
      fun after sent ⟨⟨latched, votes, term⟩, _, proposals⟩ =>
        AnchorStep.quiet (fun h => by cases h) latched votes term
          fun e member response payload => ?_
    rw [(proposals e member).2] at payload
    cases payload

theorem voteRequest_anchor (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.requestVoteRequest request)) after
            sent)
        (receive caps self source before (.requestVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;>
    subst eq
  · exact AnchorStep.raised ⟨source, _, rfl, bump⟩ fun voter member => by
      split at member <;> simp [bumpedState] at member
  · refine AnchorStep.quiet (fun h => by cases h) ?_ ?_ ?_ fun e member response payload => ?_
    · split <;> exact Or.inl ⟨rfl, rfl⟩
    · split <;> rfl
    · split <;> rfl
    · simp at member
      subst member
      simp at payload

theorem preVoteRequest_anchor (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.requestPreVoteRequest request)) after
            sent)
        (receive caps self source before (.requestPreVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestPreVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;>
    subst eq
  · exact AnchorStep.raised ⟨source, _, rfl, bump⟩ fun voter member => by
      simp [bumpedState] at member
  · exact {
      timeout := fun eq => by cases eq
      grants := fun e member response payload granted => by
        simp only [List.append_nil, List.mem_singleton] at member
        subst member
        cases payload
        have := of_decide_eq_true granted
        exact Or.inl (by simpa using this.2.2)
      keep := fun _ _ => Or.inl (Latched.refl self _)
      counts := fun voter member => Or.inr (Or.inl ⟨fun eq => (by cases eq), member⟩)
      fresh := fun lt => absurd lt (lt_irrefl _)
    }

theorem voteResponse_anchor (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.requestVoteResponse response)) after
            sent)
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
    fun _ => ?_
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (AnchorStep.raised ⟨source, _, rfl, bump⟩ fun voter member => by
        simp [bumpedState] at member)
  · refine Sends.ite' (fun won => ?_) fun _ => Sends.pure'
      (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp))
    refine Sends.mono
      (Sends.and' (electIfQuorum_kept self _) (electIfQuorum_noGrant self _))
      fun after sent ⟨⟨votes, term⟩, noGrant⟩ => ?_
    exact {
      timeout := fun eq => by cases eq
      grants := fun e member response eq _ => (noGrant e member response eq).elim
      keep := fun _ role => by
        rcases role with r | r <;> rw [r] at won <;> exact absurd won.1 (by simp)
      counts := fun voter member => by
        rw [votes] at member
        exact Or.inr (Or.inl ⟨fun eq => (by cases eq), member⟩)
      fresh := fun lt => by
        rw [term] at lt
        exact absurd lt (lt_irrefl _)
    }

theorem preVoteResponse_anchor (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.requestPreVoteResponse response))
            after sent)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
    fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (AnchorStep.raised ⟨source, _, rfl, bump⟩ fun voter member => by
        simp [bumpedState] at member)
  · refine Sends.ite' (fun won => ?_) fun _ => Sends.pure'
      (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp))
    have notKept : forall known (role : before.role = .follower \/ before.role = .primary),
        (known : before.primaryKnown = true) = known -> False := by
      intro _ role _
      rcases role with r | r <;> rw [r] at won <;> exact absurd won.1 (by simp)
    refine Sends.ite' (fun quorum => ?_) fun _ => Sends.pure' ?_
    · refine Sends.mono
        (Sends.and' (becomeCandidate_kept self _) (becomeCandidate_noGrant self _))
        fun after sent ⟨⟨votes, _⟩, noGrant⟩ => ?_
      exact {
        timeout := fun eq => by cases eq
        grants := fun e member response eq _ => (noGrant e member response eq).elim
        keep := fun known role => (notKept known role rfl).elim
        counts := fun voter member => by
          rw [votes] at member
          simp at member
        fresh := fun _ _ => ⟨fun eq => (by cases eq), fun _ _ eq => (by
          cases eq
          exact ⟨won.2.1, won.2.2, quorum⟩)⟩
      }
    · exact {
        timeout := fun eq => by cases eq
        grants := fun e member => by simp at member
        keep := fun known role => (notKept known role rfl).elim
        counts := fun voter member => by
          rcases Finset.mem_insert.mp member with rfl | old
          · exact Or.inr (Or.inr ⟨response, rfl, won.2.1, won.2.2⟩)
          · exact Or.inr (Or.inl ⟨fun eq => (by cases eq), old⟩)
        fresh := fun lt => absurd lt (lt_irrefl _)
      }

theorem proposeVote_anchor (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun after sent =>
          AnchorStep self before (.receive source (.proposeRequestVoteRequest term)) after
            sent)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp)))
    fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_)
    fun _ =>
      Sends.pure'
        (AnchorStep.quiet (fun h => by cases h) (Latched.refl self _) rfl rfl (by simp))
  refine Sends.mono
    (Sends.and' (becomeCandidate_kept self _) (becomeCandidate_noGrant self _))
    fun after sent ⟨⟨votes, _⟩, noGrant⟩ => ?_
  exact {
    timeout := fun eq => by cases eq
    grants := fun e member response eq _ => (noGrant e member response eq).elim
    keep := fun _ _ => Or.inr (Or.inr (Or.inr (Or.inr ⟨source, by rw [start.1]⟩)))
    counts :=
      fun voter member => by
        rw [votes] at member
        simp at member
    fresh := fun _ _ => ⟨fun eq => (by cases eq), fun _ _ eq => (by cases eq)⟩
  }

/-- Every local step satisfies `AnchorStep`. -/
theorem anchorStep (before : NodeState) (event : Event)
    : Sends (fun after sent => AnchorStep self before event after sent)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_anchor self before contents
      | sendEntries destination batchEnds =>
          exact sendEntries_anchor self before destination batchEnds
      | timeout kind =>
          cases kind with
          | election => exact startElection_anchor self before
          | checkQuorum => exact checkQuorum_anchor self before
      | nominateSuccessor => exact nominate_anchor self before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_anchor self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_anchor self before source response
      | requestVoteRequest request => exact voteRequest_anchor self before source request
      | requestVoteResponse response =>
          exact voteResponse_anchor self before source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_anchor self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_anchor self before source response
      | proposeRequestVoteRequest term => exact proposeVote_anchor self before source term

end Steps

theorem LocalTransition.anchorStep {before after : Model.State}
    (transition : LocalTransition before after)
    : AnchorStep transition.actor transition.pre transition.event transition.post
        transition.outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ :=
    Leadership.anchorStep transition.actor transition.pre transition.event {} _ _
      transition.ran
  simpa [eq] using holds

end CCFRaft.Proofs.Leadership
