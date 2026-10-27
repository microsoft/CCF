module

public import CCFRaft.Proofs.Safety.LeaderFlow

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Where AppendEntries traffic comes from

A node sends AppendEntries responses only while handling an AppendEntries
request. A primary sends AppendEntries requests only from `sendEntries`, with
the request of one batch of the pass, or when a configuration change adds peers.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node

/-- The step that may send `envelope`, for AppendEntries traffic. -/
def Origin (before : NodeState) (event : Event) (envelope : Model.Envelope) : Prop :=
  (forall response,
    envelope.payload = .appendEntriesResponse response
    -> exists source request, event = .receive source (.appendEntriesRequest request))
  /\ forall request,
      envelope.payload = .appendEntriesRequest request
      -> before.role = .primary
      -> (exists batchEnds batch,
            event = .internal (.sendEntries envelope.target batchEnds)
            /\ isPass before.log (before.sentIndex envelope.target) batchEnds = true
            /\ batch ∈ passBatches (before.sentIndex envelope.target) batchEnds
            /\ request = makeAppendEntriesRequest before batch.1 batch.2)
          \/ exists contents content,
              event = .internal (.append contents)
              /\ content ∈ contents
              /\ Not (content.metadata.configuration = none)

/-- Not an AppendEntries response. -/
def NoResponse (envelope : Model.Envelope) : Prop :=
  forall response, Not (envelope.payload = .appendEntriesResponse response)

namespace Origin

variable {before : NodeState} {event : Event} {envelope : Model.Envelope}

theorem quiet (response : NoResponse envelope)
    (request : forall request, Not (envelope.payload = .appendEntriesRequest request))
    : Origin before event envelope :=
  ⟨fun r eq => (response r eq).elim, fun r eq _ => (request r eq).elim⟩

theorem follower (response : NoResponse envelope) (role : Not (before.role = .primary))
    : Origin before event envelope :=
  ⟨fun r eq => (response r eq).elim, fun _ _ leader => (role leader).elim⟩

theorem answer {source : NodeID} {received : AppendEntriesRequest}
    (eq : event = .receive source (.appendEntriesRequest received))
    (request : forall request, Not (envelope.payload = .appendEntriesRequest request))
    : Origin before event envelope :=
  ⟨fun _ _ => ⟨source, received, eq⟩, fun r eq _ => (request r eq).elim⟩

end Origin

theorem LeaderStart.noResponse {self : NodeID} {term : Nat} {state : NodeState}
    {envelope : Model.Envelope} (start : LeaderStart self term state envelope)
    : NoResponse envelope := by
  intro response eq
  rcases start with ⟨_, propose⟩ | ⟨_, _, request, payload, _⟩
  · rw [eq] at propose
    cases propose
  · rw [eq] at payload
    cases payload

theorem AEStep.responses {self source : NodeID} {w : NodeState} {r : AppendEntriesRequest}
    {after : NodeState} {sent : List Model.Envelope}
    (step : AEStep self source w r after sent)
    : forall e,
        e ∈ sent -> forall request, Not (e.payload = .appendEntriesRequest request) := by
  intro e member request eq
  rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩ | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;>
    simp only [List.mem_singleton, List.not_mem_nil] at member
  · subst member
    cases eq
  · subst member
    cases eq

theorem observe_leader (before : NodeState) {message : Message}
    (bumping : Bumping message) (leader : before.role = .primary)
    : Not ((observeTerm before message).role = .candidate)
      /\ Not ((observeTerm before message).role = .preVoteCandidate) := by
  rcases observe_bumping before bumping with ⟨_, eq⟩ | ⟨_, eq⟩ <;> rw [eq] <;>
    simp [bumpedState, leader]

section Steps

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem appendEntry_origin (state : NodeState) (content : EntryContent)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent -> NoResponse e /\ Not (content.metadata.configuration = none))
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (by simp)
    · rename_i nodes configured
      refine Sends.guard_bind fun _ => ?_
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind'
        (Sends.forIn' (R := NoResponse) fun _ _ _ =>
          Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_)
        fun _ _ done => Sends.pure' fun e member =>
          ⟨done e (by simpa using member), fun none => by rw [configured] at none; cases none⟩
      subst eq
      simp only [List.append_nil, List.mem_singleton] at member
      subst member
      intro _ eq
      cases eq

theorem becomeCandidate_quiet (state : NodeState)
    : Sends (fun (_ : NodeState) sent => forall e, e ∈ sent -> NoResponse e)
        (becomeCandidate caps state self) :=
  Sends.mono (becomeCandidate_sends self state)
    fun _ _ result e member => by
      rcases result with ⟨_, votes⟩ | ⟨_, _, started⟩
      · intro response eq
        rw [(votes e member).2] at eq
        cases eq
      · rcases started e member with start | ⟨_, vote⟩
        · exact start.noResponse
        · intro response eq
          rw [vote] at eq
          cases eq

theorem appendBatch_origin (before : NodeState) (contents : List EntryContent)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e, e ∈ sent -> Origin before (.internal (.append contents)) e)
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.foldlM_mem
      (I :=
        fun (_ : NodeState) (sent : List Model.Envelope) =>
          forall e,
            e ∈ sent
            -> NoResponse e
                /\ exists content,
                    content ∈ contents /\ Not (content.metadata.configuration = none))
      contents
      (fun value sent item member held =>
        Sends.mono (appendEntry_origin self value item)
          fun _ later fresh e mem => by
            rcases List.mem_append.mp mem with old | new
            · exact held e old
            · exact ⟨(fresh e new).1, item, member, (fresh e new).2⟩)
      before []
      (by simp))
    fun appended sent held => ?_
  refine Sends.mono (advanceCommit_sends self appended)
    fun _ later ⟨_, proposals⟩ e mem => ?_
  have mem' : e ∈ sent \/ e ∈ later := by simpa using mem
  rcases mem' with old | new
  · obtain ⟨response, content, member, configured⟩ := held e (by simpa using old)
    exact ⟨fun r eq => (response r eq).elim,
      fun _ _ _ => Or.inr ⟨contents, content, rfl, member, configured⟩⟩
  · have payload := (proposals e new).2
    exact Origin.quiet (fun _ eq => by rw [payload] at eq; cases eq)
      fun _ eq => by rw [payload] at eq; cases eq

theorem sendEntries_origin (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent -> Origin before (.internal (.sendEntries destination batchEnds)) e)
        (act caps self before (.sendEntries destination batchEnds)) := by
  simp only [act]
  refine Sends.mono (sendEntries_pass self before destination batchEnds)
    fun _ sent pass e member => ?_
  obtain ⟨batch, inBatches, rfl⟩ := pass.sends e member
  refine ⟨(fun _ eq => by cases eq),
    fun request eq _ => Or.inl ⟨batchEnds, batch, rfl, pass.valid, inBatches, ?_⟩⟩
  cases eq
  rfl

theorem startElection_origin (before : NodeState)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e, e ∈ sent -> Origin before (.internal (.timeout .election)) e)
        (act caps self before (.timeout .election)) := by
  simp only [act]
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ _ ⟨can, empty⟩ => ?_
  subst empty
  have role : Not (before.role = .primary) := by
    rcases can.1 with eq | eq | eq <;> rw [eq] <;> simp
  unfold becomePreVoteCandidate
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_quiet self _) fun _ _ quiet e member =>
      Origin.follower (quiet e (by simpa using member)) role
  · refine Sends.bind' (broadcast_sends self _ _) fun _ _ sent => Sends.pure' fun e member =>
      Origin.follower ?_ role
    intro response eq
    rw [(sent e (by simpa using member)).2.2] at eq
    cases eq

theorem checkQuorum_origin (before : NodeState)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e, e ∈ sent -> Origin before (.internal (.timeout .checkQuorum)) e)
        (act caps self before (.timeout .checkQuorum)) := by
  simp only [act]
  unfold checkQuorum
  exact Sends.bind' Sends.guard'
    fun _ _ ⟨_, empty⟩ => by
      subst empty
      exact Sends.pure' (by simp)

theorem nominate_origin (before : NodeState)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e, e ∈ sent -> Origin before (.internal .nominateSuccessor) e)
        (act caps self before .nominateSuccessor) :=
  Sends.mono (nominate_sends self before)
    fun _ _ ⟨_, _, proposals⟩ e member => by
      have payload := (proposals e member).2
      exact Origin.quiet (fun _ eq => by rw [payload] at eq; cases eq)
        fun _ eq => by rw [payload] at eq; cases eq

theorem appendEntriesRequest_origin (before : NodeState) (source : NodeID)
    (request : AppendEntriesRequest)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent -> Origin before (.receive source (.appendEntriesRequest request)) e)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨_, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · exact Sends.mono (aeStep self source _ request (le_refl _)) fun _ _ step e member =>
      Origin.answer rfl (step.responses e member)
  · exact Sends.mono (aeStep self source _ request le) fun _ _ step e member =>
      Origin.answer rfl (step.responses e member)

theorem appendEntriesResponse_origin (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent
            -> Origin before (.receive source (.appendEntriesResponse response)) e)
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  simp only [handleAppendEntriesResponse]
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp))
    fun _ => Sends.pure' (by simp)
  exact Sends.mono (advanceCommit_sends self _) fun _ _ ⟨_, proposals⟩ e member => by
    have payload := (proposals e member).2
    exact Origin.quiet (fun _ eq => by rw [payload] at eq; cases eq)
      fun _ eq => by rw [payload] at eq; cases eq

theorem voteRequest_origin (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent -> Origin before (.receive source (.requestVoteRequest request)) e)
        (receive caps self source before (.requestVoteRequest request)) := by
  simp only [receive, handleRequestVoteRequest]
  refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_
  subst eq
  simp only [List.append_nil, List.mem_singleton] at member
  subst member
  exact Origin.quiet (fun _ eq => by cases eq) fun _ eq => by cases eq

theorem preVoteRequest_origin (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent
            -> Origin before (.receive source (.requestPreVoteRequest request)) e)
        (receive caps self source before (.requestPreVoteRequest request)) := by
  simp only [receive, handleRequestPreVoteRequest]
  refine Sends.bind' (Sends.send _ _ _) fun _ _ eq => Sends.pure' fun e member => ?_
  subst eq
  simp only [List.append_nil, List.mem_singleton] at member
  subst member
  exact Origin.quiet (fun _ eq => by cases eq) fun _ eq => by cases eq

theorem voteResponse_origin (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent -> Origin before (.receive source (.requestVoteResponse response)) e)
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  simp only [handleRequestVoteResponse]
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (by simp)
  have role : Not (before.role = .primary) := fun leader =>
    (observe_leader before (message := .requestVoteResponse response) trivial leader).1 won.1
  refine Sends.mono (electIfQuorum_sends self _) fun _ _ result e member => ?_
  rcases result with ⟨_, rfl⟩ | ⟨_, _, _, started⟩
  · cases member
  · exact Origin.follower (started e member).noResponse role

theorem preVoteResponse_origin (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent
            -> Origin before (.receive source (.requestPreVoteResponse response)) e)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  simp only [handleRequestPreVoteResponse]
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (by simp)
  have role : Not (before.role = .primary) := fun leader =>
    (observe_leader before (message := .requestPreVoteResponse response) trivial leader).2
      won.1
  refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by simp)
  exact Sends.mono (becomeCandidate_quiet self _) fun _ _ quiet e member =>
    Origin.follower (quiet e member) role

theorem proposeVote_origin (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun (_ : NodeState) sent =>
          forall e,
            e ∈ sent
            -> Origin before (.receive source (.proposeRequestVoteRequest term)) e)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (by simp)) fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_) fun _ => Sends.pure' (by simp)
  have role : Not (before.role = .primary) := by
    rcases start.2.1 with eq | eq | eq <;> rw [eq] <;> simp
  exact Sends.mono (becomeCandidate_quiet self _) fun _ _ quiet e member =>
    Origin.follower (quiet e member) role

/-- Every step's AppendEntries traffic has an `Origin`. -/
theorem origin (before : NodeState) (event : Event)
    : Sends
        (fun (_ : NodeState) sent => forall e, e ∈ sent -> Origin before event e)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_origin self before contents
      | sendEntries destination batchEnds =>
          exact sendEntries_origin self before destination batchEnds
      | timeout kind =>
          cases kind with
          | election => exact startElection_origin self before
          | checkQuorum => exact checkQuorum_origin self before
      | nominateSuccessor => exact nominate_origin self before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_origin self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_origin self before source response
      | requestVoteRequest request => exact voteRequest_origin self before source request
      | requestVoteResponse response =>
          exact voteResponse_origin self before source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_origin self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_origin self before source response
      | proposeRequestVoteRequest term => exact proposeVote_origin self before source term

end Steps

end CCFRaft.Proofs.Safety
