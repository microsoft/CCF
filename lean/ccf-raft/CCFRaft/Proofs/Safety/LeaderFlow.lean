module

public import CCFRaft.Proofs.Safety.Flow

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Replication frontiers

How one step of a primary that keeps its role and term moves `sentIndex` and
`matchIndex` for a peer, and how a node handles AppendEntries from its own term.
-/

namespace CCFRaft.Proofs.Safety

open CCFRaft.Proofs.Ledger
open CCF
open Model.Node

namespace Sends

variable {Node Message Notification : Type} {α γ : Type}

/-- `foldlM'` with access to the membership of each folded item. -/
theorem foldlM_mem {I : α -> List (Envelope Node Message) -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    : forall (items : List γ),
        (forall value sent item,
          item ∈ items
          -> I value sent
          -> Sends (fun next later => I next (sent ++ later)) (f value item))
        -> forall (init : α) (sent : List (Envelope Node Message)),
            I init sent
            -> Sends (fun result later => I result (sent ++ later)) (items.foldlM f init)
  | [], _, _, _, holds => by
      simpa using pure' (P := fun result later => I result (_ ++ later)) (by simpa using holds)
  | item :: items, step, init, sent, holds => by
      simp only [List.foldlM_cons]
      refine bind' (step init sent item List.mem_cons_self holds) fun value later kept => ?_
      refine mono
        (foldlM_mem items (fun v s i member h => step v s i (List.mem_cons_of_mem _ member) h)
          value (sent ++ later) kept)
        fun _ rest done => ?_
      simpa [List.append_assoc] using done

end Sends

/-! ## AppendEntries handling -/

theorem AEStep.term {self source : NodeID} {w : NodeState} {r : AppendEntriesRequest}
    {after : NodeState} {sent : List Model.Envelope}
    (step : AEStep self source w r after sent)
    : after.currentTerm = w.currentTerm := by
  rcases step with ⟨_, rfl, _⟩ | ⟨_, _, _, rfl, _⟩ | ⟨_, _, _, _, term, _⟩
  · rfl
  · rfl
  · exact term

theorem AEStep.frontiers {self source : NodeID} {w : NodeState} {r : AppendEntriesRequest}
    {after : NodeState} {sent : List Model.Envelope}
    (step : AEStep self source w r after sent)
    : after.sentIndex = w.sentIndex /\ after.matchIndex = w.matchIndex := by
  rcases step with ⟨_, rfl, _⟩ | ⟨_, _, _, rfl, _⟩ | ⟨_, _, _, _, _, _, _, _, sent, matched, _⟩
  · exact ⟨rfl, rfl⟩
  · exact ⟨rfl, rfl⟩
  · exact ⟨sent, matched⟩

theorem awareState_primary {z : NodeState} (r : AppendEntriesRequest)
    (leader : z.role = .primary)
    : awareState z r = z := by
  simp [awareState, leader]

/-! ## Primary frontiers -/

/-- How one step of a primary that keeps its role and term moves `peer`'s
`matchIndex` and `sentIndex`. -/
def Frontier (peer : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    : Prop :=
  (after.matchIndex peer = before.matchIndex peer
    \/ exists response,
        event = .receive peer (.appendEntriesResponse response)
        /\ response.success = true
        /\ response.term = before.currentTerm
        /\ after.matchIndex peer = max (before.matchIndex peer) response.lastLogIndex)
  /\ (after.sentIndex peer = before.sentIndex peer
      \/ (exists batchEnds,
            event = .internal (.sendEntries peer batchEnds)
            /\ before.sentIndex peer <= after.sentIndex peer
            /\ after.sentIndex peer <= before.log.length)
      \/ (exists response,
            event = .receive peer (.appendEntriesResponse response)
            /\ response.success = false
            /\ after.sentIndex peer
                = max
                    (min
                      (findHighestPossibleMatch before.log response.lastLogIndex
                        response.term)
                      (before.sentIndex peer))
                    (before.matchIndex peer))
      \/ exists contents content,
          event = .internal (.append contents)
          /\ content ∈ contents
          /\ Not (content.metadata.configuration = none))

/-- `Frontier`, for steps that keep the primary in its role and term. -/
def LeaderFlow (peer : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    : Prop :=
  after.role = .primary
  -> after.currentTerm = before.currentTerm
  -> Frontier peer before event after

namespace LeaderFlow

variable {peer : NodeID} {before after : NodeState} {event : Event}

theorem keep (sent : after.sentIndex = before.sentIndex)
    (matched : after.matchIndex = before.matchIndex)
    : LeaderFlow peer before event after :=
  fun _ _ => ⟨Or.inl (congrFun matched peer), Or.inl (congrFun sent peer)⟩

theorem deposed (role : Not (after.role = .primary))
    : LeaderFlow peer before event after :=
  fun leader => (role leader).elim

theorem bumped (term : Not (after.currentTerm = before.currentTerm))
    : LeaderFlow peer before event after :=
  fun _ same => (term same).elim

end LeaderFlow

section Steps

variable (self peer : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem appendEntry_frontier (state : NodeState) (content : EntryContent)
    : Sends
        (fun next (_ : List Model.Envelope) =>
          next.matchIndex = state.matchIndex
          /\ (content.metadata.configuration = none -> next.sentIndex = state.sentIndex))
        (appendEntry caps self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' ⟨rfl, fun _ => rfl⟩
    · rename_i nodes configured
      refine Sends.guard_bind fun _ => ?_
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind'
        (Sends.forIn' (R := fun _ => True) fun _ _ _ =>
          Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' fun _ _ => trivial)
        fun _ _ _ => Sends.pure' ⟨rfl, fun none => ?_⟩
      rw [configured] at none
      cases none

theorem appendBatch_flow (before : NodeState) (contents : List EntryContent)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.internal (.append contents)) after)
        (act caps self before (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind'
    (Sends.foldlM_mem
      (I :=
        fun (state : NodeState) (_ : List Model.Envelope) =>
          state.matchIndex = before.matchIndex
          /\ (state.sentIndex = before.sentIndex
              \/ exists content,
                  content ∈ contents /\ Not (content.metadata.configuration = none)))
      contents
      (fun value _ item member ⟨matched, sent⟩ =>
        Sends.mono (appendEntry_frontier self value item)
          fun next _ ⟨matched', sent'⟩ => by
            refine ⟨matched'.trans matched, ?_⟩
            by_cases none : item.metadata.configuration = none
            · rcases sent with sent | configured
              · exact Or.inl ((sent' none).trans sent)
              · exact Or.inr configured
            · exact Or.inr ⟨item, member, none⟩)
      before [] ⟨rfl, Or.inl rfl⟩)
    fun appended _ ⟨matched, sent⟩ => ?_
  refine Sends.mono (advanceCommit_sends self appended) fun after _ ⟨advance, _⟩ _ _ => ?_
  refine ⟨Or.inl (by rw [advance.matchIndex, matched]), ?_⟩
  rcases sent with sent | ⟨content, member, configured⟩
  · exact Or.inl (by rw [advance.sentIndex, sent])
  · exact Or.inr (Or.inr (Or.inr ⟨contents, content, rfl, member, configured⟩))

theorem sendEntries_flow (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.internal (.sendEntries destination batchEnds)) after)
        (sendEntries caps self before destination batchEnds) :=
  Sends.mono (sendEntries_pass self before destination batchEnds)
    fun _ _ pass _ _ => by
      refine ⟨Or.inl (by rw [pass.state]), ?_⟩
      by_cases same : destination = peer
      · subst same
        exact Or.inr (Or.inl ⟨batchEnds, rfl, pass.advances, pass.bounded⟩)
      · exact Or.inl (pass.other (Ne.symm same))

theorem startElection_flow (before : NodeState) (leader : before.role = .primary)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.internal (.timeout .election)) after)
        (startElection caps before self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ _ ⟨can, _⟩ => ?_
  rcases can.1 with eq | eq | eq <;> rw [leader] at eq <;> cases eq

theorem checkQuorum_flow (before : NodeState)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.internal (.timeout .checkQuorum)) after)
        (checkQuorum before self) := by
  unfold checkQuorum
  exact Sends.bind' Sends.guard' fun _ _ _ => Sends.pure' (LeaderFlow.deposed (by simp))

theorem nominate_flow (before : NodeState)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.internal .nominateSuccessor) after)
        (act caps self before .nominateSuccessor) :=
  Sends.mono (nominate_sends self before)
    fun _ _ ⟨same, _, _⟩ => by
      subst same
      exact LeaderFlow.keep rfl rfl

theorem appendEntriesRequest_flow (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (request : AppendEntriesRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.appendEntriesRequest request)) after)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · refine Sends.mono (aeStep self source _ request (le_refl _)) fun after _ step =>
      LeaderFlow.bumped fun same => ?_
    rw [step.term, awareState_term] at same
    exact absurd same (Nat.ne_of_gt bump)
  · refine Sends.mono (aeStep self source _ request le) fun after _ step => ?_
    rw [awareState_primary request leader] at step
    exact LeaderFlow.keep step.frontiers.1 step.frontiers.2

theorem appendEntriesResponse_flow (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (response : AppendEntriesResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.appendEntriesResponse response))
            after)
        (receive caps self source before (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)) fun _ => ?_
  rcases observe_response before response with ⟨_, bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · exact Sends.ite' (fun _ => Sends.pure' (LeaderFlow.deposed (by simp [bumpedState])))
      fun notFollower => absurd notFollower (by simp [bumpedState])
  refine Sends.ite' (fun notLeader => absurd leader (by simpa using notLeader))
    fun _ => ?_
  refine Sends.ite' (fun success => ?_) fun failure => ?_
  · refine Sends.ite' (fun same => ?_) fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)
    refine Sends.mono (advanceCommit_sends self _) fun after _ ⟨advance, _⟩ _ _ =>
      ⟨?_, Or.inl (by rw [advance.sentIndex])⟩
    by_cases is : source = peer
    · subst is
      exact Or.inr ⟨response, rfl, success, same, by rw [advance.matchIndex]; simp⟩
    · exact Or.inl (by rw [advance.matchIndex]; exact Function.update_of_ne (Ne.symm is) _ _)
  · refine Sends.pure' fun _ _ => ⟨Or.inl rfl, ?_⟩
    by_cases is : source = peer
    · subst is
      exact Or.inr (Or.inr (Or.inl ⟨response, rfl, by simpa using failure, by simp⟩))
    · exact Or.inl (Function.update_of_ne (Ne.symm is) _ _)

theorem voteRequest_flow (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.requestVoteRequest request)) after)
        (receive caps self source before (.requestVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_ <;> split
  · exact LeaderFlow.deposed (by simp [bumpedState])
  · exact LeaderFlow.deposed (by simp [bumpedState])
  · exact LeaderFlow.keep rfl rfl
  · exact LeaderFlow.keep rfl rfl

theorem preVoteRequest_flow (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.requestPreVoteRequest request)) after)
        (receive caps self source before (.requestPreVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestPreVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
  · exact LeaderFlow.deposed (by simp [bumpedState])
  · exact LeaderFlow.keep rfl rfl

theorem voteResponse_flow (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (response : RequestVoteResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.requestVoteResponse response)) after)
        (receive caps self source before (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)) fun _ => ?_
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · exact Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (LeaderFlow.deposed (by simp [bumpedState]))
  · exact Sends.ite' (fun won => absurd won.1 (by rw [leader]; simp)) fun _ =>
      Sends.pure' (LeaderFlow.keep rfl rfl)

theorem preVoteResponse_flow (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (response : RequestVoteResponse)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.requestPreVoteResponse response))
            after)
        (receive caps self source before (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)) fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · exact Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (LeaderFlow.deposed (by simp [bumpedState]))
  · exact Sends.ite' (fun won => absurd won.1 (by rw [leader]; simp)) fun _ =>
      Sends.pure' (LeaderFlow.keep rfl rfl)

theorem proposeVote_flow (before : NodeState) (leader : before.role = .primary)
    (source : NodeID) (term : Nat)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          LeaderFlow peer before (.receive source (.proposeRequestVoteRequest term))
            after)
        (receive caps self source before (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite' (fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)) fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_) fun _ => Sends.pure' (LeaderFlow.keep rfl rfl)
  rcases start.2.1 with eq | eq | eq <;> rw [leader] at eq <;> cases eq

/-- Every step of a primary moves each peer's frontiers as `LeaderFlow`. -/
theorem leader_flow (before : NodeState) (leader : before.role = .primary) (event : Event)
    : Sends (fun after (_ : List Model.Envelope) => LeaderFlow peer before event after)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_flow self peer before contents
      | sendEntries destination batchEnds =>
          exact sendEntries_flow self peer before destination batchEnds
      | timeout kind =>
          cases kind with
          | election => exact startElection_flow self peer before leader
          | checkQuorum => exact checkQuorum_flow self peer before
      | nominateSuccessor => exact nominate_flow self peer before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_flow self peer before leader source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_flow self peer before leader source response
      | requestVoteRequest request =>
          exact voteRequest_flow self peer before source request
      | requestVoteResponse response =>
          exact voteResponse_flow self peer before leader source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_flow self peer before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_flow self peer before leader source response
      | proposeRequestVoteRequest term =>
          exact proposeVote_flow self peer before leader source term

/-! ## Receiving AppendEntries -/

/-- Receiving AppendEntries no newer than the receiver's term runs `AEStep`. -/
theorem receive_ae (before : NodeState) (source : NodeID) (request : AppendEntriesRequest)
    (le : request.term <= before.currentTerm)
    : Sends (AEStep self source (awareState before request) request)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, _⟩ | ⟨_, eq⟩
  · exact absurd le (Nat.not_le.mpr bump)
  · rw [eq]
    exact aeStep self source _ request le

/-- Receiving AppendEntries raises the receiver's term to at least the request's. -/
theorem receive_ae_term (before : NodeState) (source : NodeID)
    (request : AppendEntriesRequest)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          request.term <= after.currentTerm /\ before.currentTerm <= after.currentTerm)
        (receive caps self source before (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · refine Sends.mono (aeStep self source _ request (le_refl _)) fun after _ step => ?_
    rw [step.term, awareState_term]
    exact ⟨le_refl _, bump.le⟩
  · refine Sends.mono (aeStep self source _ request le) fun after _ step => ?_
    rw [step.term, awareState_term]
    exact ⟨le, le_refl _⟩

end Steps

end CCFRaft.Proofs.Safety
