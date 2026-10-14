module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Safety.History
public import CCFRaft.Proofs.Safety.Sends
public import CCFRaft.Proofs.Ledger
public import CCFRaft.Proofs.Safety.Lists
public import CCFRaft.Proofs.Direct.CommitFrontier

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# What one local step does

`summary` is the only place the safety proof unfolds the node behaviour. It
classifies every successful step by the state changes and sends that matter
for safety. Later proofs work from this classification alone.
-/

namespace CCFRaft.Proofs.Safety

open CCFRaft.Proofs.Config CCFRaft.Proofs.Ledger

open CCF
open Model.Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

/-- `observeTerm` adopting a newer message term. -/
def Bump (before observed : NodeState Node TxId) (term : Nat) : Prop :=
  before.currentTerm < term
  /\ observed.currentTerm = term
  /\ observed.role = .follower
  /\ observed.votedFor = none
  /\ observed.log = before.log
  /\ observed.commitIndex = before.commitIndex

/-- Messages carrying no log, vote or acknowledgement evidence, sent by a
node whose state afterwards is `state`. -/
def Plain (state : NodeState Node TxId) : Message Node TxId -> Prop
  | .appendEntriesRequest _ => False
  | .appendEntriesResponse response =>
      response.success = false
      /\ (response.term = state.currentTerm
          \/ exists k, response.term = termAt state.log k)
  | .requestVoteRequest _ => False
  | .requestVoteResponse response =>
      response.voteGranted = false /\ response.term = state.currentTerm
  | .requestPreVote request => request.term = state.currentTerm
  | .requestPreVoteResponse response => response.term = state.currentTerm
  | .proposeVoteRequest term => term = state.currentTerm

/-- An AppendEntries request consistent with its sender's resulting state. -/
def AEOk (self target : Node) (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Prop :=
  Not (target = self)
  /\ request.term = state.currentTerm
  /\ request.prevLogIndex <= state.log.length
  /\ request.prevLogTerm = termAt state.log request.prevLogIndex
  /\ request.entries <+: state.log.drop request.prevLogIndex
  /\ request.leaderCommit <= state.commitIndex

/-- A leader-side send: plain, or a consistent AppendEntries request. -/
def LeaderSend (self : Node) (state : NodeState Node TxId)
    (envelope : Model.Envelope Node TxId)
    : Prop :=
  envelope.source = self
  /\ (Plain state envelope.payload
      \/ exists request,
          envelope.payload = .appendEntriesRequest request
          /\ AEOk self envelope.target state request)

/-- The state change of `advanceCommit`. -/
def Advance (self : Node) (middle state : NodeState Node TxId) : Prop :=
  state = middle
  \/ (state.log = middle.log
      /\ state.currentTerm = middle.currentTerm
      /\ state.votedFor = middle.votedFor
      /\ state.matchIndex = middle.matchIndex
      /\ state.sentIndex = middle.sentIndex
      /\ state.votesGranted = middle.votesGranted
      /\ middle.commitIndex < state.commitIndex
      /\ state.commitIndex = highestCommittableIndex (inferInstance) middle self
      /\ (state.role = middle.role \/ state.role = .none))

/-! ## The step summary -/

/-- Messages whose receipt may raise the receiver's term. -/
def Bumping : Message Node TxId -> Prop
  | .appendEntriesResponse _ => False
  | .proposeVoteRequest _ => False
  | _ => True

/-- The candidate state a step campaigns with: a fresh election or the
existing candidacy with possibly more votes. -/
def Campaign (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    (candidate : NodeState Node TxId)
    : Prop :=
  candidate.role = .candidate
  /\ candidate.log = before.log
  /\ candidate.commitIndex = before.commitIndex
  /\ ((Not (before.role = .none)
        /\ candidate.currentTerm = before.currentTerm + 1
        /\ candidate.votedFor = some self
        /\ candidate.votesGranted = {self})
      \/ (before.role = .candidate
          /\ candidate.currentTerm = before.currentTerm
          /\ (candidate.votedFor = before.votedFor \/ before.votedFor = none)
          /\ forall voter,
              voter ∈ candidate.votesGranted
              -> voter ∈ before.votesGranted
                  \/ exists response,
                      event = .receive voter (.requestVoteResponse response)
                      /\ response.term = before.currentTerm
                      /\ response.voteGranted = true))

/-- The step wins an election with `candidate`. -/
def Wins (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    (after : NodeState Node TxId)
    : Prop :=
  exists candidate,
    Campaign self before event candidate
    /\ hasQuorum (candidate.activeConfigurations (inferInstance)) candidate.votesGranted
    /\ Advance self (leaderState candidate) after

/-- The follower accepted AppendEntries `request`. -/
def Accepted (before : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    (after : NodeState Node TxId)
    : Prop :=
  request.term = after.currentTerm
  /\ before.currentTerm <= request.term
  /\ before.commitIndex <= request.prevLogIndex
  /\ (request.prevLogIndex = 0
      \/ (request.prevLogIndex <= before.log.length
          /\ termAt before.log request.prevLogIndex = request.prevLogTerm))
  /\ after.log = acceptLog before.log request
  /\ after.commitIndex
      = max before.commitIndex
          (maxCommittableIndexUpTo after.log
            (min request.leaderCommit (request.prevLogIndex + request.entries.length)))

/-- How a step changes the log and commit index. -/
inductive Kind (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    (after : NodeState Node TxId)
    : Prop where
  | same (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
  | append (entries : List (Entry Node TxId)) (sent : Node -> Nat)
    (leader : before.role = .leader)
    (terms : forall entry, entry ∈ entries -> entry.term = before.currentTerm)
    (advance
      : Advance self { before with log := before.log ++ entries, sentIndex := sent }
          after)
  | ack (source : Node) (response : AppendEntriesResponse)
    (received : event = .receive source (.appendEntriesResponse response))
    (leader : before.role = .leader) (success : response.success = true)
    (term : response.term = before.currentTerm)
    (advance
      : Advance self
          {
            before with
              matchIndex :=
                Function.update before.matchIndex source
                  (max (before.matchIndex source) response.lastLogIndex)
          }
          after)
  | accept (source : Node) (request : AppendEntriesRequest Node TxId)
    (received : event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted before request after)
  | elect (elected : Wins self before event after)

/-- What a step may send, relative to its sender's states. -/
def SendOK (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    (after : NodeState Node TxId) (envelope : Model.Envelope Node TxId)
    : Prop :=
  envelope.source = self
  /\ match envelope.payload with
      | .appendEntriesRequest request =>
          AEOk self envelope.target after request
          /\ Not (after.role = .candidate)
          /\ ((before.role = .leader /\ after.currentTerm = before.currentTerm)
              \/ Wins self before event after)
      | .appendEntriesResponse response =>
          response.success = true
          -> exists source request,
              event = .receive source (.appendEntriesRequest request)
              /\ Accepted before request after
              /\ response.term = after.currentTerm
              /\ response.lastLogIndex = request.prevLogIndex + request.entries.length
      | .requestVoteRequest request =>
          request.term = after.currentTerm
          /\ before.currentTerm < after.currentTerm
          /\ (after.role = .candidate -> makeRequestVoteRequest after = request)
      | .requestVoteResponse response =>
          response.term = after.currentTerm
          /\ (response.voteGranted = true
              -> exists request,
                  event = .receive envelope.target (.requestVoteRequest request)
                  /\ request.term = after.currentTerm
                  /\ voteLogUpToDate before request
                  /\ after.votedFor = some envelope.target)
      | message => message.term = after.currentTerm

/-- Everything the safety proof needs to know about one local step. -/
structure Summary (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    (after : NodeState Node TxId) (sent : List (Model.Envelope Node TxId))
    : Prop where
  term_le : before.currentTerm <= after.currentTerm
  vote_keep
    : after.currentTerm = before.currentTerm
      -> forall voted, before.votedFor = some voted -> after.votedFor = some voted
  active
    : (Not (after.role = .none) \/ Not (sent = []))
      -> Not (before.role = .none)
          \/ 2 <= before.currentTerm
          \/ exists source message,
              event = .receive source message
              /\ Bumping message
              /\ message.term <= after.currentTerm
  candidate : after.role = .candidate -> Campaign self before event after
  leader
    : after.role = .leader
      -> (before.role = .leader /\ after.currentTerm = before.currentTerm)
          \/ Wins self before event after
  matchIndex
    : after.role = .leader -> before.role = .leader
      -> after.currentTerm = before.currentTerm
      -> forall peer,
          after.matchIndex peer = before.matchIndex peer
          \/ exists response,
              event = .receive peer (.appendEntriesResponse response)
              /\ response.success = true
              /\ response.term = before.currentTerm
              /\ after.matchIndex peer = response.lastLogIndex
  kind : Kind self before event after
  sends : forall envelope, envelope ∈ sent -> SendOK self before event after envelope

/-! ## Commit selection -/

theorem highestCommittableIndex_spec (state : NodeState Node TxId) (self : Node)
    (ahead : state.commitIndex < highestCommittableIndex (inferInstance) state self)
    : let index := highestCommittableIndex (inferInstance) state self
      index <= state.log.length
      /\ isSignatureAt state.log index = true
      /\ termAt state.log index = state.currentTerm
      /\ hasQuorum (state.activeConfigurations (inferInstance))
          ((state.activeMembers (inferInstance)).filter
            fun node => node = self \/ state.matchIndex node >= index) := by
  intro index
  have holds := Direct.foldl_select_max_pos _ _ (show 0 < index by omega)
  refine ⟨?_, holds.2.1, holds.2.2.1, holds.2.2.2⟩
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue holds.2.1
  exact Ledger.entryAtSomeIndexBound found

/-- The state change of `electIfQuorum` on a candidate state. -/
def Elect (self : Node) (candidate state : NodeState Node TxId) : Prop :=
  state = candidate
  \/ (candidate.role = .candidate
      /\ hasQuorum (candidate.activeConfigurations (inferInstance)) candidate.votesGranted
      /\ Advance self (leaderState candidate) state)

/-- A fresh candidate built from an observed state. -/
def Fresh (self : Node) (observed candidate : NodeState Node TxId) : Prop :=
  candidate.role = .candidate
  /\ candidate.currentTerm = observed.currentTerm + 1
  /\ candidate.log = observed.log
  /\ candidate.commitIndex = observed.commitIndex
  /\ candidate.votedFor = some self
  /\ candidate.votesGranted = {self}

/-- An AppendEntries request from `self` consistent with `log` and `commit`. -/
def AEFrom (self : Node) (term commit : Nat) (log : List (Entry Node TxId))
    (envelope : Model.Envelope Node TxId)
    : Prop :=
  envelope.source = self
  /\ Not (envelope.target = self)
  /\ exists request,
      envelope.payload = .appendEntriesRequest request
      /\ request.term = term
      /\ request.prevLogIndex <= log.length
      /\ request.prevLogTerm = termAt log request.prevLogIndex
      /\ request.entries <+: log.drop request.prevLogIndex
      /\ request.leaderCommit <= commit

theorem AEFrom.extend {self : Node} {term commit commit' : Nat}
    {log log' : List (Entry Node TxId)} {envelope : Model.Envelope Node TxId}
    (sent : AEFrom self term commit log envelope) (extends_ : log <+: log')
    (le : commit <= commit')
    : AEFrom self term commit' log' envelope := by
  obtain ⟨source, target, request, payload, term, prev, prevTerm, entries, leaderCommit⟩ := sent
  refine ⟨source, target, request, payload, term, prev.trans extends_.length_le, ?_, ?_,
    leaderCommit.trans le⟩
  · rw [prevTerm, termAt_of_prefix extends_ prev]
  · obtain ⟨rest, rfl⟩ := extends_
    rw [List.drop_append_of_le_length prev]
    exact entries.trans (List.prefix_append _ _)

theorem AEFrom.ok {self : Node} {state : NodeState Node TxId}
    {envelope : Model.Envelope Node TxId}
    (sent : AEFrom self state.currentTerm state.commitIndex state.log envelope)
    : exists request,
        envelope.payload = .appendEntriesRequest request
        /\ AEOk self envelope.target state request := by
  obtain ⟨_, target, request, payload, term, prev, prevTerm, entries, leaderCommit⟩ := sent
  exact ⟨request, payload, target, term, prev, prevTerm, entries, leaderCommit⟩

theorem Advance.log {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.log = middle.log := by
  rcases advance with rfl | h <;> grind

theorem Advance.term {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.currentTerm = middle.currentTerm := by
  rcases advance with rfl | h <;> grind

theorem Advance.votedFor {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.votedFor = middle.votedFor := by
  rcases advance with rfl | h <;> grind

theorem Advance.matchIndex {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.matchIndex = middle.matchIndex := by
  rcases advance with rfl | h <;> grind

theorem Advance.sentIndex {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.sentIndex = middle.sentIndex := by
  rcases advance with rfl | h <;> grind

theorem Advance.votesGranted {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.votesGranted = middle.votesGranted := by
  rcases advance with rfl | h <;> grind

theorem Advance.commit_le {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : middle.commitIndex <= state.commitIndex := by
  rcases advance with rfl | h <;> grind

theorem Advance.role {self : Node} {middle state : NodeState Node TxId}
    (advance : Advance self middle state)
    : state.role = middle.role \/ state.role = .none := by
  rcases advance with rfl | h <;> grind

section Effects

variable (self : Node)

local notation "caps" => (Capabilities.record self : Caps Node TxId)

theorem nominate_sends (state : NodeState Node TxId)
    : Sends
        (fun _ sent =>
          forall e,
            e ∈ sent
            -> e.source = self /\ e.payload = .proposeVoteRequest state.currentTerm)
        (nominateSuccessor (inferInstance) caps state self) := by
  unfold nominateSuccessor
  split
  · exact Sends.mono (Sends.send _ _ _) fun _ sent eq => by simp [eq]
  · exact Sends.pure' (by simp)

theorem advanceCommit_sends (middle : NodeState Node TxId)
    : Sends
        (fun state sent =>
          Advance self middle state
          /\ forall e,
              e ∈ sent
              -> e.source = self /\ e.payload = .proposeVoteRequest middle.currentTerm)
        (advanceCommit (inferInstance) caps middle self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun _ => Sends.pure' ⟨Or.inl rfl, by simp⟩) fun ahead => ?_
  have advanced : Advance self middle
      (middle.recordCommit self (highestCommittableIndex (inferInstance) middle self)) :=
    Or.inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, by simp [NodeState.recordCommit]; omega, rfl,
      Or.inl rfl⟩
  have retired : Advance self middle
      { middle.recordCommit self (highestCommittableIndex (inferInstance) middle self) with
          role := .none, leaderKnown := false } :=
    Or.inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, by simp [NodeState.recordCommit]; omega, rfl,
      Or.inr rfl⟩
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' ⟨retired, by simp⟩)
    fun _ => Sends.pure' ⟨advanced, by simp⟩
  exact Sends.bind' (nominate_sends self middle)
    fun _ sent nominated =>
      Sends.pure' ⟨retired, by simpa using nominated⟩

theorem broadcast_sends (state : NodeState Node TxId) (message : Message Node TxId)
    : Sends
        (fun _ sent =>
          forall e,
            e ∈ sent -> e.source = self /\ Not (e.target = self) /\ e.payload = message)
        (broadcastToOthers (inferInstance) caps self state message) := by
  unfold broadcastToOthers
  refine Sends.bind'
    (Sends.forIn'
      (R := fun e => e.source = self /\ Not (e.target = self) /\ e.payload = message)
      fun peer _ member => ?_)
    fun _ sent done => Sends.pure' (by simpa using done)
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  have : Not (peer = self) := by simp [Finset.mem_sort] at member; exact member.1
  simp [eq, this]

/-- The sends of a new leader: a nomination or a heartbeat. -/
def LeaderStart (self : Node) (term : Nat) (state : NodeState Node TxId)
    (envelope : Model.Envelope Node TxId)
    : Prop :=
  (envelope.source = self /\ envelope.payload = .proposeVoteRequest term)
  \/ AEFrom self state.currentTerm state.commitIndex state.log envelope

theorem becomeLeader_sends (candidate : NodeState Node TxId)
    : Sends
        (fun state sent =>
          Advance self (leaderState candidate) state
          /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm state e)
        (becomeLeader (inferInstance) caps self candidate) := by
  unfold becomeLeader
  refine Sends.bind' (advanceCommit_sends self _)
    fun leader sent ⟨advance, nominated⟩ => ?_
  refine Sends.bind' (Q := fun _ later => forall e, e ∈ later ->
      AEFrom self leader.currentTerm leader.commitIndex leader.log e)
    (Sends.forIn' fun peer _ member => ?_) fun _ later beats => Sends.pure' ⟨advance, ?_⟩
  · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member => ?_
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst member
    have other : Not (peer = self) := by simp [Finset.mem_sort, eligiblePeers] at member; exact member.1
    have sentEq : leader.sentIndex peer = leader.log.length := by
      rw [advance.sentIndex, advance.log]
      simp [leaderState]
    refine ⟨rfl, other, _, rfl, rfl, ?_, rfl, ?_, le_rfl⟩ <;>
      simp [makeAppendEntriesRequest, sentEq, messageEntries]
  · intro e member
    rcases List.mem_append.mp (by simpa using member) with old | new
    · have := nominated e old
      exact Or.inl ⟨this.1, by simpa [leaderState] using this.2⟩
    · exact Or.inr (beats e new)

theorem electIfQuorum_sends (candidate : NodeState Node TxId)
    : Sends
        (fun state sent =>
          (state = candidate /\ sent = [])
          \/ (candidate.role = .candidate
              /\ hasQuorum (candidate.activeConfigurations (inferInstance))
                  candidate.votesGranted
              /\ Advance self (leaderState candidate) state
              /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm state e))
        (electIfQuorum (inferInstance) caps self candidate) := by
  unfold electIfQuorum
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Or.inl ⟨rfl, rfl⟩)
  exact Sends.mono (becomeLeader_sends self candidate) fun _ _ done =>
    Or.inr ⟨won.1, won.2.1, done⟩

/-- The candidate state `becomeCandidate` builds from `state`. -/
def freshCandidate (self : Node) (state : NodeState Node TxId) : NodeState Node TxId :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some self
      leaderKnown := false
      votesGranted := {self}
      preVotesGranted := ∅
  }

theorem becomeCandidate_sends (state : NodeState Node TxId)
    : Sends
        (fun next sent =>
          ((next = freshCandidate self state
              /\ forall e,
                  e ∈ sent
                  -> e.source = self
                      /\ e.payload
                          = .requestVoteRequest
                              (makeRequestVoteRequest (freshCandidate self state)))
            \/ (hasQuorum
                  ((freshCandidate self state).activeConfigurations (inferInstance))
                  {self}
                /\ Advance self (leaderState (freshCandidate self state)) next
                /\ forall e,
                    e ∈ sent
                    -> LeaderStart self (state.currentTerm + 1) next e
                        \/ (e.source = self
                            /\ e.payload
                                = .requestVoteRequest
                                    (makeRequestVoteRequest
                                      (freshCandidate self state))))))
        (becomeCandidate (inferInstance) caps state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_sends self (freshCandidate self state))
    fun next sent elected => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ later requests => Sends.pure' ?_
  simp only [List.append_nil]
  rcases elected with ⟨rfl, rfl⟩ | ⟨_, quorum, advance, started⟩
  · exact Or.inl ⟨rfl, fun e member => by
      have := requests e (by simpa using member)
      exact ⟨this.1, this.2.2⟩⟩
  · refine Or.inr ⟨by simpa [freshCandidate] using quorum, advance, fun e member => ?_⟩
    rcases List.mem_append.mp member with old | new
    · exact Or.inl (by simpa [freshCandidate] using started e old)
    · have := requests e new
      exact Or.inr ⟨this.1, this.2.2⟩

/-- The pre-vote candidate state built from `state`. -/
def preVoteState (self : Node) (state : NodeState Node TxId) : NodeState Node TxId :=
  {
    state with
      role := .preVoteCandidate, leaderKnown := false, preVotesGranted := {self}
  }

end Effects

/-- What a campaigning step sends or becomes. -/
def CampaignResult (self : Node) (before candidate after : NodeState Node TxId)
    (sent : List (Model.Envelope Node TxId))
    : Prop :=
  let request (e : Model.Envelope Node TxId) :=
    e.source = self
    /\ e.payload = .requestVoteRequest (makeRequestVoteRequest candidate)
    /\ before.currentTerm < candidate.currentTerm
  (after = candidate /\ forall e, e ∈ sent -> request e)
  \/ (hasQuorum (candidate.activeConfigurations (inferInstance)) candidate.votesGranted
      /\ Advance self (leaderState candidate) after
      /\ forall e,
          e ∈ sent -> LeaderStart self candidate.currentTerm after e \/ request e)

theorem campaign_summary {self : Node} {before candidate after : NodeState Node TxId}
    {event : Event Node TxId} {sent : List (Model.Envelope Node TxId)}
    (campaign : Campaign self before event candidate)
    (result : CampaignResult self before candidate after sent)
    : Summary self before event after sent := by
  have termLe : before.currentTerm <= candidate.currentTerm := by
    rcases campaign.2.2.2 with fresh | kept <;> omega
  have notNone : Not (before.role = .none) := by
    rcases campaign.2.2.2 with fresh | kept
    · exact fresh.1
    · rw [kept.1]; simp
  have notLeaderKeep : before.role = .leader -> candidate.currentTerm = before.currentTerm
      -> False := by
    intro leader same
    rcases campaign.2.2.2 with fresh | kept
    · omega
    · rw [kept.1] at leader; cases leader
  have voteKeep : candidate.currentTerm = before.currentTerm -> forall voted,
      before.votedFor = some voted -> candidate.votedFor = some voted := by
    intro same voted votedEq
    rcases campaign.2.2.2 with fresh | kept
    · omega
    · rcases kept.2.2.1 with eq | none
      · rw [eq]; exact votedEq
      · rw [none] at votedEq; cases votedEq
  unfold CampaignResult at result
  rcases result with ⟨rfl, requests⟩ | ⟨quorum, advance, started⟩
  · refine ⟨termLe, voteKeep, fun _ => Or.inl notNone, fun _ => campaign,
      fun leader => (by rw [campaign.1] at leader; cases leader),
      fun _ leader same => (notLeaderKeep leader same).elim,
      Kind.same campaign.2.1 campaign.2.2.1, fun e member => ?_⟩
    obtain ⟨source, payload, lt⟩ := requests e member
    refine ⟨source, ?_⟩
    rw [payload]
    exact ⟨rfl, lt, fun _ => rfl⟩
  · replace advance : Advance self (leaderState candidate) after :=
      advance
    have termEq : after.currentTerm = candidate.currentTerm := by
      rw [advance.term]; rfl
    have elected : Wins self before event after := ⟨candidate, campaign, quorum, advance⟩
    have notCandidate : Not (after.role = .candidate) := by
      rcases advance.role with eq | eq <;> rw [eq] <;> simp [leaderState]
    refine ⟨termEq ▸ termLe, fun same voted votedEq => ?_, fun _ => Or.inl notNone,
      fun candidate' => (notCandidate candidate').elim, fun _ => Or.inr elected,
      fun _ leader same => (notLeaderKeep leader (termEq ▸ same)).elim,
      Kind.elect elected, fun e member => ?_⟩
    · rw [advance.votedFor]
      exact voteKeep (termEq ▸ same) voted votedEq
    · rcases started e member with (⟨source, payload⟩ | beat) | ⟨source, payload, lt⟩
      · refine ⟨source, ?_⟩
        rw [payload]
        exact termEq.symm
      · obtain ⟨request, payload, ok⟩ := beat.ok
        refine ⟨beat.1, ?_⟩
        rw [payload]
        exact ⟨ok, notCandidate, Or.inr elected⟩
      · refine ⟨source, ?_⟩
        rw [payload]
        exact ⟨termEq.symm, termEq ▸ lt, fun c => (notCandidate c).elim⟩

theorem quiet_summary {self : Node} {before after : NodeState Node TxId}
    {event : Event Node TxId} {sent : List (Model.Envelope Node TxId)}
    (role : after.role = before.role) (term : after.currentTerm = before.currentTerm)
    (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
    (voted : after.votedFor = before.votedFor)
    (votes : after.votesGranted = before.votesGranted)
    (matchEq : after.matchIndex = before.matchIndex)
    (active
      : Not (sent = [])
        -> Not (before.role = .none)
            \/ 2 <= before.currentTerm
            \/ exists source message,
                event = .receive source message
                /\ Bumping message
                /\ message.term <= after.currentTerm)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent := by
  refine ⟨term.ge, fun _ voted' votedEq => voted ▸ votedEq, fun either => ?_,
    fun candidate => ⟨candidate, log, commit, Or.inr ⟨role ▸ candidate, term, Or.inl voted,
      fun voter member => Or.inl (votes ▸ member)⟩⟩,
    fun leader => Or.inl ⟨role ▸ leader, term⟩,
    fun _ _ _ peer => Or.inl (congrFun matchEq peer), Kind.same log commit, sends⟩
  rcases either with notNone | nonempty
  · exact Or.inl (role ▸ notNone)
  · exact active nonempty

theorem bumped_summary {self : Node} {before after : NodeState Node TxId}
    {event : Event Node TxId} {sent : List (Model.Envelope Node TxId)}
    (lt : before.currentTerm < after.currentTerm)
    (notCandidate : Not (after.role = .candidate))
    (notLeader : Not (after.role = .leader))
    (active
      : exists source message,
          event = .receive source message
          /\ Bumping message
          /\ message.term <= after.currentTerm)
    (kind : Kind self before event after)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent :=
  ⟨
    lt.le,
    fun same => by omega,
    fun _ => Or.inr (Or.inr active),
    fun candidate => (notCandidate candidate).elim,
    fun leader => (notLeader leader).elim,
    fun leader => (notLeader leader).elim,
    kind,
    sends
  ⟩

/-- The state after adopting a newer term. -/
def bumpedState (state : NodeState Node TxId) (term : Nat) : NodeState Node TxId :=
  {
    state with
      role := .follower,
      currentTerm := term,
      votedFor := none,
      leaderKnown := false,
      isNewFollower := true,
      preVotesGranted := ∅
  }

theorem observe_bumping (before : NodeState Node TxId) {message : Message Node TxId}
    (bumping : Bumping message)
    : (before.currentTerm < message.term
        /\ observeTerm before message = bumpedState before message.term)
      \/ (message.term <= before.currentTerm /\ observeTerm before message = before) := by
  by_cases bump : before.currentTerm < message.term
  · refine Or.inl ⟨bump, ?_⟩
    cases message <;> simp_all [Bumping, observeTerm, updateTerm, bumpedState]
  · refine Or.inr ⟨Nat.not_lt.mp bump, ?_⟩
    cases message <;> simp_all [Bumping, observeTerm, updateTerm]

theorem updateTerm_of_lt {state : NodeState Node TxId} {term : Nat}
    (lt : state.currentTerm < term)
    : updateTerm state term
      = {
        state with
          role := .follower,
          currentTerm := term,
          votedFor := none,
          leaderKnown := false,
          isNewFollower := true,
          preVotesGranted := ∅
      } := by
  simp [updateTerm, lt]

theorem updateTerm_of_le {state : NodeState Node TxId} {term : Nat}
    (le : term <= state.currentTerm)
    : updateTerm state term = state := by
  simp [updateTerm, Nat.not_lt.mpr le]

section Election

variable (self : Node)

local notation "caps" => (Capabilities.record self : Caps Node TxId)

theorem becomeCandidate_result (state : NodeState Node TxId)
    (before : NodeState Node TxId) (term : state.currentTerm = before.currentTerm)
    : Sends
        (fun next sent =>
          CampaignResult self before (freshCandidate self state) next sent)
        (becomeCandidate (inferInstance) caps state self) := by
  refine Sends.mono (becomeCandidate_sends self state) fun next sent done => ?_
  have lt : before.currentTerm < (freshCandidate self state).currentTerm := by
    simp [freshCandidate, term]
  rcases done with ⟨rfl, requests⟩ | ⟨quorum, advance, started⟩
  · exact Or.inl ⟨rfl, fun e member => ⟨(requests e member).1, (requests e member).2, lt⟩⟩
  · refine Or.inr ⟨by simpa [freshCandidate] using quorum, advance, fun e member => ?_⟩
    rcases started e member with start | ⟨source, payload⟩
    · exact Or.inl start
    · exact Or.inr ⟨source, payload, lt⟩

theorem fresh_campaign {self : Node} {before state : NodeState Node TxId}
    {event : Event Node TxId} (active : Not (before.role = .none))
    (term : state.currentTerm = before.currentTerm) (log : state.log = before.log)
    (commit : state.commitIndex = before.commitIndex)
    : Campaign self before event (freshCandidate self state) := by
  refine ⟨rfl, log, commit, Or.inl ⟨active, ?_, rfl, rfl⟩⟩
  simp [freshCandidate, term]

theorem checkQuorum_summary (state : NodeState Node TxId) (input : Input Node TxId)
    : Sends (fun after sent => Summary self state (.internal input) after sent)
        (checkQuorum (inferInstance) state self) := by
  unfold checkQuorum
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => Sends.pure' ?_
  subst empty
  refine ⟨
    le_rfl,
    fun _ voted eq => eq,
    fun _ => Or.inl (by rw [leader]; simp),
    fun c => by simp at c,
    fun c => by simp at c,
    fun c => by simp at c,
    Kind.same rfl rfl,
    by simp
  ⟩

theorem nominate_summary (state : NodeState Node TxId)
    : Sends
        (fun after sent => Summary self state (.internal .nominateSuccessor) after sent)
        (act (inferInstance) caps self state .nominateSuccessor) := by
  simp only [act]
  refine Sends.bind' Sends.guard' fun _ sent ⟨leader, empty⟩ => ?_
  subst empty
  refine Sends.bind' (nominate_sends self state) fun _ sent nominated => Sends.pure' ?_
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by rw [leader]; simp)) fun e member => ?_
  obtain ⟨source, payload⟩ := nominated e (by simpa using member)
  refine ⟨source, ?_⟩
  rw [payload]
  rfl

theorem sendEntries_summary (state : NodeState Node TxId) (destination : Node)
    (endIndex : Nat)
    : Sends
        (fun after sent =>
          Summary self state (.internal (.sendEntries destination endIndex)) after sent)
        (sendEntries (inferInstance) caps self state destination endIndex) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, peer, le, bound, _⟩, empty⟩ => ?_
  subst empty
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  subst eq
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by rw [leader]; simp)) fun e member => ?_
  simp only [List.nil_append, List.append_nil, List.mem_singleton] at member
  subst member
  have other : Not (destination = self) := by
    simp [eligiblePeers] at peer; exact peer.1
  refine ⟨
    rfl,
    ⟨other, rfl, le.trans bound, rfl, ?_, le_rfl⟩,
    by simp [leader],
    Or.inl ⟨leader, rfl⟩
  ⟩
  exact List.take_prefix _ _

theorem startElection_summary (state : NodeState Node TxId)
    : Sends
        (fun after sent => Summary self state (.internal (.timeout .election)) after sent)
        (startElection (inferInstance) caps state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  have notNone : Not (state.role = .none) := by
    rcases can.1 with eq | eq | eq <;> rw [eq] <;> simp
  refine Sends.ite' (fun _ => ?_) fun _ =>
    Sends.mono (becomeCandidate_result self state state rfl) fun after sent result =>
      campaign_summary (fresh_campaign notNone rfl rfl rfl) result
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_result self _ state rfl) fun after sent result =>
      campaign_summary (fresh_campaign notNone rfl rfl rfl) result
  · refine Sends.bind' (broadcast_sends self _ _) fun _ sent requests => Sends.pure' ?_
    simp only [List.append_nil]
    refine ⟨le_rfl, fun _ voted eq => eq, fun _ => Or.inl notNone, fun c => by simp at c,
      fun c => by simp at c, fun c => by simp at c, Kind.same rfl rfl, fun e member => ?_⟩
    obtain ⟨source, _, payload⟩ := requests e member
    refine ⟨source, ?_⟩
    rw [payload]
    rfl

theorem voteRequest_summary (before : NodeState Node TxId) (source : Node)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteRequest request)) after sent)
        (receive (inferInstance) caps self source before
          (.requestVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event Node TxId)
        /\ Bumping message /\ message.term <= (bumpedState before request.term).currentTerm :=
      ⟨source, _, rfl, trivial, le_refl _⟩
    split <;> rename_i granted <;> simp only [decide_eq_true_eq] at granted
    · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event Node TxId)
        /\ Bumping message /\ message.term <= before.currentTerm :=
      ⟨source, _, rfl, trivial, le⟩
    split <;> rename_i granted <;> simp only [decide_eq_true_eq] at granted
    · refine ⟨le_rfl, fun _ voted votedEq => ?_, fun _ => Or.inr (Or.inr active),
        fun candidate => ⟨candidate, rfl, rfl, Or.inr ⟨candidate, rfl, ?_,
          fun voter member => Or.inl member⟩⟩,
        fun leader => Or.inl ⟨leader, rfl⟩, fun _ _ _ _ => Or.inl rfl, Kind.same rfl rfl,
        fun e member => ?_⟩
      · rcases granted.2.2.2 with none | some
        · rw [none] at votedEq; cases votedEq
        · rw [some] at votedEq; exact votedEq
      · rcases granted.2.2.2 with none | some
        · exact Or.inr none
        · exact Or.inl some.symm
      · simp at member
        subst member
        exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    · refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun _ => Or.inr (Or.inr active)) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩

theorem preVoteRequest_summary (before : NodeState Node TxId) (source : Node)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVote request)) after sent)
        (receive (inferInstance) caps self source before (.requestPreVote request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVote request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestPreVote] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;>
    subst eq
  · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
      ⟨source, _, rfl, trivial, le_refl _⟩ (Kind.same rfl rfl) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩
  · refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
      (fun _ => Or.inr (Or.inr ⟨source, _, rfl, trivial, le⟩)) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩

theorem proposeVote_summary (before : NodeState Node TxId) (source : Node) (term : Nat)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.proposeVoteRequest term)) after sent)
        (receive (inferInstance) caps self source before (.proposeVoteRequest term)) := by
  simp only [receive, observeTerm, handleProposeVoteRequest]
  refine Sends.ite' (fun start => ?_)
    fun _ =>
      Sends.pure'
        (quiet_summary rfl rfl rfl rfl rfl rfl rfl (fun empty => (empty rfl).elim)
          (by simp))
  have notNone : Not (before.role = .none) := by
    rcases start.2.1 with eq | eq | eq <;> rw [eq] <;> simp
  exact Sends.mono (becomeCandidate_result self before before rfl)
    fun after sent result =>
      campaign_summary (fresh_campaign notNone rfl rfl rfl) result

theorem elect_result {before candidate after : NodeState Node TxId}
    {sent : List (Model.Envelope Node TxId)}
    (elected
      : (after = candidate /\ sent = [])
        \/ (candidate.role = .candidate
            /\ hasQuorum (candidate.activeConfigurations (inferInstance))
                candidate.votesGranted
            /\ Advance self (leaderState candidate) after
            /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm after e))
    : CampaignResult self before candidate after sent := by
  rcases elected with ⟨rfl, rfl⟩ | ⟨_, quorum, advance, started⟩
  · exact Or.inl ⟨rfl, by simp⟩
  · exact Or.inr ⟨quorum, advance, fun e member => Or.inl (started e member)⟩

theorem voteResponse_summary (before : NodeState Node TxId) (source : Node)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteResponse response)) after
            sent)
        (receive (inferInstance) caps self source before
          (.requestVoteResponse response)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, le_refl _⟩ (Kind.same rfl rfl) (by simp))
  · refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun empty => (empty rfl).elim) (by simp))
    have campaign : Campaign self before (.receive source (.requestVoteResponse response))
        { before with votesGranted := insert source before.votesGranted } := by
      refine ⟨won.1, rfl, rfl, Or.inr ⟨won.1, rfl, Or.inl rfl, fun voter member => ?_⟩⟩
      rcases Finset.mem_insert.mp member with rfl | old
      · exact Or.inr ⟨response, rfl, won.2.1, won.2.2⟩
      · exact Or.inl old
    exact Sends.mono (electIfQuorum_sends self _) fun after sent elected =>
      campaign_summary campaign (elect_result self elected)

theorem preVoteResponse_summary (before : NodeState Node TxId) (source : Node)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVoteResponse response)) after
            sent)
        (receive (inferInstance) caps self source before
          (.requestPreVoteResponse response)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, le_refl _⟩ (Kind.same rfl rfl) (by simp))
  · refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun empty => (empty rfl).elim) (by simp))
    have notNone : Not (before.role = .none) := by rw [won.1]; simp
    refine Sends.ite' (fun _ => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun empty => (empty rfl).elim) (by simp))
    exact Sends.mono (becomeCandidate_result self _ before rfl) fun after sent result =>
      campaign_summary (fresh_campaign notNone rfl rfl rfl) result

theorem observe_response (before : NodeState Node TxId) (response : AppendEntriesResponse)
    : (before.role = .leader
        /\ before.currentTerm < response.term
        /\ observeTerm before (.appendEntriesResponse response)
            = bumpedState before response.term)
      \/ ((before.role = .leader -> response.term <= before.currentTerm)
          /\ observeTerm before (.appendEntriesResponse response) = before) := by
  by_cases leader : before.role = .leader
  · by_cases bump : before.currentTerm < response.term
    · exact Or.inl ⟨leader, bump, by simp [observeTerm, updateTerm, leader, bump, bumpedState]⟩
    · exact Or.inr ⟨fun _ => Nat.not_lt.mp bump, by simp [observeTerm, updateTerm, bump]⟩
  · exact Or.inr ⟨fun yes => (leader yes).elim, by simp [observeTerm, leader]⟩

theorem appendEntriesResponse_summary (before : NodeState Node TxId) (source : Node)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesResponse response)) after
            sent)
        (receive (inferInstance) caps self source before
          (.appendEntriesResponse response)) := by
  simp only [receive]
  rcases observe_response before response with ⟨leader, bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · refine Sends.ite' (fun _ => Sends.pure' ?_) fun notFollower => absurd notFollower
      (by simp [bumpedState])
    refine ⟨bump.le, fun same => by simp [bumpedState] at same; omega,
      fun _ => Or.inl (by rw [leader]; simp), fun c => by simp [bumpedState] at c,
      fun c => by simp [bumpedState] at c, fun c => by simp [bumpedState] at c,
      Kind.same rfl rfl, by simp⟩
  · have quiet := fun (after : NodeState Node TxId) (role : after.role = before.role)
        (term : after.currentTerm = before.currentTerm) (log : after.log = before.log)
        (commit : after.commitIndex = before.commitIndex)
        (voted : after.votedFor = before.votedFor)
        (votes : after.votesGranted = before.votesGranted)
        (matchEq : after.matchIndex = before.matchIndex) =>
      quiet_summary (self := self) (event := .receive source (.appendEntriesResponse response))
        (sent := []) role term log commit voted votes matchEq
        (fun empty => (empty rfl).elim) (by simp)
    refine Sends.ite' (fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl))
      fun leader => ?_
    simp only [bne_iff_ne, ne_eq, Decidable.not_not] at leader
    refine Sends.ite' (fun success => ?_) fun _ =>
      Sends.pure' (quiet _ rfl rfl rfl rfl rfl rfl rfl)
    refine Sends.ite' (fun term => ?_) fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl)
    refine Sends.mono (advanceCommit_sends self _) fun after sent ⟨advance, nominated⟩ => ?_
    have notCandidate : Not (after.role = .candidate) := by
      rcases advance.role with eq | eq <;> rw [eq] <;> simp [leader]
    refine ⟨advance.term.ge, fun _ voted eq => by rw [advance.votedFor]; exact eq,
      fun _ => Or.inl (by rw [leader]; simp), fun c => (notCandidate c).elim,
      fun _ => Or.inl ⟨leader, advance.term⟩, fun _ _ _ peer => ?_,
      Kind.ack source response rfl leader success term advance, fun e member => ?_⟩
    · rw [advance.matchIndex]
      by_cases same : peer = source
      · subst same
        simp only [Function.update_self]
        rcases max_choice (before.matchIndex peer) response.lastLogIndex with eq | eq <;>
          rw [eq]
        · exact Or.inl rfl
        · exact Or.inr ⟨response, rfl, success, term, rfl⟩
      · exact Or.inl (by simp [Function.update, same])
    · obtain ⟨source', payload⟩ := nominated e member
      refine ⟨source', ?_⟩
      rw [payload]
      exact advance.term.symm

end Election

/-- What the AppendEntries request handler does, relative to the observed state. -/
def AEReply (self source : Node) (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) (after : NodeState Node TxId)
    (sent : List (Model.Envelope Node TxId))
    : Prop :=
  after.currentTerm = state.currentTerm
  /\ after.votedFor = state.votedFor
  /\ after.matchIndex = state.matchIndex
  /\ after.votesGranted = state.votesGranted
  /\ (after.role = state.role \/ after.role = .follower)
  /\ (after.role = .candidate -> after = state)
  /\ ((after.log = state.log
        /\ after.commitIndex = state.commitIndex
        /\ forall e,
            e ∈ sent
            -> e.source = self
                /\ exists response,
                    e.payload = .appendEntriesResponse response
                    /\ response.success = false)
      \/ (request.term = state.currentTerm
          /\ state.commitIndex <= request.prevLogIndex
          /\ appendEntryMatchesLog state request
          /\ after.log = acceptLog state.log request
          /\ after.commitIndex
              = max state.commitIndex
                  (maxCommittableIndexUpTo after.log
                    (min request.leaderCommit
                      (request.prevLogIndex + request.entries.length)))
          /\ exists e,
              sent = [e]
              /\ e.source = self
              /\ e.target = source
              /\ e.payload
                  = .appendEntriesResponse
                      {
                        term := state.currentTerm,
                        success := true,
                        lastLogIndex := request.prevLogIndex + request.entries.length
                      }))

omit [LinearOrder Node] [Inhabited TxId] in
theorem fromLeader_spec (self : Node) (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : let result := handleAppendEntiresFromLeader self state request
      result.1.currentTerm = state.currentTerm
      /\ result.1.votedFor = state.votedFor
      /\ result.1.matchIndex = state.matchIndex
      /\ result.1.votesGranted = state.votesGranted
      /\ result.1.role = state.role
      /\ result.1.log
          = state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      /\ result.1.commitIndex
          = max state.commitIndex
              (maxCommittableIndexUpTo result.1.log
                (min request.leaderCommit
                  (request.prevLogIndex + request.entries.length)))
      /\ result.2
          = {
            term := state.currentTerm,
            success := true,
            lastLogIndex := request.prevLogIndex + request.entries.length
          } := by
  obtain ⟨_, eq⟩ := Ledger.handleAppendEntiresFromLeader_eq self state request
  simp [eq]

theorem aeReply (self source : Node) (z : NodeState Node TxId)
    (r : AppendEntriesRequest Node TxId) (le : r.term <= z.currentTerm)
    : Sends (AEReply self source z r)
        (handleAppendEntriesRequest (Capabilities.record self) self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    ({ z with role := Role.follower, isNewFollower := true } : NodeState Node TxId) else z) = w
  have wTerm : w.currentTerm = z.currentTerm := by rw [← hw]; split <;> rfl
  have wLog : w.log = z.log := by rw [← hw]; split <;> rfl
  have wCommit : w.commitIndex = z.commitIndex := by rw [← hw]; split <;> rfl
  have wVoted : w.votedFor = z.votedFor := by rw [← hw]; split <;> rfl
  have wMatch : w.matchIndex = z.matchIndex := by rw [← hw]; split <;> rfl
  have wVotes : w.votesGranted = z.votesGranted := by rw [← hw]; split <;> rfl
  have wRole : w.role = z.role \/ w.role = .follower := by rw [← hw]; split <;> simp
  have wCand : w.role = .candidate -> w = z := by
    rw [← hw]; split
    · simp
    · intro _; rfl
  have wSame : r.term = z.currentTerm -> Not (w.role = .candidate) := by
    intro same
    rw [← hw]
    split
    · simp
    · rename_i keep
      intro role
      exact keep ⟨same, by simp [role]⟩
  have common := fun (after : NodeState Node TxId) (sent : List (Model.Envelope Node TxId))
      (rest : (after.log = z.log /\ after.commitIndex = z.commitIndex
        /\ forall e, e ∈ sent -> e.source = self /\ exists response,
          e.payload = .appendEntriesResponse response /\ response.success = false)
      \/ (r.term = z.currentTerm /\ z.commitIndex <= r.prevLogIndex
        /\ appendEntryMatchesLog z r
        /\ after.log = acceptLog z.log r
        /\ after.commitIndex = max z.commitIndex
          (maxCommittableIndexUpTo after.log
            (min r.leaderCommit (r.prevLogIndex + r.entries.length)))
        /\ exists e, sent = [e] /\ e.source = self /\ e.target = source
          /\ e.payload = .appendEntriesResponse
            { term := z.currentTerm, success := true,
              lastLogIndex := r.prevLogIndex + r.entries.length }))
      (term : after.currentTerm = w.currentTerm) (voted : after.votedFor = w.votedFor)
      (matchEq : after.matchIndex = w.matchIndex) (votes : after.votesGranted = w.votesGranted)
      (role : after.role = w.role) (cand : after.role = .candidate -> after = w) =>
    (⟨term.trans wTerm, voted.trans wVoted, matchEq.trans wMatch, votes.trans wVotes,
      role ▸ wRole, fun c => (cand c).trans (wCand (role ▸ c)), rest⟩
      : AEReply self source z r after sent)
  refine Sends.ite' (fun reject => ?_) fun accept => ?_
  · have nack : forall payload, (exists response, payload = Message.appendEntriesResponse response
        /\ response.success = false) -> Sends (AEReply self source z r)
        (do (Capabilities.record self).send payload source; pure w
          : NodeEffect Node TxId _) :=
      fun payload isNack => Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' (by
        subst eq
        refine common w _ (Or.inl ⟨wLog, wCommit, fun e member => ?_⟩) rfl rfl rfl rfl rfl
          fun _ => rfl
        simp at member
        subst member
        exact ⟨rfl, isNack⟩)
    exact Sends.ite' (fun _ => nack _ ⟨_, rfl, rfl⟩) fun _ => nack _ ⟨_, rfl, rfl⟩
  have same : r.term = z.currentTerm := by omega
  have notCand := wSame same
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (common _ [] (Or.inl ⟨wLog, wCommit, by simp⟩)
          rfl rfl rfl rfl rfl fun c => (notCand c).elim))
    fun go => ?_
  have matches_ : appendEntryMatchesLog z r := by
    have m : appendEntryMatchesLog w r := by tauto
    unfold appendEntryMatchesLog at m ⊢
    rw [wLog] at m
    exact m
  have commitLe : z.commitIndex <= r.prevLogIndex := by
    rw [← wCommit]; omega
  generalize hv : (if hasTermConflict ({ w with leaderKnown := true } : NodeState Node TxId) r
      then ({ w with
        leaderKnown := true, log := w.log.take r.prevLogIndex, isNewFollower := false }
        : NodeState Node TxId)
      else { w with leaderKnown := true }) = v
  have vLog : v.log = (if ((z.log.drop r.prevLogIndex).zip r.entries).any
        (fun (existing, incoming) => existing.term != incoming.term) then
      z.log.take r.prevLogIndex else z.log) := by
    have cEq : hasTermConflict ({ w with leaderKnown := true } : NodeState Node TxId) r
        <-> ((z.log.drop r.prevLogIndex).zip r.entries).any
          (fun (existing, incoming) => existing.term != incoming.term) = true := by
      show ((w.log.drop r.prevLogIndex).zip r.entries).any _ = true <-> _
      rw [wLog]
    rw [← hv]
    by_cases c : hasTermConflict ({ w with leaderKnown := true } : NodeState Node TxId) r
    · rw [ite_eq_left c, ite_eq_left (cEq.mp c)]
      show w.log.take _ = _
      rw [wLog]
    · rw [ite_eq_right c, ite_eq_right fun yes => c (cEq.mpr yes)]
      exact wLog
  have vTerm : v.currentTerm = w.currentTerm := by rw [← hv]; split <;> rfl
  have vCommit : v.commitIndex = w.commitIndex := by rw [← hv]; split <;> rfl
  have vVoted : v.votedFor = w.votedFor := by rw [← hv]; split <;> rfl
  have vMatch : v.matchIndex = w.matchIndex := by rw [← hv]; split <;> rfl
  have vVotes : v.votesGranted = w.votesGranted := by rw [← hv]; split <;> rfl
  have vRole : v.role = w.role := by rw [← hv]; split <;> rfl
  obtain ⟨term, voted, matchEq, votes, role, log, commit, response⟩ :=
    fromLeader_spec self v r
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  subst eq
  refine common _ _ (Or.inr ⟨same, commitLe, matches_, ?_, ?_, _, rfl, rfl, rfl, ?_⟩)
    (term.trans vTerm) (voted.trans vVoted) (matchEq.trans vMatch) (votes.trans vVotes)
    (role.trans vRole) fun c => (notCand (vRole ▸ role ▸ c)).elim
  · rw [log, vLog]
    rfl
  · rw [commit, vCommit, wCommit]
  · rw [response, vTerm, wTerm]

theorem aeReply_summary {self source : Node} {before z after : NodeState Node TxId}
    {request : AppendEntriesRequest Node TxId} {sent : List (Model.Envelope Node TxId)}
    (log : z.log = before.log) (commit : z.commitIndex = before.commitIndex)
    (termLe : before.currentTerm <= z.currentTerm)
    (reply : AEReply self source z request after sent)
    : Kind self before (.receive source (.appendEntriesRequest request)) after
      /\ forall e,
          e ∈ sent
          -> SendOK self before (.receive source (.appendEntriesRequest request)) after
              e := by
  obtain ⟨term, _, _, _, _, _, rest⟩ := reply
  rcases rest with ⟨log', commit', nacks⟩ | ⟨same, commitLe, matches_, accepted, committed, e,
    rfl, source', _, payload⟩
  · refine ⟨Kind.same (log'.trans log) (commit'.trans commit), fun e member => ?_⟩
    obtain ⟨source', response, payload, failed⟩ := nacks e member
    refine ⟨source', ?_⟩
    rw [payload]
    intro success
    rw [failed] at success
    cases success
  · have acceptedBy : Accepted before request after := by
      refine ⟨same.trans term.symm, same ▸ termLe, commit ▸ commitLe, ?_, log ▸ accepted,
        ?_⟩
      · unfold appendEntryMatchesLog at matches_
        rw [log] at matches_
        exact matches_
      · rw [committed, commit]
    refine ⟨Kind.accept source request rfl acceptedBy, fun e' member => ?_⟩
    simp only [List.mem_singleton] at member
    subst member
    refine ⟨source', ?_⟩
    rw [payload]
    exact fun _ => ⟨source, request, rfl, acceptedBy, term.symm, rfl⟩

theorem appendEntriesRequest_summary (self : Node) (before : NodeState Node TxId)
    (source : Node) (request : AppendEntriesRequest Node TxId)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (receive (inferInstance) (Capabilities.record self) self source before
          (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · refine Sends.mono (aeReply self source _ request (le_refl _)) fun after sent reply => ?_
    obtain ⟨kind, sends⟩ := aeReply_summary (before := before) (z := bumpedState before request.term) rfl rfl
      bump.le reply
    obtain ⟨term, _, _, _, role, _, _⟩ := reply
    have follower : after.role = .follower := by
      rcases role with eq | eq <;> rw [eq]; rfl
    exact bumped_summary (term ▸ bump) (by simp [follower]) (by simp [follower])
      ⟨source, _, rfl, trivial, term ▸ le_refl _⟩ kind sends
  · refine Sends.mono (aeReply self source _ request le) fun after sent reply => ?_
    obtain ⟨kind, sends⟩ := aeReply_summary (before := before) rfl rfl le_rfl reply
    obtain ⟨term, voted, matchEq, votes, role, cand, _⟩ := reply
    refine ⟨term.ge, fun _ voted' eq => voted ▸ eq,
      fun _ => Or.inr (Or.inr ⟨source, _, rfl, trivial, term ▸ le⟩), fun c => ?_,
      fun leader => ?_, fun _ _ _ peer => Or.inl (congrFun matchEq peer), kind, sends⟩
    · have eq := cand c
      rw [eq] at c ⊢
      exact ⟨c, rfl, rfl, Or.inr ⟨c, rfl, Or.inl rfl, fun voter member => Or.inl member⟩⟩
    · rcases role with eq | eq
      · exact Or.inl ⟨eq ▸ leader, term⟩
      · rw [eq] at leader; cases leader

/-! ## Appending a batch -/

/-- A partially appended batch: new entries at the leader's term, and
heartbeats consistent with the current log. -/
def BatchState (self : Node) (before state : NodeState Node TxId)
    (sent : List (Model.Envelope Node TxId))
    : Prop :=
  (exists entries sentIndex,
    state = { before with log := before.log ++ entries, sentIndex := sentIndex }
    /\ forall entry, entry ∈ entries -> entry.term = before.currentTerm)
  /\ forall e, e ∈ sent -> AEFrom self before.currentTerm before.commitIndex state.log e

theorem BatchState.push {self : Node} {before state : NodeState Node TxId}
    {sent : List (Model.Envelope Node TxId)} (batch : BatchState self before state sent)
    (content : EntryContent Node TxId)
    : BatchState self before
        { state with log := state.log ++ [{ term := state.currentTerm, content }] }
        sent := by
  obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
  refine ⟨
    ⟨entries ++ [{ term := before.currentTerm, content }], sentIndex, by simp, ?_⟩,
    fun e member => (beats e member).extend (List.prefix_append _ _) le_rfl
  ⟩
  intro entry member
  rcases List.mem_append.mp member with old | new
  · exact terms entry old
  · simp at new; rw [new]

theorem appendEntry_batch (self : Node) (before : NodeState Node TxId)
    (state : NodeState Node TxId) (sent : List (Model.Envelope Node TxId))
    (content : EntryContent Node TxId) (batch : BatchState self before state sent)
    : Sends (fun next later => BatchState self before next (sent ++ later))
        (appendEntry (inferInstance) (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (by simpa using batch.push content)
    · rename_i nodes _
      refine Sends.guard_bind fun _ => ?_
      obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
      refine Sends.bind'
        (Sends.forIn' (R := AEFrom self before.currentTerm before.commitIndex
          (before.log ++ entries)) fun peer _ member => ?_)
        fun _ later sentBeats => Sends.pure' ?_
      · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member' => ?_
        simp only [eq, List.append_nil, List.mem_singleton] at member'
        subst member'
        have added := (Finset.mem_sort _).mp member
        have other : Not (peer = self) := (Finset.mem_erase.mp added).1
        refine ⟨rfl, other, _, rfl, rfl, ?_, ?_, ?_, le_rfl⟩ <;>
          simp only [makeAppendEntriesRequest, ite_eq_left added, messageEntries] <;> simp
      · have batch : BatchState self before
            { before with
                log := before.log ++ entries
                sentIndex := fun peer =>
                  if peer ∈ (nodes \ eligiblePeers (inferInstance)
                      { before with log := before.log ++ entries, sentIndex } self).erase self
                  then (before.log ++ entries).length else sentIndex peer }
            (sent ++ later) :=
          ⟨⟨entries, _, rfl, terms⟩, fun e member => by
            rcases List.mem_append.mp member with old | new
            · exact beats e old
            · exact sentBeats e new⟩
        simpa using batch.push content

theorem appendBatch_summary (self : Node) (state : NodeState Node TxId)
    (contents : List (EntryContent Node TxId))
    : Sends
        (fun after sent => Summary self state (.internal (.append contents)) after sent)
        (act (inferInstance) (Capabilities.record self) self state
          (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => ?_
  subst empty
  have start : BatchState self state state [] :=
    ⟨⟨[], state.sentIndex, by simp, by simp⟩, by simp⟩
  refine Sends.bind' (Sends.mono (Sends.foldlM' (I := BatchState self state)
      (fun value sent' item batch => appendEntry_batch self state value sent' item batch)
      contents state [] start) fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  refine Sends.mono (advanceCommit_sends self appended)
    fun after later ⟨advance, nominated⟩ => ?_
  obtain ⟨⟨entries, sentIndex, eq, terms⟩, beats⟩ := batch
  have term : after.currentTerm = state.currentTerm := by rw [advance.term, eq]
  have log : after.log = appended.log := advance.log
  have role : after.role = .leader \/ after.role = .none := by
    rcases advance.role with r | r
    · rw [r, eq]; exact Or.inl leader
    · exact Or.inr r
  have commit : state.commitIndex <= after.commitIndex := by
    have := advance.commit_le; rw [eq] at this; exact this
  refine ⟨
    term.ge,
    fun _ voted votedEq => by rw [advance.votedFor, eq]; exact votedEq,
    fun _ => Or.inl (by rw [leader]; simp),
    fun c => by rcases role with r | r <;> simp [r] at c,
    fun _ => Or.inl ⟨leader, term⟩,
    fun _ _ _ peer => Or.inl (by rw [advance.matchIndex, eq]),
    Kind.append entries sentIndex leader terms (eq ▸ advance),
    fun e member => ?_
  ⟩
  rcases List.mem_append.mp (by simpa using member) with old | new
  · have from_ : AEFrom self after.currentTerm after.commitIndex after.log e :=
      term ▸ (beats e old).extend (log ▸ List.prefix_refl _) commit
    obtain ⟨request, payload, ok⟩ := from_.ok
    refine ⟨from_.1, ?_⟩
    rw [payload]
    exact ⟨ok, by rcases role with r | r <;> simp [r], Or.inl ⟨leader, term⟩⟩
  · obtain ⟨source, payload⟩ := nominated e new
    refine ⟨source, ?_⟩
    rw [payload]
    show appended.currentTerm = after.currentTerm
    rw [advance.term]

/-- Every local step satisfies the step summary. -/
theorem summary (self : Node) (before : NodeState Node TxId) (event : Event Node TxId)
    : Sends (fun after sent => Summary self before event after sent)
        (Model.Node.step (inferInstance) (Capabilities.record self) self before
          event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_summary self before contents
      | sendEntries destination endIndex =>
          exact sendEntries_summary self before destination endIndex
      | timeout kind =>
          cases kind with
          | election => exact startElection_summary self before
          | checkQuorum => exact checkQuorum_summary self before _
      | nominateSuccessor => exact nominate_summary self before
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_summary self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_summary self before source response
      | requestVoteRequest request => exact voteRequest_summary self before source request
      | requestVoteResponse response =>
          exact voteResponse_summary self before source response
      | requestPreVote request => exact preVoteRequest_summary self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_summary self before source response
      | proposeVoteRequest term => exact proposeVote_summary self before source term

theorem LocalTransition.summary {before after : Model.State Node TxId}
    (transition : LocalTransition before after)
    : Summary transition.actor transition.pre transition.event transition.post
        transition.outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ := Safety.summary transition.actor transition.pre transition.event {}
    _ _ transition.ran
  simpa [eq] using holds

end CCFRaft.Proofs.Safety
