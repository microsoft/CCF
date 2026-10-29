module

public import CCFRaft.Proofs.Safety.Records

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One step of an execution

`Ctx nodes after before rest` packages one step from `before` to `after`, with
the invariant holding at every suffix of `before :: rest`. The lemmas here
relate the records of the extended history to those before the step.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Ledger

variable [Config.InitialConfiguration]

/-! ## Winning an election -/

theorem primaryState_log_prefix (state : NodeState)
    : (primaryState state).log <+: state.log := by
  simp only [primaryState]
  split
  · exact List.take_prefix _ _
  · exact List.prefix_refl _

/-- The facts of a won election used by the safety proof. -/
theorem Wins.facts {self : NodeID} {before' : NodeState} {event : Event}
    {after' : NodeState} (wins : Wins self before' event after')
    : exists candidate,
        Campaign self before' event candidate
        /\ hasQuorum
            (activeConfigurations before'.log before'.commitIndex)
            candidate.votesGranted
        /\ after'.log = (primaryState candidate).log
        /\ after'.currentTerm = candidate.currentTerm
        /\ after'.votedFor = candidate.votedFor
        /\ (forall peer, after'.matchIndex peer = 0)
        /\ (after'.role = .primary \/ after'.role = .none)
        /\ candidate.commitIndex <= after'.commitIndex := by
  obtain ⟨candidate, campaign, quorum, advance⟩ := wins
  have ⟨_, logEq, commitEq, _⟩ := campaign
  refine ⟨candidate, campaign, ?_, ?_⟩
  · have : candidate.activeConfigurations
        = activeConfigurations before'.log before'.commitIndex := by
      rw [← logEq, ← commitEq]
      rfl
    rw [← this]
    exact quorum
  rcases advance with ⟨rfl, _⟩ | ⟨log, term, voted, matchEq, _, _, lt, _, role⟩
  · exact ⟨rfl, rfl, rfl, fun _ => rfl, Or.inl rfl, le_rfl⟩
  · refine ⟨log, term, voted, fun peer => by rw [matchEq]; rfl, ?_, ?_⟩
    · rcases role with role | role
      · exact Or.inl role
      · exact Or.inr role.1
    · simp only [primaryState] at lt
      omega

/-- One step of an execution, the invariant holding before it. -/
structure Ctx (nodes : List NodeID) (after before : Model.State) (rest : History) where
  exec : Exec nodes (after :: before :: rest)
  tr : LocalTransition before after
  good : Good (before :: rest)

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

abbrev actor : NodeID := c.tr.actor
abbrev pre : NodeState := c.tr.pre
abbrev post : NodeState := c.tr.post
abbrev event : Event := c.tr.event
abbrev sent : List Model.Envelope := c.tr.outputs.outgoing

theorem sum : Summary c.actor c.pre c.event c.post c.sent := c.tr.summary

theorem prior : Exec nodes (before :: rest) :=
  c.exec.suffix (List.suffix_cons _ _) (List.cons_ne_nil _ _)

theorem all {clause : History -> Prop} (project : forall {h}, Inv h -> clause h)
    : Everywhere clause (before :: rest) :=
  c.good.everywhere project

theorem inv : Inv (before :: rest) := c.good _ (List.suffix_refl _) (List.cons_ne_nil _ _)

theorem suffix_tail : before :: rest <:+ after :: before :: rest := List.suffix_cons _ _

/-! ## Current states -/

theorem pre_now : Now (before :: rest) c.actor c.pre := c.tr.pre_mem

theorem post_now : Now (after :: before :: rest) c.actor c.post := c.tr.post_mem

theorem now_pre {state : NodeState} (now : Now (before :: rest) c.actor state)
    : state = c.pre :=
  now_unique c.prior now c.pre_now

theorem now_post {state : NodeState} (now : Now (after :: before :: rest) c.actor state)
    : state = c.post :=
  now_unique c.exec now c.post_now

theorem now_after {node : NodeID} {state : NodeState}
    (now : Now (after :: before :: rest) node state)
    : (node = c.actor /\ state = c.post)
      \/ (Not (node = c.actor) /\ Now (before :: rest) node state) :=
  c.tr.mem_after now

theorem now_other {node : NodeID} {state : NodeState}
    (different : Not (node = c.actor)) (now : Now (before :: rest) node state)
    : Now (after :: before :: rest) node state :=
  c.tr.other_mem now different

theorem seen_after {node : NodeID} {state : NodeState}
    (seen : Seen (after :: before :: rest) node state)
    : Seen (before :: rest) node state \/ (node = c.actor /\ state = c.post) := by
  rcases seen.cons with now | old
  · rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, now⟩
    · exact Or.inr ⟨rfl, rfl⟩
    · exact Or.inl now.seen
  · exact Or.inl old

theorem pre_seen : Seen (before :: rest) c.actor c.pre := c.pre_now.seen

theorem post_seen : Seen (after :: before :: rest) c.actor c.post := c.post_now.seen

theorem frontier_pre : c.pre.commitIndex <= c.pre.log.length :=
  c.pre_seen.commit_le c.prior

theorem frontier_post : c.post.commitIndex <= c.post.log.length :=
  c.post_seen.commit_le c.exec

/-! ## Received messages -/

theorem received {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        Pending (before :: rest) envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  rcases c.tr.source with ⟨input, internal, _⟩ | ⟨envelope, queued, target, receive, _⟩
  · have : c.tr.event = _ := eq
    rw [internal] at this
    cases this
  · have : c.tr.event = _ := eq
    rw [receive] at this
    cases this
    exact ⟨envelope, queued, rfl, target, rfl⟩

/-- The evidence carried by a received message. -/
theorem received_ok {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        MessageOK (before :: rest) envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
  exact ⟨envelope, c.inv.messages envelope pending, sourceEq, targetEq, payload⟩

theorem received_term {source : NodeID} {message : Message}
    (eq : c.event = .receive source message) (bumping : Bumping message)
    : 2 <= message.term := by
  obtain ⟨envelope, pending, _, _, rfl⟩ := c.received eq
  exact c.inv.message_terms envelope pending bumping

/-! ## Terms -/

theorem term_le : c.pre.currentTerm <= c.post.currentTerm := Summary.term_le c.sum

theorem pre_two (active : Not (c.pre.role = .none)) : 2 <= c.pre.currentTerm :=
  c.inv.active c.actor c.pre c.pre_now active

/-- An active node or a sender has term at least two. -/
theorem post_two (active : Not (c.post.role = .none) \/ Not (c.sent = []))
    : 2 <= c.post.currentTerm := by
  have le := c.term_le
  rcases Summary.active c.sum active with role | two | ⟨source, message, eq, bumping, bound⟩
  · have := c.pre_two role
    omega
  · omega
  · have := c.received_term eq bumping
    omega

/-! ## Elections in the extended history -/

theorem elected_after {node : NodeID} {term commit : Nat} {log : List Entry}
    (elected : Elected (after :: before :: rest) node term log commit)
    : Elected (before :: rest) node term log commit
      \/ ElectStep after before rest node term log commit := by
  obtain ⟨a, b, r, suffix, step⟩ := elected
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · cases same
    exact Or.inr step
  · exact Or.inl ⟨a, b, r, inner, step⟩

/-- A new election is the actor's, campaigning with its state before the step. -/
theorem electStep {node : NodeID} {term commit : Nat} {log : List Entry}
    (step : ElectStep after before rest node term log commit)
    : node = c.actor
      /\ c.pre.log = log
      /\ c.pre.commitIndex = commit
      /\ (c.pre.currentTerm < term
          \/ (c.pre.currentTerm = term /\ c.pre.role = .candidate))
      /\ c.post.currentTerm = term
      /\ (c.post.role = .primary \/ c.post.role = .none)
      /\ log.take (maxCommittableIndex log) <+: c.post.log
      /\ 3 <= term := by
  obtain ⟨candidate, leader, candidateMem, leaderMem, logEq, commitEq, _, termCase, leaderTerm,
    leaderRole, winning, three, _⟩ := step
  rcases c.now_after leaderMem with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have := c.now_pre candidateMem
    subst this
    exact ⟨rfl, logEq, commitEq, termCase, leaderTerm, leaderRole, winning, three⟩
  · have := now_unique c.prior old candidateMem
    subst this
    rcases termCase with lt | ⟨_, role⟩
    · omega
    · rcases leaderRole with role' | role' <;> rw [role'] at role <;> cases role

theorem led_after {node : NodeID} {term : Nat}
    (led : Led (after :: before :: rest) node term)
    : Led (before :: rest) node term
      \/ exists log commit, ElectStep after before rest node term log commit := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact Or.inl (Or.inl bootstrap)
  · rcases c.elected_after elected with old | step
    · exact Or.inl (Or.inr ⟨log, commit, old⟩)
    · exact Or.inr ⟨log, commit, step⟩

theorem led_other {node : NodeID} {term : Nat} (different : Not (node = c.actor))
    (led : Led (after :: before :: rest) node term)
    : Led (before :: rest) node term := by
  rcases c.led_after led with old | ⟨_, _, step⟩
  · exact old
  · exact absurd (c.electStep step).1 different

theorem canon_after {term : Nat} {log : List Entry}
    (canon : Canon (after :: before :: rest) term log)
    : Canon (before :: rest) term log
      \/ exists node state,
          CanonNow (after :: before :: rest) node state term /\ state.log = log := by
  obtain ⟨earlier, suffix, rest'⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · exact Or.inr rest'
  · exact Or.inl ⟨earlier, inner, rest'⟩

end Ctx

end CCFRaft.Proofs.Safety
