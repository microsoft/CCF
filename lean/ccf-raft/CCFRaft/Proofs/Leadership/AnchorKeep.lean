module

public import CCFRaft.Proofs.Leadership.AnchorNode
public import CCFRaft.Proofs.Direct.AppendOnly
public import CCFRaft.Proofs.Leadership.Membership

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One step keeps an anchored term quiet

A step keeps `QuietTerm`, which lacks the pre-vote clause of `QuietAmong`, given
an anchor of nodes that know the primary (`AnchorBase`). A participant
moves past the term only by a fresh campaign in it, and a fresh campaign needs a
quorum of pre-votes, which meets the anchor when every active configuration of
the participant is blocked by it. An anchor node knows the primary, so it grants
no pre-vote, and it keeps knowing the primary and its role unless it times out,
fails a quorum check, sees a newer term, is asked to campaign, or retires.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

/-- A quorum of the active configurations of a configuration history stays a
quorum as the commit index grows. -/
theorem quorum_of_commit {log log' : List Entry} {small large : Nat}
    (history : configurationHistory log' = configurationHistory log) (le : small <= large)
    {voters : Finset NodeID} (quorum : hasQuorum (activeConfigurations log small) voters)
    : hasQuorum (activeConfigurations log' large) voters := by
  obtain ⟨nonempty, all⟩ := quorum
  unfold activeConfigurations at nonempty all ⊢
  dsimp only at nonempty all ⊢
  rw [history]
  have mono := length_filter_index_mono (configurationHistory log) le
  generalize configurationHistory log = configurations at nonempty all mono ⊢
  have bound := List.length_filter_le
    (fun configuration : Configuration => decide (configuration.index <= large))
    configurations
  generalize (configurations.filter fun configuration => configuration.index <= small).length
    = few at nonempty all mono ⊢
  generalize (configurations.filter fun configuration => configuration.index <= large).length
    = many at mono bound ⊢
  have split : configurations.drop (many - 1)
      = (configurations.drop (few - 1)).drop (many - 1 - (few - 1)) := by
    rw [List.drop_drop]
    congr 1
    omega
  refine ⟨?_, List.all_eq_true.mpr fun configuration member => ?_⟩
  · have := mt List.drop_eq_nil_iff.mpr nonempty
    rw [Ne, List.drop_eq_nil_iff]
    omega
  · rw [split] at member
    exact List.all_eq_true.mp all configuration (List.mem_of_mem_drop member)

/-- An anchor: participants, including `leader`, that form a quorum of its active
configurations and lie in its latest one, are in `term` and know its primary,
and whose pre-votes no participant pre-vote candidate of `term` has counted. The
step lemmas over it take as hypotheses on the step that every quorum the actor can
count meets the anchor, and that a pre-vote candidate outside the anchor
receives no granted pre-vote of the term from it. Stale grants sent before an
anchored start may still be in flight, so the latter need not hold there. -/
structure AnchorBase (participants anchor : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  subset : anchor ⊆ participants
  leaderIn : leader ∈ anchor
  quorum
    : forall local_,
        (leader, local_) ∈ state.nodes -> hasQuorum local_.activeConfigurations anchor
  members
    : forall local_,
        (leader, local_) ∈ state.nodes
        -> forall node,
            node ∈ anchor
            -> Not (node = leader)
            -> node ∈ latestConfigurationMembers local_.activeConfigurations
  settled
    : forall node,
        node ∈ anchor
        -> exists local_,
            (node, local_) ∈ state.nodes
            /\ local_.currentTerm = term
            /\ local_.primaryKnown = true
            /\ (local_.role = .follower \/ local_.role = .primary)
  notCounted
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> node ∈ participants
        -> local_.role = .preVoteCandidate
        -> local_.currentTerm = term
        -> Disjoint local_.preVotesGranted anchor

variable [Config.InitialConfiguration]

section Step

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest) {participants anchor : Finset NodeID}
  {leader : NodeID} {term : Nat} (quiet : QuietTerm participants leader term before)

include c quiet

/-- The primary, as the head of the history before the step. -/
theorem QuietTerm.lead
    : exists local_, Lead nodes (before :: rest) leader term local_ := by
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, c.prior, now, primary, termEq⟩

/-- A participant receives no message past the term. -/
theorem QuietTerm.not_raised (actorIn : c.actor ∈ participants)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (preTerm : c.pre.currentTerm = term)
    : Not (Raised c.pre c.event) := by
  rintro ⟨source, message, eventEq, lt⟩
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eventEq
  have := quiet.messages envelope pending (sourceEq ▸ isolated _ _ eventEq)
    (targetEq ▸ actorIn)
  rw [payload] at this
  omega

/-- A step of the primary keeps the configuration history of its log, when it
receives only from participants and appends no configuration. -/
theorem QuietTerm.history_keep (leaderIn : leader ∈ participants)
    (same : c.actor = leader)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    : configurationHistory c.post.log = configurationHistory c.pre.log := by
  obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
  have now : Now (before :: rest) c.actor local_ := by
    rw [same]
    exact lead.now
  have localEq := c.now_pre now
  have primary : c.pre.role = .primary := localEq ▸ lead.primary
  have termEq : c.pre.currentTerm = term := localEq ▸ lead.term
  have ran := c.tr.ran
  cases eventEq : c.tr.event with
  | internal input =>
      rw [eventEq] at ran
      by_cases appending : exists contents, input = .append contents
      · obtain ⟨contents, rfl⟩ := appending
        obtain ⟨log, _⟩ := CommitLiveness.append_log c.tr.actor c.tr.pre contents _ _ _ ran
        show configurationHistory c.tr.post.log = _
        rw [log]
        refine configurationHistory_append_none fun entry member => ?_
        obtain ⟨content, contentIn, rfl⟩ := List.mem_map.mp member
        exact plain contents eventEq content contentIn
      · have kept := act_log c.tr.actor c.tr.pre input primary
          (fun contents eq => appending ⟨contents, eq⟩) _ _ _ ran
        show configurationHistory c.tr.post.log = _
        rw [kept]
  | receive source message =>
      rw [eventEq] at ran
      have kept := receive_log c.tr.actor c.tr.pre source message primary
        (fun request payloadEq => by
          obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ :=
            c.received (eventEq.trans (by rw [payloadEq]))
          have targetLeader : envelope.target = leader := targetEq.trans same
          have le := quiet.messages envelope pending
            (sourceEq ▸ isolated source message eventEq) (targetLeader ▸ leaderIn)
          rw [payload] at le
          have notTerm : Not (request.term = term) := fun current =>
            (lead.request pending payload current).2.1 targetLeader
          change request.term <= term at le
          have termEq' : c.tr.pre.currentTerm = term := termEq
          omega) _ _ _ ran
      show configurationHistory c.tr.post.log = _
      rw [kept]

/-- An anchor node is settled in the term before the step. -/
theorem AnchorBase.pre_settled (base : AnchorBase participants anchor leader term before)
    (actorIn : c.actor ∈ anchor)
    : c.pre.currentTerm = term
      /\ c.pre.primaryKnown = true
      /\ (c.pre.role = .follower \/ c.pre.role = .primary) := by
  obtain ⟨local_, now, termEq, known, role⟩ := base.settled _ actorIn
  have localEq : local_ = c.pre := c.now_pre now
  subst localEq
  exact ⟨termEq, known, role⟩

/-- A pre-vote candidate is outside the anchor. -/
theorem AnchorBase.pre_outside (base : AnchorBase participants anchor leader term before)
    (actorIn : c.actor ∈ participants) (preVote : c.pre.role = .preVoteCandidate)
    : c.actor ∈ participants \ anchor := by
  refine Finset.mem_sdiff.mpr ⟨actorIn, fun inAnchor => ?_⟩
  obtain ⟨_, _, role⟩ := AnchorBase.pre_settled c quiet base inAnchor
  rcases role with role | role <;> rw [role] at preVote <;> cases preVote

section Base

variable (base : AnchorBase participants anchor leader term before)
  (meets
    : c.actor ∈ participants
      -> forall voters,
          hasQuorum c.pre.activeConfigurations voters
          -> exists voter, voter ∈ voters /\ voter ∈ anchor)
  (ungranted
    : c.actor ∈ participants \ anchor -> c.pre.role = .preVoteCandidate
      -> c.pre.currentTerm = term
      -> forall source response,
          c.event = .receive source (.requestPreVoteResponse response)
          -> response.term = term
          -> response.voteGranted = true
          -> source ∉ anchor)
  (isolated
    : c.actor ∈ participants
      -> forall source message,
          c.event = .receive source message -> source ∈ participants)
  (timeout
    : c.actor ∈ anchor
      -> c.event = .internal (.timeout .election)
      -> c.pre.currentTerm < term)
  (proposed
    : c.actor ∈ participants
      -> forall source, Not (c.event = .receive source (.proposeRequestVoteRequest term)))

include base meets ungranted isolated timeout proposed

/-- A participant's term after its step stays within the term. -/
theorem AnchorBase.post_term (actorIn : c.actor ∈ participants)
    : c.post.currentTerm <= term := by
  have preLe := quiet.terms _ _ c.pre_now actorIn
  have step := LocalTransition.anchorStep c.tr
  rcases Summary.term_cause c.sum with le | ⟨eq, cause⟩ | ⟨source, message, eq, le⟩
  · omega
  · by_contra beyond
    have preTerm : c.pre.currentTerm = term := by omega
    have notRaised := QuietTerm.not_raised c quiet actorIn (isolated actorIn) preTerm
    have up : c.pre.currentTerm < c.post.currentTerm := by omega
    obtain ⟨fromTimeout, fromResponse⟩ := step.fresh up notRaised
    rcases cause with timeoutEq | ⟨source, response, eventEq, preVote⟩ | ⟨source, eventEq⟩
    · obtain ⟨voter, voterIn, inAnchor⟩ := meets actorIn _ (fromTimeout timeoutEq)
      rw [Finset.mem_singleton.mp voterIn] at inAnchor
      have := timeout inAnchor timeoutEq
      omega
    · obtain ⟨termEq, granted, quorum⟩ := fromResponse source response eventEq
      obtain ⟨voter, voterIn, inAnchor⟩ := meets actorIn _ quorum
      rcases Finset.mem_insert.mp voterIn with rfl | old
      · exact ungranted (AnchorBase.pre_outside c quiet base actorIn preVote) preVote preTerm
          _ _ eventEq (termEq.trans preTerm) granted inAnchor
      · exact Finset.disjoint_left.mp
          (base.notCounted _ _ c.pre_now actorIn preVote preTerm) old inAnchor
    · exact proposed actorIn source (preTerm ▸ eventEq)
  · obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
    have := quiet.messages envelope pending (sourceEq ▸ isolated actorIn _ _ eq)
      (targetEq ▸ actorIn)
    rw [payload] at this
    omega

/-- Only the primary can propose a vote in the term, and it does not. -/
theorem AnchorBase.no_proposal
    (nominate : c.actor = leader -> Not (c.event = .internal .nominateSuccessor))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    {envelope : Model.Envelope} (sent : envelope ∈ c.sent)
    : Not (envelope.payload = .proposeRequestVoteRequest term) := by
  intro payload
  obtain ⟨_, ok⟩ := Summary.sends c.sum envelope sent
  rw [payload] at ok
  obtain ⟨termEq, origin⟩ := ok
  obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
  have led := c.post_led (origin.imp (fun primary => ⟨primary.1, primary.2.1⟩) id)
  rw [← termEq] at led
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have same : c.actor = leader :=
    inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail)
  have actorIn : c.actor ∈ anchor := same ▸ base.leaderIn
  have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
  rcases origin with ⟨_, _, cause⟩ | wins
  · rcases cause with eventEq | retired'
    · exact nominate same eventEq
    · exact retired actorIn retired'
  · obtain ⟨candidate, campaign, _, _, postTerm, _⟩ := Wins.facts wins
    have bound := AnchorBase.post_term c quiet base meets ungranted isolated timeout proposed
      (base.subset actorIn)
    rcases campaign.2.2.2 with ⟨_, freshTerm, _⟩ | kept
    · have := lead.term
      rw [pre] at this
      omega
    · have := lead.primary
      rw [pre, kept.1] at this
      cases this

/-- A step keeps the term quiet among participants when every message a
participant receives comes from a participant and is no proposal for the term,
and no anchor node times out in the term, fails a quorum check or retires. -/
theorem AnchorBase.quiet_step
    (check : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    : QuietTerm participants leader term after := by
  have postLe : c.actor ∈ participants -> c.post.currentTerm <= term := fun actorIn =>
    AnchorBase.post_term c quiet base meets ungranted isolated timeout proposed actorIn
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have leaderIn : leader ∈ participants := base.subset base.leaderIn
  refine ⟨
    fun node local_ now nodeIn => ?_,
    fun envelope queued sourceIn targetIn => ?_,
    ?_
  ⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · exact postLe (same ▸ nodeIn)
    · exact quiet.terms _ _ old nodeIn
  · rcases c.tr.mem_network queued with old | new
    · exact quiet.messages envelope old sourceIn targetIn
    · obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
      have postLe := postLe (sourceEq ▸ sourceIn)
      have logLe := termAt_le_term inv c.post_now
      cases h : envelope.payload with
      | appendEntriesRequest request =>
          simp only [h] at ok
          have := ok.1.2.1
          simp only [Message.term]
          omega
      | appendEntriesResponse response =>
          simp only [h] at ok
          simp only [Message.term]
          rcases ok.1 with eq | ⟨index, eq⟩
          · omega
          · have := logLe index
            omega
      | requestVoteRequest request =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
      | requestVoteResponse response =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
      | requestPreVoteRequest request =>
          simp only [h, Message.term] at ok ⊢
          omega
      | requestPreVoteResponse response =>
          simp only [h, Message.term] at ok ⊢
          omega
      | proposeRequestVoteRequest proposed =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
  · obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
    by_cases same : c.actor = leader
    · have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
      have preTerm : c.pre.currentTerm = term := pre ▸ lead.term
      have prePrimary : c.pre.role = .primary := pre ▸ lead.primary
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        have := c.term_le
        have := postLe (same ▸ leaderIn)
        omega
      have actorIn : c.actor ∈ anchor := same ▸ base.leaderIn
      refine ⟨c.post, same ▸ c.post_now, ?_, termEq.trans preTerm⟩
      rcases Summary.role_keep c.sum prePrimary termEq with primary | retired' | eventEq
          | ⟨source, request, eventEq, requestTerm⟩
      · exact primary
      · exact (retired actorIn retired').elim
      · exact (check actorIn eventEq).elim
      · obtain ⟨envelope, pending, _, target, payload⟩ := c.received eventEq
        have := (lead.request pending payload (requestTerm.trans preTerm)).2.1
        exact (this (target.trans same)).elim
    · exact ⟨local_, c.now_other (Ne.symm same) lead.now, lead.primary, lead.term⟩

/-- A step keeps the anchor base under the hypotheses of `AnchorBase.quiet_step`,
when the primary appends no configuration. -/
theorem AnchorBase.step
    (check : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    : AnchorBase participants anchor leader term after := by
  have actorStep := LocalTransition.anchorStep c.tr
  have postLe : c.actor ∈ participants -> c.post.currentTerm <= term := fun actorIn =>
    AnchorBase.post_term c quiet base meets ungranted isolated timeout proposed actorIn
  have leaderIn : leader ∈ participants := base.subset base.leaderIn
  have history : c.actor = leader
      -> configurationHistory c.post.log = configurationHistory c.pre.log := fun same =>
    QuietTerm.history_keep c quiet leaderIn same (isolated (same ▸ leaderIn)) plain
  have preLeader : c.actor = leader -> (leader, c.pre) ∈ before.nodes := fun same => by
    rw [← same]
    exact c.pre_now
  refine ⟨base.subset, base.leaderIn, fun local_ now => ?_,
    fun local_ now node nodeIn different => ?_, fun node nodeIn => ?_,
    fun node local_ now nodeIn preVote termEq => ?_⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · exact quorum_of_commit (history same.symm)
        (CCFRaft.Proofs.Direct.extends_step c.tr.ran).1
        (base.quorum _ (preLeader same.symm))
    · exact base.quorum _ old
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have member := base.members _ (preLeader same.symm) node nodeIn different
      unfold NodeState.activeConfigurations at member ⊢
      rw [latest_active] at member ⊢
      rwa [history same.symm]
    · exact base.members _ old node nodeIn different
  · obtain ⟨local_, now, termEq, known, role⟩ := base.settled node nodeIn
    by_cases same : node = c.actor
    · rw [same] at nodeIn now ⊢
      have actorIn : c.actor ∈ participants := base.subset nodeIn
      have localEq : local_ = c.pre := c.now_pre now
      subst localEq
      have notRaised := QuietTerm.not_raised c quiet actorIn (isolated actorIn) termEq
      have postTerm : c.post.currentTerm = term := by
        have := c.term_le
        have := postLe actorIn
        omega
      refine ⟨c.post, c.post_now, postTerm, ?_⟩
      rcases actorStep.keep known role with latched | exempt
      · rcases latched with ⟨roleEq, knownEq⟩ | retired'
        · exact ⟨knownEq.trans known, roleEq ▸ role⟩
        · exact (retired nodeIn retired').elim
      · rcases exempt with eventEq | eventEq | up | ⟨source, eventEq⟩
        · have := timeout nodeIn eventEq
          omega
        · exact (check nodeIn eventEq).elim
        · exact (notRaised up).elim
        · exact (proposed actorIn source (termEq ▸ eventEq)).elim
    · exact ⟨local_, c.now_other same now, termEq, known, role⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have actorIn : c.actor ∈ participants := same ▸ nodeIn
      obtain ⟨keptTerm, cause⟩ := Summary.pre_vote c.sum preVote
      have preTerm : c.pre.currentTerm = term := keptTerm.symm.trans termEq
      refine Finset.disjoint_left.mpr fun voter voterIn inAnchor => ?_
      rcases actorStep.counts voter voterIn with ⟨eventEq, rfl⟩ | ⟨notTimeout, old⟩
          | ⟨response, eventEq, responseTerm, granted⟩
      · have := timeout inAnchor eventEq
        omega
      · rcases cause with prePreVote | eventEq
        · exact Finset.disjoint_left.mp
            (base.notCounted _ _ c.pre_now actorIn prePreVote preTerm) old inAnchor
        · exact notTimeout eventEq
      · rcases cause with prePreVote | eventEq'
        · exact ungranted (AnchorBase.pre_outside c quiet base actorIn prePreVote) prePreVote
            preTerm _ _ eventEq (responseTerm.trans preTerm) granted inAnchor
        · cases eventEq'.symm.trans eventEq
    · exact base.notCounted _ _ old nodeIn preVote termEq

end Base

end Step

end CCFRaft.Proofs.Leadership
