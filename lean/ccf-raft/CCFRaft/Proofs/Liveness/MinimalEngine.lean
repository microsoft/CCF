module

public import CCFRaft.Proofs.Liveness.MinimalAcks
public import CCFRaft.Proofs.Liveness.MinimalSynced

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# An anchor engine from a minimal start

From a minimal start the term stays anchored by the primary and its configuration.
Every node stays in the term with a plain extension of the primary's starting log,
so every quorum a node can count includes a member of the latest configuration,
and no anchor node retires. No pre-vote candidate appears until half an election
timeout after the start, by which time every grant sent before the start has been
delivered, and an anchor node sends none afterwards. The primary hears from every
anchor node often enough that its quorum checks never step it down.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Leadership
open CCFRaft.Proofs.StablePrimary (Acts)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- A quorum of configurations meets every superset of the latest one. -/
theorem meets_of_latest {configurations : List Configuration}
    {voters anchor : Finset NodeID} (quorum : hasQuorum configurations voters)
    (latest : latestConfigurationMembers configurations ⊆ anchor)
    : exists voter, voter ∈ voters /\ voter ∈ anchor := by
  cases lastEq : configurations.getLast? with
  | none => exact absurd (List.getLast?_eq_none_iff.mp lastEq) quorum.1
  | some last =>
      have majority := hasQuorum_majority quorum (List.mem_of_getLast? lastEq)
      unfold hasConfigurationMajority at majority
      obtain ⟨voter, inter⟩ : (voters ∩ last.nodes).Nonempty := by
        rw [← Finset.card_pos]
        omega
      obtain ⟨inVoters, inNodes⟩ := Finset.mem_inter.mp inter
      refine ⟨voter, inVoters, latest ?_⟩
      simp only [latestConfigurationMembers, lastEq, Option.map_some, Option.getD_some]
      exact inNodes

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- No node is a pre-vote candidate before `since`. -/
def PreVotesLate (since : Real) (point : W) : Prop :=
  forall node local_,
    (node, local_) ∈ (proto point).nodes
    -> local_.role = .preVoteCandidate
    -> since <= time point

/-- The invariant of a minimal start: the anchor invariant, every node in the term
with a plain extension of `base`, and no pre-vote candidate before `since`. -/
structure MinInv (participants anchor : Finset NodeID) (leader : NodeID) (term : Nat)
    (base : List Entry) (since : Real) (point : W)
    : Prop where
  inv : AnchorBaseInv participants anchor leader term (proto point)
  proposals : NoProposals participants term point
  synced : Synced base term (proto point)
  late : PreVotesLate since point

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- A pre-vote candidate outside the anchor receives no granted pre-vote from it,
if no pre-vote candidate appears until more than a delay after the start: a grant
sent before the start has been delivered by then, and an anchor node sends none
from the start while the anchor invariant holds. -/
theorem ungranted_of_late {maxDelay fresh : Real}
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (quick : maxDelay < fresh)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (good : GoodBase trace start duration participants) {first : W}
    (firstFound : trace.stateAt start = some first) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (within : Within trace start duration index)
    (invariant
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> AnchorBaseInv participants anchor leader term (proto point))
    (late : PreVotesLate (time first + fresh) step.before) {action : Model.Action}
    (selected : step.action.action = some action) {rest : History}
    (c : Ctx nodes (proto step.after) (proto step.before) rest)
    (acts : Acts action c.tr.actor c.tr.event)
    : c.actor ∈ participants \ anchor
      -> c.pre.role = .preVoteCandidate
      -> c.pre.currentTerm = term
      -> forall source response,
          c.event = .receive source (.requestPreVoteResponse response)
          -> response.term = term
          -> response.voteGranted = true
          -> source ∉ anchor := by
  intro actorIn preVote _ source response eventEq _ granted sourceIn
  have indexFound := Trace.stateAt_of_stepAt stepped
  have pastFresh := late c.actor c.pre c.pre_now preVote
  cases action with
  | «local» node input =>
      obtain ⟨_, eventEq'⟩ := acts
      cases eventEq'.symm.trans eventEq
  | deliver envelope =>
      obtain ⟨actorEq, eventEq'⟩ := acts
      obtain ⟨sourceEq, payloadEq⟩ :=
        Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
      obtain ⟨packet, actionEq, rfl⟩
          : exists packet, step.action = .deliver packet /\ packet.envelope = envelope := by
        cases h : step.action <;> simp_all [Liveness.Event.action]
      have consumed : step.action.consumedPacket = some packet := by
        rw [actionEq]
        rfl
      obtain ⟨sent, sentLt, sentAt⟩ := admissible.consumed_sent stepped consumed
      obtain ⟨sender, _, emitted, senderStepped, senderSelected, out, member, _, _, sentTime⟩ :=
        admissible.sentAt_emitted sentAt
      by_cases early : sent < start
      · have targetLive : packet.envelope.target ∈ live step.before :=
          good.participantsLive index step.before _ within indexFound
            (by rw [← actorEq]; exact (Finset.mem_sdiff.mp actorIn).1)
        have deadline :=
          pending_deadline bounded indexFound (admissible.consumed_pending stepped consumed)
            targetLive
        have := admissible.time_le early.le (Trace.stateAt_of_stepAt senderStepped) firstFound
        rw [sentTime] at deadline
        linarith
      · push Not at early
        obtain ⟨_, c', acts', out'⟩ := ctx_at admissible senderStepped senderSelected
        rw [out, Option.some.injEq] at out'
        rw [out'] at member
        obtain ⟨sourceIs, _⟩ := Summary.sends c'.sum packet.envelope member
        have actorIn' : c'.actor ∈ anchor := by
          rw [← sourceIs, sourceEq]
          exact sourceIn
        have inv' :=
          invariant sent sender.before early sentLt.le (Trace.stateAt_of_stepAt senderStepped)
        obtain ⟨preTerm, known, _⟩ :=
          AnchorBase.pre_settled c' inv'.quiet inv'.anchored actorIn'
        have within' := within_of_le admissible within indexFound early sentLt.le
        rcases (LocalTransition.anchorStep c'.tr).grants packet.envelope member response
            payloadEq granted with unknown | up
        · rw [known] at unknown
          cases unknown
        · exact QuietTerm.not_raised c' inv'.quiet (inv'.anchored.subset actorIn')
            (ctx_isolated admissible good within' senderStepped senderSelected c' acts'
              (inv'.anchored.subset actorIn'))
            preTerm up

/-- From a minimal start, `MinInv` holds at every recorded state of a good period
below any bound, provided no anchor node other than the primary times out in the
term at least `fresh` after the start while the anchor invariant has held so far. -/
theorem minimal_invariant {interval timeout maxDelay fresh : Real}
    (diverges : TimeDiverges trace)
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some interval))
    (scheduling : CheckQuorumScheduling trace timeout)
    (ratio : 12 * maxDelay + 8 * max interval 0 < timeout) (quick : maxDelay < fresh)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID} {base : List Entry}
    (good : GoodBase trace start duration participants)
    (listed : forall node, node ∈ nodes -> node ∈ participants)
    (behind : BacklogTerms trace start leader anchor 0)
    (latest : latestConfigurationMembers (configurationHistory base) ⊆ anchor)
    (never : forall node, node ∈ anchor -> retirementIndexInLog node base = none)
    {first : W} (firstFound : trace.stateAt start = some first)
    (initial : MinInv participants anchor leader term base (time first + fresh) first)
    (startAcks
      : forall peer,
          peer ∈ anchor
          -> Not (peer = leader)
          -> AckedAfter trace start leader peer (time first - interval))
    (late
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> Not (node = leader)
          -> time first + fresh <= time step.before)
    {bound : Nat}
    (noLateTimeout
      : forall index step node state first,
          start <= index
          -> index < bound
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> nodeState (proto step.before) node = some state
          -> node ∈ anchor
          -> Not (node = leader)
          -> state.currentTerm = term
          -> trace.stateAt start = some first
          -> time first + fresh <= time step.before
          -> (forall earlier point,
                start <= earlier
                -> earlier <= index
                -> trace.stateAt earlier = some point
                -> AnchorBaseInv participants anchor leader term (proto point)
                    /\ NoProposals participants term point)
          -> False)
    : forall index point,
        index <= bound
        -> Within trace start duration index
        -> trace.stateAt index = some point
        -> MinInv participants anchor leader term base (time first + fresh) point := by
  have subset := initial.inv.anchored.subset
  have leaderIn := initial.inv.anchored.leaderIn
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      intro point inBound within recorded
      by_cases atStart : index = start
      · subst index
        rw [firstFound, Option.some.injEq] at recorded
        subst recorded
        exact initial
      rcases index with _ | index
      · exact absurd (Nat.le_zero.mp within.1) (Ne.symm atStart)
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp recorded
      have afterStart : start <= index := by have := within.1; omega
      have indexFound := Trace.stateAt_of_stepAt stepped
      have windowed
          : forall earlier, start <= earlier -> earlier <= index
              -> Within trace start duration earlier :=
        fun earlier after le => within_of_le admissible within recorded after (by omega)
      have earlier_
          : forall earlier point,
              start <= earlier
              -> earlier <= index
              -> trace.stateAt earlier = some point
              -> MinInv participants anchor leader term base (time first + fresh) point :=
        fun earlier point after le found =>
          ih earlier (by omega) point (by omega) (windowed earlier after le) found
      have projected
          : forall earlier point,
              start <= earlier
              -> earlier <= index
              -> trace.stateAt earlier = some point
              -> AnchorBaseInv participants anchor leader term (proto point)
                  /\ NoProposals participants term point :=
        fun earlier point after le found =>
          ⟨(earlier_ earlier point after le found).inv,
            (earlier_ earlier point after le found).proposals⟩
      have indexWithin := windowed index afterStart le_rfl
      have now := earlier_ index step.before afterStart le_rfl indexFound
      have advances : time step.before <= time step.after := (admissible.timing.next stepped).1
      rcases selected : step.action.action with _ | action
      · have stutter := admissible.stutter stepped selected
        refine ⟨by rw [stutter]; exact now.inv,
          NoProposals.stutter admissible stepped selected now.proposals,
          by rw [stutter]; exact now.synced, fun node local_ member role => ?_⟩
        rw [stutter] at member
        exact (now.late node local_ member role).trans advances
      obtain ⟨rest, c, acts, out⟩ := ctx_at admissible stepped selected
      have local_ : forall input, c.event = .internal input
          -> step.action = .local c.actor input :=
        fun _ eventEq => anchor_local_of_internal selected acts eventEq
      have actorIn : c.actor ∈ participants :=
        listed _ (listed_of_mem admissible indexFound c.pre_now)
      have isolated := ctx_isolated admissible good indexWithin stepped selected c acts
      have plain := ctx_plain admissible good indexWithin stepped selected c acts
      have notLeader : c.event = .internal (.timeout .election) -> Not (c.actor = leader) := by
        intro eventEq same
        obtain ⟨leaderLocal, lead⟩ := QuietTerm.lead c now.inv.quiet
        have now' : Now (proto step.before :: rest) c.actor leaderLocal := by
          rw [same]
          exact lead.now
        have primary := lead.primary
        rw [c.now_pre now'] at primary
        exact (LocalTransition.anchorStep c.tr).timeout eventEq primary
      have meets
          : c.actor ∈ participants
            -> forall voters,
                hasQuorum c.pre.activeConfigurations voters
                -> exists voter, voter ∈ voters /\ voter ∈ anchor := by
        intro _ voters quorum
        refine meets_of_latest quorum ?_
        unfold NodeState.activeConfigurations
        rw [latest_active, (now.synced _ _ c.pre_now).2.history]
        exact latest
      have ungranted :=
        ungranted_of_late admissible bounded quick good firstFound stepped indexWithin
          (fun earlier point after le found => (earlier_ earlier point after le found).inv)
          now.late selected c acts
      have timeout
          : c.actor ∈ anchor
            -> c.event = .internal (.timeout .election)
            -> c.pre.currentTerm < term := by
        intro actorIn' eventEq
        exfalso
        obtain ⟨preTerm, _, _⟩ :=
          AnchorBase.pre_settled c now.inv.quiet now.inv.anchored actorIn'
        exact noLateTimeout index step c.actor c.pre first afterStart (by omega) indexWithin
          stepped (local_ _ eventEq) c.tr.found actorIn' (notLeader eventEq) preTerm
          firstFound
          (late index step c.actor afterStart stepped (local_ _ eventEq) (notLeader eventEq))
          projected
      have proposed
          : c.actor ∈ participants
            -> forall source, Not (c.event = .receive source (.proposeRequestVoteRequest term)) :=
        fun actorIn source eventEq =>
          NoProposals.not_received admissible stepped selected acts now.proposals actorIn
            eventEq (isolated actorIn _ _ eventEq)
      have check
          : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)) := by
        intro actorIn' eventEq
        have ran : (checkQuorum c.tr.pre c.tr.actor).run {} = some (c.tr.post, c.tr.outputs) := by
          have ran := c.tr.ran
          have eventEq' : c.tr.event = .internal (.timeout .checkQuorum) := eventEq
          rw [eventEq'] at ran
          exact ran
        obtain ⟨_, _, primary⟩ := checkQuorum_guard c.tr.actor c.tr.pre {} _ _ ran
        obtain ⟨_, lead⟩ := QuietTerm.lead c now.inv.quiet
        obtain ⟨preTerm, _, _⟩ :=
          AnchorBase.pre_settled c now.inv.quiet now.inv.anchored actorIn'
        have led := c.inv.leader_led c.actor c.pre c.pre_now primary
        rw [preTerm] at led
        have same : c.actor = leader := lead.unique led
        exact no_check_quorum admissible diverges bounded nonneg heartbeats scheduling ratio
          good behind subset leaderIn firstFound startAcks stepped afterStart indexWithin
          projected (by rw [← same]; exact local_ _ eventEq)
      have terms
          : forall node local_,
              (node, local_) ∈ (proto step.after).nodes -> local_.currentTerm <= term := by
        intro node local_ member
        rcases c.now_after member with ⟨_, rfl⟩ | ⟨_, old⟩
        · exact AnchorBase.post_term c now.inv.quiet now.inv.anchored meets ungranted isolated
            timeout proposed actorIn
        · exact (now.synced node local_ old).1.le
      have synced :=
        Synced.step admissible good indexWithin (subset leaderIn) stepped now.inv.quiet terms
          now.synced
      have retained
          : forall node local_,
              (node, local_) ∈ (proto step.after).nodes
              -> node ∈ anchor
              -> Not (local_.isRetiredCommitted node) :=
        fun node local_ member nodeIn =>
          not_retired_of_history (synced node local_ member).2.history (never node nodeIn)
      have retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor) :=
        fun actorIn' => retained _ _ c.post_now actorIn'
      refine ⟨
        ⟨
          AnchorBase.quiet_step c now.inv.quiet now.inv.anchored meets ungranted isolated
            timeout proposed check retired,
          AnchorBase.step c now.inv.quiet now.inv.anchored meets ungranted isolated
            timeout proposed check retired plain,
          retained
        ⟩,
        NoProposals.after_sent admissible stepped selected out now.proposals
          fun _ sent _ _ =>
            AnchorBase.no_proposal c now.inv.quiet now.inv.anchored meets ungranted
              isolated timeout proposed
              (fun same eventEq =>
                good.noNominations index step leader indexWithin stepped
                  (by rw [← same]; exact local_ _ eventEq))
              retired sent,
        synced,
        fun node local_ member role => ?_
      ⟩
      rcases c.now_after member with ⟨_, rfl⟩ | ⟨_, old⟩
      · obtain ⟨_, cause⟩ := Summary.pre_vote c.sum role
        rcases cause with preVote | eventEq
        · exact (now.late _ _ c.pre_now preVote).trans advances
        · exact (late index step c.actor afterStart stepped (local_ _ eventEq)
            (notLeader eventEq)).trans advances
      · exact (now.late node local_ old role).trans advances

/-- From a minimal start the anchor is an engine for `fresh`, under the hypotheses
of `minimal_invariant`. -/
theorem minimal_engine {interval timeout maxDelay fresh : Real}
    (diverges : TimeDiverges trace)
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some interval))
    (scheduling : CheckQuorumScheduling trace timeout)
    (ratio : 12 * maxDelay + 8 * max interval 0 < timeout) (quick : maxDelay < fresh)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID} {base : List Entry}
    (good : GoodBase trace start duration participants)
    (listed : forall node, node ∈ nodes -> node ∈ participants)
    (behind : BacklogTerms trace start leader anchor 0)
    (latest : latestConfigurationMembers (configurationHistory base) ⊆ anchor)
    (never : forall node, node ∈ anchor -> retirementIndexInLog node base = none)
    {first : W} (firstFound : trace.stateAt start = some first)
    (initial : MinInv participants anchor leader term base (time first + fresh) first)
    (startAcks
      : forall peer,
          peer ∈ anchor
          -> Not (peer = leader)
          -> AckedAfter trace start leader peer (time first - interval))
    (late
      : forall index step node,
          start <= index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> Not (node = leader)
          -> time first + fresh <= time step.before)
    : AnchorEngine trace start duration leader term participants anchor fresh := by
  refine ⟨initial.inv.anchored.subset, initial.inv.anchored.leaderIn,
    fun bound noLateTimeout index point le within found => ?_⟩
  have inv :=
    minimal_invariant admissible diverges bounded nonneg heartbeats scheduling ratio quick
      good listed behind latest never firstFound initial startAcks late noLateTimeout index
      point le within found
  exact ⟨inv.inv, inv.proposals⟩

end CCFRaft.Proofs.Liveness
