module

public import CCFRaft.Proofs.Leadership.AnchorWindow
public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.Timers
public import CCFRaft.Proofs.Replication.Run
public import CCFRaft.Proofs.Timed.Acks
public import CCFRaft.Proofs.Timed.Window

@[expose] public section

/-!
# A stable window while participants catch up

`stable_window_catchup_engine` derives a stable window over the anchor from an
anchor engine, given a bound on how far participants' logs diverge from the
primary's at the start (`BacklogTerms`). A lagging participant rejects
AppendEntries, and a rejection does not reset its election timer. Timer resets
come instead from acknowledgements: a participant sends a successful
AppendEntries response only from a step that accepts a request, and accepting
passes the log check, which resets its timer (`reset_of_ack`). The primary's
repair of a participant whose unagreed suffix spans at most `backlog` terms ends
in such an acknowledgement within `repair maxDelay heartbeatInterval backlog`, so
every participant's timer is reset within `repair + heartbeatInterval + maxDelay`
of every point of the window (`acks_before_timeout`), and `recent_reset` rules
out timeouts while the freshness exceeds that gap.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.Timed (
  Env clock cut peer_acks ackBound env_of_window window_end stable_cut participant_term
    cut_sentAt stepAt_of_cut stateAt_of_cut cut_stateAt_of_le cut_nodeAt clock_eq
    agreedPrefix_eq
  )

/-- The time within which a participant acknowledges at least the primary's log
at a given point, if the primary's log beyond their common prefix spanned at most
`backlog` terms at the start of the window: a few delays and heartbeat intervals
for stale traffic to drain, and two rounds of rejection and retry per such term,
plus two for the primary's own new entries. -/
def repair (delay interval : Real) (backlog : Nat) : Real :=
  6 * delay + 4 * interval + 2 * ((backlog : Real) + 1) * (2 * delay + interval)

theorem repair_eq (delay interval : Real) (backlog : Nat)
    : repair delay interval backlog = ackBound delay interval backlog := by
  unfold repair ackBound
  push_cast
  ring

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

omit [HasProtocol W Model.State] [HasTime W] [HasLive W] in
/-- If the peer acknowledges within `bound` of every point, then within
`delay + interval + bound` after every point it sends a successful acknowledgement.
The primary passes within `interval` of a delay after the point, and the
acknowledgement delivered after that pass was sent after the point, because
delivery takes at most `delay`. The trace and its clock are abstract so that this
applies to a cut of a recording. -/
theorem ack_sent_within {trace : Trace W Liveness.Event} {clock : Nat -> Real}
    {start last : Nat} {stop delay interval bound : Real} {peer receiver : NodeID}
    (mono
      : forall index later, index <= later -> later <= last -> clock index <= clock later)
    (ends : forall index step, trace.stepAt index = some step -> index < last)
    (prompt
      : forall index step packet sent,
          trace.stepAt index = some step
          -> step.action = .deliver packet
          -> SentAt trace sent packet
          -> clock index <= clock sent + delay)
    (sentOf
      : forall index step packet,
          trace.stepAt index = some step
          -> step.action = .deliver packet
          -> exists sent, sent < index /\ SentAt trace sent packet)
    (passes
      : forall moment : Real,
          clock start <= moment
          -> moment + interval <= stop
          -> exists index step,
              start <= index
              /\ moment < clock index
              /\ clock index <= moment + interval
              /\ trace.stepAt index = some step)
    (acks
      : forall base,
          start <= base
          -> base <= last
          -> clock base + bound <= stop
          -> exists later step reply response,
              base < later
              /\ clock later <= clock base + bound
              /\ trace.stepAt later = some step
              /\ step.action = .deliver reply
              /\ reply.envelope.source = peer
              /\ reply.envelope.target = receiver
              /\ reply.envelope.payload = .appendEntriesResponse response
              /\ response.success = true)
    (delayNonneg : 0 <= delay) (boundNonneg : 0 <= bound) {index : Nat}
    (startLe : start <= index) (indexLe : index <= last)
    (timely : clock index + (delay + interval + bound) <= stop)
    : exists sent reply response,
        index < sent
        /\ clock sent <= clock index + (delay + interval + bound)
        /\ SentAt trace sent reply
        /\ reply.envelope.source = peer
        /\ reply.envelope.target = receiver
        /\ reply.envelope.payload = .appendEntriesResponse response
        /\ response.success = true := by
  have startClock := mono start index startLe indexLe
  obtain ⟨base, baseStep, baseStart, baseAfter, baseBefore, baseStepped⟩ :=
    passes (clock index + delay) (by linarith) (by linarith)
  have baseLt := ends base baseStep baseStepped
  obtain ⟨later, step, reply, response, after, laterClock, stepped, delivers, source, target,
      payload, success⟩ := acks base baseStart baseLt.le (by linarith)
  have laterLt := ends later step stepped
  obtain ⟨sent, sentLt, sentAt⟩ := sentOf later step reply stepped delivers
  have arrival := prompt later step reply sent stepped delivers sentAt
  have baseLe := mono base later after.le laterLt.le
  have sentLe := mono sent later sentLt.le laterLt.le
  have indexLt : index < sent := by
    by_contra early
    have := mono sent index (by omega) indexLe
    linarith
  exact ⟨
    sent,
    reply,
    response,
    indexLt,
    by linarith,
    sentAt,
    source,
    target,
    payload,
    success
  ⟩

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- The step that sends a successful AppendEntries response resets its sender's
election timer: it accepts a request, which passes the log check. -/
theorem reset_of_ack {index : Nat} {packet : Packet} (sent : SentAt trace index packet)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (success : response.success = true)
    : exists step,
        trace.stepAt index = some step /\ ElectionReset step packet.envelope.source := by
  obtain ⟨step, action, actor, event, state, next, outputs, stepped, selected, acts, found, ran,
      _, member, source⟩ := sent_step admissible sent
  obtain ⟨_, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
  have facts : Summary actor state event next outputs.outgoing := by simpa [eq] using holds
  have ok := (Summary.sends facts _ member).2
  rw [payload] at ok
  obtain ⟨requester, request, eventEq, accepted, _, _⟩ := ok.2 success
  obtain ⟨_, termLe, _, _, check, _⟩ := accepted
  refine ⟨step, stepped, ?_⟩
  cases action with
  | «local» node input =>
      obtain ⟨_, internal⟩ := acts
      rw [internal] at eventEq
      cases eventEq
  | deliver envelope =>
      obtain ⟨actorEq, received⟩ := acts
      rw [received] at eventEq
      obtain ⟨_, payloadEq⟩ := Model.Node.Event.receive.inj eventEq
      cases delivered : step.action with
      | deliver delivered' =>
          rw [delivered] at selected
          simp only [Liveness.Event.action, Option.some.injEq] at selected
          injection selected with selected
          rw [ElectionReset, delivered]
          refine ⟨by rw [selected, ← actorEq, source], ?_⟩
          rw [show nodeState (proto step.before) packet.envelope.source = some state by
            rw [source]; exact found]
          refine Or.inr ?_
          rw [selected, payloadEq]
          rcases Nat.lt_or_ge state.currentTerm request.term with lt | ge
          · exact Or.inl lt
          · exact Or.inr ⟨by omega, Or.inr (Or.inr check)⟩
      | _ => simp [delivered, Liveness.Event.action] at selected

/-- A node that sends a successful acknowledgement within `gap` after every early
enough point of the window does not time out at least `fresh` after the start,
where `fresh` exceeds `gap` and is at most half an election timeout. -/
theorem no_timeout_of_acks {bounds : Bounds} {receiver : NodeID}
    (elections : ElectionSpacing trace (some (bounds.electionTimeout / 2)))
    {gap fresh : Real} (ratio : gap < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2) {start index : Nat}
    {step : CCF.Execution.Step W Liveness.Event} {node : NodeID}
    (afterStart : start <= index) (stepped : trace.stepAt index = some step)
    (event : step.action = .local node (.timeout .election)) {first : W}
    (firstFound : trace.stateAt start = some first)
    (late : time first + fresh <= time step.before)
    (acks
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> time point + gap < time step.before
          -> exists sent sender reply response,
              earlier < sent
              /\ trace.stepAt sent = some sender
              /\ time sender.before <= time point + gap
              /\ SentAt trace sent reply
              /\ reply.envelope.source = node
              /\ reply.envelope.target = receiver
              /\ reply.envelope.payload = .appendEntriesResponse response
              /\ response.success = true)
    : False := by
  obtain ⟨reset, resetPoint, _, before, resetFound, recent, resetStep, resetStepped, isReset⟩ :=
    recent_reset
      (fun _ _ _ _ le firstFound lastFound => admissible.time_le le firstFound lastFound)
      ratio afterStart firstFound (Trace.stateAt_of_stepAt stepped) late
      (reset := fun later =>
        exists reset, trace.stepAt later = some reset /\ ElectionReset reset node)
      (fun earlier point after le recorded early => by
        obtain ⟨sent, sender, reply, response, after, senderStepped, inTime, sentAt, source, _,
            payload, success⟩ := acks earlier point after le recorded early
        obtain ⟨reset, resetStepped, isReset⟩ := reset_of_ack admissible sentAt payload success
        rw [senderStepped, Option.some.injEq] at resetStepped
        subst reset
        exact ⟨sent, sender.before, after, Trace.stateAt_of_stepAt senderStepped, inTime,
          sender, senderStepped, source ▸ isReset⟩)
  have := elections reset index resetStep step node before resetStepped stepped event isReset
  rw [Trace.stateAt_of_stepAt resetStepped, Option.some.injEq] at resetFound
  rw [← resetFound] at recent
  linarith

/-- A node of `peers` that acknowledges the primary within `ackBound` sends a
successful acknowledgement within `maxDelay + interval + ackBound` after every
point before its timeout. The window is cut strictly before the timeout, where the
facts about the prefix give a stable window over `peers` for `peer_acks`. -/
theorem acks_before_timeout {heartbeatInterval maxDelay : Real}
    (diverges : TimeDiverges trace)
    (bounded : Satisfies trace (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some heartbeatInterval))
    {start : Nat} {duration : Real} {leader node : NodeID} {term backlog : Nat}
    {participants peers : Finset NodeID}
    (good : GoodBase trace start duration participants)
    (behind : BacklogTerms trace start leader peers backlog)
    (subset : peers ⊆ participants)
    (leaderIn : leader ∈ peers) (nodeIn : node ∈ peers)
    (different : Not (node = leader))
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (within : Within trace start duration index)
    {first : W} (firstFound : trace.stateAt start = some first)
    (quiet
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> QuietAmong peers leader term (proto point) /\ NoProposals peers term point)
    (quorum
      : forall earlier point state,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> nodeState (proto point) leader = some state
          -> hasQuorum state.activeConfigurations (Inter.inter (live point) peers))
    (tracked
      : forall earlier point state,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> nodeState (proto point) leader = some state
          -> node ∈ eligiblePeers state leader)
    (current
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> exists state,
              nodeState (proto point) node = some state /\ state.currentTerm = term)
    (retains
      : forall earlier point state,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> nodeState (proto point) leader = some state
          -> Not (state.isRetiredCommitted leader))
    : forall earlier point,
        start <= earlier
        -> earlier <= index
        -> trace.stateAt earlier = some point
        -> time point
              + (maxDelay
                  + max heartbeatInterval 0
                  + ackBound maxDelay (max heartbeatInterval 0) backlog)
            < time step.before
        -> exists sent sender reply response,
            earlier < sent
            /\ trace.stepAt sent = some sender
            /\ time sender.before
                <= time point
                    + (maxDelay
                        + max heartbeatInterval 0
                        + ackBound maxDelay (max heartbeatInterval 0) backlog)
            /\ SentAt trace sent reply
            /\ reply.envelope.source = node
            /\ reply.envelope.target = leader
            /\ reply.envelope.payload = .appendEntriesResponse response
            /\ response.success = true := by
  intro earlier point afterStart le recorded early
  set interval := max heartbeatInterval 0 with intervalEq
  have intervalNonneg : 0 <= interval := le_max_right _ _
  set bound := ackBound maxDelay interval backlog with boundEq
  have boundNonneg : 0 <= bound := by
    rw [boundEq]; unfold ackBound; positivity
  set gap := maxDelay + interval + bound with gapEq
  have indexFound := Trace.stateAt_of_stepAt stepped
  set stop := (time point + gap + time step.before) / 2 with stopEq
  have firstLe := admissible.time_le afterStart firstFound recorded
  set duration' := stop - time first with durationEq
  have durationNonneg : 0 <= duration' := by rw [durationEq, stopEq]; linarith
  -- A state of the shorter window precedes the timeout.
  have below : forall moment point', Within trace start duration' moment
      -> trace.stateAt moment = some point' -> moment < index := by
    intro moment point' inside found
    have := inside.2 first point' firstFound found
    by_contra late
    have := admissible.time_le (Nat.le_of_not_lt late) indexFound found
    rw [durationEq, stopEq] at *
    linarith
  have widen : forall moment point', Within trace start duration' moment
      -> trace.stateAt moment = some point' -> Within trace start duration moment :=
    fun moment point' inside found =>
      within_of_le admissible within indexFound inside.1 (below moment point' inside found).le
  have window : StableWindow trace start duration' leader term peers := {
    stableLeader := fun moment point' inside found =>
      quiet moment point' inside.1 (below moment point' inside found).le found
    staysActive := ⟨
      fun moment point' inside found =>
        good.participantsLive moment point' leader (widen _ _ inside found) found
          (subset leaderIn),
      fun moment point' state inside found nodeFound =>
        retains moment point' state inside.1 (below moment point' inside found).le found
          nodeFound⟩
    liveQuorum := fun moment point' state inside found leaderFound =>
      quorum moment point' state inside.1 (below moment point' inside found).le found
        leaderFound
    lossless := fun moment step' packet inside stepped' dropped => by
      have inside' := widen _ _ inside (Trace.stateAt_of_stepAt stepped')
      rintro (⟨source, target⟩ | ⟨source, target⟩)
      · exact good.lossless moment step' packet inside' stepped' dropped
          ⟨source ▸ subset leaderIn, subset target⟩
      · exact good.lossless moment step' packet inside' stepped' dropped
          ⟨subset source, target ▸ subset leaderIn⟩
  }
  have gapNonneg : 0 <= gap := by rw [gapEq]; linarith
  obtain ⟨last, lastPoint, startLe, lastFound, inside, beyond⟩ :=
    window_end admissible.timing diverges durationNonneg firstFound
  have earlierLe : earlier <= last := by
    by_contra late
    have := beyond earlier point (by omega) recorded
    rw [durationEq, stopEq] at this
    linarith
  have stable :=
    stable_cut admissible window.stableLeader window.staysActive startLe inside firstFound
  have eligibleAt : forall moment state, start <= moment -> moment <= last
      -> nodeAt trace moment leader = some state -> node ∈ eligiblePeers state leader := by
    intro moment state after le' found
    obtain ⟨point', pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
    have lastBelow := below last lastPoint (inside last startLe le_rfl) lastFound
    exact tracked moment point' state after (by omega) pointFound nodeFound
  have env :=
    env_of_window admissible bounded diverges heartbeats durationNonneg window firstFound startLe
      lastFound inside beyond nodeIn
      (good.participantsLive last lastPoint node (widen _ _ (inside last startLe le_rfl) lastFound)
        lastFound (subset nodeIn))
      eligibleAt
  have cutAdmissible := Proofs.Timed.Admissible.cut admissible last
  have acks := fun base (startLe' : start <= base) (baseLe : base <= last) timely =>
    peer_acks cutAdmissible stable different env
      (fun moment point' after le' found => by
        obtain ⟨le'', found⟩ := stateAt_of_cut found
        have lastBelow := below last lastPoint (inside last startLe le_rfl) lastFound
        exact current moment point' after (by omega) found)
      (fun moment state after found => by
        obtain ⟨le', found'⟩ := cut_nodeAt found
        exact eligibleAt moment state after le' found')
      nonneg intervalNonneg (backlog := backlog)
      (fun other primary otherFound primaryFound => by
        rw [Proofs.Timed.cut_nodeAt_of_le startLe] at otherFound primaryFound
        obtain ⟨point', pointFound, primaryNode⟩ := nodeAt_eq_some.mp primaryFound
        obtain ⟨point'', pointFound', otherNode⟩ := nodeAt_eq_some.mp otherFound
        rw [pointFound, Option.some.injEq] at pointFound'
        subst pointFound'
        have := behind point' primary node other pointFound primaryNode nodeIn otherNode
        rwa [agreedPrefix_eq] at this)
      startLe' baseLe timely
  have earlierClock : clock (cut trace last) earlier = time point :=
    clock_eq (by rw [cut_stateAt_of_le earlierLe]; exact recorded)
  obtain ⟨sent, reply, response, after, sentClock, sentAt, source, target, payload, success⟩ :=
    ack_sent_within (trace := cut trace last) (clock := clock (cut trace last))
      (stop := time first + duration') (bound := bound) (peer := node) (receiver := leader)
      env.mono env.ends env.prompt
      (fun moment step' packet stepped' delivers =>
        cutAdmissible.consumed_sent stepped' (by rw [delivers]; rfl))
      (fun moment low high => by
        obtain ⟨found, step', _, a, b, c, d, _⟩ := env.passes moment low high
        exact ⟨found, step', a, b, c, d⟩)
      (fun base startLe' baseLe timely => by
        obtain ⟨later, step', reply, acked, lt, clockLe, stepped', delivers, envelope, _⟩ :=
          acks base startLe' baseLe timely
        exact ⟨later, step', reply, { term, success := true, lastLogIndex := acked }, lt,
          clockLe, stepped', delivers, by simp [envelope], by simp [envelope], by simp [envelope],
          rfl⟩)
      nonneg boundNonneg afterStart earlierLe
      (by rw [earlierClock, durationEq, stopEq]; linarith)
  obtain ⟨sender, senderStepped, _⟩ := id sentAt
  obtain ⟨sentLt, senderStepped'⟩ := stepAt_of_cut senderStepped
  have senderClock : clock (cut trace last) sent = time sender.before :=
    clock_eq (by rw [cut_stateAt_of_le sentLt.le]; exact Trace.stateAt_of_stepAt senderStepped')
  refine ⟨
    sent,
    sender,
    reply,
    response,
    after,
    senderStepped',
    ?_,
    (cut_sentAt sentLt).mp sentAt,
    source,
    target,
    payload,
    success
  ⟩
  rw [senderClock, earlierClock] at sentClock
  exact sentClock

/-- A stable window over the anchor from an anchor engine, in which the term also
stays quiet over all participants, while anchor nodes catch up. -/
theorem stable_window_catchup_engine [HasTimers W] {bounds : Bounds} {maxDelay : Real}
    (timers : ElectionTimeouts trace (some (bounds.electionTimeout / 2)))
    (bounded : Satisfies trace (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace) (nonneg : 0 <= maxDelay)
    (heartbeats : HeartbeatScheduling trace (some bounds.heartbeatInterval))
    {backlog : Nat} {fresh : Real}
    (ratio
      : repair maxDelay (max bounds.heartbeatInterval 0) backlog
          + max bounds.heartbeatInterval 0
          + maxDelay
        < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2) {start : Nat} {duration : Real}
    {leader : NodeID} {term : Nat} {participants anchor : Finset NodeID}
    (engine : AnchorEngine trace start duration leader term participants anchor fresh)
    (good : GoodBase trace start duration participants)
    (behind : BacklogTerms trace start leader anchor backlog)
    : StableWindow trace start duration leader term anchor
      /\ Window.StableTerm trace start duration leader term participants := by
  have elections :=
    Liveness.electionSpacing_of_timeouts admissible.timing timers
  have gapLt
      : maxDelay + max bounds.heartbeatInterval 0
          + ackBound maxDelay (max bounds.heartbeatInterval 0) backlog
        < fresh := by
    rw [← repair_eq]; linarith
  have anchored := engine
  have inv
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> AnchorBaseInv participants anchor leader term (proto point)
              /\ NoProposals participants term point :=
    fun index point =>
      engine.core index
        (fun _ _ node _ _ afterStart _ within' stepped timeout _ nodeIn different _
            firstFound late invariant =>
          have inside {earlier : Nat} (after : start <= earlier) (le : earlier <= _) :=
            within_of_le admissible within' (Trace.stateAt_of_stepAt stepped) after le
          no_timeout_of_acks admissible elections gapLt freshLe afterStart stepped timeout
            firstFound late
            (acks_before_timeout admissible diverges bounded nonneg heartbeats good
              behind anchored.subset anchored.leaderIn nodeIn different stepped
              within' firstFound
              (fun earlier point after le found =>
                ⟨(invariant earlier point after le found).1.quietAmong admissible found,
                  NoProposals.mono (invariant earlier point after le found).2
                    anchored.subset⟩)
              (fun earlier point _ after le found leaderFound =>
                (invariant earlier point after le found).1.liveQuorum good (inside after le)
                  found leaderFound)
              (fun earlier point _ after le found leaderFound =>
                (invariant earlier point after le found).1.tracked nodeIn different
                  leaderFound)
              (fun earlier point after le found => by
                obtain ⟨_, exec⟩ := history_at admissible found
                obtain ⟨local_, now, termEq, _⟩ :=
                  (invariant earlier point after le found).1.anchored.settled node nodeIn
                exact ⟨local_, found_of_now exec now, termEq⟩)
              (fun earlier point state after le found leaderFound =>
                (invariant earlier point after le found).1.retained leader state
                  (Concrete.mem_of_nodeState leaderFound) anchored.leaderIn)))
        index point le_rfl
  refine ⟨
    {
      stableLeader := fun index point within found =>
        ⟨(inv index point within found).1.quietAmong admissible found,
          NoProposals.mono (inv index point within found).2 anchored.subset⟩
      staysActive := ⟨
        fun index point within found =>
          good.participantsLive index point leader within found
            (anchored.subset anchored.leaderIn),
        fun index point state within found leaderFound =>
          (inv index point within found).1.retained leader state
            (Concrete.mem_of_nodeState leaderFound) anchored.leaderIn⟩
      liveQuorum := fun index point _ within found leaderFound =>
        (inv index point within found).1.liveQuorum good within found leaderFound
      lossless := fun index step packet within stepped dropped => by
        rintro (⟨source, target⟩ | ⟨source, target⟩)
        · exact good.lossless index step packet within stepped dropped
            ⟨source ▸ anchored.subset anchored.leaderIn, anchored.subset target⟩
        · exact good.lossless index step packet within stepped dropped
            ⟨anchored.subset source, target ▸ anchored.subset anchored.leaderIn⟩
    },
    fun index point within found =>
      ⟨(inv index point within found).1.quiet, (inv index point within found).2⟩
  ⟩

end Recorded

end CCFRaft.Proofs.Leadership
