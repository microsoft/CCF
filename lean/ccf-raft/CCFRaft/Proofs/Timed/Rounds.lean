module

public import CCFRaft.Proofs.Timed.Clock
public import CCFRaft.Proofs.Timed.Potential
public import CCFRaft.Proofs.Replication.Peer

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Probing a fixed peer log

While a peer's log stays fixed, each heartbeat pass probes at the primary's retry
index for the peer. Once a pass has raised that index to the agreement, a probe
is either acknowledged exactly at the agreement, which is then the end of the
primary's log, or rejected; the rejection lowers the retry index to a position
that needs fewer rounds. The next pass follows within the heartbeat bound, so an
acknowledgement of the whole log is sent within a bounded time.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start last : Nat} {stop delay interval : Real} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID} (different : Not (peer = leader))
  (env : Env trace start last stop delay interval leader peer)
  (nonneg : 0 <= delay)
  (eligible
    : forall index state,
        start <= index
        -> nodeAt trace index leader = some state
        -> peer ∈ eligiblePeers state leader)

/-- The first pass to the peer after `index`, within the heartbeat bound. -/
theorem next_pass (env : Env trace start last stop delay interval leader peer)
    {index : Nat} (startLe : start <= index) (le : index <= last)
    (deadline : clock trace index + interval <= stop)
    : exists pass step batchEnds,
        index < pass
        /\ clock trace pass <= clock trace index + interval
        /\ trace.stepAt pass = some step
        /\ step.action = .local leader (.sendEntries peer batchEnds)
        /\ forall middle step' ends,
            index < middle
            -> middle < pass
            -> trace.stepAt middle = some step'
            -> Not (step'.action = .local leader (.sendEntries peer ends)) := by
  obtain ⟨q, qStep, qEnds, _, lower, _, qStepped, qEvent⟩ :=
    env.passes (clock trace index) (env.mono start index startLe le) deadline
  have qLt := env.ends q qStep qStepped
  have indexLt : index < q := by
    by_contra early
    have := env.mono q index (by omega) le
    linarith
  classical
  have exists_pass
      : exists middle, index < middle
        /\ exists step ends, trace.stepAt middle = some step
          /\ step.action = .local leader (.sendEntries peer ends) :=
    ⟨q, indexLt, qStep, qEnds, qStepped, qEvent⟩
  obtain ⟨passLt, step, ends, stepped, event⟩ := Nat.find_spec exists_pass
  have least := Nat.find_min' exists_pass ⟨indexLt, qStep, qEnds, qStepped, qEvent⟩
  refine ⟨Nat.find exists_pass, step, ends, passLt, ?_, stepped, event, ?_⟩
  · have := env.mono _ q least qLt.le
    linarith
  · intro middle step' ends' after before stepped' event'
    exact Nat.find_min exists_pass before ⟨after, step', ends', stepped', event'⟩

include admissible stable different env nonneg eligible

variable {log : List Entry} {agreed origin : Nat}

/-- A property of the primary at `low` that each step up to `high` preserves. -/
theorem leader_induct {motive : NodeState -> Prop} {low high : Nat}
    (startLe : start <= low)
    (base : forall state, nodeAt trace low leader = some state -> motive state)
    (next
      : forall index step before after,
          low <= index
          -> index < high
          -> trace.stepAt index = some step
          -> nodeState (proto step.before) leader = some before
          -> nodeState (proto step.after) leader = some after
          -> motive before
          -> motive after)
    : forall index state,
        low <= index
        -> index <= high
        -> nodeAt trace index leader = some state
        -> motive state := by
  intro index state le
  induction index, le using Nat.le_induction generalizing state with
  | base => exact fun _ found => base state found
  | succ index le ih =>
      intro highLe found
      obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp pointFound
      obtain ⟨_, before, beforeFound, _⟩ :=
        stable.leads (startLe.trans le) (Trace.stateAt_of_stepAt stepped)
      exact next index step before state le (by omega) stepped beforeFound nodeFound
        (ih before (by omega) (by rw [nodeAt_before stepped, beforeFound]))

/-- Without a pass, the retry index rises at most to the agreement. -/
theorem cap (regime : Regime stable peer log agreed origin) {low high : Nat}
    (began : origin <= low) (le : low <= high)
    (noPass
      : forall middle step ends,
          low <= middle
          -> middle < high
          -> trace.stepAt middle = some step
          -> Not (step.action = .local leader (.sendEntries peer ends)))
    {state state' : NodeState} (found : nodeAt trace low leader = some state)
    (found' : nodeAt trace high leader = some state')
    : max (state'.sentIndex peer) agreed <= max (state.sentIndex peer) agreed := by
  refine leader_induct admissible stable different env nonneg eligible
    (motive := fun current => max (current.sentIndex peer) agreed
      <= max (state.sentIndex peer) agreed)
    (low := low) (high := high) (regime.afterStart.trans began)
    (fun current currentFound => by
      rw [found, Option.some.injEq] at currentFound
      subst currentFound
      exact le_rfl)
    (fun index step before after lowLe lt stepped beforeFound afterFound held => ?_)
    high state' le le_rfl found'
  have afterStart := regime.afterStart.trans (began.trans lowLe)
  have beforeNode : nodeAt trace index leader = some before := by
    rw [nodeAt_before stepped, beforeFound]
  rcases (leader_move admissible stable peer afterStart stepped beforeFound afterFound).2
      with same | ⟨ends, _, event, _, _⟩ | ⟨_, _, _, _, _, _, _, value⟩ | ⟨_, _, _, _, _, aimed⟩
  · rw [same]
    exact held
  · exact absurd event (noPass index step ends lowLe lt stepped)
  · have := match_le_agreed admissible stable different regime (began.trans lowLe) beforeNode
    rw [value]
    omega
  · exact absurd (eligible index before afterStart beforeNode) aimed

/-- After a pass late enough that every later delivery was sent in the regime,
the retry index stays at or above the agreement. -/
theorem floor_after (regime : Regime stable peer log agreed origin) {pass : Nat}
    (began : origin <= pass) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt pass = some step) {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    (late : clock trace origin + delay < clock trace pass)
    : forall index state,
        pass < index
        -> nodeAt trace index leader = some state
        -> agreed <= state.sentIndex peer := by
  have passLt := env.ends pass step stepped
  have afterStart := regime.afterStart
  obtain ⟨_, before, beforeFound, _, _, notRetired⟩ :=
    stable.leads (afterStart.trans began) (Trace.stateAt_of_stepAt stepped)
  obtain ⟨next, _, nextFound, passed, _⟩ := pass_step admissible stepped event beforeFound
  have frontier := (passed.complete notRetired).1
  have agreement :=
    regime.agreement pass before began (by rw [nodeAt_before stepped, beforeFound])
  have := agree_le_right log before.log
  intro index state after found
  refine leader_induct admissible stable different env nonneg eligible
    (motive := fun current => agreed <= current.sentIndex peer)
    (low := pass + 1)
    (high := index)
    (by omega)
    (fun current currentFound => by
      rw [nodeAt_succ stepped, nextFound, Option.some.injEq] at currentFound
      subst currentFound
      omega)
    (fun middle step' before' after' lowLe _ stepped' beforeFound' afterFound' held => ?_)
    index state after le_rfl found
  have := floor_step admissible stable different regime
    (fun index state after found => eligible index state (afterStart.trans after) found)
    stepped' (by omega) (fun packet event' => ?_) beforeFound' afterFound'
  · omega
  obtain ⟨sent, sentLt, sentAt⟩ := admissible.consumed_sent stepped' (by rw [event']; rfl)
  refine ⟨sent, ?_, sentLt, sentAt⟩
  by_contra early
  have middleLt := env.ends middle step' stepped'
  have := env.prompt middle step' packet sent stepped' event' sentAt
  have := env.mono sent origin (by omega) (by omega)
  have := env.mono pass middle (by omega) middleLt.le
  linarith

/-- After a pass, the primary's retry index for the peer stays within its log. -/
theorem sent_le_length (regime : Regime stable peer log agreed origin) {pass : Nat}
    (began : origin <= pass) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt pass = some step) {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    : forall index state,
        pass < index
        -> nodeAt trace index leader = some state
        -> state.sentIndex peer <= state.log.length := by
  have afterStart := regime.afterStart
  obtain ⟨_, before, beforeFound, _⟩ :=
    stable.leads (afterStart.trans began) (Trace.stateAt_of_stepAt stepped)
  obtain ⟨next, _, nextFound, passed, _⟩ := pass_step admissible stepped event beforeFound
  have grows := (stable_log_prefix admissible stable (afterStart.trans began) (Nat.le_succ pass)
    (by rw [nodeAt_before stepped, beforeFound])
    (by rw [nodeAt_succ stepped, nextFound])).length_le
  have := passed.bounded
  intro index state after found
  refine leader_induct admissible stable different env nonneg eligible
    (motive := fun current => current.sentIndex peer <= current.log.length)
    (low := pass + 1)
    (high := index)
    (by omega)
    (fun current currentFound => by
      rw [nodeAt_succ stepped, nextFound, Option.some.injEq] at currentFound
      subst currentFound
      omega)
    (fun middle step' before' after' lowLe _ stepped' beforeFound' afterFound' held => ?_)
    index state after le_rfl found
  have middleStart : start <= middle := by omega
  have beforeNode : nodeAt trace middle leader = some before' := by
    rw [nodeAt_before stepped', beforeFound']
  have grows' := (stable_log_prefix admissible stable middleStart (Nat.le_succ middle) beforeNode
    (by rw [nodeAt_succ stepped', afterFound'])).length_le
  rcases (leader_move admissible stable peer middleStart stepped' beforeFound' afterFound').2
      with same | ⟨_, _, _, passed', _⟩ | ⟨_, _, _, _, _, _, _, value⟩ | ⟨_, _, _, _, _, aimed⟩
  · omega
  · have := passed'.bounded
    omega
  · have := match_le_agreed admissible stable different regime (by omega) beforeNode
    have := regime.agreement middle before' (by omega) beforeNode
    have := agree_le_right log before'.log
    rw [value]
    omega
  · exact absurd (eligible middle before' middleStart beforeNode) aimed

/-- A pass at or above the agreement is acknowledged at the agreement, which is
then the end of the primary's log, or its rejection, delivered inside the
recording, lowers the rounds left. -/
theorem probe_within (regime : Regime stable peer log agreed origin) {pass : Nat}
    (began : origin <= pass) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt pass = some step) {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    (floor : agreed <= before.sentIndex peer)
    (timely : clock trace pass + 2 * delay <= stop) {reference : NodeState}
    (referenceFound : nodeAt trace last leader = some reference)
    : (agreed = before.log.length
        /\ exists index reply,
            pass < index
            /\ clock trace index <= clock trace pass + delay
            /\ SentAt trace index reply
            /\ reply.envelope
                = {
                  source := peer
                  target := leader
                  payload :=
                    .appendEntriesResponse
                      { term, success := true, lastLogIndex := agreed }
                })
      \/ exists answered,
          pass < answered
          /\ answered < last
          /\ clock trace answered <= clock trace pass + 2 * delay
          /\ forall state,
              nodeAt trace (answered + 1) leader = some state
              -> rounds log reference.log agreed (max (state.sentIndex peer) agreed)
                  < rounds log reference.log agreed (before.sentIndex peer) := by
  have afterStart := regime.afterStart
  have passLt := env.ends pass step stepped
  have passNode : nodeAt trace pass leader = some before := by
    rw [nodeAt_before stepped, found]
  have notRetired := stable.notRetired (afterStart.trans began) passNode
  obtain ⟨_, _, _, passed, _⟩ := pass_step admissible stepped event found
  have valid := passed.valid
  obtain ⟨first, rest, rfl⟩ : exists first rest, batchEnds = first :: rest := by
    cases batchEnds with
    | nil => simp [isPass] at valid
    | cons first rest => exact ⟨first, rest, rfl⟩
  have member
      : (before.sentIndex peer, first) ∈ passBatches (before.sentIndex peer) (first :: rest) := by
    simp [passBatches]
  obtain ⟨_, _, highLe⟩ := passed.batch_bounds member
  obtain ⟨packet, sentAt, envelope, _⟩ :=
    pass_sends admissible stepped event found notRetired member
  have source : packet.envelope.source = leader := by rw [envelope]; rfl
  have target : packet.envelope.target = peer := by rw [envelope]; rfl
  have payload
      : packet.envelope.payload
        = .appendEntriesRequest (makeAppendEntriesRequest before (before.sentIndex peer) first) := by
    rw [envelope]; rfl
  have prevEq
      : (makeAppendEntriesRequest before (before.sentIndex peer) first).prevLogIndex
        = before.sentIndex peer := rfl
  have lengthEq
      : (makeAppendEntriesRequest before (before.sentIndex peer) first).entries.length
        = first - before.sentIndex peer := messageEntries_length highLe
  generalize makeAppendEntriesRequest before (before.sentIndex peer) first = request
    at payload prevEq lengthEq
  obtain ⟨x, stepX, passLtX, steppedX, eventX⟩ :=
    env.arrives pass packet (afterStart.trans began) sentAt (Or.inl ⟨source, target⟩)
      (by linarith)
  have xLt := env.ends x stepX steppedX
  have clockX := env.prompt x stepX packet pass steppedX eventX sentAt
  obtain ⟨_, primary, primaryFound, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt steppedX)
  have xNode : nodeAt trace x leader = some primary := by
    rw [nodeAt_before steppedX, primaryFound]
  obtain ⟨rTerm, _, _, outcome⟩ :=
    answer admissible stable different regime
      (fun index state after found => eligible index state (afterStart.trans after) found)
      steppedX eventX sentAt began passLtX source target payload passNode primaryFound floor
  rcases outcome with ⟨above, w, wTerm, wLog, prevLe, prevTerm, mismatch, reply, replySent,
      replyEnvelope⟩ | ⟨reached, reply, replySent, replyEnvelope⟩
  · right
    have replySource : reply.envelope.source = peer := by rw [replyEnvelope]
    have replyTarget : reply.envelope.target = leader := by rw [replyEnvelope]
    obtain ⟨y, stepY, xLtY, steppedY, eventY⟩ :=
      env.arrives x reply (by omega) replySent (Or.inr ⟨replySource, replyTarget⟩) (by linarith)
    have yLt := env.ends y stepY steppedY
    have clockY := env.prompt y stepY reply x steppedY eventY replySent
    refine ⟨y, by omega, yLt, by linarith, fun state stateFound => ?_⟩
    obtain ⟨_, current, currentFound, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt steppedY)
    have currentNode : nodeAt trace y leader = some current := by
      rw [nodeAt_before steppedY, currentFound]
    rw [nodeAt_succ steppedY] at stateFound
    have value := nack_exact admissible stable (by omega : start <= y) steppedY
      (by rw [eventY]; rfl) replyTarget (by rw [replyEnvelope]) (nackResponse_failure w request)
      currentFound stateFound
      (by rw [replySource]; exact eligible y current (by omega) currentNode)
    rw [replySource] at value
    have matchLe :=
      match_le_agreed admissible stable different regime (by omega : origin <= y) currentNode
    obtain ⟨lastPoint, lastFound, _⟩ := nodeAt_eq_some.mp referenceFound
    obtain ⟨z, zFound, zTerm, zLog⟩ := regime.state last lastPoint (by omega) lastFound
    have view := view_at admissible stable different (by omega : start <= last) referenceFound
      (by rw [nodeAt_of_stateAt lastFound, zFound]) zTerm
    have agreement := regime.agreement last reference (by omega) referenceFound
    have xPrefix := stable_log_prefix admissible stable (by omega : start <= x)
      (by omega : x <= last) xNode referenceFound
    have xyPrefix := stable_log_prefix admissible stable (by omega : start <= x)
      (by omega : x <= y) xNode currentNode
    have yPrefix := stable_log_prefix admissible stable (by omega : start <= y)
      (by omega : y <= last) currentNode referenceFound
    have transfer := termAt_of_prefix xPrefix prevLe
    rw [← transfer] at prevTerm mismatch
    have positive := view.positive
    have matching := view.matching
    rw [zLog] at positive matching
    have fewer := retry_rounds (follower := log) (log := reference.log) (current := current.log)
      view.leaderSorted positive matching agreement yPrefix wLog wTerm rTerm
      (prevLe.trans xyPrefix.length_le) prevTerm mismatch
    have retryEq
        : retry current.log w request
          = findHighestPossibleMatch current.log (nackResponse w request).lastLogIndex
            (nackResponse w request).term := rfl
    rw [prevEq] at fewer above
    have bound : max (state.sentIndex peer) agreed <= max (retry current.log w request) agreed := by
      rw [value, retryEq]
      omega
    refine (rounds_mono bound).trans_lt ?_
    rcases le_total agreed (retry current.log w request) with high | low
    · rw [max_eq_left high]
      exact fewer
    · rw [max_eq_right low, rounds_of_le le_rfl]
      exact rounds_pos above
  · left
    refine ⟨?_, x, reply, passLtX, clockX, replySent, replyEnvelope⟩
    cases rest with
    | nil =>
        simp [isPass] at valid
        omega
    | cons next rest =>
        simp [isPass] at valid
        omega

/-- Passes after the floor is reached acknowledge the primary's whole log within
one probe per round left. -/
theorem iterate (regime : Regime stable peer log agreed origin) {floorFrom : Nat}
    (floorHolds
      : forall index state,
          floorFrom < index
          -> nodeAt trace index leader = some state
          -> agreed <= state.sentIndex peer)
    (intervalNonneg : 0 <= interval)
    {reference : NodeState} (referenceFound : nodeAt trace last leader = some reference)
    (count : Nat)
    : forall pass step batchEnds before,
        floorFrom < pass
        -> origin <= pass
        -> trace.stepAt pass = some step
        -> step.action = .local leader (.sendEntries peer batchEnds)
        -> nodeState (proto step.before) leader = some before
        -> rounds log reference.log agreed (before.sentIndex peer) <= count
        -> clock trace pass + count * (2 * delay + interval) + 2 * delay <= stop
        -> exists acked index reply,
            pass <= acked
            /\ (forall state,
                  nodeAt trace acked leader = some state -> agreed = state.log.length)
            /\ acked < index
            /\ clock trace index
                <= clock trace pass + count * (2 * delay + interval) + delay
            /\ SentAt trace index reply
            /\ reply.envelope
                = {
                  source := peer
                  target := leader
                  payload :=
                    .appendEntriesResponse
                      { term, success := true, lastLogIndex := agreed }
                } := by
  have rate : 0 <= 2 * delay + interval := by linarith
  obtain ⟨lastPoint, lastFound⟩ := env.lastFound
  induction count with
  | zero =>
      intro pass step batchEnds before floorLt began stepped event found roundsLe timely
      have passNode : nodeAt trace pass leader = some before := by
        rw [nodeAt_before stepped, found]
      simp only [Nat.cast_zero, zero_mul, add_zero] at timely ⊢
      rcases probe_within admissible stable different env nonneg eligible regime began stepped
          event found (floorHolds pass before floorLt passNode) timely referenceFound
          with ⟨agreedEq, index, reply, lt, clockLe, sent, envelope⟩
            | ⟨answered, _, answeredLt, _, fewer⟩
      · exact ⟨pass, index, reply, le_rfl,
          fun state stateFound => by
            rw [passNode, Option.some.injEq] at stateFound
            subst stateFound
            exact agreedEq,
          lt, clockLe, sent, envelope⟩
      · exfalso
        obtain ⟨point, pointFound⟩ := Trace.stateAt_ge_stable answeredLt lastFound
        obtain ⟨next, nextNode⟩ :=
          stable.found (by have := regime.afterStart; omega) pointFound
        have := fewer next nextNode
        omega
  | succ count ih =>
      intro pass step batchEnds before floorLt began stepped event found roundsLe timely
      have passNode : nodeAt trace pass leader = some before := by
        rw [nodeAt_before stepped, found]
      have spread := mul_nonneg (Nat.cast_nonneg (α := Real) count) rate
      have expand
          : ((count + 1 : Nat) : Real) * (2 * delay + interval)
            = count * (2 * delay + interval) + (2 * delay + interval) := by
        push_cast
        ring
      rw [expand] at timely ⊢
      rcases probe_within admissible stable different env nonneg eligible regime began stepped
          event found (floorHolds pass before floorLt passNode) (by linarith) referenceFound
          with ⟨agreedEq, index, reply, lt, clockLe, sent, envelope⟩
            | ⟨answered, passLt, answeredLt, clockAnswered, fewer⟩
      · exact ⟨pass, index, reply, le_rfl,
          fun state stateFound => by
            rw [passNode, Option.some.injEq] at stateFound
            subst stateFound
            exact agreedEq,
          lt, by linarith, sent, envelope⟩
      have afterStart := regime.afterStart
      obtain ⟨point, pointFound⟩ := Trace.stateAt_ge_stable answeredLt lastFound
      obtain ⟨next, nextNode⟩ := stable.found (by omega) pointFound
      have fewer := fewer next nextNode
      obtain ⟨q, stepQ, endsQ, answeredLtQ, clockQ, steppedQ, eventQ, noPass⟩ :=
        next_pass env (by omega : start <= answered) answeredLt.le (by linarith)
      obtain ⟨_, beforeQ, foundQ, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt steppedQ)
      have nodeQ : nodeAt trace q leader = some beforeQ := by
        rw [nodeAt_before steppedQ, foundQ]
      have capped := cap admissible stable different env nonneg eligible regime
        (low := answered + 1) (high := q) (by omega) (by omega)
        (fun middle step' ends le lt => noPass middle step' ends (by omega) lt) nextNode nodeQ
      have floorQ := floorHolds q beforeQ (by omega) nodeQ
      rw [max_eq_left floorQ] at capped
      have := rounds_mono (follower := log) (log := reference.log) (agreed := agreed) capped
      obtain ⟨acked, index, reply, le, all, lt, clockLe, sent, envelope⟩ :=
        ih q stepQ endsQ beforeQ (by omega) (by omega) steppedQ eventQ foundQ (by omega)
          (by linarith)
      exact ⟨acked, index, reply, by omega, all, lt, by linarith, sent, envelope⟩

/-- In a regime whose rounds are bounded, the peer acknowledges the primary's
whole log at a pass after `first`, within a bounded time. -/
theorem regime_acks (regime : Regime stable peer log agreed origin) {first : Nat}
    (began : origin <= first) (firstLe : first <= last)
    (late : clock trace origin + delay < clock trace first)
    (intervalNonneg : 0 <= interval) {reference : NodeState}
    (referenceFound : nodeAt trace last leader = some reference) {count : Nat}
    (roundsLe
      : forall position,
          position <= reference.log.length
          -> rounds log reference.log agreed position <= count)
    (timely
      : clock trace first + 2 * interval + count * (2 * delay + interval) + 2 * delay
        <= stop)
    : exists acked index reply,
        first < acked
        /\ (forall state,
              nodeAt trace acked leader = some state -> agreed = state.log.length)
        /\ acked < index
        /\ clock trace index
            <= clock trace first + 2 * interval + count * (2 * delay + interval) + delay
        /\ SentAt trace index reply
        /\ reply.envelope
            = {
              source := peer
              target := leader
              payload :=
                .appendEntriesResponse { term, success := true, lastLogIndex := agreed }
            } := by
  have rate : 0 <= 2 * delay + interval := by linarith
  have spread := mul_nonneg (Nat.cast_nonneg (α := Real) count) rate
  have afterStart := regime.afterStart
  obtain ⟨p0, step0, ends0, firstLt0, clock0, stepped0, event0, _⟩ :=
    next_pass env (by omega : start <= first) firstLe (by linarith)
  have lt0 := env.ends p0 step0 stepped0
  have mono0 := env.mono first p0 firstLt0.le lt0.le
  have floorHolds := floor_after admissible stable different env nonneg eligible regime
    (by omega) stepped0 event0 (by linarith)
  have bounded := sent_le_length admissible stable different env nonneg eligible regime
    (by omega) stepped0 event0
  obtain ⟨p1, step1, ends1, lt01, clock1, stepped1, event1, _⟩ :=
    next_pass env (by omega : start <= p0) lt0.le (by linarith)
  have lt1 := env.ends p1 step1 stepped1
  obtain ⟨_, before1, found1, _⟩ := stable.leads (by omega) (Trace.stateAt_of_stepAt stepped1)
  have node1 : nodeAt trace p1 leader = some before1 := by
    rw [nodeAt_before stepped1, found1]
  have within := bounded p1 before1 lt01 node1
  have grows :=
    (stable_log_prefix admissible stable (by omega) lt1.le node1 referenceFound).length_le
  obtain ⟨acked, index, reply, le, all, lt, clockLe, sent, envelope⟩ :=
    iterate admissible stable different env nonneg eligible regime floorHolds intervalNonneg
      referenceFound count p1 step1 ends1 before1 lt01 (by omega) stepped1 event1 found1
      (roundsLe _ (by omega)) (by linarith)
  exact ⟨acked, index, reply, by omega, all, lt, by linarith, sent, envelope⟩

end CCFRaft.Proofs.Timed
