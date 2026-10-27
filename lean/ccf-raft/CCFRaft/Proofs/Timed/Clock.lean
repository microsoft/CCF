module

public import CCFRaft.Proofs.Timed.Window

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Timing on a window cut

The replication argument reads time on the recording cut at the window's last
state. Three facts carry the timing assumptions there: a delivery happens within
the maximum delay of its send, a packet between the primary and a live peer sent
early enough is delivered inside the cut, and heartbeat passes to the peer recur
within the heartbeat bound. Time cannot jump past a due heartbeat, so a pass
follows any instant early enough in the window.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Leadership (quietAmong_leader)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- The time of a recorded state, and zero past the end of the recording. -/
noncomputable def clock (trace : Trace W Liveness.Event) (index : Nat) : Real :=
  ((trace.stateAt index).map time).getD 0

theorem clock_eq {trace : Trace W Liveness.Event} {index : Nat} {point : W}
    (found : trace.stateAt index = some point)
    : clock trace index = time point := by
  simp [clock, found]

/-- Timing facts about a recording that ends at `last`, inside a window that ends
at real time `stop`, for the primary `leader` and one peer. -/
structure Env (trace : Trace W Liveness.Event) (start last : Nat)
    (stop delay interval : Real) (leader peer : NodeID)
    : Prop where
  startLe : start <= last
  lastFound : exists point, trace.stateAt last = some point
  ends : forall index step, trace.stepAt index = some step -> index < last
  mono
    : forall index later,
        index <= later -> later <= last -> clock trace index <= clock trace later
  bounded : forall index, index < last -> clock trace index <= stop
  prompt
    : forall index step packet sent,
        trace.stepAt index = some step
        -> step.action = .deliver packet
        -> SentAt trace sent packet
        -> clock trace index <= clock trace sent + delay
  arrives
    : forall index packet,
        start <= index
        -> SentAt trace index packet
        -> ((packet.envelope.source = leader /\ packet.envelope.target = peer)
            \/ (packet.envelope.source = peer /\ packet.envelope.target = leader))
        -> clock trace index + delay <= stop
        -> exists later step,
            index < later
            /\ trace.stepAt later = some step
            /\ step.action = .deliver packet
  passes
    : forall bound : Real,
        clock trace start <= bound
        -> bound + interval <= stop
        -> exists index step batchEnds,
            start <= index
            /\ bound < clock trace index
            /\ clock trace index <= bound + interval
            /\ trace.stepAt index = some step
            /\ step.action = .local leader (.sendEntries peer batchEnds)

section Derive

variable [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- The window's timing assumptions, read on the cut at its last state. -/
theorem env_of_window {maxDelay heartbeat : Real}
    (bounded : Satisfies trace (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace)
    (heartbeats : HeartbeatScheduling trace (some heartbeat)) {start last : Nat}
    {duration : Real} (nonneg : 0 <= duration) {leader : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (window : StableWindow trace start duration leader term participants)
    {first lastPoint : W} (firstFound : trace.stateAt start = some first)
    (afterStart : start <= last) (lastFound : trace.stateAt last = some lastPoint)
    (inside
      : forall index,
          start <= index -> index <= last -> Within trace start duration index)
    (beyond
      : forall index point,
          last < index
          -> trace.stateAt index = some point
          -> time first + duration < time point)
    {peer : NodeID} (peerMember : peer ∈ participants) (peerLive : peer ∈ live lastPoint)
    (eligible
      : forall index state,
          start <= index
          -> index <= last
          -> nodeAt trace index leader = some state
          -> peer ∈ eligiblePeers state leader)
    : Env (cut trace last) start last (time first + duration) maxDelay (max heartbeat 0)
        leader peer := by
  have timeMono := fun {earlier later : Nat} (le : earlier <= later) {a b : W}
      (found : trace.stateAt earlier = some a) (found' : trace.stateAt later = some b) =>
    Proofs.Liveness.time_mono admissible.timing le found found'
  -- Recorded states no later than the window's end lie in the cut.
  have early : forall index point,
      trace.stateAt index = some point -> time point <= time first + duration -> index <= last := by
    intro index point found le
    by_contra late
    have := beyond index point (by omega) found
    linarith
  -- A busy step starting no later than the window's end is a step of the cut.
  have busyIn : forall index step,
      trace.stepAt index = some step -> Not (step.action = .idle)
      -> time step.before <= time first + duration -> index < last := by
    intro index step stepped busy le
    have after := (admissible.timing.next stepped).2 busy
    have := early (index + 1) step.after (Trace.stateAt_succ_of_stepAt stepped) (by linarith)
    omega
  have clockCut : forall index point, index <= last -> trace.stateAt index = some point
      -> clock (cut trace last) index = time point := by
    intro index point le found
    rw [clock_eq (by rw [cut_stateAt_of_le le]; exact found)]
  have peerLiveAt : forall index point, index <= last -> trace.stateAt index = some point
      -> peer ∈ live point :=
    fun index point le found => admissible.live_anti le found lastFound peerLive
  have leaderLiveAt : forall index point, start <= index -> index <= last
      -> trace.stateAt index = some point -> leader ∈ live point :=
    fun index point le le' found =>
      window.staysActive.live index point (inside index le le') found
  have stopNonneg : time first <= time first + duration := by linarith
  refine ⟨
    afterStart,
    ⟨lastPoint, by rw [cut_stateAt_of_le le_rfl]; exact lastFound⟩,
    fun _ _ stepped => (stepAt_of_cut stepped).1,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro index later le le'
    obtain ⟨a, aFound⟩ := Trace.stateAt_ge_stable (le.trans le') lastFound
    obtain ⟨b, bFound⟩ := Trace.stateAt_ge_stable le' lastFound
    rw [clockCut index a (le.trans le') aFound, clockCut later b le' bFound]
    exact timeMono le aFound bFound
  · intro index lt
    have le := lt.le
    obtain ⟨a, aFound⟩ := Trace.stateAt_ge_stable le lastFound
    rw [clockCut index a le aFound]
    rcases Nat.le_total index start with low | high
    · have := timeMono low aFound firstFound
      linarith
    · exact (inside index high le).2 first a firstFound aFound
  · intro index step packet sent stepped action sentAt
    obtain ⟨lt, stepped⟩ := stepAt_of_cut stepped
    obtain ⟨sentLt, _⟩ := stepAt_of_cut (Exists.choose_spec sentAt).1
    have sentAt' := (cut_sentAt sentLt).mp sentAt
    have member :=
      Proofs.Liveness.Admissible.consumed_pending admissible stepped (by rw [action]; rfl)
    have targetLive := admissible.actor_live stepped (by rw [action]; rfl)
    have deadline :=
      Proofs.Liveness.pending_deadline bounded (Trace.stateAt_of_stepAt stepped) member targetLive
    obtain ⟨sentStep, _, _, sentStepped, _, _, _, _, _, sentTime⟩ :=
      Proofs.Liveness.Admissible.sentAt_emitted admissible sentAt'
    rw [clockCut index step.before lt.le (Trace.stateAt_of_stepAt stepped),
      clockCut sent sentStep.before sentLt.le (Trace.stateAt_of_stepAt sentStepped)]
    linarith
  · intro index packet le sentAt link deadline
    obtain ⟨indexLt, _⟩ := stepAt_of_cut (Exists.choose_spec sentAt).1
    have sentAt' := (cut_sentAt indexLt).mp sentAt
    obtain ⟨sentStep, _, _, sentStepped, _, _, _, _, _, sentTime⟩ :=
      Proofs.Liveness.Admissible.sentAt_emitted admissible sentAt'
    obtain ⟨step', stepped', member, _⟩ := sentAt'
    rw [sentStepped, Option.some.injEq] at stepped'
    subst step'
    rw [clockCut index sentStep.before indexLt.le (Trace.stateAt_of_stepAt sentStepped)] at deadline
    have afterFound := Trace.stateAt_succ_of_stepAt sentStepped
    have targetLive : packet.envelope.target ∈ live sentStep.after := by
      rcases link with ⟨_, target⟩ | ⟨_, target⟩
      · rw [target]; exact peerLiveAt (index + 1) _ indexLt afterFound
      · rw [target]; exact leaderLiveAt (index + 1) _ (by omega) indexLt afterFound
    obtain ⟨later, step, le', stepped, timeLe, outcome⟩ :=
      Proofs.Liveness.Admissible.consumed_within admissible bounded diverges afterFound member
        targetLive
    have within : time step.before <= time first + duration := by linarith
    have laterLe := early later step.before (Trace.stateAt_of_stepAt stepped) within
    rcases outcome with consumed | crashed
    · cases action : step.action with
      | deliver delivered =>
          rw [action] at consumed
          simp only [Event.consumedPacket, Option.some.injEq] at consumed
          subst delivered
          have lt := busyIn later step stepped (by rw [action]; simp) within
          exact ⟨
            later,
            step,
            by omega,
            by rw [cut_stepAt_of_lt lt]; exact stepped,
            action
          ⟩
      | drop dropped =>
          rw [action] at consumed
          simp only [Event.consumedPacket, Option.some.injEq] at consumed
          subst dropped
          exact absurd
            (Or.imp (fun h => ⟨h.1, h.2 ▸ peerMember⟩) (fun h => ⟨h.1 ▸ peerMember, h.2⟩)
              link)
            (window.lossless later step packet (inside later (by omega) laterLe) stepped
              action)
      | _ => simp [action, Event.consumedPacket] at consumed
    · have lt := busyIn later step stepped (by rw [crashed]; simp) within
      have afterLater := Trace.stateAt_succ_of_stepAt stepped
      have dead : Not (packet.envelope.target ∈ live step.after) := by
        have next := admissible.crash.next stepped
        simp only [crashModel, crashSystem, crashed, Event.actor] at next
        split_ifs at next
        · simp only [Option.some.injEq] at next
          rw [← next]
          simp
      rcases link with ⟨_, target⟩ | ⟨_, target⟩
      · rw [target] at dead
        exact absurd (peerLiveAt (later + 1) _ lt afterLater) dead
      · rw [target] at dead
        exact absurd (leaderLiveAt (later + 1) _ (by omega) lt afterLater) dead
  · intro bound startLe deadline
    rw [clockCut start first afterStart firstFound] at startLe
    classical
    have exists_past : exists index, start <= index
        /\ exists point, trace.stateAt index = some point /\ bound < time point := by
      obtain ⟨far, farPoint, farFound, late⟩ := diverges (bound + 1)
      refine ⟨far, ?_, farPoint, farFound, by linarith⟩
      by_contra before
      have := timeMono (Nat.le_of_not_le before) farFound firstFound
      linarith
    let past := Nat.find exists_past
    obtain ⟨pastLe, pastPoint, pastFound, pastLate⟩ := Nat.find_spec exists_past
    have startLt : start < past := by
      rcases Nat.eq_or_lt_of_le pastLe with same | lt
      · rw [← same, firstFound, Option.some.injEq] at pastFound
        subst pastFound
        linarith
      · exact lt
    obtain ⟨point, found⟩ := Trace.stateAt_ge_stable (Nat.sub_le past 1) pastFound
    have pointEarly : time point <= bound := by
      by_contra late
      exact Nat.find_min exists_past (show past - 1 < past by omega)
        ⟨by omega, point, found, lt_of_not_ge late⟩
    have pointIn : past - 1 <= last := early _ point found (by
      have := le_max_right heartbeat 0
      linarith)
    have due : PeerDue point leader peer := by
      have within := inside (past - 1) (by omega) pointIn
      obtain ⟨state, nodeFound, primary, _⟩ :=
        quietAmong_leader admissible found (window.stableLeader _ point within found).1
      exact ⟨leaderLiveAt _ point (by omega) pointIn found, peerLiveAt _ point pointIn found,
        state, nodeFound, primary,
        window.staysActive.notRetired _ point state within found nodeFound,
        eligible _ state (by omega) pointIn (by rw [nodeAt_of_stateAt found, nodeFound])⟩
    obtain ⟨later, laterPoint, le, laterFound, timeLe, outcome⟩ :=
      heartbeats leader peer (past - 1) point found due
    simp only [Deadline] at timeLe
    have laterEarly : time laterPoint <= time first + duration := by
      have := le_max_left heartbeat 0
      linarith
    have laterIn := early later laterPoint laterFound laterEarly
    rcases outcome with notDue | ⟨step, stepped, batchEnds, action⟩
    · exfalso
      apply notDue
      have within := inside later (by omega) laterIn
      obtain ⟨state, nodeFound, primary, _⟩ :=
        quietAmong_leader admissible laterFound (window.stableLeader _ laterPoint within laterFound).1
      exact ⟨leaderLiveAt _ laterPoint (by omega) laterIn laterFound,
        peerLiveAt _ laterPoint laterIn laterFound, state, nodeFound, primary,
        window.staysActive.notRetired _ laterPoint state within laterFound nodeFound,
        eligible _ state (by omega) laterIn (by rw [nodeAt_of_stateAt laterFound, nodeFound])⟩
    · have busy : Not (step.action = .idle) := by rw [action]; simp
      rw [Trace.stateAt_of_stepAt stepped, Option.some.injEq] at laterFound
      subst laterFound
      have lt := busyIn later step stepped busy laterEarly
      have notFirst : past <= later := by
        by_contra early'
        have same : later = past - 1 := by omega
        subst same
        have after := (admissible.timing.next stepped).2 busy
        have succFound := Trace.stateAt_succ_of_stepAt stepped
        rw [show past - 1 + 1 = past by omega, pastFound, Option.some.injEq] at succFound
        subst succFound
        rw [Trace.stateAt_of_stepAt stepped, Option.some.injEq] at found
        subst found
        linarith
      have := timeMono notFirst pastFound (Trace.stateAt_of_stepAt stepped)
      refine ⟨later, step, batchEnds, by omega, ?_, ?_, by rw [cut_stepAt_of_lt lt]; exact stepped,
        action⟩
      · rw [clockCut later step.before lt.le (Trace.stateAt_of_stepAt stepped)]
        linarith
      · rw [clockCut later step.before lt.le (Trace.stateAt_of_stepAt stepped)]
        have := le_max_left heartbeat 0
        linarith

end Derive

section Restrict

variable {trace : Trace W Liveness.Event}

theorem clock_cut {last index : Nat} (le : index <= last)
    : clock (cut trace last) index = clock trace index := by
  simp only [clock, cut_stateAt_of_le le]

/-- The timing facts on a shorter cut that ends where the clock first passes an
earlier deadline `bound`. -/
theorem Env.restrict {start last : Nat} {stop delay interval : Real}
    {leader peer : NodeID} (env : Env trace start last stop delay interval leader peer)
    {cutoff : Nat} {bound : Real} (startLe : start <= cutoff) (le : cutoff <= last)
    (stopLe : bound <= stop)
    (below : forall index, index < cutoff -> clock trace index <= bound)
    (beyond : cutoff < last -> bound < clock trace cutoff)
    : Env (cut trace cutoff) start cutoff bound delay interval leader peer := by
  -- A step whose clock is within the bound is a step of the shorter cut.
  have inside : forall index step, trace.stepAt index = some step
      -> clock trace index <= bound -> index < cutoff := by
    intro index step stepped clockLe
    have lt := env.ends index step stepped
    by_contra late
    have := beyond (by omega)
    have := env.mono cutoff index (by omega) lt.le
    linarith
  obtain ⟨lastPoint, lastFound⟩ := env.lastFound
  obtain ⟨point, pointFound⟩ := Trace.stateAt_ge_stable le lastFound
  refine ⟨
    startLe,
    ⟨point, by rw [cut_stateAt_of_le le_rfl]; exact pointFound⟩,
    fun _ _ stepped => (stepAt_of_cut stepped).1,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro index later le' le''
    rw [clock_cut (le'.trans le''), clock_cut le'']
    exact env.mono index later le' (le''.trans le)
  · intro index lt
    rw [clock_cut lt.le]
    exact below index lt
  · intro index step packet sent stepped action sentAt
    obtain ⟨lt, stepped⟩ := stepAt_of_cut stepped
    obtain ⟨sentLt, _⟩ := stepAt_of_cut (Exists.choose_spec sentAt).1
    rw [clock_cut lt.le, clock_cut sentLt.le]
    exact env.prompt index step packet sent stepped action ((cut_sentAt sentLt).mp sentAt)
  · intro index packet afterStart sentAt ends deadline
    obtain ⟨sentLt, _⟩ := stepAt_of_cut (Exists.choose_spec sentAt).1
    have sentAt := (cut_sentAt sentLt).mp sentAt
    rw [clock_cut sentLt.le] at deadline
    obtain ⟨later, step, after, stepped, action⟩ :=
      env.arrives index packet afterStart sentAt ends (by linarith)
    have := env.prompt later step packet index stepped action sentAt
    have lt := inside later step stepped (by linarith)
    exact ⟨later, step, after, by rw [cut_stepAt_of_lt lt]; exact stepped, action⟩
  · intro low startLe' deadline
    rw [clock_cut startLe] at startLe'
    obtain ⟨index, step, batchEnds, afterStart, lower, upper, stepped, action⟩ :=
      env.passes low startLe' (by linarith)
    have lt := inside index step stepped (by linarith)
    exact ⟨index, step, batchEnds, afterStart, by rw [clock_cut lt.le]; exact lower,
      by rw [clock_cut lt.le]; exact upper, by rw [cut_stepAt_of_lt lt]; exact stepped, action⟩

end Restrict

end CCFRaft.Proofs.Timed
