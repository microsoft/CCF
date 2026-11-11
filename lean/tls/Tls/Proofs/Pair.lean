-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Pass
public import Tls.Proofs.Flow
public import Tls.Properties.Streams
public import CCF.Execution

@[expose] public section

/-!
The invariants of two engines on one connection, and what follows from them: both ends stay
coherent and settled, every pass consumes work, and plaintext in flight is conserved.
-/

namespace Tls.Proofs

open Tls.Model Tls.Model.Pair Tls.Properties

/-- What a pass at `side` observes. -/
def envAt (state : Pair.State) (side : Side) : Env :=
  { saturated := state.saturated side, peerClosed := !(state.conn side.peer).alive }

/-- What a pass at `side` acts on. -/
def ioAt (state : Pair.State) (side : Side) : Io :=
  { conn := state.conn side, socket := state.socket side }

theorem pass_alive (config : Config) (env : Env) (io next : Io)
    (passed : pass config env io = some next)
    : io.conn.alive = true := by
  unfold pass at passed
  dsimp only at passed
  split at passed
  · next enabled =>
      simp only [Bool.and_eq_true] at enabled
      exact enabled.1
  · cases passed

theorem pass_step (config : Config) (state next : Pair.State) (actor : Side)
    (stepped : Pair.step config state (.pass actor) = some next)
    : ∃ io,
        pass config (envAt state actor) (ioAt state actor) = some io
        ∧ next = state.setIo actor io := by
  simp only [Pair.step, State.pass, Option.map_eq_some_iff] at stepped
  obtain ⟨io, passed, rfl⟩ := stepped
  exact ⟨io, passed, rfl⟩

/-- Both ends are coherent. -/
def BothCoherent (config : Config) (state : Pair.State) : Prop :=
  ∀ side, Coherent config (state.conn side)

theorem step_coherent (config : Config) (engine : config.Engine) (state next : Pair.State)
    (action : Pair.Action) (coherent : BothCoherent config state)
    (stepped : Pair.step config state action = some next)
    : BothCoherent config next := by
  cases action with
  | pass actor =>
      obtain ⟨io, passed, rfl⟩ := pass_step config state next actor stepped
      have kept :=
        (pass_local
            config
            _
            _
            io
            engine
            (coherent actor)
            (fun _ member => by simp [ioAt] at member)
            passed).1
      intro side
      have other := coherent side
      cases actor <;> cases side <;> simp_all [State.setIo, State.conn]
  | send actor data =>
      simp only [Pair.step, Option.map_eq_some_iff] at stepped
      obtain ⟨conn, sent, rfl⟩ := stepped
      have kept := send_local config data _ conn (coherent actor) sent
      intro side
      have other := coherent side
      cases actor <;> cases side <;> simp_all [State.setConn, State.conn]
  | abort actor =>
      simp only [Pair.step] at stepped
      split at stepped
      · cases stepped
        have kept := abort_local config _ (coherent actor)
        intro side
        have other := coherent side
        cases actor <;> cases side <;> simp_all [State.setConn, State.conn]
      · cases stepped
  | admission actor saturated =>
      intro side
      have other := coherent side
      cases actor <;> cases stepped <;> cases side <;> simp_all [State.conn]

theorem pair_coherent (config : Config) (engine : config.Engine) (state : Pair.State)
    (reachable : (pair config).Reachable state)
    : BothCoherent config state := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec (pair config) with
  | initial initialized =>
      cases initialized
      intro side
      cases side <;> exact initial_local config engine
  | step _ transition ih => exact step_coherent config engine _ _ _ ih transition

/-- Each live end is settled, and no requested KeyUpdate is on its way to either end. -/
def BothSettled (state : Pair.State) : Prop :=
  ∀ side,
    ((state.conn side).alive = true → Settled (state.conn side))
    ∧ .keyUpdate true ∉ (state.conn side).ssl.input ++ (state.socket side).inbound

theorem work_split (state : Pair.State) (side : Side)
    : work state = ioWork (ioAt state side) + endWork (state.conn side.peer) := by
  cases side <;> simp only [work, ioWork, ioAt, State.conn, State.socket, Side.peer] <;> omega

theorem work_setIo (state : Pair.State) (side : Side) (io : Io)
    : work (state.setIo side io) = ioWork io + endWork (state.conn side.peer) := by
  cases side <;> simp only [work, ioWork, State.setIo, State.conn, Side.peer] <;> omega

theorem pass_settled (config : Config) (engine : config.Engine) (kernel : config.Kernel)
    (state next : Pair.State) (actor : Side) (coherent : BothCoherent config state)
    (settled : BothSettled state)
    (stepped : Pair.step config state (.pass actor) = some next)
    : BothSettled next ∧ work next < work state := by
  obtain ⟨io, passed, rfl⟩ := pass_step config state next actor stepped
  have alive := pass_alive config _ _ io passed
  have outbound : .keyUpdate true ∉ (ioAt state actor).socket.outbound := by
    have peer := (settled actor.peer).2
    cases actor <;> simp_all [ioAt, State.socket, State.conn, Side.peer]
  obtain ⟨nextSettled, inboundFree, outboundFree, less⟩ :=
    pass_pair
      config
      _
      _
      io
      engine
      kernel
      (coherent actor)
      ((settled actor).1 alive)
      (settled actor).2
      outbound
      passed
  refine ⟨?_, ?_⟩
  · intro side
    have other := settled side
    cases actor
    <;> cases side
    <;> simp_all [State.setIo, State.conn, State.socket, ioAt]
  · rw [work_setIo, work_split state actor]
    omega

theorem work_setConn (state : Pair.State) (side : Side) (conn : Conn)
    : work (state.setConn side conn) + endWork (state.conn side)
      = work state + endWork conn := by
  cases side <;> simp only [work, State.setConn, State.conn] <;> omega

theorem send_settled (config : Config) (data : List Payload) (conn next : Conn)
    (settled : conn.alive = true → Settled conn)
    (sent : send config data conn = some next)
    : (next.alive = true → Settled next)
      ∧ next.ssl.input = conn.ssl.input
      ∧ endWork next ≤ endWork conn + 6 * data.length + 2 := by
  unfold send at sent
  split at sent
  · next alive =>
      obtain ⟨⟨notQueued, notInit, notReadBlocked⟩, notPaused, wakeRead, _⟩ :=
        settled alive
      split at sent
      · cases sent
        refine ⟨fun _ => ⟨⟨notQueued, notInit, notReadBlocked⟩, notPaused, wakeRead, ?_⟩, rfl, ?_⟩
        · simp
        · simp only [endWork, List.length_append]
          grind [List.isEmpty_iff, List.append_eq_nil_iff]
      · cases sent
        refine ⟨by simp, rfl, ?_⟩
        simp only [endWork]
        grind
  · cases sent

theorem step_settled (config : Config) (engine : config.Engine) (kernel : config.Kernel)
    (state next : Pair.State) (action : Pair.Action)
    (coherent : BothCoherent config state) (settled : BothSettled state)
    (stepped : Pair.step config state action = some next)
    : BothSettled next
      ∧ (if isPass action then 1 else 0) + work next ≤ work state + addedWork action := by
  cases action with
  | pass actor =>
      have passed := pass_settled config engine kernel state next actor coherent settled stepped
      refine ⟨passed.1, ?_⟩
      simp only [isPass, addedWork, ite_true]
      omega
  | send actor data =>
      simp only [Pair.step, Option.map_eq_some_iff] at stepped
      obtain ⟨conn, sent, rfl⟩ := stepped
      obtain ⟨kept, input, bound⟩ := send_settled config data _ conn (settled actor).1 sent
      have total := work_setConn state actor conn
      refine ⟨?_, ?_⟩
      · intro side
        have other := settled side
        cases actor <;> cases side <;> simp_all [State.setConn, State.conn, State.socket]
      · simp only [isPass, addedWork, Bool.false_eq_true, ite_false]
        omega
  | abort actor =>
      simp only [Pair.step] at stepped
      split at stepped
      · next alive =>
          cases stepped
          have total := work_setConn state actor { state.conn actor with alive := false }
          refine ⟨?_, ?_⟩
          · intro side
            have other := settled side
            cases actor <;> cases side <;> simp_all [State.setConn, State.conn, State.socket]
          · simp only [isPass, addedWork, endWork, alive] at total ⊢
            grind
      · cases stepped
  | admission actor saturated =>
      refine ⟨?_, ?_⟩
      · intro side
        have other := settled side
        cases actor <;> cases stepped <;> cases side <;> simp_all [State.conn, State.socket]
      · cases actor <;> cases stepped <;> simp [isPass, addedWork, work]

theorem pair_settled (config : Config) (engine : config.Engine) (kernel : config.Kernel)
    (state : Pair.State) (reachable : (pair config).Reachable state)
    : BothSettled state := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec (pair config) with
  | initial initialized =>
      cases initialized
      intro side
      cases side
      <;> refine ⟨fun _ => ⟨⟨rfl, by simp [State.conn, Conn.initial], rfl⟩, rfl, ?_, ?_⟩, ?_⟩
      <;> simp [State.conn, State.socket, Conn.initial]
  | @step state next action reachable transition ih =>
      exact (step_settled
              config
              engine
              kernel
              state
              next
              action
              (pair_coherent config engine state reachable)
              ih
              transition).1

/-- The plaintext on its way to `side`, oldest first. -/
def inFlight (state : Pair.State) (side : Side) : List Payload :=
  payloads ((state.conn side).ssl.input ++ (state.socket side).inbound)
  ++ (state.conn side.peer).output

theorem step_flow (config : Config) (state next : Pair.State) (action : Pair.Action)
    (side : Side) (coherent : BothCoherent config state)
    (stepped : Pair.step config state action = some next)
    : delivered config state side action ++ inFlight next side
      = inFlight state side ++ accepted config state side.peer action := by
  cases action with
  | pass actor =>
      obtain ⟨io, passed, rfl⟩ := pass_step config state next actor stepped
      obtain ⟨_, incomingKept, outgoingKept⟩ :=
        pass_flow config (envAt state actor) (ioAt state actor) io (coherent actor).head passed
      have observed : State.pass config state actor = some io := passed
      simp only [incoming, outgoing, ioAt, List.map_nil, List.nil_append, payloads_append]
        at incomingKept outgoingKept
      cases actor
      <;> cases side
      <;> simp_all [delivered, deliveries, accepted, inFlight, State.setIo, State.conn,
        State.socket, Side.peer, payloads_append]
      <;> grind
  | send actor data =>
      simp only [Pair.step, Option.map_eq_some_iff] at stepped
      obtain ⟨conn, sent, rfl⟩ := stepped
      unfold send at sent
      split at sent
      · split at sent
        · cases sent
          cases actor
          <;> cases side
          <;> simp_all [delivered, deliveries, accepted, inFlight, State.setConn, State.conn,
            State.socket, Side.peer]
        · cases sent
          cases actor
          <;> cases side
          <;> simp_all [delivered, deliveries, accepted, inFlight, State.setConn, State.conn,
            State.socket, Side.peer]
      · cases sent
  | abort actor =>
      simp only [Pair.step] at stepped
      split at stepped
      · cases stepped
        cases actor
        <;> cases side
        <;> simp [delivered, deliveries, accepted, inFlight, State.setConn, State.conn,
          State.socket, Side.peer]
      · cases stepped
  | admission actor saturated =>
      cases actor
      <;> cases stepped
      <;> cases side
      <;> simp [delivered, deliveries, accepted, inFlight, State.conn, State.socket, Side.peer]

theorem run_reachable (config : Config) (actions : List Pair.Action)
    (start final : Pair.State) (reachable : (pair config).Reachable start)
    (run : CCF.Execution.Run (pair config) start actions final)
    : (pair config).Reachable final := by
  induction actions generalizing start with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn (pair config)
      exact reachable
  | cons action rest ih =>
      cases run using @CCF.Execution.Run.casesOn (pair config) with
      | cons stepped remaining => exact ih _ (.step reachable stepped) remaining

theorem run_flow (config : Config) (engine : config.Engine) (side : Side)
    (actions : List Pair.Action) (start final : Pair.State)
    (coherent : BothCoherent config start)
    (run : CCF.Execution.Run (pair config) start actions final)
    : deliveredAlong config side start actions ++ inFlight final side
      = inFlight start side ++ acceptedAlong config side.peer start actions := by
  induction actions generalizing start with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn (pair config)
      simp [deliveredAlong, acceptedAlong, collect]
  | cons action rest ih =>
      cases run using @CCF.Execution.Run.casesOn (pair config) with
      | @cons _ middle _ _ _ stepped remaining =>
          have stepped : Pair.step config start action = some middle := stepped
          have first := step_flow config start middle action side coherent stepped
          have later := ih middle (step_coherent config engine _ _ _ coherent stepped) remaining
          simp only [deliveredAlong, acceptedAlong, collect, stepped] at later ⊢
          rw [List.append_assoc, later, ← List.append_assoc, first, List.append_assoc]

theorem run_work (config : Config) (engine : config.Engine) (kernel : config.Kernel)
    (actions : List Pair.Action) (start final : Pair.State)
    (reachable : (pair config).Reachable start)
    (run : CCF.Execution.Run (pair config) start actions final)
    : (actions.filter isPass).length + work final
      ≤ work start + (actions.map addedWork).sum := by
  induction actions generalizing start with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn (pair config)
      simp
  | cons action rest ih =>
      cases run using @CCF.Execution.Run.casesOn (pair config) with
      | @cons _ middle _ _ _ stepped remaining =>
          have later := ih middle (.step reachable stepped) remaining
          have first :=
            (step_settled
                config
                engine
                kernel
                start
                middle
                action
                (pair_coherent config engine start reachable)
                (pair_settled config engine kernel start reachable)
                stepped).2
          simp only [List.filter_cons, List.map_cons, List.sum_cons]
          split <;> simp_all <;> omega

theorem pass_enabled (config : Config) (env : Env) (io : Io)
    (enabled
      : (io.conn.alive
          && (io.conn.dirty || readableEvent env io || writableEvent config env io))
        = true)
    : ∃ next, pass config env io = some next := by
  unfold pass
  dsimp only
  simp only [enabled, ↓reduceIte]
  exact ⟨_, rfl⟩

theorem progress_enabled (config : Config) (engine : config.Engine)
    (kernel : config.Kernel) (state : Pair.State)
    (reachable : (pair config).Reachable state) (side : Side)
    (leftAlive : state.left.alive = true) (rightAlive : state.right.alive = true)
    (transit : InTransit state side) (admitting : state.saturated side = false)
    : ∃ actor next,
        Pair.step config state (.pass actor) = some next ∧ work next < work state := by
  have coherent := pair_coherent config engine state reachable
  have settled := pair_settled config engine kernel state reachable
  have alive : ∀ end_, (state.conn end_).alive = true := by
    intro end_
    cases end_ <;> assumption
  suffices enabled
            :
    ∃ actor,
      ((ioAt state actor).conn.alive
        && ((ioAt state actor).conn.dirty
            || readableEvent (envAt state actor) (ioAt state actor)
            || writableEvent config (envAt state actor) (ioAt state actor)))
      = true by
    obtain ⟨actor, enabled⟩ := enabled
    obtain ⟨next, passed⟩ := pass_enabled config _ _ enabled
    have stepped : Pair.step config state (.pass actor) = some (state.setIo actor next) := by
      simp only [Pair.step]
      rw [show State.pass config state actor = some next from passed]
      rfl
    exact ⟨
      actor,
      _,
      stepped,
      (pass_settled config engine kernel state _ actor coherent settled stepped).2
    ⟩
  obtain ⟨⟨_, _, notReadBlocked⟩, notPaused, wakeRead, _⟩ := (settled side).1 (alive side)
  obtain ⟨⟨_, _, peerNotReadBlocked⟩, _, _, peerWakeWrite⟩ :=
    (settled side.peer).1 (alive side.peer)
  by_cases buffered : (state.conn side).ssl.input ≠ [] ∨ (state.socket side).inbound ≠ []
  · refine ⟨side, ?_⟩
    simp only [ioAt, envAt, readableEvent, readInterestWithheld, alive side, admitting,
      notPaused, notReadBlocked]
    rcases buffered with input | inbound
    · simp [wakeRead input]
    · simp [inbound]
  · refine ⟨side.peer, ?_⟩
    have queued : (state.conn side.peer).output ≠ [] := by
      rcases transit with output | inbound | input
      · exact output
      · exact absurd (Or.inr inbound) buffered
      · exact absurd (Or.inl input) buffered
    have writable : pollsWritable config (state.socket side.peer) = true := by
      have empty : (state.socket side.peer).outbound = [] := by
        have : (state.socket side).inbound = [] := by
          false_or_by_contra
          exact buffered (Or.inr ‹_›)
        cases side <;> simpa [State.socket, Side.peer] using this
      have := kernel.2
      simp [pollsWritable, empty]
      omega
    simp only [ioAt, envAt, writableEvent, alive side.peer, writable, peerNotReadBlocked]
    rcases peerWakeWrite queued with dirty | wantWrite
    · simp [dirty]
    · simp [wantWrite]

theorem quiescent_delivered (config : Config) (engine : config.Engine)
    (kernel : config.Kernel) (actions : List Pair.Action) (final : Pair.State)
    (run : CCF.Execution.Run (pair config) {} actions final) (side : Side)
    (leftAlive : final.left.alive = true) (rightAlive : final.right.alive = true)
    (admitting : final.saturated side = false)
    (stuck : ∀ actor, Pair.step config final (.pass actor) = none)
    : deliveredAlong config side {} actions
      = acceptedAlong config side.peer {} actions := by
  have initial : (pair config).Reachable {} := .initial rfl
  have reachable := run_reachable config actions {} final initial run
  have flow :=
    run_flow config engine side actions {} final (pair_coherent config engine {} initial) run
  have settledNow : ¬InTransit final side := by
    intro transit
    obtain ⟨actor, next, stepped, _⟩ :=
      progress_enabled
        config
        engine
        kernel
        final
        reachable
        side
        leftAlive
        rightAlive
        transit
        admitting
    rw [stuck actor] at stepped
    cases stepped
  have empty : inFlight final side = [] := by
    simp only [InTransit, not_or, Decidable.not_not] at settledNow
    simp [inFlight, settledNow.1, settledNow.2.1, settledNow.2.2, payloads]
  have start : inFlight {} side = [] := by
    cases side <;> simp [inFlight, State.conn, State.socket, Conn.initial, payloads, Side.peer]
  rw [empty, start] at flow
  simpa using flow

theorem stream_integrity (config : Config) (engine : config.Engine)
    (actions : List Pair.Action) (final : Pair.State)
    (run : CCF.Execution.Run (pair config) {} actions final) (side : Side)
    : deliveredAlong config side {} actions
      <+: acceptedAlong config side.peer {} actions := by
  have initial : (pair config).Reachable {} := .initial rfl
  have flow :=
    run_flow config engine side actions {} final (pair_coherent config engine {} initial) run
  have start : inFlight {} side = [] := by
    cases side <;> simp [inFlight, State.conn, State.socket, Conn.initial, payloads, Side.peer]
  rw [start, List.nil_append] at flow
  exact ⟨_, flow⟩

theorem deadlock_free (config : Config) : (pair config).DeadlockFree := by
  intro state _
  exact ⟨.admission .left false, _, rfl⟩

end Tls.Proofs
