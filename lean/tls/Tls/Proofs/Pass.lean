-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Settled

@[expose] public section

/-!
A worker pass over a connection whose peer never requests a KeyUpdate keeps the connection
settled and strictly reduces the work measure.
-/

namespace Tls.Proofs

open Tls.Model Tls.Properties

/-- A quiet connection whose buffered input and queued output each have a wake-up pending. -/
structure Settled (conn : Conn) : Prop where
  /-- No KeyUpdate is outstanding. -/
  quiet : Quiet conn
  /-- Read interest is not withheld behind a write. -/
  notPaused : conn.readPaused = false
  /-- Buffered input has a readable event pending. -/
  wakeRead : conn.ssl.input ≠ [] → conn.pendingRead = true
  /-- Queued output has a pass or a writable event pending. -/
  wakeWrite : conn.output ≠ [] → conn.dirty = true ∨ conn.wantWrite = true

/-- The work measure of one end and its socket. -/
def ioWork (io : Io) : Nat :=
  endWork io.conn + 2 * io.socket.inbound.length + 2 * io.socket.outbound.length

theorem ioWork_eq (io : Io)
    : ioWork io
      = writeWork io
        + readWork io
        + (if io.conn.dirty then 2 else 0)
        + (if io.conn.wantWrite && io.conn.output.isEmpty then 1 else 0)
        + (if io.conn.pendingRead && io.conn.ssl.input.isEmpty then 1 else 0)
        + (if io.conn.alive then 1 else 0) := by
  simp only [ioWork, endWork, writeWork, readWork]
  omega

theorem prefetchStage_quiet (config : Config) (env : Env) (readable : Bool) (io : Io)
    (quiet : io.conn.alive = true → Quiet io.conn)
    : prefetchStage config env readable io = io
      ∧ (io.conn.alive = true → readBlockedByWrite io.conn = false) := by
  have unblocked : io.conn.alive = true → readBlockedByWrite io.conn = false := by
    intro alive
    obtain ⟨notQueued, notInit, _⟩ := quiet alive
    simp [readBlockedByWrite, inInit, notQueued, notInit]
  refine ⟨?_, unblocked⟩
  unfold prefetchStage
  split
  · next condition =>
      simp only [Bool.and_eq_true] at condition
      have := unblocked condition.1.1.1.1
      simp_all
  · rfl

/-- What the first stage of a pass does to a settled connection. -/
structure RetryOutcome (config : Config) (env : Env) (io next : Io) : Prop where
  /-- The connection stays coherent. -/
  coherent : Coherent config next.conn
  /-- The connection stays quiet. -/
  quiet : next.conn.alive = true → Quiet next.conn
  /-- No requested KeyUpdate is written. -/
  unrequested : .keyUpdate true ∉ next.socket.outbound
  /-- The input buffer is unchanged. -/
  input : next.conn.ssl.input = io.conn.ssl.input
  /-- The receive buffer is unchanged. -/
  inbound : next.socket.inbound = io.socket.inbound
  /-- `pendingRead` is unchanged. -/
  pendingRead : next.conn.pendingRead = io.conn.pendingRead
  /-- `dirty` is unchanged. -/
  dirty : next.conn.dirty = io.conn.dirty
  /-- A spent writable wake-up is not created. -/
  flag
    : next.conn.wantWrite = true
      → next.conn.output = []
      → io.conn.wantWrite = true ∧ io.conn.output = []
  /-- Writing does not add work. -/
  work : writeWork next ≤ writeWork io
  /-- A retried write on a writable socket consumes work. -/
  progress
    : io.conn.writeRetry = true
      → next.conn.alive = true
      → pollsWritable config io.socket = true ∨ env.peerClosed = true
      → writeWork next < writeWork io
  /-- Without a write to retry, nothing happens. -/
  same : io.conn.writeRetry = false → next = io

theorem retryStage_pair (config : Config) (env : Env) (io : Io) (engine : config.Engine)
    (kernel : config.Kernel) (coherent : Coherent config io.conn)
    (alive : io.conn.alive = true) (quiet : Quiet io.conn)
    (unrequested : .keyUpdate true ∉ io.socket.outbound)
    : RetryOutcome config env io (retryStage config env io) := by
  unfold retryStage
  split
  · next retrying =>
      have kept := doWrite_local config env io engine coherent alive
      have nonempty := (coherent.retry alive retrying).2.1
      obtain ⟨q, u, i, n, p, d, _, settled, dead, w, progress⟩ :=
        doWrite_pair config env io kernel coherent alive quiet unrequested
      refine ⟨kept.1, q, u, i, n, p, d, ?_, w, fun _ live room => progress live nonempty room, ?_⟩
      · intro wants empty
        cases stillAlive : (doWrite config env io).conn.alive
        · have := dead stillAlive
          simp_all
        · have := (settled stillAlive).1 empty
          simp_all
      · intro notRetrying
        simp_all
  · exact ⟨
      coherent,
      fun _ => quiet,
      unrequested,
      rfl,
      rfl,
      rfl,
      rfl,
      fun wants empty => ⟨wants, empty⟩,
      Nat.le_refl _,
      fun retrying => by simp_all,
      fun _ => rfl
    ⟩

theorem readStage_pair (config : Config) (env : Env) (readable : Bool) (io : Io)
    (engine : config.Engine) (coherent : Coherent config io.conn)
    (alive : io.conn.alive = true) (quiet : Quiet io.conn)
    (unrequested : .keyUpdate true ∉ io.conn.ssl.input ++ io.socket.inbound)
    : Coherent config (readStage config env readable io).1.conn
      ∧ ReadOutcome
          env
          (if readable then config.readsPerPass else 0)
          io
          (readStage config env readable io) := by
  have reads := engine.2.2
  unfold readStage
  split
  · have kept :=
      doRead_local
        config
        env
        engine
        config.readsPerPass
        io
        coherent
        alive
        (fun _ => ⟨quiet.notInit, quiet.notQueued⟩)
        (fun _ => True)
        (fun _ _ => trivial)
        (fun _ _ => trivial)
    refine ⟨kept.1, ?_⟩
    obtain ⟨q, u, o, ob, ww, pr, d, wr, rp, p, w, m, s, progress⟩ :=
      doRead_pair config env engine config.readsPerPass io alive quiet unrequested
    exact ⟨q, u, o, ob, ww, pr, d, wr, rp, p, w, m, s, fun open_ _ => progress open_ (by omega)⟩
  · next skipped =>
      refine ⟨coherent, ?_⟩
      have unreadable : readable = false := by simp_all
      constructor <;> simp_all

theorem pass_pair (config : Config) (env : Env) (io next : Io) (engine : config.Engine)
    (kernel : config.Kernel) (coherent : Coherent config io.conn)
    (settled : Settled io.conn)
    (inboundUnrequested : .keyUpdate true ∉ io.conn.ssl.input ++ io.socket.inbound)
    (outboundUnrequested : .keyUpdate true ∉ io.socket.outbound)
    (passed : pass config env io = some next)
    : (next.conn.alive = true → Settled next.conn)
      ∧ .keyUpdate true ∉ next.conn.ssl.input ++ next.socket.inbound
      ∧ .keyUpdate true ∉ next.socket.outbound
      ∧ ioWork next < ioWork io := by
  obtain ⟨quiet, notPaused, wakeRead, wakeWrite⟩ := settled
  unfold pass at passed
  dsimp only at passed
  split at passed
  · next enabled =>
      have live : io.conn.alive = true := by
        simp only [Bool.and_eq_true] at enabled
        exact enabled.1
      have readableOpen : readableEvent env io = true → env.saturated = false := by
        simp [readableEvent, readInterestWithheld]
        grind
      have readableWhy
        : readableEvent env io = true
          → io.conn.pendingRead = true ∨ io.socket.inbound ≠ [] ∨ env.peerClosed = true := by
        simp [readableEvent]
        grind
      have pendingReadable
        : env.saturated = false → io.conn.pendingRead = true → readableEvent env io = true := by
        simp [readableEvent, readInterestWithheld, notPaused, quiet.notReadBlocked]
        grind
      have reason
        : io.conn.dirty = true
          ∨ readableEvent env io = true
          ∨ (io.conn.wantWrite = true
            ∧ (pollsWritable config io.socket = true ∨ env.peerClosed = true)) := by
        simp [writableEvent, live] at enabled
        grind
      have reads := engine.2.2
      have appRetry : io.conn.ssl.pending.isApp = true → io.conn.writeRetry = true := by
        intro app
        cases pending : io.conn.ssl.pending <;> simp [pending, Pending.isApp] at app
        exact coherent.pendingApp live _ pending
      have retryFacts := coherent.retry live
      simp only [pollsWritable] at reason
      generalize readableEvent env io = readable
        at readableOpen readableWhy pendingReadable reason passed
      rw [driveReady_stages] at passed
      have retried :=
        retryStage_pair config env io engine kernel coherent live quiet
          outboundUnrequested
      generalize retryStage config env io = retriedIo at retried passed
      obtain ⟨same, unblocked⟩ :=
        prefetchStage_quiet config env readable retriedIo retried.quiet
      rw [same] at passed
      obtain ⟨c1, q1, u1, i1, n1, _, _, f1, w1, g1, s1⟩ := retried
      split at passed
      · next stopped =>
          have dead : retriedIo.conn.alive = false := by
            cases stillAlive : retriedIo.conn.alive
            · rfl
            · simp [stillAlive, unblocked stillAlive] at stopped
          cases passed
          simp only [completeDrive]
          refine ⟨by simp [dead], by simpa [i1, n1] using inboundUnrequested, u1, ?_⟩
          rw [ioWork_eq, ioWork_eq]
          simp only [writeWork, readWork] at w1 ⊢
          grind
      · next proceeding =>
          have alive1 : retriedIo.conn.alive = true := by
            cases stillAlive : retriedIo.conn.alive
            · simp [stillAlive] at proceeding
            · rfl
          obtain ⟨c3, q3, u3, o3, ob3, ww3, pr3, d3, wr3, rp3, p3, w3, m3, s3, g3⟩ :=
            readStage_pair
              config
              env
              readable
              retriedIo
              engine
              c1
              alive1
              (q1 alive1)
              (by simpa [i1, n1] using inboundUnrequested)
          generalize readStage config env readable retriedIo = readResult
            at c3 q3 u3 o3 ob3 ww3 pr3 d3 wr3 rp3 p3 w3 m3 s3 g3 passed
          obtain ⟨readIo, more⟩ := readResult
          unfold writeStage at passed
          dsimp only at c3 q3 u3 o3 ob3 ww3 pr3 d3 wr3 rp3 p3 w3 m3 s3 g3 passed
          split at passed
          · next alive3 =>
              have c4 := (doWrite_local config env readIo engine c3 alive3).1
              obtain ⟨q4, u4, i4, n4, p4, d4, rp4, settled4, dead4, w4, g4⟩ :=
                doWrite_pair config env readIo kernel c3 alive3 (q3 alive3) (by rw [ob3]; exact u1)
              generalize doWrite config env readIo = writtenIo
                at c4 q4 u4 i4 n4 p4 d4 rp4 settled4 dead4 w4 g4 passed
              cases passed
              simp only [completeDrive]
              refine ⟨?_, by simpa [i4, n4] using u3, u4, ?_⟩
              · intro alive4
                obtain ⟨notQueued, notInit, notReadBlocked⟩ := q4 alive4
                have := settled4 alive4
                constructor
                · exact ⟨notQueued, notInit, notReadBlocked⟩
                · simp [readBlockedByWrite, inInit, notQueued, notInit]
                · intro nonempty
                  simp [readBlockedByWrite, inInit, notQueued, notInit, notReadBlocked, hasInput, nonempty]
                · simp
                  grind
              · rw [ioWork_eq, ioWork_eq]
                clear inboundUnrequested outboundUnrequested u1 u3 u4 c1 c3 c4 coherent enabled same
                  unblocked proceeding engine kernel
                simp only [
                  writeWork,
                  readWork,
                  pollsWritable,
                  hasInput,
                  Bool.and_eq_true,
                  Bool.or_eq_true,
                  Bool.not_eq_eq_eq_not,
                  Bool.not_true,
                  List.isEmpty_iff,
                  List.isEmpty_eq_false_iff,
                  decide_eq_true_eq
                ] at w1 w3 w4 g1 g3 g4 reason ⊢
                cases saturated : env.saturated
                <;> cases isReadable : readable
                <;> cases retrying : io.conn.writeRetry
                <;> grind (splits := 30)
          · next dead3 =>
              cases passed
              simp only [completeDrive]
              refine ⟨by simp [dead3], u3, by rw [ob3]; exact u1, ?_⟩
              rw [ioWork_eq, ioWork_eq]
              simp only [writeWork, readWork, pollsWritable] at w1 w3 g1 g3 ⊢
              cases retrying : io.conn.writeRetry
                <;> cases saturated : env.saturated
                <;> grind [hasInput, List.isEmpty_iff, List.isEmpty_eq_false_iff]
  · cases passed

end Tls.Proofs
