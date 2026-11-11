-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Basic

@[expose] public section

/-!
The invariant of one connection against an arbitrary peer and owner, and its preservation by
every operation of the engine model.
-/

namespace Tls.Proofs

open Tls.Model

/-- What holds of every connection, whatever its peer and owner do. -/
structure Coherent (config : Config) (conn : Conn) : Prop where
  /-- No forbidden OpenSSL operation has been performed. -/
  notMisused : conn.ssl.misused = false
  /-- The sending key is within its budget. -/
  sent : conn.ssl.sent ≤ config.recordBudget
  /-- Unless a KeyUpdate is already constructed, a record is left for it. -/
  reserve : conn.ssl.pending ≠ .update → conn.ssl.sent + 1 ≤ config.recordBudget
  /-- The input buffer is within its size. -/
  input : conn.ssl.input.length ≤ config.inputBuffer
  /-- The engine's count does not understate the queued output. -/
  queued : conn.output.length ≤ conn.queued
  /-- The engine's count is within the bound. -/
  bound : ∀ bound, config.maxQueuedOutput = some bound → conn.queued ≤ bound
  /-- A pending application record is the head of the queued output. -/
  head : ∀ payload, conn.ssl.pending = .app payload → conn.output.head? = some payload
  /-- The receiving key is within its budget. -/
  received : conn.alive = true → conn.ssl.received ≤ config.recordBudget
  /-- A pending application record is recorded as a write retry. -/
  pendingApp
    : conn.alive = true
      → ∀ payload, conn.ssl.pending = .app payload → conn.writeRetry = true
  /-- A write retry has a pending record, queued output, and waits for the socket. -/
  retry
    : conn.alive = true → conn.writeRetry = true
      → conn.ssl.pending ≠ .none
        ∧ conn.output ≠ []
        ∧ conn.wantWrite = true
        ∧ conn.readWantsWrite = false
  /-- A read blocked on a write has a constructed KeyUpdate and waits for the socket. -/
  readWrite
    : conn.alive = true
      → conn.readWantsWrite = true
      → conn.ssl.pending = .update ∧ conn.wantWrite = true
  /-- A constructed KeyUpdate belongs to a blocked read or to a write retry. -/
  update
    : conn.alive = true
      → conn.ssl.pending = .update
      → conn.readWantsWrite = true ∨ conn.writeRetry = true

theorem sslWrite_local (config : Config) (env : Env) (payload : Payload) (ssl : Ssl)
    (socket : Socket) (budget : 2 ≤ config.recordBudget)
    (notMisused : ssl.misused = false) (sent : ssl.sent ≤ config.recordBudget)
    (reserve : ssl.pending ≠ .update → ssl.sent + 1 ≤ config.recordBudget)
    (head : ∀ pending, ssl.pending = .app pending → pending = payload)
    (scheduled
      : ssl.pending = .none
        → ssl.updateQueued = false
        → ssl.sent + 2 ≤ config.recordBudget)
    : (sslWrite config env payload ssl socket).2.1.misused = false
      ∧ (sslWrite config env payload ssl socket).2.1.sent ≤ config.recordBudget
      ∧ ((sslWrite config env payload ssl socket).2.1.pending ≠ .update
          → (sslWrite config env payload ssl socket).2.1.sent + 1 ≤ config.recordBudget)
      ∧ (sslWrite config env payload ssl socket).2.1.received = ssl.received
      ∧ (sslWrite config env payload ssl socket).2.1.input = ssl.input
      ∧ ((sslWrite config env payload ssl socket).1 = .written
          → (sslWrite config env payload ssl socket).2.1.pending = .none)
      ∧ ((sslWrite config env payload ssl socket).1 = .wantWrite
          → (sslWrite config env payload ssl socket).2.1.pending ≠ .none
            ∧ ∀ pending,
                (sslWrite config env payload ssl socket).2.1.pending = .app pending
                → pending = payload)
      ∧ ((sslWrite config env payload ssl socket).1 = .failed
          → (sslWrite config env payload ssl socket).2.1 = ssl) := by
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases queued : ssl.updateQueued = true
  <;> by_cases closed : env.peerClosed = true
  <;> simp [sslWrite, flushUpdate, Ssl.startUpdate, *]
  <;> grind

theorem sslRead_local (config : Config) (env : Env) (ssl : Ssl) (socket : Socket)
    (budget : 2 ≤ config.recordBudget) (notMisused : ssl.misused = false)
    (sent : ssl.sent ≤ config.recordBudget)
    (reserve : ssl.pending ≠ .update → ssl.sent + 1 ≤ config.recordBudget)
    (input : ssl.input.length ≤ config.inputBuffer)
    (received : ssl.received ≤ config.recordBudget)
    (legal : ¬(ssl.updateQueued = true ∧ ssl.pending.isApp = true))
    : (sslRead config env ssl socket).2.1.misused = false
      ∧ (sslRead config env ssl socket).2.1.sent ≤ config.recordBudget
      ∧ ((sslRead config env ssl socket).2.1.pending ≠ .update
          → (sslRead config env ssl socket).2.1.sent + 1 ≤ config.recordBudget)
      ∧ (sslRead config env ssl socket).2.1.input.length ≤ config.inputBuffer
      ∧ (∀ payload,
          (sslRead config env ssl socket).2.1.pending = .app payload
          ↔ ssl.pending = .app payload)
      ∧ ((sslRead config env ssl socket).1 = .wantWrite
          ↔ (sslRead config env ssl socket).2.1.pending = .update)
      ∧ (ssl.pending ≠ .update
          → ssl.updateQueued = false
          → (sslRead config env ssl socket).2.1.pending = ssl.pending)
      ∧ ((sslRead config env ssl socket).1 ≠ .failed
          → (sslRead config env ssl socket).2.1.received ≤ config.recordBudget)
      ∧ ∀ delivery,
          (sslRead config env ssl socket).1 = .data delivery
          → delivery.keyRecord ≤ config.recordBudget := by
  cases pending : ssl.pending
  <;> by_cases accepted : accepts config socket = true
  <;> by_cases queued : ssl.updateQueued = true
  <;> by_cases empty : ssl.input = []
  <;> simp [sslRead, flushUpdate, refill, Ssl.startUpdate, Pending.isApp, *] at legal ⊢
  <;> (repeat' split)
  <;> simp_all
  <;> grind [→ take_cons_length]

theorem doWrite_local (config : Config) (env : Env) (io : Io) (engine : config.Engine)
    (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    : Coherent config (doWrite config env io).conn
      ∧ (doWrite config env io).delivered = io.delivered := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := coherent
  unfold doWrite
  split
  · exact ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩, rfl⟩
  · split
    · refine ⟨?_, rfl⟩
      constructor <;> grind
    · split
      · refine ⟨?_, rfl⟩
        constructor <;> grind
      · next payload rest output _ =>
          obtain ⟨updateQueued, misused, scheduled, s1, s2, s3, _, _⟩ :=
            schedule_spec config io.conn
          rw [scheduled]
          have pending := pending_cases io.conn.ssl.pending
          have notMisused : misused = false := by grind
          have write :=
            sslWrite_local
              config
              env
              payload
              ⟨
                io.conn.ssl.sent,
                io.conn.ssl.received,
                io.conn.ssl.pending,
                updateQueued,
                io.conn.ssl.input,
                misused
              ⟩
              io.socket
              engine.1
              notMisused
              h2
              h3
              (by grind)
              (by grind)
          dsimp only at write ⊢
          generalize
            sslWrite
              config
              env
              payload
              ⟨
                io.conn.ssl.sent,
                io.conn.ssl.received,
                io.conn.ssl.pending,
                updateQueued,
                io.conn.ssl.input,
                misused
              ⟩
              io.socket
            = out
            at write ⊢
          obtain ⟨result, ssl, socket⟩ := out
          cases result
          <;> refine ⟨?_, rfl⟩
          <;> simp only [close] at write ⊢
          <;> constructor
          <;> grind

theorem doRead_local (config : Config) (env : Env) (engine : config.Engine) (fuel : Nat)
    (io : Io) (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    (unblocked
      : io.conn.writeRetry = true
        → io.conn.ssl.pending ≠ .update ∧ io.conn.ssl.updateQueued = false)
    (allowed : Delivery → Prop)
    (inBudget : ∀ delivery, delivery.keyRecord ≤ config.recordBudget → allowed delivery)
    (within : ∀ delivery ∈ io.delivered, allowed delivery)
    : Coherent config (doRead config env fuel io).1.conn
      ∧ ∀ delivery ∈ (doRead config env fuel io).1.delivered, allowed delivery := by
  induction fuel generalizing io with
  | zero =>
      simp only [doRead]
      exact ⟨coherent, within⟩
  | succ fuel ih =>
      obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := coherent
      simp only [doRead]
      split
      · exact ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩, within⟩
      · have legal : ¬(io.conn.ssl.updateQueued = true ∧ io.conn.ssl.pending.isApp = true) := by
          intro ⟨queued, app⟩
          cases pending : io.conn.ssl.pending <;> simp [pending, Pending.isApp] at app
          grind
        have read :=
          sslRead_local config env io.conn.ssl io.socket engine.1 h1 h2 h3 h4 (h8 alive) legal
        generalize sslRead config env io.conn.ssl io.socket = out at read ⊢
        obtain ⟨result, ssl, socket⟩ := out
        cases result with
        | failed =>
            dsimp only [close] at read ⊢
            refine ⟨?_, within⟩
            constructor <;> grind
        | wantWrite =>
            dsimp only at read ⊢
            refine ⟨?_, within⟩
            constructor <;> grind
        | data delivery =>
            dsimp only at read ⊢
            have next
              : Coherent
                  config
                  { io.conn with ssl, readWantsWrite := false } := by
              constructor <;> grind
            have delivered : ∀ entry ∈ io.delivered ++ [delivery], allowed entry := by
              intro entry member
              rcases List.mem_append.mp member with old | new
              · exact within entry old
              · have same : entry = delivery := by simpa using new
                rw [same]
                exact inBudget delivery (read.2.2.2.2.2.2.2.2 delivery rfl)
            split
            · exact ⟨next, delivered⟩
            · exact ih _ next alive (by grind) delivered
        | wantRead progressed =>
            dsimp only at read ⊢
            have next
              : Coherent
                  config
                  { io.conn with ssl, readWantsWrite := false } := by
              constructor <;> grind
            split
            · next continuing =>
                refine ih _ next alive ?_ within
                simp [readBlockedByWrite, inInit] at continuing
                grind
            · exact ⟨next, within⟩

theorem prefetch_local (config : Config) (env : Env) (io : Io) (engine : config.Engine)
    (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    : Coherent config (prefetch config env io).conn
      ∧ (prefetch config env io).delivered = io.delivered := by
  obtain ⟨input, inbound, filled, bounded, _, _, _⟩ := refill_spec config io.conn.ssl io.socket
  have next : Coherent config { io.conn with ssl := { io.conn.ssl with input } } := by
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := coherent
    constructor <;> grind
  simp only [prefetch, filled]
  split
  · refine ⟨?_, rfl⟩
    obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _⟩ := next
    simp only [close]
    constructor <;> grind
  · exact doWrite_local config env _ engine next alive

theorem driveReady_local (config : Config) (env : Env) (readable : Bool) (io : Io)
    (engine : config.Engine) (coherent : Coherent config io.conn)
    (alive : io.conn.alive = true)
    (within : ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget)
    : Coherent config (driveReady config env readable io).1.conn
      ∧ ∀ delivery ∈ (driveReady config env readable io).1.delivered,
          delivery.keyRecord ≤ config.recordBudget := by
  rw [driveReady_stages]
  have retried
    : Coherent config (retryStage config env io).conn
      ∧ (retryStage config env io).delivered = io.delivered := by
    unfold retryStage
    split
    · exact doWrite_local config env io engine coherent alive
    · exact ⟨coherent, rfl⟩
  generalize retryStage config env io = retriedIo at retried ⊢
  have fetched
    : Coherent config (prefetchStage config env readable retriedIo).conn
      ∧ (prefetchStage config env readable retriedIo).delivered = io.delivered := by
    unfold prefetchStage
    split
    · next condition =>
        have live : retriedIo.conn.alive = true := by
          simp only [Bool.and_eq_true] at condition
          exact condition.1.1.1.1
        have result := prefetch_local config env retriedIo engine retried.1 live
        exact ⟨result.1, result.2.trans retried.2⟩
    · exact retried
  generalize prefetchStage config env readable retriedIo = fetchedIo at fetched ⊢
  have within : ∀ delivery ∈ fetchedIo.delivered, delivery.keyRecord ≤ config.recordBudget := by
    rw [fetched.2]
    exact within
  split
  · exact ⟨fetched.1, within⟩
  · next proceed =>
      simp only [Bool.or_eq_true, Bool.not_eq_true', not_or, Bool.not_eq_false] at proceed
      obtain ⟨live, unblocked⟩ := proceed
      have read
          : Coherent config (readStage config env readable fetchedIo).1.conn
            ∧ ∀ delivery ∈ (readStage config env readable fetchedIo).1.delivered,
                delivery.keyRecord ≤ config.recordBudget := by
        unfold readStage
        split
        · refine doRead_local config env engine _ fetchedIo fetched.1 live ?_ _
            (fun _ ok => ok) within
          obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _⟩ := fetched.1
          simp [readBlockedByWrite, inInit] at unblocked
          grind
        · exact ⟨fetched.1, within⟩
      generalize readStage config env readable fetchedIo = readResult at read ⊢
      unfold writeStage
      split
      · next stillLive =>
          have written := doWrite_local config env readResult.1 engine read.1 stillLive
          refine ⟨written.1, ?_⟩
          dsimp only
          rw [written.2]
          exact read.2
      · exact read

theorem pass_local (config : Config) (env : Env) (io next : Io) (engine : config.Engine)
    (coherent : Coherent config io.conn)
    (within : ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget)
    (passed : pass config env io = some next)
    : Coherent config next.conn
      ∧ ∀ delivery ∈ next.delivered, delivery.keyRecord ≤ config.recordBudget := by
  unfold pass at passed
  dsimp only at passed
  split at passed
  · next enabled =>
      have live : io.conn.alive = true := by
        simp only [Bool.and_eq_true] at enabled
        exact enabled.1
      have driven :=
        driveReady_local config env (readableEvent env io) io engine coherent live within
      generalize driveReady config env (readableEvent env io) io = result at driven passed
      obtain ⟨driven, more⟩ := result
      cases passed
      obtain ⟨⟨_, _, _, _, _, _, _, _, _, _, _, _⟩, deliveries⟩ := driven
      exact ⟨by constructor <;> assumption, deliveries⟩
  · cases passed

theorem send_local (config : Config) (data : List Payload) (conn next : Conn)
    (coherent : Coherent config conn) (sent : send config data conn = some next)
    : Coherent config next := by
  obtain ⟨_, _, _, _, _, h6, _, _, _, _, _, _⟩ := coherent
  unfold send at sent
  split at sent
  · split at sent
    · next accepted =>
        cases sent
        have fits
          : ∀ bound, config.maxQueuedOutput = some bound → conn.queued + data.length ≤ bound := by
          intro bound configured
          simp [admitsOutput, configured] at accepted
          have := h6 bound configured
          omega
        constructor <;> grind [List.append_eq_nil_iff, List.head?_append]
    · cases sent
      constructor <;> grind
  · cases sent

theorem abort_local (config : Config) (conn : Conn) (coherent : Coherent config conn)
    : Coherent config { conn with alive := false } := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _⟩ := coherent
  constructor <;> grind

theorem initial_local (config : Config) (engine : config.Engine)
    : Coherent config Conn.initial := by
  have := engine.1
  constructor <;> simp [Conn.initial]
  omega

end Tls.Proofs
