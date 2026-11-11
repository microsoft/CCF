-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Proofs.Local
public import Tls.Properties.Stages

@[expose] public section

/-!
A pass which is not atomic preserves the invariant of one connection, and an atomic pass is
one of them.
-/

namespace Tls.Proofs

open Tls.Model Tls.Properties

theorem coherent_reads (config : Config) (reads : Nat) (conn : Conn)
    (coherent : Coherent { config with readsPerPass := reads } conn)
    : Coherent config conn := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := coherent
  exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩

theorem reads_coherent (config : Config) (reads : Nat) (conn : Conn)
    (coherent : Coherent config conn)
    : Coherent { config with readsPerPass := reads } conn := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := coherent
  exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩

theorem interleavedDrive_stages (config : Config) (interleaving : Interleaving)
    (readable : Bool) (io : Io)
    : interleavedDrive config interleaving readable io
      = if !(prefetchStage
              config
              (interleaving.env .prefetch)
              readable
              (interleaving.enter
                .prefetch
                (retryStage config (interleaving.env .retry)
                  (interleaving.enter .retry io)))).conn.alive
            || readBlockedByWrite
                (prefetchStage
                  config
                  (interleaving.env .prefetch)
                  readable
                  (interleaving.enter
                    .prefetch
                    (retryStage config (interleaving.env .retry)
                      (interleaving.enter .retry io)))).conn then
          (
            prefetchStage
              config
              (interleaving.env .prefetch)
              readable
              (interleaving.enter
                .prefetch
                (retryStage config (interleaving.env .retry)
                  (interleaving.enter .retry io))),
            false
          )
        else
          writeStage
            config
            (interleaving.env .write)
            (
              interleaving.enter
                .write
                (readStage
                  { config with readsPerPass := interleaving.reads }
                  (interleaving.env .read)
                  readable
                  (interleaving.enter
                    .read
                    (prefetchStage
                      config
                      (interleaving.env .prefetch)
                      readable
                      (interleaving.enter
                        .prefetch
                        (retryStage
                          config
                          (interleaving.env .retry)
                          (interleaving.enter .retry io)))))).1,
              (readStage
                { config with readsPerPass := interleaving.reads }
                (interleaving.env .read)
                readable
                (interleaving.enter
                  .read
                  (prefetchStage
                    config
                    (interleaving.env .prefetch)
                    readable
                    (interleaving.enter
                      .prefetch
                      (retryStage
                        config
                        (interleaving.env .retry)
                        (interleaving.enter .retry io)))))).2
            ) := by
  rfl

theorem interleavedDrive_local (config : Config) (interleaving : Interleaving)
    (readable : Bool) (io : Io) (engine : config.Engine)
    (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    (within : ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget)
    : Coherent config (interleavedDrive config interleaving readable io).1.conn
      ∧ ∀ delivery ∈ (interleavedDrive config interleaving readable io).1.delivered,
          delivery.keyRecord ≤ config.recordBudget := by
  rw [interleavedDrive_stages]
  have retried
    : Coherent config
        (retryStage config (interleaving.env .retry) (interleaving.enter .retry io)).conn
      ∧ (retryStage config (interleaving.env .retry) (interleaving.enter .retry io)).delivered
        = io.delivered := by
    unfold retryStage
    split
    · exact doWrite_local config _ (interleaving.enter .retry io) engine coherent alive
    · exact ⟨coherent, rfl⟩
  generalize retryStage config (interleaving.env .retry) (interleaving.enter .retry io) = retriedIo
    at retried ⊢
  have fetched
    : Coherent config
        (prefetchStage
            config
            (interleaving.env .prefetch)
            readable
            (interleaving.enter .prefetch retriedIo)).conn
      ∧ (prefetchStage
            config
            (interleaving.env .prefetch)
            readable
            (interleaving.enter .prefetch retriedIo)).delivered
        = io.delivered := by
    unfold prefetchStage
    split
    · next condition =>
        have live : (interleaving.enter .prefetch retriedIo).conn.alive = true := by
          simp only [Bool.and_eq_true] at condition
          exact condition.1.1.1.1
        have result :=
          prefetch_local
            config
            (interleaving.env .prefetch)
            (interleaving.enter .prefetch retriedIo)
            engine
            retried.1
            live
        exact ⟨result.1, result.2.trans retried.2⟩
    · exact retried
  generalize
    prefetchStage
      config
      (interleaving.env .prefetch)
      readable
      (interleaving.enter .prefetch retriedIo)
    = fetchedIo
    at fetched ⊢
  have within : ∀ delivery ∈ fetchedIo.delivered, delivery.keyRecord ≤ config.recordBudget := by
    rw [fetched.2]
    exact within
  split
  · exact ⟨fetched.1, within⟩
  · next proceed =>
      simp only [Bool.or_eq_true, Bool.not_eq_true', not_or, Bool.not_eq_false] at proceed
      obtain ⟨live, unblocked⟩ := proceed
      have free
        : fetchedIo.conn.writeRetry = true
          → fetchedIo.conn.ssl.pending ≠ .update ∧ fetchedIo.conn.ssl.updateQueued = false := by
        obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _⟩ := fetched.1
        simp [readBlockedByWrite, inInit] at unblocked
        grind
      have read
        : Coherent config
            (readStage
                { config with readsPerPass := interleaving.reads }
                (interleaving.env .read)
                readable
                (interleaving.enter .read fetchedIo)).1.conn
          ∧ ∀ delivery
              ∈ (readStage
                    { config with readsPerPass := interleaving.reads }
                    (interleaving.env .read)
                    readable
                    (interleaving.enter .read fetchedIo)).1.delivered,
              delivery.keyRecord ≤ config.recordBudget := by
        unfold readStage
        split
        · rcases Nat.eq_zero_or_pos interleaving.reads with none | some
          · simp only [none, doRead]
            exact ⟨fetched.1, within⟩
          · have result :=
              doRead_local
                { config with readsPerPass := interleaving.reads }
                (interleaving.env .read)
                ⟨engine.1, engine.2.1, some⟩
                interleaving.reads
                (interleaving.enter .read fetchedIo)
                (reads_coherent config _ _ fetched.1)
                live
                free
                (fun delivery => delivery.keyRecord ≤ config.recordBudget)
                (fun _ ok => ok)
                within
            exact ⟨coherent_reads config _ _ result.1, result.2⟩
        · exact ⟨fetched.1, within⟩
      generalize
        readStage
          { config with readsPerPass := interleaving.reads }
          (interleaving.env .read)
          readable
          (interleaving.enter .read fetchedIo)
        = readResult
        at read ⊢
      unfold writeStage
      split
      · next stillLive =>
          have written :=
            doWrite_local
              config
              (interleaving.env .write)
              (interleaving.enter .write readResult.1)
              engine
              read.1
              stillLive
          refine ⟨written.1, ?_⟩
          dsimp only
          rw [written.2]
          exact read.2
      · exact read

theorem interleavedPass_local (config : Config) (interleaving : Interleaving)
    (readable : Bool) (io : Io) (engine : config.Engine)
    (coherent : Coherent config io.conn) (alive : io.conn.alive = true)
    (within : ∀ delivery ∈ io.delivered, delivery.keyRecord ≤ config.recordBudget)
    : Coherent config (interleavedPass config interleaving readable io).conn
      ∧ ∀ delivery ∈ (interleavedPass config interleaving readable io).delivered,
          delivery.keyRecord ≤ config.recordBudget := by
  have driven := interleavedDrive_local config interleaving readable io engine coherent alive within
  unfold interleavedPass
  generalize interleavedDrive config interleaving readable io = result at driven ⊢
  obtain ⟨⟨_, _, _, _, _, _, _, _, _, _, _, _⟩, deliveries⟩ := driven
  exact ⟨by constructor <;> assumption, deliveries⟩

theorem replayable_coherent (config : Config) (engine : config.Engine) (conn : Conn)
    (reached : Replayable config conn)
    : Coherent config conn := by
  induction reached with
  | initial => exact initial_local config engine
  | send data _ sent ih => exact send_local config data _ _ ih sent
  | abort _ ih => exact abort_local config _ ih
  | pass interleaving readable socket _ alive ih =>
      exact (interleavedPass_local
              config
              interleaving
              readable
              _
              engine
              ih
              alive
              (fun _ absent => by simp at absent)).1

theorem pass_interleaved (config : Config) (env : Env) (io next : Io)
    (passed : pass config env io = some next)
    : next = interleavedPass config (.atomic config env) (readableEvent env io) io := by
  unfold pass at passed
  dsimp only at passed
  split at passed
  · cases passed
    rfl
  · cases passed

end Tls.Proofs
