// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Generic building blocks for deterministically interleaving real
// production code paths (e.g. Store::commit()'s batching loop, or a Tx's
// write-set serialisation) with a concurrent action injected from a
// controller thread (e.g. a Store::rollback() triggered by a real raft
// view change).
//
// Two complementary tools are provided:
//  - Checkpoint: a named pause/release rendezvous, for pinning an exact
//    interleaving (a worker thread pauses at a point of interest; a
//    controller thread waits for that, performs some action, then releases
//    it).
//  - random_delay: an unpinned timing-fuzz helper, for shaking loose races
//    whose exact window is not known up front.
//
// Neither of these requires any changes to production code: they attach via
// existing extension points (ccf::kv::CommittableTx::WriteSetObserver, and
// wrapping ccf::kv::PendingTx).

#include "kv/kv_types.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>

namespace ccf::kv::test
{
  // A single pause/release rendezvous point. One thread calls pause() and
  // blocks; another thread calls wait_until_paused() to learn that the first
  // thread has reached this point, does whatever it needs to do while the
  // first thread is parked, then calls release() to let it continue.
  //
  // A Checkpoint may be reused for multiple pause/release cycles (e.g. one
  // per iteration of a batching loop, or one per fuzzer iteration), as long
  // as each cycle's pause() is fully released before the next one begins.
  class Checkpoint
  {
    std::mutex lock;
    std::condition_variable paused_cv;
    std::condition_variable resume_cv;
    bool paused = false;
    bool resume = false;

  public:
    // Optional name, purely for log/assertion messages when a test uses
    // several Checkpoints at once.
    const std::string name;

    Checkpoint(std::string name_ = "") : name(std::move(name_)) {}

    // Called by the worker thread. Blocks until a controller thread calls
    // release().
    void pause()
    {
      {
        std::lock_guard<std::mutex> guard(lock);
        // Consume any leftover `resume` from a previous pause/release cycle
        // on this Checkpoint before waiting on it again, so this can be
        // safely reused (see release(), which deliberately does not touch
        // this flag itself, to avoid racing with the very wait() below).
        resume = false;
        paused = true;
      }
      paused_cv.notify_one();

      std::unique_lock<std::mutex> guard(lock);
      resume_cv.wait(guard, [this]() { return resume; });
    }

    // Called by the controller thread. Blocks until a worker thread has
    // called pause().
    void wait_until_paused()
    {
      std::unique_lock<std::mutex> guard(lock);
      paused_cv.wait(guard, [this]() { return paused; });
      // Consume `paused`, so this Checkpoint can be reused for a later
      // pause/release cycle without wait_until_paused() immediately
      // (incorrectly) returning for a pause() call that hasn't happened yet.
      paused = false;
    }

    // Called by the controller thread. Releases a worker thread waiting in
    // pause().
    void release()
    {
      std::lock_guard<std::mutex> guard(lock);
      resume = true;
      resume_cv.notify_one();
    }

    // Convenience for the controller thread: wait for a worker to arrive,
    // then immediately release it. Useful when the interleaving only needs a
    // happens-before edge (e.g. "let this transaction's local application
    // complete before doing anything else") rather than an inspection
    // window.
    void wait_until_paused_and_release()
    {
      wait_until_paused();
      release();
    }
  };

  // A ccf::kv::CommittableTx::WriteSetObserver-compatible adaptor which
  // pauses at a Checkpoint every time it is invoked, i.e. once the
  // transaction's write set has been serialised but before it is handed to
  // Store::commit().
  inline auto checkpoint_write_set_observer(Checkpoint& checkpoint)
  {
    return [&checkpoint](const auto&, const auto&) { checkpoint.pause(); };
  }

  // A ccf::kv::CommittableTx::PostApplyObserver-compatible adaptor which
  // pauses at a Checkpoint once the transaction's writes have been applied
  // locally, but before any side effect that outlives it is registered.
  inline auto checkpoint_post_apply_observer(Checkpoint& checkpoint)
  {
    return [&checkpoint]() { checkpoint.pause(); };
  }

  // Wraps another PendingTx, and pauses at a Checkpoint after the inner
  // PendingTx has produced its result (i.e. after the entry's local
  // application to the KV is complete) but before that result is returned to
  // Store::commit()'s batching loop. Use this to pin a rollback so it lands
  // strictly between two entries of the same in-flight commit batch.
  class PausingPendingTx : public ccf::kv::PendingTx
  {
    std::unique_ptr<ccf::kv::PendingTx> inner;
    Checkpoint& checkpoint;

  public:
    PausingPendingTx(
      std::unique_ptr<ccf::kv::PendingTx> inner_, Checkpoint& checkpoint_) :
      inner(std::move(inner_)),
      checkpoint(checkpoint_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto info = inner->call();
      checkpoint.pause();
      return info;
    }
  };

  // Pure timing-fuzz helper (no pinned interleaving): sleeps the calling
  // thread for a pseudo-random duration in [0, max), drawn from the given
  // RNG. Used by actors that should jitter relative to one another without
  // the test dictating an exact interleaving.
  inline void random_delay(std::mt19937& rng, std::chrono::microseconds max)
  {
    if (max.count() <= 0)
    {
      return;
    }

    const auto delay_us =
      std::uniform_int_distribution<int64_t>(0, max.count() - 1)(rng);
    std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
  }
}
