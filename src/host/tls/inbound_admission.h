// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <utility>
#include <vector>

namespace asynchost
{
  // A node-wide bound on inbound data which has been read off sockets but not
  // yet processed by the sessions it was handed to.
  //
  // Without such a bound, a client which sends faster than the node can
  // execute grows node memory without limit: nothing else in the read path
  // consults how far behind the application is.
  //
  // The bound is node-wide rather than per-connection, so a single connection
  // can exhaust the budget and pause the others. That is deliberate: a
  // per-connection limit would have to be smaller than one maximum-sized
  // request before it could bound total node memory to the same figure.
  //
  // Accounting is in bytes rather than in queued items because bytes are the
  // resource being defended. The two happen to be within a constant factor
  // today (the transport hands over at most one read chunk at a time), but
  // that is an artefact of the current read loop rather than a property to
  // rely on.
  class InboundAdmission
  {
  public:
    // Called to ask a transport to re-examine its read interest.
    using Waker = std::function<void()>;

    explicit InboundAdmission(size_t limit_) : limit(limit_) {}

    // True while the node has more unprocessed inbound data than it is willing
    // to hold. Transports stop reading (but do not close anything) until this
    // goes false again.
    [[nodiscard]] bool saturated() const
    {
      return pending.load(std::memory_order_relaxed) >= limit;
    }

    [[nodiscard]] size_t bytes_pending() const
    {
      return pending.load(std::memory_order_relaxed);
    }

    // Bytes have been handed to a session and are not yet processed.
    void queued(size_t n)
    {
      const size_t after = pending.fetch_add(n) + n;
      if (after >= limit && !reported_saturated.exchange(true))
      {
        LOG_INFO_FMT(
          "Inbound queue limit reached ({} bytes queued, limit {}); pausing "
          "reads until the node catches up",
          after,
          limit);
      }
    }

    // A session has finished with bytes previously passed to queued(). If this
    // brings the node back under the limit, every registered transport is
    // woken, not just the one which happened to make room - otherwise an
    // interface with no traffic of its own would stay paused indefinitely.
    void consumed(size_t n)
    {
      if (n == 0)
      {
        return;
      }
      const size_t before = pending.fetch_sub(n);
      if (before >= limit && (before - n) < limit)
      {
        reported_saturated.store(false);
        LOG_INFO_FMT("Inbound queue back under limit; resuming reads");
        wake_all();
      }
    }

    // Transports register while they are running and unregister as they stop,
    // so that wake_all() never touches a server which is tearing down. Returns
    // a token to pass to unregister_waker().
    size_t register_waker(Waker waker)
    {
      const std::lock_guard<std::mutex> guard(wakers_mutex);
      const size_t token = next_token++;
      wakers.emplace_back(token, std::move(waker));
      return token;
    }

    void unregister_waker(size_t token)
    {
      const std::lock_guard<std::mutex> guard(wakers_mutex);
      std::erase_if(
        wakers, [token](const auto& entry) { return entry.first == token; });
    }

  private:
    void wake_all()
    {
      // Copied out so that no transport's own locks are taken while holding
      // this one - consumed() is called from session workers, and unregister
      // happens during a transport's shutdown.
      std::vector<Waker> to_wake;
      {
        const std::lock_guard<std::mutex> guard(wakers_mutex);
        to_wake.reserve(wakers.size());
        for (const auto& [token, waker] : wakers)
        {
          to_wake.push_back(waker);
        }
      }
      for (const auto& waker : to_wake)
      {
        waker();
      }
    }

    std::atomic<size_t> pending{0};
    const size_t limit;
    // Only so that a sustained overload does not log on every crossing.
    std::atomic<bool> reported_saturated{false};

    std::mutex wakers_mutex;
    std::vector<std::pair<size_t, Waker>> wakers;
    size_t next_token = 0;
  };
}
