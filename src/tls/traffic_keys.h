// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <openssl/ssl.h>

namespace ccf::tls
{
  struct TrafficKeyPolicy
  {
    // Below RFC 8446 section 5.5's AES-GCM limit of 2^24.5 full records.
    static constexpr uint64_t MAX_RECORD_BUDGET = uint64_t{1} << 24;
    uint64_t record_budget = uint64_t{1} << 20;
  };

  class TrafficKeys
  {
    uint64_t sent = 0;
    uint64_t limit;
    bool active = false;
    bool exceeded = false;

  public:
    explicit TrafficKeys(const TrafficKeyPolicy& policy) :
      limit(policy.record_budget)
    {}

    void start()
    {
      active = true;
    }

    static void observe(
      int writing,
      int /*version*/,
      int type,
      const void* data,
      size_t size,
      SSL* /*ssl*/,
      void* argument)
    {
      auto& keys = *static_cast<TrafficKeys*>(argument);
      if (!keys.active || writing == 0)
      {
        return;
      }
      if (type == SSL3_RT_INNER_CONTENT_TYPE)
      {
        // One event per constructed encrypted record, not per write retry.
        keys.exceeded |= ++keys.sent > keys.limit;
      }
      else if (
        type == SSL3_RT_HANDSHAKE && size == 5 &&
        *static_cast<const uint8_t*>(data) == SSL3_MT_KEY_UPDATE)
      {
        // The KeyUpdate record itself was charged to the old key.
        keys.sent = 0;
      }
    }

    [[nodiscard]] bool update_due() const
    {
      return sent >= limit - 1;
    }

    [[nodiscard]] bool failed() const
    {
      return exceeded;
    }
  };
}
