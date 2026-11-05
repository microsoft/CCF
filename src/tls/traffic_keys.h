// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <openssl/ssl.h>

namespace ccf::tls
{
  // Internal configuration, not a node-config or operator option.
  struct TrafficKeyPolicy
  {
    // Below RFC 8446 section 5.5's AES-GCM limit of 2^24.5 full records.
    static constexpr uint64_t MAX_RECORD_BUDGET = uint64_t{1} << 24;
    uint64_t record_budget = uint64_t{1} << 20;
  };

  class TrafficKeys
  {
    uint64_t sent = 0;
    uint64_t received = 0;
    bool exceeded = false;
    bool active = false;
    uint64_t limit;

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
      const void* buffer,
      size_t size,
      SSL* /*ssl*/,
      void* argument)
    {
      auto& self = *static_cast<TrafficKeys*>(argument);
      if (!self.active)
      {
        return;
      }
      const auto* bytes = static_cast<const uint8_t*>(buffer);
      if (type == SSL3_RT_INNER_CONTENT_TYPE)
      {
        // Unlike message callbacks, this event occurs once per encrypted
        // record, including handshake/alert records and empty application
        // records. Output is observed at construction, not BIO retry.
        auto& count = writing != 0 ? self.sent : self.received;
        if (++count > self.limit)
        {
          self.exceeded = true;
        }
      }
      else if (
        type == SSL3_RT_HANDSHAKE && size == 5 &&
        bytes[0] == SSL3_MT_KEY_UPDATE)
      {
        // KeyUpdate itself uses the OLD key. OpenSSL reports the complete
        // message before installing the new key; a failed operation must
        // therefore still close the connection, never deliver plaintext.
        if (writing != 0)
        {
          self.sent = 0;
        }
        else
        {
          self.received = 0;
        }
      }
    }

    [[nodiscard]] bool failed() const
    {
      return exceeded;
    }

    [[nodiscard]] bool update_due() const
    {
      // Leave one record under the old sending key for KeyUpdate itself.
      return sent >= limit - 1;
    }
  };
}
