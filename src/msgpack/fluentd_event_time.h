// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/encode.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace ccf::msgpack
{
  // Validated wrapper for Fluentd's application-defined EventTime extension
  // type, not the MessagePack Timestamp extension type (-1). The two have
  // different layouts and should remain separate types.
  //
  // Wire format (fixext8): 0xD7 0x00 <seconds_be4> <nanoseconds_be4>.
  //
  // Construction takes a system_clock::time_point so callers cannot swap the
  // seconds and nanoseconds operands, and callers with a time_point do not
  // have to decompose it by hand.
  //
  // Range limitations enforced by make():
  //   - Seconds since the epoch must fit in uint32_t. The range ends at
  //     2106-02-07 06:28:15 UTC.
  //   - The time_point must not predate the epoch.
  //
  // If timestamps past 2106 are needed, add the MessagePack Timestamp 64 form
  // as a sibling type.
  class FluentdEventTime
  {
  public:
    // Throws MsgpackEncodeError(INVALID_EVENT_TIME) when tp is outside
    // EventTime's uint32 seconds range. The diagnostic includes the offending
    // epoch value.
    //
    // The wire format carries 32-bit nanoseconds. The encoded precision is
    // limited by system_clock's resolution.
    [[nodiscard]] static FluentdEventTime make(
      std::chrono::system_clock::time_point tp)
    {
      const auto since_epoch = tp.time_since_epoch();

      // Checking the original duration catches negative fractions of a second,
      // which duration_cast<seconds> would truncate to zero.
      if (since_epoch < std::chrono::system_clock::duration::zero())
      {
        const auto ns_signed =
          std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch)
            .count();
        throw MsgpackEncodeError::make(
          Error::INVALID_EVENT_TIME,
          "time_point predates the epoch (since_epoch_ns=" +
            std::to_string(ns_signed) + ")");
      }

      const auto secs =
        std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
      const auto secs_count = secs.count();
      if (
        secs_count > static_cast<int64_t>(std::numeric_limits<uint32_t>::max()))
      {
        throw MsgpackEncodeError::make(
          Error::INVALID_EVENT_TIME,
          "time_point beyond 2106-02-07 06:28:15 UTC (seconds=" +
            std::to_string(secs_count) + ")");
      }

      const auto ns_count =
        std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch - secs)
          .count();
      return FluentdEventTime{
        static_cast<uint32_t>(secs_count), static_cast<uint32_t>(ns_count)};
    }

    [[nodiscard]] uint32_t seconds() const
    {
      return s_;
    }

    [[nodiscard]] uint32_t nanoseconds() const
    {
      return ns_;
    }

    bool operator==(const FluentdEventTime&) const = default;

  private:
    FluentdEventTime(uint32_t s, uint32_t ns) : s_(s), ns_(ns) {}

    uint32_t s_;
    uint32_t ns_;
  };

  // Fluentd EventTime always uses ext type 0 in fixext8 form. The 12-byte ext
  // form is unnecessary because the seconds field is limited to uint32_t.
  inline void write_fluentd_event_time(
    std::vector<uint8_t>& buf, FluentdEventTime t)
  {
    constexpr uint8_t FLUENTD_EVENT_TIME_EXT_TYPE = 0x00;
    buf.push_back(fmt_byte::FIXEXT_8);
    buf.push_back(FLUENTD_EVENT_TIME_EXT_TYPE);
    utils::write_be<uint32_t>(buf, t.seconds());
    utils::write_be<uint32_t>(buf, t.nanoseconds());
  }
} // namespace ccf::msgpack
