// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/pal.h"
#include "ds/ring_buffer_types.h"

#include <limits>
#include <vector>

struct StubWriter : public ringbuffer::AbstractWriter
{
public:
  struct Write
  {
    ringbuffer::Message m;
    bool finished;
    std::vector<uint8_t> contents;
  };
  ccf::Pal::Mutex writes_mutex;
  std::vector<Write> writes;

  Write& get_write(const WriteMarker& marker)
  {
    if (!marker.has_value() || marker.value() >= writes.size())
    {
      throw std::logic_error("Invalid marker");
    }
    return writes[marker.value()];
  }

  WriteMarker prepare(
    ringbuffer::Message m,
    size_t size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    std::lock_guard<ccf::Pal::Mutex> guard(writes_mutex);
    const auto seqno = writes.size();
    writes.push_back(Write{m, false, {}});
    return seqno;
  }

  void finish(const WriteMarker& marker) override
  {
    std::lock_guard<ccf::Pal::Mutex> guard(writes_mutex);
    get_write(marker).finished = true;
  }

  WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    std::lock_guard<ccf::Pal::Mutex> guard(writes_mutex);
    auto& write = get_write(marker);
    write.contents.insert(write.contents.end(), bytes, bytes + size);
    return marker;
  }

  size_t get_max_message_size() override
  {
    return std::numeric_limits<size_t>::max();
  }
};