// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"

#include <frame_generated.h>

namespace kv
{
  struct DetachedFlatbuffer
  {
  private:
    uint8_t* d;
    size_t s;
    size_t offset;

  public:
    DetachedFlatbuffer(uint8_t* data_, size_t size_, size_t offset_) :
      d(data_),
      s(size_),
      offset(offset_)
    {}

    const uint8_t* data()
    {
      return d + offset;
    }

    size_t size()
    {
      return s;
    }

    std::vector<uint8_t> to_vec()
    {
      return std::move(std::vector<uint8_t>(d + offset, d + s));
    }

    const Frame* root()
    {
      flatbuffers::BufferRef<Frame> ref(const_cast<uint8_t*>(d + offset), s);
      return ref.GetRoot();
    }

    void destroy()
    {
      delete[] d;
    }
  };

  class FlatbufferSerialiser
  {
  private:
    flatbuffers::FlatBufferBuilder builder;
    flatbuffers::Offset<Frame> frame;

  public:
    FlatbufferSerialiser(
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& derived)
    {
      auto fb_replicated = builder.CreateVector(replicated);
      auto fb_derived = builder.CreateVector(derived);

      frame = CreateFrame(builder, fb_replicated, fb_derived);
      builder.Finish(frame);
    }

    DetachedFlatbuffer get_flatbuffer()
    {
      size_t size;
      size_t offset;
      auto data = builder.ReleaseRaw(size, offset);
      return {data, size, offset};
    }
  };

  class FlatbufferDeserialiser
  {
  private:
    const Frame* frame;

  public:
    FlatbufferDeserialiser(const uint8_t* frame_) : frame(GetFrame(frame_)) {}

    const Frame* get_frame()
    {
      return frame;
    }

    std::vector<std::pair<const uint8_t*, size_t>> get_frames()
    {
      return {{frame->replicated()->Data(), frame->replicated()->size()},
              {frame->derived()->Data(), frame->derived()->size()}};
    }

    const uint8_t* replicated()
    {
      return frame->replicated()->Data();
    }

    size_t replicated_size()
    {
      return frame->replicated()->size();
    }

    const uint8_t* derived()
    {
      return frame->derived()->Data();
    }

    size_t derived_size()
    {
      return frame->derived()->size();
    }
  };
}