// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"

#include <frame_generated.h>

namespace kv
{
  namespace frame
  {
    // These static functions provide access to the Frame internals without the
    // need to create a deserialiser
    static const Frame* root(const uint8_t* data)
    {
      return GetFrame(data);
    }

    static const CBuffer replicated(const uint8_t* data)
    {
      auto frame = GetFrame(data);
      return {frame->replicated()->Data(), frame->replicated()->size()};
    }

    static const CBuffer derived(const uint8_t* data)
    {
      auto frame = GetFrame(data);
      return {frame->derived()->Data(), frame->derived()->size()};
    }

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

      std::unique_ptr<flatbuffers::DetachedBuffer> get_detached_buffer()
      {
        return std::make_unique<flatbuffers::DetachedBuffer>(builder.Release());
      }
    };

    class FlatbufferDeserialiser
    {
    private:
      const Frame* frame;

    public:
      FlatbufferDeserialiser(const uint8_t* frame_) : frame(GetFrame(frame_)) {}

      std::vector<CBuffer> get_frames()
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
}