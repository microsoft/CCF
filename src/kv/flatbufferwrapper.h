// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <frame_generated.h>

namespace kv
{
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

    flatbuffers::DetachedBuffer get_flatbuffer()
    {
      return builder.Release();
    }
  };

  class FlatbufferDeserialiser
  {
  private:
    const Frame* frame;

  public:
    FlatbufferDeserialiser(uint8_t* frame_) : frame(GetFrame(frame_)) {}

    const Frame* get_frame()
    {
      return frame;
    }
  };
}