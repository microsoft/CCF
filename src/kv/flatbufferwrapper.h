// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <data_generated.h>

namespace kv
{
  class FlatbufferSerialiser
  {
  private:
    flatbuffers::FlatBufferBuilder builder;
    flatbuffers::Offset<data::Data> data;

  public:
    FlatbufferSerialiser(
      const std::vector<uint8_t>& replicated,
      const std::vector<uint8_t>& derived)
    {
      auto fb_replicated = builder.CreateVector(replicated);
      auto fb_derived = builder.CreateVector(derived);

      data = data::CreateData(builder, fb_replicated, fb_derived);
      builder.Finish(data);
    }

    std::vector<uint8_t> get_flatbuffer()
    {
      auto buf = builder.GetBufferPointer();
      return std::move(std::vector<uint8_t>(buf, buf + builder.GetSize()));
    }
  };

  class FlatbufferDeserialiser
  {
  private:
    const data::Data* data;

  public:
    FlatbufferDeserialiser(const std::vector<uint8_t>& data_) :
      data(data::GetData(data_.data()))
    {}

    std::vector<uint8_t> get_replicated()
    {
      return std::move(std::vector<uint8_t>(
        data->replicated()->begin(), data->replicated()->end()));
    }
  };
}