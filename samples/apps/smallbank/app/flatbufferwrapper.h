// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"

#include <bank_generated.h>

namespace kv
{
  namespace bank
  {
    static const Bank* root(const uint8_t* data)
    {
      return GetBank(data);
    }

    static const std::string name(const uint8_t* data)
    {
      auto bn = root(data);
      return bn->name()->str();
    }

    class FlatbufferSerializer
    {
    private:
      flatbuffers::FlatBufferBuilder builder;
      flatbuffers::Offset<Bank> bank;

    public:
      FlatbufferSerializer(const std::string& name)
      {
        auto bn = builder.CreateString(name);
        bank = CreateBank(builder, bn);
        builder.Finish(bank);
      }

      CBuffer get_buffer()
      {
        return {builder.GetBufferPointer(), builder.GetSize()};
      }
    };
  }
}