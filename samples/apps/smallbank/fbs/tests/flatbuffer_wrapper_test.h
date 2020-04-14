// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../flatbuffer_wrapper.h"

#include <large_payload_generated.h>

class LargePayloadSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<LargePayload> large_payload;

public:
  LargePayloadSerializer(const std::vector<uint8_t>& payload)
  {
    large_payload = CreateLargePayload(builder, builder.CreateVector(payload));
    builder.Finish(large_payload);
  }
};

class LargePayloadDeserializer
{
private:
  const LargePayload* root;

public:
  LargePayloadDeserializer(const uint8_t* data) :
    root(flatbuffers::GetRoot<LargePayload>(data))
  {}

  std::vector<uint8_t> payload()
  {
    return std::vector<uint8_t>{root->payload()->Data(),
                                root->payload()->Data() +
                                  root->payload()->size()};
  }
};
