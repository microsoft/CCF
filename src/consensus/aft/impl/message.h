// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <limits>

namespace aft
{
  enum class MessageTag : uint64_t
  {
    Request = 0,
    Status = 1,
    NotSet = std::numeric_limits<uint64_t>::max()
  };

// Each message starts with the following format.
#pragma pack(push)
#pragma pack(1)
  struct MessageRep
  {
    MessageRep() : MessageRep(MessageTag::NotSet) {}
    MessageRep(MessageTag tag_) : tag(tag_) {}
    MessageTag tag;
  };
#pragma pack(pop)

  class IMessage
  {
  public:
    IMessage() = default;
    virtual ~IMessage() = default;

    virtual bool should_encrypt() const = 0;
    virtual void serialize_message(uint8_t* data, size_t size) const = 0;
    virtual size_t size() const = 0;
  };

  inline MessageTag get_message_type(const uint8_t* data)
  {
    return reinterpret_cast<const MessageRep*>(data)->tag;
  }
}