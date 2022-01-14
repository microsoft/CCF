// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

#include <string>
#include <vector>

using BlobKey = std::string;
using EncryptedBlob = std::vector<uint8_t>;

/// Cache-related ringbuffer messages
enum CacheMessage : ringbuffer::Message
{
  DEFINE_RINGBUFFER_MSG_TYPE(store_blob),

  DEFINE_RINGBUFFER_MSG_TYPE(get_blob),

  DEFINE_RINGBUFFER_MSG_TYPE(response_blob),
  DEFINE_RINGBUFFER_MSG_TYPE(no_blob),
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  CacheMessage::store_blob, BlobKey, EncryptedBlob);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(CacheMessage::get_blob, BlobKey);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  CacheMessage::response_blob, BlobKey, EncryptedBlob);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(CacheMessage::no_blob, BlobKey);