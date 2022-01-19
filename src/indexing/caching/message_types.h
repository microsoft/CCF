// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

#include <string>
#include <vector>

namespace indexing::caching
{
  using BlobKey = std::string;
  using EncryptedBlob = std::vector<uint8_t>;

  /// Cache-related ringbuffer messages
  enum BlobMsg : ringbuffer::Message
  {
    DEFINE_RINGBUFFER_MSG_TYPE(store),

    DEFINE_RINGBUFFER_MSG_TYPE(get),

    DEFINE_RINGBUFFER_MSG_TYPE(response),
    DEFINE_RINGBUFFER_MSG_TYPE(not_found),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  indexing::caching::BlobMsg::store,
  indexing::caching::BlobKey,
  indexing::caching::EncryptedBlob);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  indexing::caching::BlobMsg::get, indexing::caching::BlobKey);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  indexing::caching::BlobMsg::response,
  indexing::caching::BlobKey,
  indexing::caching::EncryptedBlob);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  indexing::caching::BlobMsg::not_found, indexing::caching::BlobKey);
