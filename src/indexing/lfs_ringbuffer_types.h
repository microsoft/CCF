// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"
#include "indexing/lfs_interface.h"

namespace ccf::indexing
{
  /// LFS-related ringbuffer messages
  enum LFSMsg : ringbuffer::Message
  {
    DEFINE_RINGBUFFER_MSG_TYPE(store),

    DEFINE_RINGBUFFER_MSG_TYPE(get),

    DEFINE_RINGBUFFER_MSG_TYPE(response),
    DEFINE_RINGBUFFER_MSG_TYPE(not_found),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::indexing::LFSMsg::store,
  ccf::indexing::LFSKey,
  ccf::indexing::LFSEncryptedContents);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::indexing::LFSMsg::get, ccf::indexing::LFSKey);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::indexing::LFSMsg::response,
  ccf::indexing::LFSKey,
  ccf::indexing::LFSEncryptedContents);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ccf::indexing::LFSMsg::not_found, ccf::indexing::LFSKey);