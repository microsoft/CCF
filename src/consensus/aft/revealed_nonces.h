// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "kv/map.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace aft
{
  using Nonce = std::array<uint8_t, 32>;
  struct RevealedNonce
  {
    ccf::NodeId node_id;
    Nonce nonce;

    MSGPACK_DEFINE(node_id, nonce);

    RevealedNonce(ccf::NodeId node_id_, Nonce nonce_) :
      node_id(node_id_),
      nonce(nonce_)
    {}

    RevealedNonce() = default;
  };
  DECLARE_JSON_TYPE(RevealedNonce);
  DECLARE_JSON_REQUIRED_FIELDS(RevealedNonce, node_id, nonce)

  struct RevealedNonces
  {
    ccf::ObjectId view = 0;
    ccf::ObjectId seqno = 0;
    std::vector<RevealedNonce> nonces;

    MSGPACK_DEFINE(view, seqno, nonces);

    RevealedNonces() = default;

    RevealedNonces(ccf::ObjectId view_, ccf::ObjectId seqno_) :
      view(view_),
      seqno(seqno_)
    {}
  };
  DECLARE_JSON_TYPE(RevealedNonces);
  DECLARE_JSON_REQUIRED_FIELDS(RevealedNonces, view, seqno)
  using RevealedNoncesMap = kv::Map<ccf::ObjectId, RevealedNonces>;
}