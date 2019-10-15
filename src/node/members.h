// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/hash.h"
#include "entities.h"
#include "rawsignature.h"
#include "rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  enum class MemberStatus
  {
    ACCEPTED = 0,
    ACTIVE = 1
  };
}

MSGPACK_ADD_ENUM(ccf::MemberStatus);

namespace ccf
{
  struct MemberInfo
  {
    std::vector<uint8_t> cert;
    MemberStatus status;
    std::vector<uint8_t> keyshare;

    MSGPACK_DEFINE(cert, status, keyshare);
  };
  using Members = Store::Map<MemberId, MemberInfo>;

  inline void to_json(nlohmann::json& j, const MemberInfo& mi)
  {
    j["cert"] = mi.cert;
    j["status"] = mi.status;
    if (!mi.keyshare.empty())
    {
      j["keyshare"] = nlohmann::json::from_msgpack(mi.keyshare);
    }
  }

  inline void from_json(const nlohmann::json& j, MemberInfo& mi)
  {
    assign_j(mi.cert, j["cert"]);
    mi.status = j["status"];
    auto keyshare = j.find("keyshare");
    if (keyshare != j.end())
    {
      assign_j(mi.keyshare, nlohmann::json::to_msgpack(keyshare.value()));
    }
  }

  /** Records a signature for the last nonce and gives the next nonce to sign.
   */
  struct MemberAck : public RawSignature
  {
    //! the next nonce the member is supposed to sign
    std::vector<uint8_t> next_nonce;

    MSGPACK_DEFINE(MSGPACK_BASE(RawSignature), next_nonce);
  };
  DECLARE_JSON_TYPE_WITH_BASE(MemberAck, RawSignature)
  DECLARE_JSON_REQUIRED_FIELDS(MemberAck, next_nonce)
  using MemberAcks = Store::Map<MemberId, MemberAck>;
}