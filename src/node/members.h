// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/hash.h"
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
  DECLARE_JSON_ENUM(
    MemberStatus,
    {{MemberStatus::ACCEPTED, "ACCEPTED"}, {MemberStatus::ACTIVE, "ACTIVE"}});
}

MSGPACK_ADD_ENUM(ccf::MemberStatus);

namespace ccf
{
  struct MemberPubInfo
  {
    std::vector<uint8_t> cert;
    std::vector<uint8_t> keyshare;

    MemberPubInfo() {}

    MemberPubInfo(
      const std::vector<uint8_t>& cert_,
      const std::vector<uint8_t>& keyshare_) :
      cert(cert_),
      keyshare(keyshare_)
    {}

    MemberPubInfo(
      std::vector<uint8_t>&& cert_, std::vector<uint8_t>&& keyshare_) :
      cert(std::move(cert_)),
      keyshare(std::move(keyshare_))
    {}

    MSGPACK_DEFINE(cert, keyshare);
  };

  DECLARE_JSON_TYPE(MemberPubInfo)
  DECLARE_JSON_REQUIRED_FIELDS(MemberPubInfo, cert, keyshare)

  struct MemberInfo : MemberPubInfo
  {
    MemberStatus status = MemberStatus::ACCEPTED;

    MemberInfo() {}

    MemberInfo(
      const std::vector<uint8_t>& cert_,
      const std::vector<uint8_t>& keyshare_,
      MemberStatus status_) :
      MemberPubInfo(cert_, keyshare_),
      status(status_)
    {}

    MSGPACK_DEFINE(MSGPACK_BASE(MemberPubInfo), status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(MemberInfo, MemberPubInfo)
  DECLARE_JSON_REQUIRED_FIELDS(MemberInfo, status)
  using Members = Store::Map<MemberId, MemberInfo>;

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