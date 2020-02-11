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
  DECLARE_JSON_ENUM(
    MemberStatus,
    {{MemberStatus::ACCEPTED, "ACCEPTED"}, {MemberStatus::ACTIVE, "ACTIVE"}});
}

MSGPACK_ADD_ENUM(ccf::MemberStatus);

namespace ccf
{
  struct NewMember
  {
    std::vector<uint8_t> cert;
    std::vector<uint8_t> keyshare_encryption_key;

    NewMember() {}

    NewMember(
      const std::vector<uint8_t>& cert_,
      const std::vector<uint8_t>& keyshare_encryption_key_) :
      cert(cert_),
      keyshare_encryption_key(keyshare_encryption_key_)
    {}

    NewMember(
      std::vector<uint8_t>&& cert_,
      std::vector<uint8_t>&& keyshare_encryption_key_) :
      cert(std::move(cert_)),
      keyshare_encryption_key(std::move(keyshare_encryption_key_))
    {}

    MSGPACK_DEFINE(cert, keyshare_encryption_key);
  };

  DECLARE_JSON_TYPE(NewMember)
  DECLARE_JSON_REQUIRED_FIELDS(NewMember, cert, keyshare_encryption_key)

  struct MemberInfo : NewMember
  {
    MemberStatus status = MemberStatus::ACCEPTED;

    MemberInfo() {}

    MemberInfo(
      const std::vector<uint8_t>& cert_,
      const std::vector<uint8_t>& keyshare_encryption_key_,
      MemberStatus status_) :
      NewMember(cert_, keyshare_encryption_key_),
      status(status_)
    {}

    MSGPACK_DEFINE(MSGPACK_BASE(NewMember), status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(MemberInfo, NewMember)
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