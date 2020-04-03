// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "client_signatures.h"
#include "ds/hash.h"
#include "entities.h"
#include "raw_signature.h"

#include <msgpack/msgpack.hpp>
#include <vector>

namespace ccf
{
  enum class MemberStatus
  {
    ACCEPTED = 0,
    ACTIVE = 1,
    RETIRED = 2
  };
  DECLARE_JSON_ENUM(
    MemberStatus,
    {{MemberStatus::ACCEPTED, "ACCEPTED"},
     {MemberStatus::ACTIVE, "ACTIVE"},
     {MemberStatus::RETIRED, "RETIRED"}});
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

  /** Records a signed signature containing the last state digest and the next
   * state digest to sign
   */
  struct StateDigest
  {
    //! the next state digest the member is supposed to sign
    std::vector<uint8_t> state_digest;

    StateDigest() {}

    StateDigest(const crypto::Sha256Hash& root) :
      state_digest(root.h.begin(), root.h.end())
    {}

    MSGPACK_DEFINE(state_digest);
  };
  DECLARE_JSON_TYPE(StateDigest)
  DECLARE_JSON_REQUIRED_FIELDS(StateDigest, state_digest)

  struct MemberAck : public StateDigest
  {
    //! the signed request containing the last state digest
    SignedReq signed_req = {};

    MemberAck() {}

    MemberAck(const crypto::Sha256Hash& root) : StateDigest(root) {}

    MemberAck(const crypto::Sha256Hash& root, const SignedReq& signed_req_) :
      StateDigest(root),
      signed_req(signed_req_)
    {}

    MSGPACK_DEFINE(MSGPACK_BASE(StateDigest), signed_req);
  };
  DECLARE_JSON_TYPE_WITH_BASE(MemberAck, StateDigest)
  DECLARE_JSON_REQUIRED_FIELDS(MemberAck, signed_req)
  using MemberAcks = Store::Map<MemberId, MemberAck>;
}