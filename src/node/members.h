// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "client_signatures.h"
#include "ds/hash.h"
#include "entities.h"
#include "node_signature.h"
#include "tls/pem.h"

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
  // Current limitations of secret sharing library (sss).
  static constexpr size_t max_active_members_with_shares = 255;

  struct MemberPubInfo
  {
    tls::Pem cert;
    std::optional<tls::Pem> encryption_pub_key = std::nullopt;
    nlohmann::json member_data = nullptr;

    MemberPubInfo() {}

    MemberPubInfo(
      const tls::Pem& cert_,
      const std::optional<tls::Pem>& encryption_pub_key_ = std::nullopt,
      const nlohmann::json& member_data_ = nullptr) :
      cert(cert_),
      encryption_pub_key(encryption_pub_key_),
      member_data(member_data_)
    {}

    // TODO: Still needed?
    MemberPubInfo(
      std::vector<uint8_t>&& cert_,
      std::vector<uint8_t>&& encryption_pub_key_,
      nlohmann::json&& member_data_) :
      cert(std::move(cert_)),
      encryption_pub_key(std::move(encryption_pub_key_)),
      member_data(std::move(member_data_))
    {}

    bool operator==(const MemberPubInfo& rhs) const
    {
      return cert == rhs.cert && encryption_pub_key == rhs.encryption_pub_key &&
        member_data == rhs.member_data;
    }

    MSGPACK_DEFINE(cert, encryption_pub_key, member_data);
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(MemberPubInfo)
  DECLARE_JSON_REQUIRED_FIELDS(MemberPubInfo, cert)
  DECLARE_JSON_OPTIONAL_FIELDS(MemberPubInfo, encryption_pub_key, member_data)

  struct MemberInfo : public MemberPubInfo
  {
    MemberStatus status = MemberStatus::ACCEPTED;

    MemberInfo() {}

    MemberInfo(const MemberPubInfo& member_pub_info, MemberStatus status_) :
      MemberPubInfo(member_pub_info),
      status(status_)
    {}

    bool operator==(const MemberInfo& rhs) const
    {
      return MemberPubInfo::operator==(rhs) && status == rhs.status;
    }

    MSGPACK_DEFINE(MSGPACK_BASE(MemberPubInfo), status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(MemberInfo, MemberPubInfo)
  DECLARE_JSON_REQUIRED_FIELDS(MemberInfo, status)
  using Members = kv::Map<MemberId, MemberInfo>;

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
  using MemberAcks = kv::Map<MemberId, MemberAck>;
}