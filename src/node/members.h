// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/entity_id.h"
#include "client_signatures.h"
#include "crypto/pem.h"
#include "ds/hash.h"
#include "node_signature.h"

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
  static constexpr size_t max_active_recovery_members = 255;

  struct MemberPubInfo
  {
    crypto::Pem cert;

    // If encryption public key is set, the member is a recovery member
    std::optional<crypto::Pem> encryption_pub_key = std::nullopt;
    nlohmann::json member_data = nullptr;

    MemberPubInfo() {}

    MemberPubInfo(
      const crypto::Pem& cert_,
      const std::optional<crypto::Pem>& encryption_pub_key_ = std::nullopt,
      const nlohmann::json& member_data_ = nullptr) :
      cert(cert_),
      encryption_pub_key(encryption_pub_key_),
      member_data(member_data_)
    {}

    bool operator==(const MemberPubInfo& rhs) const
    {
      return cert == rhs.cert && encryption_pub_key == rhs.encryption_pub_key &&
        member_data == rhs.member_data;
    }

    bool is_recovery() const
    {
      return encryption_pub_key.has_value();
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
    std::string state_digest;

    StateDigest() {}

    StateDigest(const crypto::Sha256Hash& root) : state_digest(root.hex_str())
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