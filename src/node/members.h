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
  };
  DECLARE_JSON_ENUM(
    MemberStatus,
    {{MemberStatus::ACCEPTED, "Accepted"}, {MemberStatus::ACTIVE, "Active"}});
}

MSGPACK_ADD_ENUM(ccf::MemberStatus);

namespace ccf
{
  // Current limitations of secret sharing library (sss).
  static constexpr size_t max_active_recovery_members = 255;

  struct NewMember
  {
    crypto::Pem cert;

    // If encryption public key is set, the member is a recovery member
    std::optional<crypto::Pem> encryption_pub_key = std::nullopt;
    nlohmann::json member_data = nullptr;

    NewMember() {}

    NewMember(
      const crypto::Pem& cert_,
      const std::optional<crypto::Pem>& encryption_pub_key_ = std::nullopt,
      const nlohmann::json& member_data_ = nullptr) :
      cert(cert_),
      encryption_pub_key(encryption_pub_key_),
      member_data(member_data_)
    {}

    bool operator==(const NewMember& rhs) const
    {
      return cert == rhs.cert && encryption_pub_key == rhs.encryption_pub_key &&
        member_data == rhs.member_data;
    }

    MSGPACK_DEFINE(cert, encryption_pub_key, member_data);
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NewMember)
  DECLARE_JSON_REQUIRED_FIELDS(NewMember, cert)
  DECLARE_JSON_OPTIONAL_FIELDS(NewMember, encryption_pub_key, member_data)

  struct MemberDetails
  {
    MemberStatus status = MemberStatus::ACCEPTED;
    nlohmann::json member_data = nullptr;

    bool operator==(const MemberDetails& rhs) const
    {
      return status == rhs.status && member_data == rhs.member_data;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(MemberDetails)
  DECLARE_JSON_REQUIRED_FIELDS(MemberDetails, status)
  DECLARE_JSON_OPTIONAL_FIELDS(MemberDetails, member_data)

  using MemberInfo = ServiceMap<MemberId, MemberDetails>;

  using MemberCerts = kv::RawCopySerialisedMap<MemberId, crypto::Pem>;
  using MmeberPublicEncryptionKeys =
    kv::RawCopySerialisedMap<MemberId, crypto::Pem>;

  /** Records a signed signature containing the last state digest and the
   * next state digest to sign
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
  using MemberAcks = ServiceMap<MemberId, MemberAck>;
}