// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/entity_id.h"
#include "ccf/service/blit_serialiser_pem.h"
#include "ccf/service/map.h"
#include "ccf/service/signed_req.h"

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
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NewMember)
  DECLARE_JSON_REQUIRED_FIELDS(NewMember, cert)
  DECLARE_JSON_OPTIONAL_FIELDS(NewMember, encryption_pub_key, member_data)

  struct MemberDetails
  {
    /// Status of the member in the consortium
    MemberStatus status = MemberStatus::ACCEPTED;
    /** Free-form member data, can be used to associate specific roles to
        members for example. */
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
  using MemberPublicEncryptionKeys =
    kv::RawCopySerialisedMap<MemberId, crypto::Pem>;

  namespace Tables
  {
    static constexpr auto MEMBER_INFO = "public:ccf.gov.members.info";
    static constexpr auto MEMBER_CERTS = "public:ccf.gov.members.certs";
    static constexpr auto MEMBER_ENCRYPTION_PUBLIC_KEYS =
      "public:ccf.gov.members.encryption_public_keys";
  }

  /** Records a signed signature containing the last state digest and the
   * next state digest to sign
   */
  struct StateDigest
  {
    /// Next state digest the member is expected to sign.
    std::string state_digest;

    StateDigest() {}

    StateDigest(const crypto::Sha256Hash& root) : state_digest(root.hex_str())
    {}
  };
  DECLARE_JSON_TYPE(StateDigest)
  DECLARE_JSON_REQUIRED_FIELDS(StateDigest, state_digest)

  struct MemberAck : public StateDigest
  {
    /// Signed request containing the last state digest.
    std::optional<SignedReq> signed_req = std::nullopt;

    /// COSE Sign1 containing the last state digest
    std::optional<std::vector<uint8_t>> cose_sign1_req = std::nullopt;

    MemberAck() {}

    MemberAck(const crypto::Sha256Hash& root) : StateDigest(root) {}

    MemberAck(const crypto::Sha256Hash& root, const SignedReq& signed_req_) :
      StateDigest(root),
      signed_req(signed_req_)
    {}

    MemberAck(
      const crypto::Sha256Hash& root,
      const std::vector<uint8_t>& cose_sign1_req_) :
      StateDigest(root),
      cose_sign1_req(cose_sign1_req_)
    {}
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(MemberAck, StateDigest)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
  DECLARE_JSON_REQUIRED_FIELDS(MemberAck)
#pragma clang diagnostic pop
  DECLARE_JSON_OPTIONAL_FIELDS(MemberAck, signed_req, cose_sign1_req)
  using MemberAcks = ServiceMap<MemberId, MemberAck>;
  namespace Tables
  {
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.members.acks";
  }
}