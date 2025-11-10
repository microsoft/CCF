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
  enum class MemberStatus : uint8_t
  {
    ACCEPTED = 0,
    ACTIVE = 1,
  };
  DECLARE_JSON_ENUM(
    MemberStatus,
    {{MemberStatus::ACCEPTED, "Accepted"}, {MemberStatus::ACTIVE, "Active"}});

  enum class MemberRecoveryRole : uint8_t
  {
    NonParticipant = 0,
    Participant,

    /** If set then the member is to receive a key allowing it
       to single-handedly recover the network without requiring
       any other recovery member to submit their shares. */
    Owner
  };
  DECLARE_JSON_ENUM(
    MemberRecoveryRole,
    {{MemberRecoveryRole::NonParticipant, "NonParticipant"},
     {MemberRecoveryRole::Participant, "Participant"},
     {MemberRecoveryRole::Owner, "Owner"}});

  struct NewMember
  {
    ccf::crypto::Pem cert;

    // If encryption public key is set, the member is a recovery member
    std::optional<ccf::crypto::Pem> encryption_pub_key = std::nullopt;
    nlohmann::json member_data = nullptr;

    std::optional<MemberRecoveryRole> recovery_role = std::nullopt;

    NewMember() = default;

    NewMember(
      ccf::crypto::Pem cert_,
      const std::optional<ccf::crypto::Pem>& encryption_pub_key_ = std::nullopt,
      nlohmann::json member_data_ = {},
      const std::optional<MemberRecoveryRole>& recovery_role_ = std::nullopt) :
      cert(std::move(cert_)),
      encryption_pub_key(encryption_pub_key_),
      member_data(std::move(member_data_)),
      recovery_role(recovery_role_)
    {}

    bool operator==(const NewMember& rhs) const
    {
      return cert == rhs.cert && encryption_pub_key == rhs.encryption_pub_key &&
        member_data == rhs.member_data && recovery_role == rhs.recovery_role;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NewMember)
  DECLARE_JSON_REQUIRED_FIELDS(NewMember, cert)
  DECLARE_JSON_OPTIONAL_FIELDS(
    NewMember, encryption_pub_key, member_data, recovery_role);

  struct MemberDetails
  {
    /// Status of the member in the consortium
    MemberStatus status = MemberStatus::ACCEPTED;
    /** Free-form member data, can be used to associate specific roles to
        members for example. */
    nlohmann::json member_data = nullptr;

    /// Optional recovery role of the member
    std::optional<MemberRecoveryRole> recovery_role = std::nullopt;

    bool operator==(const MemberDetails& rhs) const
    {
      return status == rhs.status && member_data == rhs.member_data &&
        recovery_role == rhs.recovery_role;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(MemberDetails)
  DECLARE_JSON_REQUIRED_FIELDS(MemberDetails, status)
  DECLARE_JSON_OPTIONAL_FIELDS(MemberDetails, member_data, recovery_role)

  using MemberInfo = ServiceMap<MemberId, MemberDetails>;

  using MemberCerts = ccf::kv::RawCopySerialisedMap<MemberId, ccf::crypto::Pem>;
  using MemberPublicEncryptionKeys =
    ccf::kv::RawCopySerialisedMap<MemberId, ccf::crypto::Pem>;

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

    StateDigest() = default;

    StateDigest(const ccf::crypto::Sha256Hash& root) :
      state_digest(root.hex_str())
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

    MemberAck() = default;

    MemberAck(const ccf::crypto::Sha256Hash& root) : StateDigest(root) {}

    MemberAck(
      const ccf::crypto::Sha256Hash& root, const SignedReq& signed_req_) :
      StateDigest(root),
      signed_req(signed_req_)
    {}

    MemberAck(
      const ccf::crypto::Sha256Hash& root,
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