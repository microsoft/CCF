// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "client_signatures.h"
#include "ds/hash.h"
#include "entities.h"
#include "raw_signature.h"
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
  // This could be mitigated by not handing a recovery share to every member.
  static constexpr size_t max_active_members_count = 255;

  struct MemberPubInfo
  {
    tls::Pem cert;
    tls::Pem keyshare;

    MemberPubInfo() {}

    MemberPubInfo(const tls::Pem& cert_, const tls::Pem& keyshare_) :
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

  struct MemberInfo
  {
    std::vector<uint8_t> cert; //< DER to match key in Certs table
    tls::Pem keyshare;
    MemberStatus status = MemberStatus::ACCEPTED;

    MemberInfo() {}

    MemberInfo(
      const std::vector<uint8_t>& cert_,
      const tls::Pem& keyshare_,
      MemberStatus status_) :
      cert(cert_),
      keyshare(keyshare_),
      status(status_)
    {}

    bool operator==(const MemberInfo& rhs) const
    {
      return cert == rhs.cert && keyshare == rhs.keyshare &&
        status == rhs.status;
    }

    MSGPACK_DEFINE(cert, keyshare, status);
  };
  DECLARE_JSON_TYPE(MemberInfo)
  DECLARE_JSON_REQUIRED_FIELDS(MemberInfo, cert, keyshare, status)
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