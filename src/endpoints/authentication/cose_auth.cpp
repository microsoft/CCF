// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/ec_public_key.h"
#include "ccf/http_consts.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "crypto/cbor.h"
#include "node/cose_common.h"

#include <t_cose/t_cose_sign1_verify.h>

namespace
{
  static std::string buf_to_string(std::span<const uint8_t> buf)
  {
    return {reinterpret_cast<const char*>(buf.data()), buf.size()};
  }
}

namespace ccf
{
  namespace cose
  {
    static constexpr auto HEADER_PARAM_MSG_TYPE = "ccf.gov.msg.type";
    static constexpr auto HEADER_PARAM_MSG_PROPOSAL_ID =
      "ccf.gov.msg.proposal_id";
    static constexpr auto HEADER_PARAM_MSG_CREATED_AT =
      "ccf.gov.msg.created_at";

    std::pair<ccf::GovernanceProtectedHeader, Signature>
    extract_governance_protected_header_and_signature(
      const std::vector<uint8_t>& cose_sign1)
    {
      using namespace ccf::cbor;

      auto cose_cbor = rethrow_with_msg(
        [&]() { return parse(cose_sign1); }, "Parse COSE CBOR");

      const auto& cose_envelope = rethrow_with_msg(
        [&]() -> auto& { return cose_cbor->tag_at(18); }, "Parse COSE tag");

      const auto& phdr_raw = rethrow_with_msg(
        [&]() -> auto& { return cose_envelope->array_at(0); },
        "Parse raw protected header");

      auto phdr = rethrow_with_msg(
        [&]() { return parse(phdr_raw->as_bytes()); },
        "Decode protected header");

      ccf::GovernanceProtectedHeader parsed;

      parsed.alg = rethrow_with_msg(
        [&]() {
          return phdr->map_at(make_signed(headers::PARAM_ALG))->as_signed();
        },
        "Parse alg in protected header");

      parsed.kid = buf_to_string(rethrow_with_msg(
        [&]() {
          return phdr->map_at(make_signed(headers::PARAM_KID))->as_bytes();
        },
        "Parse kid in protected header"));

      parsed.gov_msg_created_at = rethrow_with_msg(
        [&]() {
          const int64_t value =
            phdr->map_at(make_string(HEADER_PARAM_MSG_CREATED_AT))->as_signed();
          if (value < 0)
          {
            throw CBORDecodeError(Error::TYPE_MISMATCH, "Must be non-negative");
          }
          return value;
        },
        "Parse created_at in protected header");

      try
      {
        parsed.gov_msg_type = rethrow_with_msg([&]() {
          return phdr->map_at(make_string(HEADER_PARAM_MSG_TYPE))->as_string();
        });
      }
      catch (const CBORDecodeError& err)
      {
        if (err.error_code() != Error::KEY_NOT_FOUND)
        {
          throw err;
        }
      }

      try
      {
        parsed.gov_msg_proposal_id = rethrow_with_msg([&]() {
          return phdr->map_at(make_string(HEADER_PARAM_MSG_PROPOSAL_ID))
            ->as_string();
        });
      }
      catch (const CBORDecodeError& err)
      {
        if (err.error_code() != Error::KEY_NOT_FOUND)
        {
          throw err;
        }
      }

      auto signature = rethrow_with_msg(
        [&]() { return cose_envelope->array_at(3)->as_bytes(); },
        "Parse COSE signature");

      return {parsed, signature};
    }

    std::pair<ccf::TimestampedProtectedHeader, Signature>
    extract_protected_header_and_signature(
      const std::vector<uint8_t>& cose_sign1,
      const std::string& msg_type_name,
      const std::string& created_at_name)
    {
      using namespace ccf::cbor;

      auto cose_cbor = rethrow_with_msg(
        [&]() { return parse(cose_sign1); }, "Parse COSE CBOR");

      const auto& cose_envelope = rethrow_with_msg(
        [&]() -> auto& { return cose_cbor->tag_at(18); }, "Parse COSE tag");

      const auto& phdr_raw = rethrow_with_msg(
        [&]() -> auto& { return cose_envelope->array_at(0); },
        "Parse raw protected header");

      auto phdr = rethrow_with_msg(
        [&]() { return parse(phdr_raw->as_bytes()); },
        "Decode protected header");

      ccf::TimestampedProtectedHeader parsed;

      parsed.alg = rethrow_with_msg(
        [&]() {
          return phdr->map_at(make_signed(headers::PARAM_ALG))->as_signed();
        },
        "Parse alg in protected header");

      parsed.kid = buf_to_string(rethrow_with_msg(
        [&]() {
          return phdr->map_at(make_signed(headers::PARAM_KID))->as_bytes();
        },
        "Parse kid in protected header"));

      try
      {
        parsed.msg_type = rethrow_with_msg(
          [&]() {
            return std::string(
              phdr->map_at(make_string(msg_type_name))->as_string());
          },
          "Parse msg type in protected header");
      }
      catch (const CBORDecodeError& err)
      {
        if (err.error_code() != Error::KEY_NOT_FOUND)
        {
          throw err;
        }
      }

      try
      {
        auto val = rethrow_with_msg(
          [&]() {
            return phdr->map_at(make_string(created_at_name))->as_signed();
          },
          "Parse created_at in protected header");
        if (val < 0)
        {
          throw CBORDecodeError(
            Error::TYPE_MISMATCH,
            "Header parameter created_at must be positive");
        }
        parsed.msg_created_at = val;
      }
      catch (const CBORDecodeError& err)
      {
        if (err.error_code() != Error::KEY_NOT_FOUND)
        {
          throw err;
        }
      }

      auto signature = rethrow_with_msg(
        [&]() { return cose_envelope->array_at(3)->as_bytes(); },
        "Parse COSE signature");

      return {parsed, signature};
    }
  }

  MemberCOSESign1AuthnPolicy::MemberCOSESign1AuthnPolicy(
    std::optional<std::string> gov_msg_type_) :
    gov_msg_type(std::move(gov_msg_type_)) {};
  MemberCOSESign1AuthnPolicy::~MemberCOSESign1AuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> MemberCOSESign1AuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();
    const auto content_type_it = headers.find(http::headers::CONTENT_TYPE);
    if (content_type_it == headers.end())
    {
      error_reason =
        fmt::format("Missing {} header", http::headers::CONTENT_TYPE);
      return nullptr;
    }
    if (content_type_it->second != http::headervalues::contenttype::COSE)
    {
      error_reason = fmt::format(
        "Content type is not set to {}", http::headervalues::contenttype::COSE);
      return nullptr;
    }

    auto [phdr, cose_signature] =
      cose::extract_governance_protected_header_and_signature(
        ctx->get_request_body());

    if (!cose::is_ecdsa_alg(phdr.alg))
    {
      error_reason = fmt::format("Unsupported algorithm: {}", phdr.alg);
      return nullptr;
    }

    MemberCerts members_certs_table(Tables::MEMBER_CERTS);
    auto* member_certs = tx.ro(members_certs_table);
    auto member_cert = member_certs->get(phdr.kid);
    if (member_cert.has_value())
    {
      auto verifier =
        ccf::crypto::make_cose_verifier_from_cert(member_cert->raw());

      std::span<const uint8_t> body = {
        ctx->get_request_body().data(), ctx->get_request_body().size()};
      std::span<uint8_t> authned_content;
      if (!verifier->verify(body, authned_content))
      {
        error_reason = fmt::format("Failed to validate COSE Sign1");
        return nullptr;
      }

      if (gov_msg_type.has_value())
      {
        if (!phdr.gov_msg_type.has_value())
        {
          error_reason = fmt::format(
            "Missing ccf.gov.msg.type, expected ccf.gov.msg.type to be {}",
            gov_msg_type.value());
          return nullptr;
        }

        if (phdr.gov_msg_type.value() != gov_msg_type.value())
        {
          error_reason = fmt::format(
            "Found ccf.gov.msg.type set to {}, expected ccf.gov.msg.type to be "
            "{}",
            phdr.gov_msg_type.value(),
            gov_msg_type.value());
          return nullptr;
        }
      }

      return std::make_unique<MemberCOSESign1AuthnIdentity>(
        authned_content,
        body,
        cose_signature,
        phdr.kid,
        member_cert.value(),
        phdr);
    }
    error_reason = fmt::format("Signer is not a known member");
    return nullptr;
  }

  void MemberCOSESign1AuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
    ctx->set_response_header(
      http::headers::WWW_AUTHENTICATE,
      "COSE-SIGN1 realm=\"Signed request access\"");
  }

  const OpenAPISecuritySchema MemberCOSESign1AuthnPolicy::security_schema =
    std::make_pair(
      MemberCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "cose_sign1"},
        {"description",
         "Request payload must be a COSE Sign1 document, with expected "
         "protected headers. "
         "Signer must be a member identity registered with this service."}});

  std::unique_ptr<AuthnIdentity> ActiveMemberCOSESign1AuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    auto ident =
      MemberCOSESign1AuthnPolicy::authenticate(tx, ctx, error_reason);
    if (ident != nullptr)
    {
      const auto* cose_ident =
        dynamic_cast<const MemberCOSESign1AuthnIdentity*>(ident.get());
      if (cose_ident == nullptr)
      {
        error_reason = "Unexpected Identity type";
        return nullptr;
      }

      const auto member_id = cose_ident->member_id;

      auto* member_info_handle =
        tx.template ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
      auto member = member_info_handle->get(member_id);
      if (!member.has_value() || member->status != ccf::MemberStatus::ACTIVE)
      {
        error_reason = "Signer is not an ACTIVE member";
        return nullptr;
      }
    }

    return ident;
  }

  UserCOSESign1AuthnPolicy::~UserCOSESign1AuthnPolicy() = default;

  std::unique_ptr<UserCOSESign1AuthnIdentity> UserCOSESign1AuthnPolicy::
    _authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason)
  {
    const auto& headers = ctx->get_request_headers();
    const auto content_type_it = headers.find(http::headers::CONTENT_TYPE);
    if (content_type_it == headers.end())
    {
      error_reason =
        fmt::format("Missing {} header", http::headers::CONTENT_TYPE);
      return nullptr;
    }
    if (content_type_it->second != http::headervalues::contenttype::COSE)
    {
      error_reason = fmt::format(
        "Content type is not set to {}", http::headervalues::contenttype::COSE);
      return nullptr;
    }

    auto [phdr, cose_signature] = cose::extract_protected_header_and_signature(
      ctx->get_request_body(), msg_type_name, msg_created_at_name);

    if (!cose::is_ecdsa_alg(phdr.alg))
    {
      error_reason = fmt::format("Unsupported algorithm: {}", phdr.alg);
      return nullptr;
    }

    UserCerts users_certs_table(Tables::USER_CERTS);
    auto* user_certs = tx.ro(users_certs_table);
    auto user_cert = user_certs->get(phdr.kid);
    if (user_cert.has_value())
    {
      auto verifier =
        ccf::crypto::make_cose_verifier_from_cert(user_cert->raw());

      std::span<const uint8_t> body = {
        ctx->get_request_body().data(), ctx->get_request_body().size()};
      std::span<uint8_t> authned_content;
      if (!verifier->verify(body, authned_content))
      {
        error_reason = fmt::format("Failed to validate COSE Sign1");
        return nullptr;
      }

      return std::make_unique<UserCOSESign1AuthnIdentity>(
        authned_content,
        body,
        cose_signature,
        phdr.kid,
        user_cert.value(),
        phdr);
    }
    error_reason = fmt::format("Signer is not a known user");
    return nullptr;
  }

  std::unique_ptr<AuthnIdentity> UserCOSESign1AuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    return _authenticate(tx, ctx, error_reason);
  }

  void UserCOSESign1AuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
    ctx->set_response_header(
      http::headers::WWW_AUTHENTICATE,
      "COSE-SIGN1 realm=\"Signed request access\"");
  }

  const OpenAPISecuritySchema UserCOSESign1AuthnPolicy::security_schema =
    std::make_pair(
      UserCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "cose_sign1"},
        {"description",
         "Request payload must be a COSE Sign1 document, with expected "
         "protected headers. "
         "Signer must be a user identity registered with this service."}});

  std::unique_ptr<AuthnIdentity> TypedUserCOSESign1AuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    auto identity = _authenticate(tx, ctx, error_reason);

    if (
      identity != nullptr &&
      identity->protected_header.msg_type != expected_msg_type)
    {
      error_reason = fmt::format(
        "Unexpected message type: {}, expected: {}",
        identity->protected_header.msg_type,
        expected_msg_type);
      return nullptr;
    }

    return identity;
  }
}
