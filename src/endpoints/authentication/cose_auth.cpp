// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/public_key.h"
#include "ccf/http_consts.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "node/cose_common.h"

#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>

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
      ccf::GovernanceProtectedHeader parsed;

      // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
      // t_cose doesn't support custom header parameters yet.
      UsefulBufC msg{cose_sign1.data(), cose_sign1.size()};

      QCBORError qcbor_result;

      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

      QCBORDecode_EnterArray(&ctx, nullptr);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
      }

      uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
      if (tag != CBOR_TAG_COSE_SIGN1)
      {
        throw COSEDecodeError("COSE_Sign1 is not tagged");
      }

      struct q_useful_buf_c protected_parameters;
      QCBORDecode_EnterBstrWrapped(
        &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
      QCBORDecode_EnterMap(&ctx, NULL);

      enum
      {
        ALG_INDEX,
        KID_INDEX,
        GOV_MSG_TYPE,
        GOV_MSG_PROPOSAL_ID,
        GOV_MSG_MSG_CREATED_AT,
        END_INDEX,
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = headers::PARAM_ALG;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[KID_INDEX].label.int64 = headers::PARAM_KID;
      header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      auto gov_msg_type_label = HEADER_PARAM_MSG_TYPE;
      header_items[GOV_MSG_TYPE].label.string =
        UsefulBuf_FromSZ(gov_msg_type_label);
      header_items[GOV_MSG_TYPE].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[GOV_MSG_TYPE].uDataType = QCBOR_TYPE_TEXT_STRING;

      auto gov_msg_proposal_id = HEADER_PARAM_MSG_PROPOSAL_ID;
      header_items[GOV_MSG_PROPOSAL_ID].label.string =
        UsefulBuf_FromSZ(gov_msg_proposal_id);
      header_items[GOV_MSG_PROPOSAL_ID].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[GOV_MSG_PROPOSAL_ID].uDataType = QCBOR_TYPE_TEXT_STRING;

      auto gov_msg_proposal_created_at = HEADER_PARAM_MSG_CREATED_AT;
      header_items[GOV_MSG_MSG_CREATED_AT].label.string =
        UsefulBuf_FromSZ(gov_msg_proposal_created_at);
      header_items[GOV_MSG_MSG_CREATED_AT].uLabelType = QCBOR_TYPE_TEXT_STRING;
      // Although this is really uint, specify QCBOR_TYPE_INT64
      // QCBOR_TYPE_UINT64 only matches uint values that are greater than
      // INT64_MAX
      header_items[GOV_MSG_MSG_CREATED_AT].uDataType = QCBOR_TYPE_INT64;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);

      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode protected header: {}", qcbor_result));
      }

      if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing algorithm in protected header");
      }
      parsed.alg = header_items[ALG_INDEX].val.int64;

      if (header_items[KID_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing kid in protected header");
      }
      parsed.kid = qcbor_buf_to_string(header_items[KID_INDEX].val.string);

      if (header_items[GOV_MSG_MSG_CREATED_AT].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing created_at in protected header");
      }

      if (header_items[GOV_MSG_TYPE].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.gov_msg_type =
          qcbor_buf_to_string(header_items[GOV_MSG_TYPE].val.string);
      }
      if (header_items[GOV_MSG_PROPOSAL_ID].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.gov_msg_proposal_id =
          qcbor_buf_to_string(header_items[GOV_MSG_PROPOSAL_ID].val.string);
      }
      // Really uint, but the parser doesn't enforce that, so we must check
      if (header_items[GOV_MSG_MSG_CREATED_AT].val.int64 < 0)
      {
        throw COSEDecodeError("Header parameter created_at must be positive");
      }
      parsed.gov_msg_created_at =
        header_items[GOV_MSG_MSG_CREATED_AT].val.int64;

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      QCBORItem item;
      // skip unprotected header
      QCBORDecode_VGetNextConsume(&ctx, &item);
      // payload
      QCBORDecode_GetNext(&ctx, &item);
      // signature
      QCBORDecode_GetNext(&ctx, &item);
      auto signature = item.val.string;

      QCBORDecode_ExitArray(&ctx);
      auto error = QCBORDecode_Finish(&ctx);
      if (error)
      {
        throw COSEDecodeError("Failed to decode COSE_Sign1");
      }

      Signature sig{static_cast<const uint8_t*>(signature.ptr), signature.len};
      return {parsed, sig};
    }

    std::pair<ccf::TimestampedProtectedHeader, Signature>
    extract_protected_header_and_signature(
      const std::vector<uint8_t>& cose_sign1,
      const std::string& msg_type_name,
      const std::string& created_at_name)
    {
      ccf::TimestampedProtectedHeader parsed;

      // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
      // t_cose doesn't support custom header parameters yet.
      UsefulBufC msg{cose_sign1.data(), cose_sign1.size()};

      QCBORError qcbor_result;

      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

      QCBORDecode_EnterArray(&ctx, nullptr);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
      }

      uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
      if (tag != CBOR_TAG_COSE_SIGN1)
      {
        throw COSEDecodeError("COSE_Sign1 is not tagged");
      }

      struct q_useful_buf_c protected_parameters;
      QCBORDecode_EnterBstrWrapped(
        &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
      QCBORDecode_EnterMap(&ctx, NULL);

      enum
      {
        ALG_INDEX,
        KID_INDEX,
        MSG_TYPE,
        MSG_CREATED_AT,
        END_INDEX,
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = headers::PARAM_ALG;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[KID_INDEX].label.int64 = headers::PARAM_KID;
      header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      header_items[MSG_TYPE].label.string =
        UsefulBuf_FromSZ(msg_type_name.c_str());
      header_items[MSG_TYPE].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[MSG_TYPE].uDataType = QCBOR_TYPE_TEXT_STRING;

      auto gov_msg_proposal_created_at = HEADER_PARAM_MSG_CREATED_AT;
      header_items[MSG_CREATED_AT].label.string =
        UsefulBuf_FromSZ(created_at_name.c_str());
      header_items[MSG_CREATED_AT].uLabelType = QCBOR_TYPE_TEXT_STRING;
      // Although this is really uint, specify QCBOR_TYPE_INT64
      // QCBOR_TYPE_UINT64 only matches uint values that are greater than
      // INT64_MAX
      header_items[MSG_CREATED_AT].uDataType = QCBOR_TYPE_INT64;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);

      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode protected header: {}", qcbor_result));
      }

      if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing algorithm in protected header");
      }
      parsed.alg = header_items[ALG_INDEX].val.int64;

      if (header_items[KID_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing kid in protected header");
      }
      parsed.kid = qcbor_buf_to_string(header_items[KID_INDEX].val.string);

      if (header_items[MSG_TYPE].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.msg_type =
          qcbor_buf_to_string(header_items[MSG_TYPE].val.string);
      }
      if (
        header_items[MSG_CREATED_AT].uDataType != QCBOR_TYPE_NONE &&
        // Really uint, but the parser doesn't enforce that, so we must check
        header_items[MSG_CREATED_AT].val.int64 > 0)
      {
        parsed.msg_created_at = header_items[MSG_CREATED_AT].val.int64;
      }

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      QCBORItem item;
      // skip unprotected header
      QCBORDecode_VGetNextConsume(&ctx, &item);
      // payload
      QCBORDecode_GetNext(&ctx, &item);
      // signature
      QCBORDecode_GetNext(&ctx, &item);
      auto signature = item.val.string;

      QCBORDecode_ExitArray(&ctx);
      auto error = QCBORDecode_Finish(&ctx);
      if (error)
      {
        throw COSEDecodeError("Failed to decode COSE_Sign1");
      }

      Signature sig{static_cast<const uint8_t*>(signature.ptr), signature.len};
      return {parsed, sig};
    }
  }

  MemberCOSESign1AuthnPolicy::MemberCOSESign1AuthnPolicy(
    std::optional<std::string> gov_msg_type_) :
    gov_msg_type(gov_msg_type_) {};
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
    auto member_certs = tx.ro(members_certs_table);
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
    else
    {
      error_reason = fmt::format("Signer is not a known member");
      return nullptr;
    }
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
      auto cose_ident =
        dynamic_cast<const MemberCOSESign1AuthnIdentity*>(ident.get());
      if (cose_ident == nullptr)
      {
        error_reason = "Unexpected Identity type";
        return nullptr;
      }

      const auto member_id = cose_ident->member_id;

      auto member_info_handle =
        tx.template ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
      const auto member = member_info_handle->get(member_id);
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
    auto user_certs = tx.ro(users_certs_table);
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
    else
    {
      error_reason = fmt::format("Signer is not a known user");
      return nullptr;
    }
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
