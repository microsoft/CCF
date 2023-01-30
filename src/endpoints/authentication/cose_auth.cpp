// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/public_key.h"
#include "ccf/http_consts.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
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

    std::pair<ccf::ProtectedHeader, Signature>
    extract_protected_header_and_signature(
      const std::vector<uint8_t>& cose_sign1)
    {
      ccf::ProtectedHeader parsed;

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
        GOV_MSG_CREATED_AT,
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
      header_items[GOV_MSG_CREATED_AT].label.string =
        UsefulBuf_FromSZ(gov_msg_proposal_created_at);
      header_items[GOV_MSG_CREATED_AT].uLabelType = QCBOR_TYPE_TEXT_STRING;
      // Although this is really uint, specify QCBOR_TYPE_INT64
      // QCBOR_TYPE_UINT64 only matches uint values that are greater than
      // INT64_MAX
      header_items[GOV_MSG_CREATED_AT].uDataType = QCBOR_TYPE_INT64;

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
      if (header_items[GOV_MSG_CREATED_AT].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing created_at in protected header");
      }
      if (header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.kid = qcbor_buf_to_string(header_items[KID_INDEX].val.string);
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
      parsed.alg = header_items[ALG_INDEX].val.int64;
      // Really uint, but the parser doesn't enforce that, so we must check
      if (header_items[GOV_MSG_CREATED_AT].val.int64 < 0)
      {
        throw COSEDecodeError("Header parameter created_at must be positive");
      }
      parsed.gov_msg_created_at = header_items[GOV_MSG_CREATED_AT].val.int64;

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
        throw std::runtime_error("Failed to decode COSE_Sign1");
      }

      Signature sig{static_cast<const uint8_t*>(signature.ptr), signature.len};
      return {parsed, sig};
    }
  }

  MemberCOSESign1AuthnPolicy::MemberCOSESign1AuthnPolicy() = default;
  MemberCOSESign1AuthnPolicy::~MemberCOSESign1AuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> MemberCOSESign1AuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
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
      cose::extract_protected_header_and_signature(ctx->get_request_body());

    if (!phdr.kid.has_value())
    {
      error_reason = "No kid specified in protected headers";
      return nullptr;
    }

    if (!cose::is_ecdsa_alg(phdr.alg))
    {
      error_reason = fmt::format("Unsupported algorithm: {}", phdr.alg);
      return nullptr;
    }

    MemberCerts members_certs_table(Tables::MEMBER_CERTS);
    auto member_certs = tx.ro(members_certs_table);
    auto member_cert = member_certs->get(phdr.kid.value());
    if (member_cert.has_value())
    {
      auto verifier = crypto::make_cose_verifier(member_cert->raw());

      std::span<const uint8_t> body = {
        ctx->get_request_body().data(), ctx->get_request_body().size()};
      std::span<uint8_t> authned_content;
      if (!verifier->verify(body, authned_content))
      {
        error_reason = fmt::format("Failed to validate COSE Sign1");
        return nullptr;
      }
      auto identity = std::make_unique<MemberCOSESign1AuthnIdentity>();
      identity->member_id = phdr.kid.value();
      identity->member_cert = member_cert.value();
      identity->protected_header = phdr;
      identity->envelope = body;
      identity->content = authned_content;
      identity->signature = cose_signature;
      return identity;
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
}
