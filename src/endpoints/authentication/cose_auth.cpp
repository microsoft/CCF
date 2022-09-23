// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/verifier.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "ds/lru.h"
#include "http/http_sig.h"
#include "ccf/http_consts.h"

#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>

namespace ccf
{
  namespace cose
  {
    static constexpr int64_t COSE_HEADER_PARAM_ALG = 1;
    static constexpr int64_t COSE_HEADER_PARAM_KID = 4;
    // static constexpr const char* COSE_HEADER_PARAM_??? = "";
    // static constexpr const char* COSE_HEADER_PARAM_??? = "";

    struct COSEDecodeError : public std::runtime_error
    {
      COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
    };

    struct ProtectedHeader
    {
      int64_t alg;
      std::optional<std::string> kid;
    };

    std::string qcbor_buf_to_string(const UsefulBufC& buf)
    {
      return std::string(reinterpret_cast<const char*>(buf.ptr), buf.len);
    }

    ProtectedHeader decode_protected_header(
      const std::vector<uint8_t>& cose_sign1)
    {
      ProtectedHeader parsed;

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
        END_INDEX,
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = COSE_HEADER_PARAM_ALG;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[KID_INDEX].label.int64 = COSE_HEADER_PARAM_KID;
      header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);

      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to decode protected header");
      }

      if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw COSEDecodeError("Missing algorithm in protected header");
      }
      if (header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.kid = qcbor_buf_to_string(header_items[KID_INDEX].val.string);
      }
      parsed.alg = header_items[ALG_INDEX].val.int64;

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      return parsed;
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
      error_reason = fmt::format("Missing {} header", http::headers::CONTENT_TYPE);
      return nullptr;
    }
    if (content_type_it->second != "application/cose")
    {
      error_reason = "Content type is not set to application/cose";
      return nullptr;
    }

    if (true /* Check content type */)
    {
      auto phdr = cose::decode_protected_header(ctx->get_request_body());
      LOG_INFO_FMT("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
      /*
      MemberCerts members_certs_table(Tables::MEMBER_CERTS);
      auto member_certs = tx.ro(members_certs_table);
      auto member_cert = member_certs->get(KID);
      if (member_cert.has_value())
      {
        // Verify
      }
      */
      auto identity = std::make_unique<MemberCOSESign1AuthnIdentity>();
      return identity;
    }

    error_reason = "Did not validate";
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
         "protected headers."
         "Signer must be a member identity registered with this service."}});
}
