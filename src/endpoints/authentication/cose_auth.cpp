// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/http_consts.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "ds/lru.h"
#include "http/http_sig.h"

#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>
//#include <t_cose/t_cose_common.h>

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

    bool is_ecdsa_alg(int64_t cose_alg)
    {
      return cose_alg == T_COSE_ALGORITHM_ES256 ||
        cose_alg == T_COSE_ALGORITHM_ES384 ||
        cose_alg == T_COSE_ALGORITHM_ES512;
    }

    struct COSESignatureValidationError : public std::runtime_error
    {
      COSESignatureValidationError(const std::string& msg) :
        std::runtime_error(msg)
      {}
    };

    /**
     * Verify the signature of a COSE Sign1 message using the given public key.
     *
     * Beyond the basic verification of key usage and the signature
     * itself, no particular validation of the message is done.
     */
    /*
    void verify(const std::vector<uint8_t> &cose_sign1, int64_t alg, const
    crypto::PublicKey& key)
    {
      auto phdr = decode_protected_header(cose_sign1);
      auto key_alg = key.get_cose_alg();
      if (key_alg.has_value() && phdr.alg != key_alg.value())
      {
        throw COSESignatureValidationError("Algorithm mismatch between protected
    header and public key");
      }

      if (is_ecdsa_alg(phdr.alg))
      {
        q_useful_buf_c signed_cose;
        signed_cose.ptr = cose_sign1.data();
        signed_cose.len = cose_sign1.size();

        t_cose_key cose_key;
        cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
        EVP_PKEY* evp_key = key.get_evp_pkey();
        cose_key.k.key_ptr = evp_key;

        t_cose_sign1_verify_ctx verify_ctx;
        t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
        t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

        q_useful_buf_c returned_payload;
        t_cose_err_t error = t_cose_sign1_verify(&verify_ctx, signed_cose,
    &returned_payload, nullptr); if (error)
        {
          throw COSESignatureValidationError("Signature verification failed");
        }
      }
    }
  */
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
    if (content_type_it->second != "application/cose")
    {
      error_reason = "Content type is not set to application/cose";
      return nullptr;
    }

    auto phdr = cose::decode_protected_header(ctx->get_request_body());

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
    LOG_INFO_FMT("alg: {}", phdr.alg);
    LOG_INFO_FMT("kid: {}", phdr.kid.value());

    MemberCerts members_certs_table(Tables::MEMBER_CERTS);
    auto member_certs = tx.ro(members_certs_table);
    auto member_cert = member_certs->get(phdr.kid.value());
    if (member_cert.has_value())
    {
      LOG_INFO_FMT("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
      auto verifier = crypto::make_cose_verifier(member_cert->raw());

      q_useful_buf_c signed_cose;
      signed_cose.ptr = ctx->get_request_body().data();
      signed_cose.len = ctx->get_request_body().size();
      if (!verifier->verify(signed_cose))
      {
        error_reason = fmt::format("Failed to validate COSE Sign1");
        return nullptr;
      }
    }

    auto identity = std::make_unique<MemberCOSESign1AuthnIdentity>();
    return identity;
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
