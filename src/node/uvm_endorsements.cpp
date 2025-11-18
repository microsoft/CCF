// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/uvm_endorsements.h"

#include "ds/internal_logger.h"

namespace ccf
{
  bool matches_uvm_roots_of_trust(
    const pal::UVMEndorsements& endorsements,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust)
  {
    return std::ranges::any_of(
      uvm_roots_of_trust, [&](const auto& uvm_root_of_trust) {
        size_t root_of_trust_svn = 0;
        auto result = std::from_chars(
          uvm_root_of_trust.svn.data(),
          uvm_root_of_trust.svn.data() + uvm_root_of_trust.svn.size(),
          root_of_trust_svn);
        if (result.ec != std::errc())
        {
          throw std::runtime_error(fmt::format(
            "Unable to parse svn value {} to unsigned in UVM root of trust",
            uvm_root_of_trust.svn));
        }
        size_t endorsement_svn = 0;
        result = std::from_chars(
          endorsements.svn.data(),
          endorsements.svn.data() + endorsements.svn.size(),
          endorsement_svn);
        if (result.ec != std::errc())
        {
          throw std::runtime_error(fmt::format(
            "Unable to parse svn value {} to unsigned in UVM endorsements",
            endorsements.svn));
        }

        return uvm_root_of_trust.did == endorsements.did &&
          uvm_root_of_trust.feed == endorsements.feed &&
          root_of_trust_svn <= endorsement_svn;
      });
  }

  namespace cose
  {
    namespace
    {
      constexpr auto HEADER_PARAM_ISSUER = "iss";
      constexpr auto HEADER_PARAM_FEED = "feed";

      std::vector<std::vector<uint8_t>> decode_x5chain(
        QCBORDecodeContext& ctx, const QCBORItem& x5chain)
      {
        std::vector<std::vector<uint8_t>> parsed;

        if (x5chain.uDataType == QCBOR_TYPE_ARRAY)
        {
          QCBORDecode_EnterArrayFromMapN(&ctx, headers::PARAM_X5CHAIN);
          while (true)
          {
            QCBORItem item;
            auto result = QCBORDecode_GetNext(&ctx, &item);
            if (result == QCBOR_ERR_NO_MORE_ITEMS)
            {
              break;
            }
            if (result != QCBOR_SUCCESS)
            {
              throw COSEDecodeError("Item in x5chain is not well-formed");
            }
            if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
            {
              parsed.push_back(qcbor_buf_to_byte_vector(item.val.string));
            }
            else
            {
              throw COSEDecodeError(
                "Next item in x5chain was not of type byte string");
            }
          }
          QCBORDecode_ExitArray(&ctx);
          if (parsed.empty())
          {
            throw COSEDecodeError("x5chain array length was 0 in COSE header");
          }
        }
        else if (x5chain.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
          parsed.push_back(qcbor_buf_to_byte_vector(x5chain.val.string));
        }
        else
        {
          throw COSEDecodeError(fmt::format(
            "Value type {} of x5chain in COSE header is not array or byte "
            "string",
            x5chain.uDataType));
        }

        return parsed;
      }

      UvmEndorsementsProtectedHeader decode_protected_header(
        const std::vector<uint8_t>& uvm_endorsements_raw)
      {
        UsefulBufC msg{
          uvm_endorsements_raw.data(), uvm_endorsements_raw.size()};

        QCBORError qcbor_result = QCBOR_SUCCESS;

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
          throw COSEDecodeError("Failed to parse COSE_Sign1 tag");
        }

        struct q_useful_buf_c protected_parameters = {};
        QCBORDecode_EnterBstrWrapped(
          &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
        QCBORDecode_EnterMap(&ctx, nullptr);

        enum HeaderIndex : uint8_t
        {
          ALG_INDEX,
          CONTENT_TYPE_INDEX,
          X5_CHAIN_INDEX,
          ISS_INDEX,
          FEED_INDEX,
          END_INDEX
        };
        QCBORItem header_items[END_INDEX + 1];

        header_items[ALG_INDEX].label.int64 = headers::PARAM_ALG;
        header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
        header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

        header_items[CONTENT_TYPE_INDEX].label.int64 =
          headers::PARAM_CONTENT_TYPE;
        header_items[CONTENT_TYPE_INDEX].uLabelType = QCBOR_TYPE_INT64;
        header_items[CONTENT_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

        header_items[X5_CHAIN_INDEX].label.int64 = headers::PARAM_X5CHAIN;
        header_items[X5_CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
        header_items[X5_CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

        header_items[ISS_INDEX].label.string =
          UsefulBuf_FromSZ(HEADER_PARAM_ISSUER);
        header_items[ISS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
        header_items[ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

        header_items[FEED_INDEX].label.string =
          UsefulBuf_FromSZ(HEADER_PARAM_FEED);
        header_items[FEED_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
        header_items[FEED_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

        header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

        QCBORDecode_GetItemsInMap(&ctx, header_items);
        qcbor_result = QCBORDecode_GetError(&ctx);
        if (qcbor_result != QCBOR_SUCCESS)
        {
          throw COSEDecodeError("Failed to decode protected header");
        }

        UvmEndorsementsProtectedHeader phdr = {};

        if (header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          phdr.alg = header_items[ALG_INDEX].val.int64;
        }

        if (header_items[CONTENT_TYPE_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          phdr.content_type =
            qcbor_buf_to_string(header_items[CONTENT_TYPE_INDEX].val.string);
        }

        if (header_items[X5_CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          phdr.x5_chain = decode_x5chain(ctx, header_items[X5_CHAIN_INDEX]);
        }

        if (header_items[ISS_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          phdr.iss = qcbor_buf_to_string(header_items[ISS_INDEX].val.string);
        }

        if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          phdr.feed = qcbor_buf_to_string(header_items[FEED_INDEX].val.string);
        }

        QCBORDecode_ExitMap(&ctx);
        QCBORDecode_ExitBstrWrapped(&ctx);

        qcbor_result = QCBORDecode_GetError(&ctx);
        if (qcbor_result != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to decode protected header: {}", qcbor_result));
        }

        return phdr;
      }
    }

    std::pair<UvmEndorsementsProtectedHeader, std::string>
    decode_protected_header_with_cwt(
      const std::vector<uint8_t>& uvm_endorsements_raw)
    {
      UsefulBufC msg{uvm_endorsements_raw.data(), uvm_endorsements_raw.size()};

      QCBORError qcbor_result = QCBOR_SUCCESS;

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
        throw COSEDecodeError("Failed to parse COSE_Sign1 tag");
      }

      struct q_useful_buf_c protected_parameters = {};
      QCBORDecode_EnterBstrWrapped(
        &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
      QCBORDecode_EnterMap(&ctx, nullptr);

      enum HeaderIndex : uint8_t
      {
        ALG_INDEX,
        CONTENT_TYPE_INDEX,
        X5_CHAIN_INDEX,
        CWT_CLAIMS_INDEX,
        END_INDEX
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = headers::PARAM_ALG;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[CONTENT_TYPE_INDEX].label.int64 = 259;
      header_items[CONTENT_TYPE_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[CONTENT_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      header_items[X5_CHAIN_INDEX].label.int64 = headers::PARAM_X5CHAIN;
      header_items[X5_CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[X5_CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

      header_items[CWT_CLAIMS_INDEX].label.int64 = 15;
      header_items[CWT_CLAIMS_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[CWT_CLAIMS_INDEX].uDataType = QCBOR_TYPE_MAP;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError("Failed to decode protected header");
      }

      UvmEndorsementsProtectedHeader phdr = {};

      if (header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.alg = header_items[ALG_INDEX].val.int64;
      }

      if (header_items[CONTENT_TYPE_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.content_type =
          qcbor_buf_to_string(header_items[CONTENT_TYPE_INDEX].val.string);
      }

      if (header_items[X5_CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.x5_chain = decode_x5chain(ctx, header_items[X5_CHAIN_INDEX]);
      }

      QCBORDecode_EnterMapFromMapN(&ctx, crypto::COSE_PHEADER_KEY_CWT);
      auto decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode CWT claims: {}", decode_error));
      }

      enum CwtIndex : std::uint8_t
      {
        CWT_ISS_INDEX,
        CWT_SUB_INDEX,
        CWT_SVN_INDEX,
        CWT_END_INDEX,
      };
      QCBORItem cwt_items[CWT_END_INDEX + 1];

      cwt_items[CWT_ISS_INDEX].label.int64 = 1;
      cwt_items[CWT_ISS_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cwt_items[CWT_ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      cwt_items[CWT_SUB_INDEX].label.int64 = 2;
      cwt_items[CWT_SUB_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cwt_items[CWT_SUB_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      cwt_items[CWT_SVN_INDEX].label.string = UsefulBuf_FromSZ("svn");
      cwt_items[CWT_SVN_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      cwt_items[CWT_SVN_INDEX].uDataType = QCBOR_TYPE_INT64;

      cwt_items[CWT_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, cwt_items);
      decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode CWT claim contents: {}", decode_error));
      }

      if (cwt_items[CWT_ISS_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.iss = qcbor_buf_to_string(cwt_items[CWT_ISS_INDEX].val.string);
      }

      if (cwt_items[CWT_SUB_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        phdr.feed = qcbor_buf_to_string(cwt_items[CWT_SUB_INDEX].val.string);
      }

      size_t svn{0};
      if (cwt_items[CWT_SVN_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        svn = static_cast<size_t>(cwt_items[CWT_SVN_INDEX].val.int64);
      }

      QCBORDecode_ExitMap(&ctx); // cwt

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode protected header: {}", qcbor_result));
      }

      return {phdr, std::to_string(svn)};
    }

    std::span<const uint8_t> verify_uvm_endorsements_signature(
      const ccf::crypto::Pem& leaf_cert_pub_key,
      const std::vector<uint8_t>& uvm_endorsements_raw)
    {
      auto verifier =
        ccf::crypto::make_cose_verifier_from_key(leaf_cert_pub_key);

      std::span<uint8_t> payload;
      if (!verifier->verify(uvm_endorsements_raw, payload))
      {
        throw cose::COSESignatureValidationError(
          "Signature verification failed");
      }

      return payload;
    }

  }

  pal::UVMEndorsements verify_uvm_endorsements(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust,
    bool enforce_uvm_roots_of_trust)
  {
    UvmEndorsementsProtectedHeader phdr{};
    std::string sevsnpvm_guest_svn;

    try
    {
      std::tie(phdr, sevsnpvm_guest_svn) =
        cose::decode_protected_header_with_cwt(uvm_endorsements_raw);
    }
    // Since ContainerPlat 0.2.10, UVM endorsements carry SVN in CWT claims,
    // alongside ISS and SUB(feed), so on decoding failure fallback to legacy.
    catch (const cose::COSEDecodeError&)
    {
      phdr = cose::decode_protected_header(uvm_endorsements_raw);
    }

    if (!(cose::is_rsa_alg(phdr.alg) || cose::is_ecdsa_alg(phdr.alg)))
    {
      throw std::logic_error(fmt::format(
        "Signature algorithm {} is not one of expected: RSA, ECDSA", phdr.alg));
    }

    std::vector<std::string> pem_chain;
    pem_chain.reserve(phdr.x5_chain.size());
    for (auto const& c : phdr.x5_chain)
    {
      pem_chain.emplace_back(ccf::crypto::cert_der_to_pem(c).str());
    }

    const auto& did = phdr.iss;

    ccf::crypto::Pem pubk;
    const auto jwk = nlohmann::json::parse(
      didx509::resolve_jwk(pem_chain, did, true /* ignore time */));
    const auto generic_jwk = jwk.get<ccf::crypto::JsonWebKey>();
    switch (generic_jwk.kty)
    {
      case ccf::crypto::JsonWebKeyType::RSA:
      {
        auto rsa_jwk = jwk.get<ccf::crypto::JsonWebKeyRSAPublic>();
        pubk = ccf::crypto::make_rsa_public_key(rsa_jwk)->public_key_pem();
        break;
      }
      case ccf::crypto::JsonWebKeyType::EC:
      {
        auto ec_jwk = jwk.get<ccf::crypto::JsonWebKeyECPublic>();
        pubk = ccf::crypto::make_ec_public_key(ec_jwk)->public_key_pem();
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unsupported public key type ({}) for DID {}", generic_jwk.kty, did));
      }
    }

    auto raw_payload =
      cose::verify_uvm_endorsements_signature(pubk, uvm_endorsements_raw);

    if (phdr.content_type != cose::headers::CONTENT_TYPE_APPLICATION_JSON_VALUE)
    {
      throw std::logic_error(fmt::format(
        "Unexpected payload content type {}, expected {}",
        phdr.content_type,
        cose::headers::CONTENT_TYPE_APPLICATION_JSON_VALUE));
    }

    std::string sevsnpvm_launch_measurement{};
    if (sevsnpvm_guest_svn.empty())
    {
      auto payload = nlohmann::json::parse(raw_payload);
      sevsnpvm_launch_measurement =
        payload["x-ms-sevsnpvm-launchmeasurement"].get<std::string>();
      auto sevsnpvm_guest_svn_obj = payload["x-ms-sevsnpvm-guestsvn"];
      if (sevsnpvm_guest_svn_obj.is_string())
      {
        sevsnpvm_guest_svn = sevsnpvm_guest_svn_obj.get<std::string>();
        size_t uintval = 0;
        auto result = std::from_chars(
          sevsnpvm_guest_svn.data(),
          sevsnpvm_guest_svn.data() + sevsnpvm_guest_svn.size(),
          uintval);
        if (result.ec != std::errc())
        {
          throw std::logic_error(fmt::format(
            "Unable to parse sevsnpvm_guest_svn value {} to unsigned in UVM "
            "endorsements "
            "payload",
            sevsnpvm_guest_svn));
        }
      }
      else if (sevsnpvm_guest_svn_obj.is_number_unsigned())
      {
        sevsnpvm_guest_svn =
          std::to_string(sevsnpvm_guest_svn_obj.get<size_t>());
      }
      else
      {
        throw std::logic_error(fmt::format(
          "Unexpected type {} for sevsnpvm_guest_svn in UVM endorsements "
          "payload, expected string or unsigned integer",
          sevsnpvm_guest_svn_obj.type_name()));
      }
    }
    else
    {
      sevsnpvm_launch_measurement =
        ccf::ds::to_hex(raw_payload.begin(), raw_payload.end());
    }

    if (sevsnpvm_launch_measurement != uvm_measurement.hex_str())
    {
      throw std::logic_error(fmt::format(
        "Launch measurement in UVM endorsements payload {} is not equal "
        "to UVM attestation measurement {}",
        sevsnpvm_launch_measurement,
        uvm_measurement.hex_str()));
    }

    LOG_INFO_FMT(
      "Successfully verified endorsements for attested measurement {} against "
      "{}, feed {}, svn {}",
      sevsnpvm_launch_measurement,
      did,
      phdr.feed,
      sevsnpvm_guest_svn);

    pal::UVMEndorsements end{did, phdr.feed, sevsnpvm_guest_svn};

    if (
      enforce_uvm_roots_of_trust &&
      !matches_uvm_roots_of_trust(end, uvm_roots_of_trust))
    {
      throw std::logic_error(fmt::format(
        "UVM endorsements did {}, feed {}, svn {} "
        "do not match any of the known UVM roots of trust",
        end.did,
        end.feed,
        end.svn));
    }

    return end;
  }

  namespace pal
  {
    UVMEndorsements verify_uvm_endorsements_descriptor(
      const std::vector<uint8_t>& uvm_endorsements_raw,
      const pal::PlatformAttestationMeasurement& uvm_measurement)
    {
      return verify_uvm_endorsements(
        uvm_endorsements_raw,
        uvm_measurement,
        {}, // No roots of trust
        false); // Do not check against roots of trust
    }
  }

  pal::UVMEndorsements verify_uvm_endorsements_against_roots_of_trust(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust)
  {
    return verify_uvm_endorsements(
      uvm_endorsements_raw,
      uvm_measurement,
      uvm_roots_of_trust,
      true); // Check against roots of trust
  }
}