// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/uvm_endorsements.h"

#include "crypto/cbor.h"
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
      std::vector<std::vector<uint8_t>> parse_x5chain(
        const ccf::cbor::Value& x5chain_value)
      {
        std::vector<std::vector<uint8_t>> chain;
        // x5chain can be either an array of byte strings or a single byte
        // string
        try
        {
          for (size_t i = 0; i < x5chain_value->size(); ++i)
          {
            const auto x5chain_ctx = "x5chain[" + std::to_string(i) + "]";
            const auto& bytes = ccf::cbor::rethrow_with_context(
              [&]() { return x5chain_value->array_at(i)->as_bytes(); },
              x5chain_ctx);
            chain.emplace_back(bytes.begin(), bytes.end());
          }
        }
        catch (const ccf::cbor::CBORDecodeError&)
        {
          auto bytes = ccf::cbor::rethrow_with_context(
            [&]() { return x5chain_value->as_bytes(); }, "x5chain");
          chain.emplace_back(bytes.begin(), bytes.end());
        }
        return chain;
      }

      UvmEndorsementsProtectedHeader decode_protected_header(
        std::span<const uint8_t> raw_endorsements)
      {
        auto parsed = ccf::cbor::rethrow_with_context(
          [&]() { return ccf::cbor::parse(raw_endorsements); },
          "COSE envelope");
        const auto& cose_array = ccf::cbor::rethrow_with_context(
          [&]() -> const ccf::cbor::Value& {
            return parsed->tag_at(CBOR_TAG_COSE_SIGN1);
          },
          "COSE_Sign1 tag");
        constexpr std::string_view phdr_context{"COSE_Sign1[0]"};
        const auto& phdr_bytes = ccf::cbor::rethrow_with_context(
          [&]() -> const ccf::cbor::Value& { return cose_array->array_at(0); },
          phdr_context);
        auto phdr_bytes_span = ccf::cbor::rethrow_with_context(
          [&]() { return phdr_bytes->as_bytes(); }, phdr_context);
        auto parsed_phdr = ccf::cbor::rethrow_with_context(
          [&]() { return ccf::cbor::parse(phdr_bytes_span); }, "phdr CBOR");

        UvmEndorsementsProtectedHeader result;

        result.alg = ccf::cbor::rethrow_with_context(
          [&]() {
            return parsed_phdr
              ->map_at(ccf::cbor::make_unsigned(headers::PARAM_ALG))
              ->as_signed();
          },
          "phdr: " + std::to_string(headers::PARAM_ALG));

        result.content_type = ccf::cbor::rethrow_with_context(
          [&]() {
            return std::string(
              parsed_phdr
                ->map_at(ccf::cbor::make_unsigned(headers::PARAM_CONTENT_TYPE))
                ->as_string());
          },
          "phdr: " + std::to_string(headers::PARAM_CONTENT_TYPE));

        result.x5_chain = ccf::cbor::rethrow_with_context(
          [&]() {
            return parse_x5chain(parsed_phdr->map_at(
              ccf::cbor::make_unsigned(headers::PARAM_X5CHAIN)));
          },
          "phdr: " + std::to_string(headers::PARAM_X5CHAIN));

        result.iss = ccf::cbor::rethrow_with_context(
          [&]() {
            return parsed_phdr->map_at(ccf::cbor::make_string("iss"))
              ->as_string();
          },
          "phdr: iss");

        result.feed = ccf::cbor::rethrow_with_context(
          [&]() {
            return std::string(
              parsed_phdr->map_at(ccf::cbor::make_string("feed"))->as_string());
          },
          "phdr: feed");

        return result;
      }

      std::pair<UvmEndorsementsProtectedHeader, std::string>
      decode_protected_header_with_cwt(
        std::span<const uint8_t> raw_endorsements)
      {
        auto parsed = ccf::cbor::rethrow_with_context(
          [&]() { return ccf::cbor::parse(raw_endorsements); },
          "COSE envelope");
        const auto& cose_array = ccf::cbor::rethrow_with_context(
          [&]() -> const ccf::cbor::Value& {
            return parsed->tag_at(CBOR_TAG_COSE_SIGN1);
          },
          "COSE_Sign1 tag");

        constexpr std::string_view phdr_context{"COSE_Sign1[0]"};
        const auto& phdr_bytes = ccf::cbor::rethrow_with_context(
          [&]() -> const ccf::cbor::Value& { return cose_array->array_at(0); },
          phdr_context);
        auto phdr_bytes_span = ccf::cbor::rethrow_with_context(
          [&]() { return phdr_bytes->as_bytes(); }, phdr_context);

        auto parsed_phdr = ccf::cbor::rethrow_with_context(
          [&]() { return ccf::cbor::parse(phdr_bytes_span); }, "phdr CBOR");

        UvmEndorsementsProtectedHeader result;

        result.alg = ccf::cbor::rethrow_with_context(
          [&]() {
            return parsed_phdr
              ->map_at(ccf::cbor::make_unsigned(headers::PARAM_ALG))
              ->as_signed();
          },
          "phdr: " + std::to_string(headers::PARAM_ALG));

        result.content_type = ccf::cbor::rethrow_with_context(
          [&]() {
            return std::string(parsed_phdr
                                 ->map_at(ccf::cbor::make_unsigned(
                                   headers::PARAM_CONTENT_TYPE_HASH_ENVELOPE))
                                 ->as_string());
          },
          "phdr: " + std::to_string(headers::PARAM_CONTENT_TYPE_HASH_ENVELOPE));

        result.x5_chain = ccf::cbor::rethrow_with_context(
          [&]() {
            return parse_x5chain(parsed_phdr->map_at(
              ccf::cbor::make_unsigned(headers::PARAM_X5CHAIN)));
          },
          "phdr: " + std::to_string(headers::PARAM_X5CHAIN));

        const ccf::cbor::Value& cwt_claims = ccf::cbor::rethrow_with_context(
          [&]() -> const ccf::cbor::Value& {
            return parsed_phdr->map_at(
              ccf::cbor::make_unsigned(ccf::crypto::COSE_PHEADER_KEY_CWT));
          },
          "phdr: " + std::to_string(ccf::crypto::COSE_PHEADER_KEY_CWT));

        result.iss = ccf::cbor::rethrow_with_context(
          [&]() {
            return std::string(cwt_claims
                                 ->map_at(ccf::cbor::make_unsigned(
                                   ccf::crypto::COSE_PHEADER_KEY_ISS))
                                 ->as_string());
          },
          "cwt: " + std::to_string(ccf::crypto::COSE_PHEADER_KEY_ISS));

        result.feed = ccf::cbor::rethrow_with_context(
          [&]() {
            return std::string(cwt_claims
                                 ->map_at(ccf::cbor::make_unsigned(
                                   ccf::crypto::COSE_PHEADER_KEY_SUB))
                                 ->as_string());
          },
          "cwt: " + std::to_string(ccf::crypto::COSE_PHEADER_KEY_SUB));

        uint64_t svn = ccf::cbor::rethrow_with_context(
          [&]() {
            return cwt_claims->map_at(ccf::cbor::make_string("svn"))
              ->as_unsigned();
          },
          "cwt: svn");

        return {result, std::to_string(svn)};
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
    catch (const ccf::cbor::CBORDecodeError&)
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
