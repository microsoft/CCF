// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/uvm_endorsements.h"

#include "ds/internal_logger.h"

extern "C" {
#include "evercbor/CBORNondet.h"
}

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
        cbor_nondet_t x5chain)
      {
        std::vector<std::vector<uint8_t>> parsed;

        cbor_nondet_array_iterator_t array;
        if (cbor_nondet_array_iterator_start(x5chain, &array))
        {
          cbor_nondet_t item;
          while (cbor_nondet_array_iterator_next(&array, &item))
          {
            uint8_t *payload = NULL;
            uint64_t len = 0;
            if (cbor_nondet_get_byte_string(item, &payload, &len))
            {
              parsed.push_back(std::vector<uint8_t>(payload, payload + len)); // This is a copy
            }
            else
            {
              throw COSEDecodeError(
                "Next item in x5chain was not of type byte string");
            }
          }
          if (parsed.empty())
          {
            throw COSEDecodeError("x5chain array length was 0 in COSE header");
          }
        }
        else {
          uint8_t *payload = NULL;
          uint64_t len = 0;
          if (cbor_nondet_get_byte_string(x5chain, &payload, &len)) {
            parsed.push_back(std::vector<uint8_t>(payload, payload + len)); // This is a copy
          } else {
            throw COSEDecodeError(fmt::format(
              "Value type {} of x5chain in COSE header is not array or byte "
              "string",
              cbor_nondet_major_type(x5chain)));
          }
        }

        return parsed;
      }

      UvmEndorsementsProtectedHeader decode_protected_header(
        const std::vector<uint8_t>& uvm_endorsements_raw)
      {
        cbor_nondet_t cbor;
        uint8_t * cbor_parse_input = (uint8_t *) uvm_endorsements_raw.data();
        size_t cbor_parse_size = uvm_endorsements_raw.size();

        if (! cbor_nondet_parse(true, 0, &cbor_parse_input, &cbor_parse_size, &cbor)) {
          throw COSEDecodeError("Failed to validate COSE_Sign1 as a definite-length CBOR object without floating-points and with no maps in map keys");
        }

        uint64_t tag;
        cbor_nondet_t tagged_payload;
        if (! cbor_nondet_get_tagged(cbor, &tagged_payload, &tag)) {
          throw COSEDecodeError("Failed to parse COSE_Sign1 tag");
        }
        
        if (tag != CBOR_TAG_COSE_SIGN1) {
          throw COSEDecodeError("Failed to parse COSE_Sign1 tag");
        }
        
        cbor_nondet_array_iterator_t outer_array;
        if (! cbor_nondet_array_iterator_start(tagged_payload, &outer_array)) {
          throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
        }

        cbor_nondet_t protected_parameters_as_bstr;
        if (! cbor_nondet_array_iterator_next(&outer_array, &protected_parameters_as_bstr)) {
          throw COSEDecodeError("Failed to decode COSE_Sign1 protected parameters");
        }

        uint8_t *protected_parameters_input;
        uint64_t protected_parameters_len64;
        if (! cbor_nondet_get_byte_string(protected_parameters_as_bstr, &protected_parameters_input, &protected_parameters_len64)) {
          throw COSEDecodeError("Failed to decode COSE_Sign1 protected parameters");
        }

        size_t protected_parameters_len = protected_parameters_len64;
        cbor_nondet_t protected_parameters;
        if (! cbor_nondet_parse(true, 0, &protected_parameters_input, &protected_parameters_len, &protected_parameters)) {
          throw COSEDecodeError("Failed to decode COSE_Sign1 protected parameters");
        }

        enum HeaderIndex : uint8_t
        {
          ALG_INDEX,
          CONTENT_TYPE_INDEX,
          X5_CHAIN_INDEX,
          ISS_INDEX,
          FEED_INDEX,
          END_INDEX
        };
        cbor_nondet_map_get_multiple_entry_t header_items[END_INDEX];

        header_items[ALG_INDEX].key = cbor_nondet_mk_int64(headers::PARAM_ALG);
        header_items[CONTENT_TYPE_INDEX].key = cbor_nondet_mk_int64(headers::PARAM_CONTENT_TYPE);
        header_items[X5_CHAIN_INDEX].key = cbor_nondet_mk_int64(headers::PARAM_X5CHAIN);
        if (! cbor_nondet_mk_text_string((uint8_t *)HEADER_PARAM_ISSUER, sizeof(HEADER_PARAM_ISSUER) - 1, &header_items[ISS_INDEX].key)) // sizeof() - 1 to strip the null terminator from the C-style string
        {
          throw COSEDecodeError("Failed to encode HEADER_PARAM_ISSUER");
        }
        if (! cbor_nondet_mk_text_string((uint8_t *)HEADER_PARAM_FEED, sizeof(HEADER_PARAM_FEED) - 1, &header_items[FEED_INDEX].key)) // sizeof() - 1 to strip the null terminator from the C-style string
        {
          throw COSEDecodeError("Failed to encode HEADER_PARAM_FEED");
        }

        if (! cbor_nondet_map_get_multiple(protected_parameters, header_items, END_INDEX)) {
          throw COSEDecodeError("Failed to decode protected header");
        }

        UvmEndorsementsProtectedHeader phdr = {};

        if (header_items[ALG_INDEX].found)
        {
          if (! cbor_nondet_read_int64(header_items[ALG_INDEX].value, &phdr.alg)) {
            throw "Failed to decode protected header";
          }
        }

        if (header_items[CONTENT_TYPE_INDEX].found)
        {
          uint8_t * payload = NULL;
          uint64_t len = 0;
          if (! cbor_nondet_get_text_string(header_items[CONTENT_TYPE_INDEX].value, &payload, &len)) {
            throw "Failed to decode protected header";
          }
          phdr.content_type = std::string((char*)payload, len); // This is a copy. We don't need to reinstate a null terminator because C++ strings are not null-terminated. The extra len argument to the constructor is crucial to this end.
        }

        if (header_items[X5_CHAIN_INDEX].found)
        {
          phdr.x5_chain = decode_x5chain(header_items[X5_CHAIN_INDEX].value);
        }

        if (header_items[ISS_INDEX].found)
        {
          uint8_t * payload = NULL;
          uint64_t len = 0;
          if (! cbor_nondet_get_text_string(header_items[ISS_INDEX].value, &payload, &len)) {
            throw "Failed to decode protected header";
          }
          phdr.iss = std::string((char*)payload, len); // This is a copy. We don't need to reinstate a null terminator because C++ strings are not null-terminated. The extra len argument to the constructor is crucial to this end.
        }

        if (header_items[FEED_INDEX].found)
        {
          uint8_t * payload = NULL;
          uint64_t len = 0;
          if (! cbor_nondet_get_text_string(header_items[FEED_INDEX].value, &payload, &len)) {
            throw "Failed to decode protected header";
          }
          phdr.feed = std::string((char*)payload, len); // This is a copy. We don't need to reinstate a null terminator because C++ strings are not null-terminated. The extra len argument to the constructor is crucial to this end.
        }

        return phdr;
      }
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
    auto phdr = cose::decode_protected_header(uvm_endorsements_raw);

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

    auto payload = nlohmann::json::parse(raw_payload);
    std::string sevsnpvm_launch_measurement =
      payload["x-ms-sevsnpvm-launchmeasurement"].get<std::string>();
    auto sevsnpvm_guest_svn_obj = payload["x-ms-sevsnpvm-guestsvn"];
    std::string sevsnpvm_guest_svn;
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
      sevsnpvm_guest_svn = std::to_string(sevsnpvm_guest_svn_obj.get<size_t>());
    }
    else
    {
      throw std::logic_error(fmt::format(
        "Unexpected type {} for sevsnpvm_guest_svn in UVM endorsements "
        "payload, expected string or unsigned integer",
        sevsnpvm_guest_svn_obj.type_name()));
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
