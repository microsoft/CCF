// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/ds/nonstd.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/cbor_tags.h"
#include "crypto/cose.h"

#include <chrono>
#include <cstdint>
#include <fmt/format.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tav/cbor.hpp>
#include <vector>

namespace ccf::cose::utils
{
  inline std::vector<std::vector<uint8_t>> parse_x5chain(
    const tav::cbor::Value& x5chain_value)
  {
    std::vector<std::vector<uint8_t>> chain;
    // x5chain can be either an array of byte strings or a single byte string
    try
    {
      for (size_t i = 0; i < x5chain_value.size(); ++i)
      {
        const auto x5chain_ctx = "x5chain[" + std::to_string(i) + "]";
        const auto& bytes = tav::cbor::rethrow_with_msg(
          [&]() { return x5chain_value.array_at(i).as_bytes(); }, x5chain_ctx);
        chain.emplace_back(bytes.begin(), bytes.end());
      }
    }
    catch (const tav::cbor::DecodeError&)
    {
      auto bytes = tav::cbor::rethrow_with_msg(
        [&]() { return x5chain_value.as_bytes(); }, "x5chain");
      chain.emplace_back(bytes.begin(), bytes.end());
    }
    return chain;
  }
}

namespace ccf::cose
{
  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct COSESignatureValidationError : public std::runtime_error
  {
    COSESignatureValidationError(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

  struct CwtClaims
  {
    std::optional<int64_t> iat;
    std::string iss;
    std::string sub;
    std::optional<int64_t> svn;
  };

  static void decode_cwt_claims(const tav::cbor::Value& cbor, CwtClaims& claims)
  {
    using namespace tav::cbor;

    const auto cwt_claims = rethrow_with_msg(
      [&]() {
        return cbor.map_at(make_signed(ccf::cose::header::iana::CWT_CLAIMS));
      },
      "Parse CWT claims map");

    try
    {
      const auto& iat =
        cwt_claims.map_at(make_signed(ccf::cwt::header::iana::IAT));
      try
      {
        claims.iat = iat.as_signed();
      }
      catch (const DecodeError&)
      {
        // CWT NumericDate values MUST omit CBOR tags:
        // https://www.rfc-editor.org/rfc/rfc8392.html#section-5
        // This non-conforming fallback accepts CBOR tag 1 for UVM
        // endorsement compatibility.
        claims.iat = iat.tag_at(ccf::cbor::tag::EPOCH_DATE_TIME).as_signed();
      }
    }
    catch (const DecodeError& err)
    {
      std::ignore = err; // optional field
    }

    claims.iss = rethrow_with_msg(
      [&]() {
        return cwt_claims.map_at(make_signed(ccf::cwt::header::iana::ISS))
          .as_string();
      },
      fmt::format(
        "Parse CWT claim iss({}) field", ccf::cwt::header::iana::ISS));

    claims.sub = rethrow_with_msg(
      [&]() {
        return cwt_claims.map_at(make_signed(ccf::cwt::header::iana::SUB))
          .as_string();
      },
      fmt::format(
        "Parse CWT claim sub({}) field", ccf::cwt::header::iana::SUB));

    try
    {
      claims.svn = cwt_claims.map_at(make_string(ccf::cwt::header::custom::SVN))
                     .as_signed();
    }
    catch (const DecodeError& err)
    {
      if (err.error_code() != Error::KEY_NOT_FOUND)
      {
        throw;
      }
    }
  }

  static void validate_cwt_iat_against_x5chain(
    const CwtClaims& claims,
    const std::vector<std::vector<uint8_t>>& x5chain,
    std::string_view context)
  {
    if (!claims.iat.has_value())
    {
      return;
    }

    if (x5chain.empty())
    {
      throw COSEDecodeError(
        fmt::format("No certificates in {} x5chain", context));
    }

    const auto common_validity_period =
      ccf::crypto::OpenSSL::get_x509_chain_common_validity_period(x5chain);
    if (!common_validity_period.has_value())
    {
      throw COSEDecodeError(fmt::format(
        "Certificates in {} x5chain have no common validity period", context));
    }

    const auto iat = ccf::nonstd::SystemClock::time_point{
      std::chrono::seconds{claims.iat.value()}};
    if (
      iat < common_validity_period->not_before ||
      iat > common_validity_period->not_after)
    {
      throw COSEDecodeError(fmt::format(
        "CWT iat {} in {} is outside x5chain common validity period [{}, {}]",
        claims.iat.value(),
        context,
        ccf::ds::to_x509_time_string(common_validity_period->not_before),
        ccf::ds::to_x509_time_string(common_validity_period->not_after)));
    }
  }
}
