// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "curve.h"
#include "ds/net.h"
#include "entropy.h"
#include "key_pair.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <iomanip>
#include <limits>
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <memory>
#include <string>

namespace crypto
{
  using namespace mbedtls;

  static constexpr size_t max_pem_key_size = 2048;
  static constexpr size_t max_der_key_size = 2048;

  PublicKey_mbedTLS::PublicKey_mbedTLS() {}

  PublicKey_mbedTLS::PublicKey_mbedTLS(const Pem& pem)
  {
    int rc = mbedtls_pk_parse_public_key(ctx.get(), pem.data(), pem.size());

    if (rc != 0)
    {
      throw std::logic_error(fmt::format(
        "Could not parse public key PEM: {}\n\n(Key: {})",
        error_string(rc),
        pem.str()));
    }
  }

  PublicKey_mbedTLS::PublicKey_mbedTLS(const std::vector<uint8_t>& der)
  {
    int rc = mbedtls_pk_parse_public_key(ctx.get(), der.data(), der.size());

    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Could not parse public key DER: {}", error_string(rc)));
    }
  }

  static CurveID get_curve_id(const mbedtls_pk_context* pk_ctx)
  {
    if (mbedtls_pk_can_do(pk_ctx, MBEDTLS_PK_ECKEY))
    {
      auto grp_id = mbedtls_pk_ec(*pk_ctx)->grp.id;
      switch (grp_id)
      {
        case MBEDTLS_ECP_DP_SECP384R1:
          return CurveID::SECP384R1;
        case MBEDTLS_ECP_DP_SECP256R1:
          return CurveID::SECP256R1;
        default:
          throw std::logic_error(
            fmt::format("unsupported mbedTLS group ID {}", grp_id));
      }
    }

    return CurveID::NONE;
  }

  CurveID PublicKey_mbedTLS::get_curve_id() const
  {
    return crypto::get_curve_id(ctx.get());
  }

  PublicKey_mbedTLS::PublicKey_mbedTLS(mbedtls::PKContext&& c) :
    ctx(std::move(c))
  {}

  bool PublicKey_mbedTLS::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type,
    HashBytes& bytes)
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    MBedHashProvider hp;
    bytes = hp.Hash(contents, contents_size, md_type);
    return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
  }

  bool PublicKey_mbedTLS::verify_hash(
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type)
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }

    const auto mmdt = get_md_type(md_type);

    int rc = mbedtls_pk_verify(ctx.get(), mmdt, hash, hash_size, sig, sig_size);

    if (rc)
      LOG_DEBUG_FMT("Failed to verify signature: {}", error_string(rc));

    return rc == 0;
  }

  Pem PublicKey_mbedTLS::public_key_pem() const
  {
    uint8_t data[max_pem_key_size];

    int rc = mbedtls_pk_write_pubkey_pem(ctx.get(), data, max_pem_key_size);
    if (rc != 0)
    {
      throw std::logic_error(
        "mbedtls_pk_write_pubkey_pem: " + error_string(rc));
    }

    const size_t len = strlen((char const*)data);
    return Pem(data, len);
  }

  std::vector<uint8_t> PublicKey_mbedTLS::public_key_der() const
  {
    uint8_t data[max_der_key_size];

    int len = mbedtls_pk_write_pubkey_der(ctx.get(), data, max_der_key_size);
    if (len < 0)
    {
      throw std::logic_error(
        "mbedtls_pk_write_pubkey_der: " + error_string(len));
    }

    return {data + max_der_key_size - len, data + max_der_key_size};
  };

  mbedtls_pk_context* PublicKey_mbedTLS::get_raw_context() const
  {
    return ctx.get();
  }
}