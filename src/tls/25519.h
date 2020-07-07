// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "error_string.h"
#include "pem.h"
#include "tls.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/pem.h>

namespace tls
{
  // This class parses and writes x25519 PEM keys following openssl
  // SubjectPublicKeyInfo DER format, generated by keygenerator.sh (e.g. for
  // members' public encryption key). Because the mbedtls version shipped with
  // Open Enclave does not (yet) support x25519 keys, we parse the key manually
  // here.
  class PublicX25519
  {
  private:
    static constexpr auto PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    static constexpr auto PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";
    static constexpr auto PUBLIC_KEY_PEM_HEADER_WRITE =
      "-----BEGIN PUBLIC KEY-----\n";
    static constexpr auto PUBLIC_KEY_PEM_FOOTER_WRITE =
      "-----END PUBLIC KEY-----\n";
    static constexpr auto max_25519_der_len = 64;
    static constexpr auto max_25519_pem_len = 128;
    static constexpr auto x25519_oid_len = 3;
    static constexpr char x25519_oid[x25519_oid_len] = {0x2b, 0x65, 0x6e};

    static int parse_subject_public_key_info_der(
      uint8_t** buf, size_t* len, mbedtls_asn1_buf* alg_oid)
    {
      mbedtls_asn1_buf alg_params;
      uint8_t* end = *buf + *len;

      int ret = mbedtls_asn1_get_tag(
        buf, end, len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
      if (ret != 0)
      {
        return ret;
      }

      ret = mbedtls_asn1_get_alg(buf, end, alg_oid, &alg_params);
      if (ret != 0)
      {
        return ret;
      }

      return mbedtls_asn1_get_bitstring_null(buf, end, len);
    }

    static int write_subject_public_key_info_der(
      uint8_t* buf,
      size_t size,
      size_t* len,
      const uint8_t* raw_public_key,
      size_t raw_public_key_size_bytes)
    {
      int ret = 0;

      // mbedtls asn1 write API writes backward in pubk_buf
      uint8_t* pc = buf + size;

      MBEDTLS_ASN1_CHK_ADD(
        *len,
        mbedtls_asn1_write_bitstring(
          &pc, buf, raw_public_key, raw_public_key_size_bytes * 8));

      // mbedtls_asn1_write_algorithm_identifier() is not used here as openssl
      // does not write algorithm parameters for x25519 at all if these are not
      // set
      auto pc_ = pc;
      MBEDTLS_ASN1_CHK_ADD(
        *len, mbedtls_asn1_write_oid(&pc, buf, x25519_oid, x25519_oid_len));
      MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_len(&pc, buf, pc_ - pc));
      MBEDTLS_ASN1_CHK_ADD(
        *len,
        mbedtls_asn1_write_tag(
          &pc, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

      MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_len(&pc, buf, *len));
      MBEDTLS_ASN1_CHK_ADD(
        *len,
        mbedtls_asn1_write_tag(
          &pc, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

      return ret;
    }

  public:
    static std::vector<uint8_t> parse(const Pem& public_pem)
    {
      auto pem_len = public_pem.size();
      uint8_t* raw_public_key;
      size_t raw_public_key_size;
      mbedtls_pem_context pem;

      try
      {
        mbedtls_pem_init(&pem);
        int rc = mbedtls_pem_read_buffer(
          &pem,
          PUBLIC_KEY_PEM_HEADER,
          PUBLIC_KEY_PEM_FOOTER,
          public_pem.data(),
          nullptr,
          0,
          &pem_len);
        if (rc != 0)
        {
          throw std::logic_error(fmt::format(
            "mbedtls_pem_read_buffer failed: {}", error_string(rc)));
        }

        raw_public_key = pem.buf;
        raw_public_key_size = pem.buflen;
        mbedtls_asn1_buf alg_oid;

        rc = parse_subject_public_key_info_der(
          &raw_public_key, &raw_public_key_size, &alg_oid);
        if (rc != 0)
        {
          throw std::logic_error(fmt::format(
            "Parsing public key info failed: {}", error_string(rc)));
        }

        if (memcmp(x25519_oid, alg_oid.p, x25519_oid_len) != 0)
        {
          throw std::logic_error(
            "Parsing public key failed: Key is not x25519");
        }
      }
      catch (const std::exception& e)
      {
        mbedtls_pem_free(&pem);
        throw;
      }

      std::vector<uint8_t> public_raw(
        raw_public_key, raw_public_key + raw_public_key_size);
      mbedtls_pem_free(&pem);

      return public_raw;
    }

    static Pem write(const std::vector<uint8_t>& raw_public_key)
    {
      std::vector<uint8_t> public_der(max_25519_der_len);
      std::vector<uint8_t> public_pem(max_25519_pem_len);
      size_t der_len = 0;

      auto rc = write_subject_public_key_info_der(
        public_der.data(),
        public_der.size(),
        &der_len,
        raw_public_key.data(),
        raw_public_key.size());
      if (rc < 0)
      {
        throw std::logic_error(fmt::format(
          "Error writing x25519 SubjectPublicKeyInfo DER {}",
          error_string(rc)));
      }

      auto pem_len = public_pem.size();
      rc = mbedtls_pem_write_buffer(
        PUBLIC_KEY_PEM_HEADER_WRITE,
        PUBLIC_KEY_PEM_FOOTER_WRITE,
        public_der.data() + public_der.size() - der_len,
        der_len,
        public_pem.data(),
        public_pem.size(),
        &pem_len);
      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("mbedtls_pem_write_buffer failed: {}", error_string(rc)));
      }

      return Pem(public_pem.data(), pem_len);
    }
  };
}