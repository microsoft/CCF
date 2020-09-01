// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/net.h"
#include "tls/san.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <string>

namespace tls
{
  // Unfortunately, mbedtls does not provide a convenient API to write x509v3
  // extensions for all supported Subject Alternative Name (SAN). Until they do,
  // we have to write raw ASN1 ourselves.

  // rfc5280 does not specify a maximum length for SAN,
  // but rfc1035 specified that 255 bytes is enough for a DNS name
  static constexpr auto max_san_length = 256;
  static constexpr auto max_san_entries = 8;

  // As per https://tools.ietf.org/html/rfc5280#section-4.2.1.6
  enum san_type
  {
    other_name = 0,
    rfc822_name = 1,
    dns_name = 2,
    x400_address = 3,
    directory_name = 4,
    edi_party_name = 5,
    uniform_resource_identifier = 6,
    ip_address = 7,
    registeredID = 8
  };

  inline int x509write_crt_set_subject_alt_name(
    mbedtls_x509write_cert* ctx,
    const char* name,
    san_type san = san_type::dns_name)
  {
    uint8_t san_buf[max_san_length];
    int ret = 0;
    size_t len = 0;

    // mbedtls asn1 write API writes backward in san_buf
    uint8_t* pc = san_buf + max_san_length;

    auto name_len = strlen(name);
    if (name_len > max_san_length)
    {
      throw std::logic_error(fmt::format(
        "Subject Alternative Name {} is too long ({}>{})",
        name,
        name_len,
        max_san_length));
    }

    switch (san)
    {
      case san_type::dns_name:
      {
        MBEDTLS_ASN1_CHK_ADD(
          len,
          mbedtls_asn1_write_raw_buffer(
            &pc, san_buf, (const unsigned char*)name, name_len));
        MBEDTLS_ASN1_CHK_ADD(
          len, mbedtls_asn1_write_len(&pc, san_buf, name_len));
        break;
      }

      // mbedtls (2.16.2) only supports parsing of subject alternative name that
      // is DNS= (so no IPAddress=). When connecting to a node that has
      // IPAddress set, mbedtls_ssl_set_hostname() should not be called.
      // However, it should work fine with a majority of other clients (e.g.
      // curl).
      case san_type::ip_address:
      {
        auto addr = ds::ip_to_binary(name);
        if (!addr.has_value())
        {
          throw std ::logic_error(fmt::format(
            "Subject Alternative Name {} is not a valid IPv4 or "
            "IPv6 address",
            name));
        }

        MBEDTLS_ASN1_CHK_ADD(
          len,
          mbedtls_asn1_write_raw_buffer(
            &pc, san_buf, (const unsigned char*)&addr->buf, addr->size));
        MBEDTLS_ASN1_CHK_ADD(
          len, mbedtls_asn1_write_len(&pc, san_buf, addr->size));

        break;
      }

      default:
      {
        throw std::logic_error(
          fmt::format("Subject Alternative Name {} is not supported", san));
      }
    }

    MBEDTLS_ASN1_CHK_ADD(
      len,
      mbedtls_asn1_write_tag(
        &pc, san_buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | san));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, san_buf, len));
    MBEDTLS_ASN1_CHK_ADD(
      len,
      mbedtls_asn1_write_tag(
        &pc, san_buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return mbedtls_x509write_crt_set_extension(
      ctx,
      MBEDTLS_OID_SUBJECT_ALT_NAME,
      MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
      0, // Mark SAN as non-critical
      san_buf + max_san_length - len,
      len);
  }

  inline int x509write_crt_set_subject_alt_names(
    mbedtls_x509write_cert* ctx, const std::vector<SubjectAltName>& sans)
  {
    if (sans.size() == 0)
      return 0;

    if (sans.size() > max_san_entries)
    {
      throw std::logic_error(fmt::format(
        "Cannot set more than {} subject alternative names", max_san_entries));
    }
    // The factor of two is an extremely conservative provision for ASN.1
    // metadata
    size_t buf_len = sans.size() * max_san_length * 2;

    std::vector<uint8_t> buf(buf_len);
    uint8_t* san_buf = buf.data();

    int ret = 0;
    size_t len = 0;

    // mbedtls asn1 write API writes backward in san_buf
    uint8_t* pc = san_buf + buf_len;

    for (auto& san : sans)
    {
      if (san.san.size() > max_san_length)
      {
        throw std::logic_error(fmt::format(
          "Subject Alternative Name {} is too long ({}>{})",
          san.san,
          san.san.size(),
          max_san_length));
      }

      if (san.is_ip)
      {
        // mbedtls (2.16.2) only supports parsing of subject alternative name
        // that is DNS= (so no IPAddress=). When connecting to a node that has
        // IPAddress set, mbedtls_ssl_set_hostname() should not be called.
        // However, it should work fine with a majority of other clients (e.g.
        // curl).

        auto addr = ds::ip_to_binary(san.san.c_str());
        if (!addr.has_value())
        {
          throw std ::logic_error(fmt::format(
            "Subject Alternative Name {} is not a valid IPv4 or "
            "IPv6 address",
            san.san));
        }

        MBEDTLS_ASN1_CHK_ADD(
          len,
          mbedtls_asn1_write_raw_buffer(
            &pc, san_buf, (const unsigned char*)&addr->buf, addr->size));
        MBEDTLS_ASN1_CHK_ADD(
          len, mbedtls_asn1_write_len(&pc, san_buf, addr->size));
      }
      else
      {
        MBEDTLS_ASN1_CHK_ADD(
          len,
          mbedtls_asn1_write_raw_buffer(
            &pc,
            san_buf,
            (const unsigned char*)san.san.data(),
            san.san.size()));
        MBEDTLS_ASN1_CHK_ADD(
          len, mbedtls_asn1_write_len(&pc, san_buf, san.san.size()));
      }

      MBEDTLS_ASN1_CHK_ADD(
        len,
        mbedtls_asn1_write_tag(
          &pc,
          san_buf,
          MBEDTLS_ASN1_CONTEXT_SPECIFIC |
            (san.is_ip ? san_type::ip_address : san_type::dns_name)));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, san_buf, len));
    MBEDTLS_ASN1_CHK_ADD(
      len,
      mbedtls_asn1_write_tag(
        &pc, san_buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return mbedtls_x509write_crt_set_extension(
      ctx,
      MBEDTLS_OID_SUBJECT_ALT_NAME,
      MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
      0, // Mark SAN as non-critical
      san_buf + buf_len - len,
      len);
  }
}