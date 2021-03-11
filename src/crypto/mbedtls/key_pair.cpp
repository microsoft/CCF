// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "key_pair.h"

#include "curve.h"
#include "ds/net.h"
#include "entropy.h"

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

  static mbedtls_ecp_group_id get_mbedtls_group_id(CurveID gid)
  {
    switch (gid)
    {
      case CurveID::NONE:
        return MBEDTLS_ECP_DP_NONE;
      case CurveID::SECP384R1:
        return MBEDTLS_ECP_DP_SECP384R1;
      case CurveID::SECP256R1:
        return MBEDTLS_ECP_DP_SECP256R1;
      default:
        throw std::logic_error(fmt::format("unsupported CurveID {}", gid));
    }
    return MBEDTLS_ECP_DP_NONE;
  }

  KeyPair_mbedTLS::KeyPair_mbedTLS(CurveID cid) : PublicKey_mbedTLS()
  {
    mbedtls_ecp_group_id ec = get_mbedtls_group_id(cid);
    EntropyPtr entropy = create_entropy();

    int rc =
      mbedtls_pk_setup(ctx.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc != 0)
    {
      throw std::logic_error(
        "Could not set up ECDSA context: " + error_string(rc));
    }

    rc = mbedtls_ecp_gen_key(
      ec, mbedtls_pk_ec(*ctx), entropy->get_rng(), entropy->get_data());
    if (rc != 0)
    {
      throw std::logic_error(
        "Could not generate ECDSA keypair: " + error_string(rc));
    }

    const auto actual_ec = get_mbedtls_ec_from_context(*ctx);
    if (actual_ec != ec)
    {
      throw std::logic_error(
        "Created key and received unexpected type: " +
        std::to_string(actual_ec) + " != " + error_string(ec));
    }
  }

  KeyPair_mbedTLS::KeyPair_mbedTLS(const Pem& pem, CBuffer pw)
  {
    // keylen is +1 to include terminating null byte
    int rc =
      mbedtls_pk_parse_key(ctx.get(), pem.data(), pem.size(), pw.p, pw.n);
    if (rc != 0)
    {
      throw std::logic_error(
        "Could not parse private key: " + error_string(rc));
    }
  }

  KeyPair_mbedTLS::KeyPair_mbedTLS(mbedtls::PKContext&& k) :
    PublicKey_mbedTLS(std::move(k))
  {}

  Pem KeyPair_mbedTLS::private_key_pem() const
  {
    uint8_t data[max_pem_key_size];

    int rc = mbedtls_pk_write_key_pem(ctx.get(), data, max_pem_key_size);
    if (rc != 0)
    {
      throw std::logic_error("mbedtls_pk_write_key_pem: " + error_string(rc));
    }

    const size_t len = strlen((char const*)data);
    return Pem(data, len);
  }

  Pem KeyPair_mbedTLS::public_key_pem() const
  {
    return PublicKey_mbedTLS::public_key_pem();
  }

  std::vector<uint8_t> KeyPair_mbedTLS::public_key_der() const
  {
    return PublicKey_mbedTLS::public_key_der();
  }

  bool KeyPair_mbedTLS::verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
  {
    return PublicKey_mbedTLS::verify(contents, signature);
  }

  std::vector<uint8_t> KeyPair_mbedTLS::sign(CBuffer d, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    MBedHashProvider hp;
    HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
    return sign_hash(hash.data(), hash.size());
  }

  int KeyPair_mbedTLS::sign(
    CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    MBedHashProvider hp;
    HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
    return sign_hash(hash.data(), hash.size(), sig_size, sig);
  }

  std::vector<uint8_t> KeyPair_mbedTLS::sign_hash(
    const uint8_t* hash, size_t hash_size) const
  {
    std::vector<uint8_t> sig(MBEDTLS_ECDSA_MAX_LEN);
    size_t written = sizeof(sig);

    if (sign_hash(hash, hash_size, &written, sig.data()) != 0)
    {
      return {};
    }

    sig.resize(written);
    return sig;
  }

  int KeyPair_mbedTLS::sign_hash(
    const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const
  {
    EntropyPtr entropy = create_entropy();

    const auto mmdt = get_md_type(get_md_for_ec(get_curve_id()));

    int r = mbedtls_pk_sign(
      ctx.get(),
      mmdt,
      hash,
      hash_size,
      sig,
      sig_size,
      entropy->get_rng(),
      entropy->get_data());

    return r;
  }

  Pem KeyPair_mbedTLS::create_csr(const std::string& name) const
  {
    auto csr = mbedtls::make_unique<mbedtls::X509WriteCsr>();
    mbedtls_x509write_csr_set_md_alg(csr.get(), MBEDTLS_MD_SHA512);

    if (mbedtls_x509write_csr_set_subject_name(csr.get(), name.c_str()) != 0)
      return {};

    mbedtls_x509write_csr_set_key(csr.get(), ctx.get());

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));
    EntropyPtr entropy = create_entropy();

    if (
      mbedtls_x509write_csr_pem(
        csr.get(), buf, sizeof(buf), entropy->get_rng(), entropy->get_data()) !=
      0)
      return {};

    auto len = strlen((char*)buf);
    return Pem(buf, len);
  }

  static void MCHK(int rc)
  {
    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("mbedTLS error: {}", error_string(rc)));
    }
  }

  // Unfortunately, mbedtls does not provide a convenient API to write x509v3
  // extensions for all supported Subject Alternative Name (SAN). Until they
  // do, we have to write raw ASN1 ourselves.

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

  static inline int x509write_crt_set_subject_alt_name(
    mbedtls_x509write_cert* ctx, const char* name, san_type san)
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

      // mbedtls (2.16.2) only supports parsing of subject alternative name
      // that is DNS= (so no IPAddress=). When connecting to a node that has
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

  static inline int x509write_crt_set_subject_alt_names(
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

  Pem KeyPair_mbedTLS::sign_csr(
    const Pem& issuer_cert,
    const Pem& signing_request,
    const std::vector<SubjectAltName> subject_alt_names,
    bool ca) const
  {
    auto entropy = create_entropy();
    auto csr = mbedtls::make_unique<mbedtls::X509Csr>();
    auto serial = mbedtls::make_unique<mbedtls::MPI>();
    auto crt = mbedtls::make_unique<mbedtls::X509WriteCrt>();
    auto icrt = mbedtls::make_unique<mbedtls::X509Crt>();

    MCHK(mbedtls_x509_csr_parse(
      csr.get(), signing_request.data(), signing_request.size()));

    char subject[512];
    mbedtls_x509_dn_gets(subject, sizeof(subject), &csr->subject);

    mbedtls_x509write_crt_set_md_alg(
      crt.get(), get_mbedtls_md_for_ec(get_mbedtls_ec_from_context(*ctx)));
    mbedtls_x509write_crt_set_subject_key(crt.get(), &csr->pk);

    if (!issuer_cert.empty())
    {
      MCHK(mbedtls_x509_crt_parse(
        icrt.get(), issuer_cert.data(), issuer_cert.size()));
      mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());
      char issuer_name[512];
      mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &icrt->subject);
      MCHK(mbedtls_x509write_crt_set_issuer_name(crt.get(), issuer_name));
    }
    else
    {
      mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());
      MCHK(mbedtls_x509write_crt_set_issuer_name(crt.get(), subject));
    }

    MCHK(mbedtls_mpi_fill_random(
      serial.get(), 16, entropy->get_rng(), entropy->get_data()));
    MCHK(mbedtls_x509write_crt_set_subject_name(crt.get(), subject));
    MCHK(mbedtls_x509write_crt_set_serial(crt.get(), serial.get()));

    // Note: 825-day validity range
    // https://support.apple.com/en-us/HT210176
    MCHK(mbedtls_x509write_crt_set_validity(
      crt.get(), "20210311000000", "20230611235959"));

    MCHK(mbedtls_x509write_crt_set_basic_constraints(crt.get(), ca ? 1 : 0, 0));
    MCHK(mbedtls_x509write_crt_set_subject_key_identifier(crt.get()));
    MCHK(mbedtls_x509write_crt_set_authority_key_identifier(crt.get()));

    // Because mbedtls does not support parsing x509v3 extensions from a
    // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), the CA sets the
    // SAN directly instead of reading it from the CSR
    try
    {
      MCHK(x509write_crt_set_subject_alt_names(crt.get(), subject_alt_names));
    }
    catch (const std::logic_error& err)
    {
      LOG_FAIL_FMT("Error writing SAN: {}", err.what());
      return {};
    }

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    MCHK(mbedtls_x509write_crt_pem(
      crt.get(), buf, sizeof(buf), entropy->get_rng(), entropy->get_data()));

    auto len = strlen((char*)buf);
    return Pem(buf, len);
  }
}
