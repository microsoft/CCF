// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "key_pair.h"

#include "curve.h"
#include "ds/net.h"
#include "entropy.h"
#include "hash.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <iomanip>
#include <limits>
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
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

  bool KeyPair_mbedTLS::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    return PublicKey_mbedTLS::verify(
      contents, contents_size, signature, signature_size);
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

  static int ecdsa_sign_nondet(
    mbedtls_pk_context* ctx,
    const uint8_t* hash,
    size_t hash_size,
    uint8_t* sig,
    size_t* sig_size)
  {
    EntropyPtr entropy = create_entropy();
    mbedtls_ecdsa_context* ecdsa_ctx = (mbedtls_ecdsa_context*)ctx->pk_ctx;

    mbedtls_mpi sr, ss;
    mbedtls_mpi_init(&sr);
    mbedtls_mpi_init(&ss);

    int r = mbedtls_ecdsa_sign(
      &ecdsa_ctx->grp,
      &sr,
      &ss,
      &ecdsa_ctx->d,
      hash,
      hash_size,
      entropy->get_rng(),
      entropy->get_data());

    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char* p = buf + sizeof(buf);
    size_t len = 0;
    len += mbedtls_asn1_write_mpi(&p, buf, &ss);
    len += mbedtls_asn1_write_mpi(&p, buf, &sr);
    len += mbedtls_asn1_write_len(&p, buf, len);
    len += mbedtls_asn1_write_tag(
      &p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    memcpy(sig, p, len);
    *sig_size = len;

    mbedtls_mpi_free(&sr);
    mbedtls_mpi_free(&ss);
    return 0;
  }

  int KeyPair_mbedTLS::sign_hash(
    const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const
  {
    EntropyPtr entropy = create_entropy();

    const auto mmdt = get_md_type(get_md_for_ec(get_curve_id()));

#ifdef DETERMINISTIC_ECDSA
    return mbedtls_pk_sign(
      ctx.get(),
      mmdt,
      hash,
      hash_size,
      sig,
      sig_size,
      entropy->get_rng(),
      entropy->get_data());
#else
    return ecdsa_sign_nondet(ctx.get(), hash, hash_size, sig, sig_size);
#endif
  }

  Pem KeyPair_mbedTLS::create_csr(const CertificateSubjectIdentity& csi) const
  {
    // mbedtls does not support parsing x509v3 extensions from a CSR
    // (https://github.com/ARMmbed/mbedtls/issues/2912) so disallow CSR creation
    // if any SAN is specified (use OpenSSL implementation instead)
    if (!csi.sans.empty())
    {
      throw std::logic_error("mbedtls cannot create CSR with SAN");
    }

    auto csr = mbedtls::make_unique<mbedtls::X509WriteCsr>();
    mbedtls_x509write_csr_set_md_alg(csr.get(), MBEDTLS_MD_SHA512);

    if (
      mbedtls_x509write_csr_set_subject_name(csr.get(), csi.name.c_str()) != 0)
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

  Pem KeyPair_mbedTLS::sign_csr(
    const Pem& issuer_cert,
    const Pem& signing_request,
    bool ca,
    const std::optional<std::string>& valid_from,
    const std::optional<std::string>& valid_to) const
  {
    auto entropy = create_entropy();
    auto csr = mbedtls::make_unique<mbedtls::X509Csr>();
    auto serial = mbedtls::make_unique<mbedtls::MPI>();
    auto crt = mbedtls::make_unique<mbedtls::X509WriteCrt>();
    auto icrt = mbedtls::make_unique<mbedtls::X509Crt>();

    MCHK(mbedtls_x509_csr_parse(
      csr.get(), signing_request.data(), signing_request.size()));

    // Verify self-signed CSR
    const auto info = mbedtls_md_info_from_type(csr->sig_md);
    const auto hash_size = mbedtls_md_get_size(info);
    HashBytes h(hash_size);
    MCHK(mbedtls_md(info, csr->cri.p, csr->cri.len, h.data()));
    MCHK(mbedtls_pk_verify(
      &csr->pk, csr->sig_md, h.data(), h.size(), csr->sig.p, csr->sig.len));

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
    // Note: For the mbedtls implementation, we do not check that valid_from and
    // valid_to are valid or chronological. See OpenSSL equivalent call for a
    // safer implementation.
    MCHK(mbedtls_x509write_crt_set_validity(
      crt.get(),
      valid_from.value_or("20210311000000").c_str(),
      valid_to.value_or("20230611235959").c_str()));

    MCHK(mbedtls_x509write_crt_set_basic_constraints(crt.get(), ca ? 1 : 0, 0));
    MCHK(mbedtls_x509write_crt_set_subject_key_identifier(crt.get()));
    MCHK(mbedtls_x509write_crt_set_authority_key_identifier(crt.get()));

    // Warn: Because mbedtls does not support parsing x509v3 extensions from a
    // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), so those are
    // ignored and not set in the certificate

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    MCHK(mbedtls_x509write_crt_pem(
      crt.get(), buf, sizeof(buf), entropy->get_rng(), entropy->get_data()));

    auto len = strlen((char*)buf);
    return Pem(buf, len);
  }
}
