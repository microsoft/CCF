// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/ec_key_pair.h"

#include "ccf/crypto/curve.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/csr.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/hash.h"

#define FMT_HEADER_ONLY
#include <climits>
#include <fmt/format.h>
#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <optional>
#include <stdexcept>
#include <string>

namespace ccf::crypto
{
  using namespace OpenSSL;

  ECKeyPair_OpenSSL::ECKeyPair_OpenSSL(CurveID curve_id)
  {
    int curve_nid = get_openssl_group_id(curve_id);
    Unique_EVP_PKEY_CTX pkctx;
    OpenSSL::CHECKPOSITIVE(EVP_PKEY_keygen_init(pkctx));
    OpenSSL::CHECKPOSITIVE(
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid));
    OpenSSL::CHECKPOSITIVE(
      EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE));
    EVP_PKEY* generated = nullptr;
    const auto keygen_rc = EVP_PKEY_keygen(pkctx, &generated);
    key.reset(generated);
    OpenSSL::CHECKPOSITIVE(keygen_rc);
  }

  ECKeyPair_OpenSSL::ECKeyPair_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key.reset(PEM_read_bio_PrivateKey(mem, nullptr, nullptr, nullptr));
    OpenSSL::CHECKNULL(key);
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC)
    {
      throw std::logic_error(
        "Cannot construct ECKeyPair_OpenSSL from non-EC key");
    }
  }

  ECKeyPair_OpenSSL::ECKeyPair_OpenSSL(const JsonWebKeyECPrivate& jwk)
  {
    Unique_BIGNUM d;
    auto d_raw = raw_from_b64url(jwk.d);
    OpenSSL::CHECKNULL(BN_bin2bn(d_raw.data(), d_raw.size(), d));
    auto nid = get_openssl_group_id(jwk_curve_to_curve_id(jwk.crv));
    // Note: d_raw is big endian while OSSL_PARAM_construct_BN expects native
    // endianness
    std::vector<uint8_t> d_raw_native(d_raw.size());
    CHECKPOSITIVE(BN_bn2nativepad(d, d_raw_native.data(), d_raw_native.size()));

    auto pub_buf = ECPublicKey_OpenSSL::ec_point_public_from_jwk(jwk);

    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(
      OSSL_PKEY_PARAM_GROUP_NAME,
      const_cast<char*>(OSSL_EC_curve_nid2name(nid)),
      0);
    params[1] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PUB_KEY, pub_buf.data(), pub_buf.size());
    params[2] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_PRIV_KEY, d_raw_native.data(), d_raw_native.size());
    params[3] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("EC");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    EVP_PKEY* parsed = nullptr;
    const auto rc = EVP_PKEY_fromdata(
      pctx, &parsed, EVP_PKEY_KEYPAIR, static_cast<OSSL_PARAM*>(params));
    key.reset(parsed);
    CHECK1(rc);
  }

  Pem ECKeyPair_OpenSSL::private_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PrivateKey(
      buf, key, nullptr, nullptr, 0, nullptr, nullptr));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);

    return {reinterpret_cast<uint8_t*>(bptr->data), bptr->length};
  }

  Pem ECKeyPair_OpenSSL::public_key_pem() const
  {
    return ECPublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::public_key_der() const
  {
    return ECPublicKey_OpenSSL::public_key_der();
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::private_key_der() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PrivateKey_bio(buf, key));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
  }

  bool ECKeyPair_OpenSSL::verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
  {
    return ECPublicKey_OpenSSL::verify(contents, signature);
  }

  bool ECKeyPair_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    return ECPublicKey_OpenSSL::verify(
      contents, contents_size, signature, signature_size);
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.hash(d.data(), d.size(), md_type);
    return sign_hash(hash.data(), hash.size());
  }

  int ECKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d,
    size_t* sig_size,
    uint8_t* sig,
    MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.hash(d.data(), d.size(), md_type);
    return sign_hash(hash.data(), hash.size(), sig_size, sig);
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::sign_hash(
    const uint8_t* hash, size_t hash_size) const
  {
    // Query the required signature size from this context, rather than
    // relying on EVP_PKEY_size(key). For some curves (eg - P-521), some
    // providers (eg - SymCrypt) report a smaller EVP_PKEY_size() than the
    // buffer they actually need, particularly after a private key has been
    // through a PEM round trip, which then makes signing itself fail with
    // "output buffer too small".
    Unique_EVP_PKEY_CTX pctx(key);
    OpenSSL::CHECK1(EVP_PKEY_sign_init(pctx));

    size_t written = 0;
    OpenSSL::CHECK1(EVP_PKEY_sign(pctx, nullptr, &written, hash, hash_size));

    std::vector<uint8_t> sig(written);
    OpenSSL::CHECK1(EVP_PKEY_sign(pctx, sig.data(), &written, hash, hash_size));

    sig.resize(written);
    return sig;
  }

  int ECKeyPair_OpenSSL::sign_hash(
    const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const
  {
    Unique_EVP_PKEY_CTX pctx(key);
    OpenSSL::CHECK1(EVP_PKEY_sign_init(pctx));
    OpenSSL::CHECK1(EVP_PKEY_sign(pctx, sig, sig_size, hash, hash_size));
    return 0;
  }

  Unique_X509_REQ ECKeyPair_OpenSSL::create_req(
    const X509_NAME* subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    return OpenSSL::make_csr(
      key, EVP_sha512(), subject_name, subject_alt_names, public_key);
  }

  Pem ECKeyPair_OpenSSL::create_csr(
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    return csr_to_pem(create_req(
      subject_name_from_string(subject_name), subject_alt_names, public_key));
  }

  Pem ECKeyPair_OpenSSL::create_csr(
    const std::vector<uint8_t>& subject_name_der,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    return csr_to_pem(create_req(
      subject_name_from_der(subject_name_der), subject_alt_names, public_key));
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::create_csr_der(
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    Unique_X509_REQ req = create_req(
      subject_name_from_string(subject_name), subject_alt_names, public_key);

    Unique_BIO mem;
    CHECK1(i2d_X509_REQ_bio(mem, req));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);

    return {
      reinterpret_cast<uint8_t*>(bptr->data),
      reinterpret_cast<uint8_t*>(bptr->data) + bptr->length};
  }

  Pem ECKeyPair_OpenSSL::sign_csr_impl(
    const std::optional<Pem>& issuer_cert,
    const Pem& signing_request,
    const std::string& valid_from,
    const std::string& valid_to,
    bool ca,
    Signer signer) const
  {
    return OpenSSL::sign_csr(
      key,
      get_md_type(get_md_for_ec(get_curve_id())),
      issuer_cert,
      signing_request,
      valid_from,
      valid_to,
      ca,
      signer);
  }

  CurveID ECKeyPair_OpenSSL::get_curve_id() const
  {
    return ECPublicKey_OpenSSL::get_curve_id();
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::public_key_raw() const
  {
    return ECPublicKey_OpenSSL::public_key_raw();
  }

  std::vector<uint8_t> ECKeyPair_OpenSSL::derive_shared_secret(
    const ECPublicKey& peer_key)
  {
    ccf::crypto::CurveID cid = peer_key.get_curve_id();
    int nid = ccf::crypto::ECPublicKey_OpenSSL::get_openssl_group_id(cid);
    auto pk = key_from_raw_ec_point(peer_key.public_key_raw(), nid);

    std::vector<uint8_t> shared_secret;
    size_t shared_secret_length = 0;
    Unique_EVP_PKEY_CTX ctx(key);
    CHECK1(EVP_PKEY_derive_init(ctx));
    CHECK1(EVP_PKEY_derive_set_peer(ctx, pk));
    CHECK1(EVP_PKEY_derive(ctx, nullptr, &shared_secret_length));
    shared_secret.resize(shared_secret_length);
    CHECK1(EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_length));

    return shared_secret;
  }

  ECPublicKey::Coordinates ECKeyPair_OpenSSL::coordinates() const
  {
    return ECPublicKey_OpenSSL::coordinates();
  }

  JsonWebKeyECPrivate ECKeyPair_OpenSSL::private_key_jwk(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyECPrivate jwk;
    static_cast<JsonWebKeyECPublic&>(jwk) =
      ECPublicKey_OpenSSL::public_key_jwk(kid);

    // As per https://www.openssl.org/docs/man1.0.2/man3/BN_num_bytes.html, size
    // should not be calculated with BN_num_bytes(d)!
    // Use ceiling division so curves whose bit-size is not a multiple of 8
    // (e.g. P-521 with 521 bits) get the full 66-byte buffer rather than a
    // truncated 65-byte one.
    int size = (EVP_PKEY_bits(key) + CHAR_BIT - 1) / CHAR_BIT;
    std::vector<uint8_t> bytes(size);
    Unique_BIGNUM d;
    BIGNUM* bn_d = nullptr;
    CHECK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d));
    d.reset(bn_d);
    auto rc = BN_bn2binpad(d, bytes.data(), size);
    if (rc != size)
    {
      throw std::runtime_error(fmt::format("BN_bn2binpad failed: {}", rc));
    }
    jwk.d = b64url_from_raw(bytes, false /* with_padding */);

    return jwk;
  }

  ECKeyPairPtr make_ec_key_pair(CurveID curve_id)
  {
    return std::make_shared<ECKeyPair_OpenSSL>(curve_id);
  }

  ECKeyPairPtr make_ec_key_pair(const Pem& pem)
  {
    return std::make_shared<ECKeyPair_OpenSSL>(pem);
  }

  ECKeyPairPtr make_ec_key_pair(const JsonWebKeyECPrivate& jwk)
  {
    return std::make_shared<ECKeyPair_OpenSSL>(jwk);
  }
}
