// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/eddsa_key_pair.h"

#include "openssl_wrappers.h"

namespace crypto
{
  EdDSAKeyPair_OpenSSL::EdDSAKeyPair_OpenSSL(CurveID curve_id)
  {
    int curve_nid = get_openssl_group_id(curve_id);
    key = EVP_PKEY_new();
    OpenSSL::Unique_EVP_PKEY_CTX pkctx(curve_nid);
    OpenSSL::CHECK1(EVP_PKEY_keygen_init(pkctx));
    OpenSSL::CHECK1(EVP_PKEY_keygen(pkctx, &key));
  }

  EdDSAKeyPair_OpenSSL::EdDSAKeyPair_OpenSSL(const Pem& pem)
  {
    OpenSSL::Unique_BIO mem(pem);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  EdDSAKeyPair_OpenSSL::EdDSAKeyPair_OpenSSL(const JsonWebKeyEdDSAPrivate& jwk)
  {
    if (jwk.kty != JsonWebKeyType::OKP)
    {
      throw std::logic_error(
        "Cannot construct EdDSA key pair from non-OKP JWK");
    }

    if (jwk.crv != JsonWebKeyEdDSACurve::ED25519)
    {
      throw std::logic_error(
        "Cannot construct EdDSA key pair from non-Ed25519 JWK");
    }

    auto d_raw = raw_from_b64url(jwk.d);
    OpenSSL::CHECKNULL(
      key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, d_raw.data(), d_raw.size()));
  }

  Pem EdDSAKeyPair_OpenSSL::private_key_pem() const
  {
    OpenSSL::Unique_BIO buf;

    OpenSSL::CHECK1(
      PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  Pem EdDSAKeyPair_OpenSSL::public_key_pem() const
  {
    return EdDSAPublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> EdDSAKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d) const
  {
    EVP_PKEY_CTX* pkctx = nullptr;
    OpenSSL::Unique_EVP_MD_CTX ctx;

    OpenSSL::CHECK1(EVP_DigestSignInit(ctx, &pkctx, NULL, NULL, key));

    std::vector<uint8_t> sigret(EVP_PKEY_size(key));
    size_t siglen = sigret.size();

    OpenSSL::CHECK1(
      EVP_DigestSign(ctx, sigret.data(), &siglen, d.data(), d.size()));

    sigret.resize(siglen);
    return sigret;
  }

  bool EdDSAKeyPair_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    return EdDSAPublicKey_OpenSSL::verify(
      contents, contents_size, signature, signature_size);
  }

  CurveID EdDSAKeyPair_OpenSSL::get_curve_id() const
  {
    return EdDSAPublicKey_OpenSSL::get_curve_id();
  }

  JsonWebKeyEdDSAPrivate EdDSAKeyPair_OpenSSL::private_key_jwk_eddsa(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyEdDSAPrivate jwk = {
      EdDSAPublicKey_OpenSSL::public_key_jwk_eddsa(kid)};

    std::vector<uint8_t> raw_priv(EVP_PKEY_size(key));
    size_t raw_priv_len = raw_priv.size();
    EVP_PKEY_get_raw_private_key(key, raw_priv.data(), &raw_priv_len);
    raw_priv.resize(raw_priv_len);
    jwk.d = b64url_from_raw(raw_priv, false /* with_padding */);
    return jwk;
  }
}
