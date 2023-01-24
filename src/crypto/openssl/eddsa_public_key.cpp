// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/eddsa_key_pair.h"
#include "crypto/openssl/hash.h"
#include "openssl_wrappers.h"

namespace crypto
{
  using namespace OpenSSL;

  EdDSAPublicKey_OpenSSL::EdDSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  EdDSAPublicKey_OpenSSL::EdDSAPublicKey_OpenSSL(
    const JsonWebKeyEdDSAPublic& jwk)
  {
    if (jwk.kty != JsonWebKeyType::OKP)
    {
      throw std::logic_error(
        "Cannot construct EdDSA public key from non-OKP JWK");
    }

    if (jwk.crv != JsonWebKeyEdDSACurve::ED25519)
    {
      throw std::logic_error(
        "Cannot construct EdDSA public key from non-Ed25519 JWK");
    }

    auto x_raw = raw_from_b64url(jwk.x);
    key = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, x_raw.data(), x_raw.size());
    if (key == nullptr)
    {
      throw std::logic_error("Error constructing EdDSA public key from JWK");
    }
  }

  EdDSAPublicKey_OpenSSL::~EdDSAPublicKey_OpenSSL()
  {
    if (key)
    {
      EVP_PKEY_free(key);
    }
  }

  Pem EdDSAPublicKey_OpenSSL::public_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  bool EdDSAPublicKey_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    Unique_EVP_MD_CTX ctx;
    EVP_PKEY_CTX* pkctx = nullptr;

    OpenSSL::CHECK1(EVP_DigestVerifyInit(ctx, &pkctx, NULL, NULL, key));

    return 1 ==
      EVP_DigestVerify(ctx, signature, signature_size, contents, contents_size);
  }

  int EdDSAPublicKey_OpenSSL::get_openssl_group_id(CurveID gid)
  {
    switch (gid)
    {
      case CurveID::CURVE25519:
        return EVP_PKEY_ED25519;
      default:
        throw std::logic_error(
          fmt::format("unsupported OpenSSL CurveID {}", gid));
    }
    return NID_undef;
  }

  CurveID EdDSAPublicKey_OpenSSL::get_curve_id() const
  {
    int nid = EVP_PKEY_id(key);
    switch (nid)
    {
      case NID_ED25519:
        return CurveID::CURVE25519;
      default:
        throw std::runtime_error(fmt::format("Unknown OpenSSL curve {}", nid));
    }
    return CurveID::NONE;
  }

  JsonWebKeyEdDSAPublic EdDSAPublicKey_OpenSSL::public_key_jwk_eddsa(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyEdDSAPublic jwk;
    std::vector<uint8_t> raw_pub(EVP_PKEY_size(key));
    size_t raw_pub_len = raw_pub.size();
    EVP_PKEY_get_raw_public_key(key, raw_pub.data(), &raw_pub_len);
    raw_pub.resize(raw_pub_len);
    jwk.x = b64url_from_raw(raw_pub, false);
    jwk.crv = curve_id_to_jwk_eddsa_curve(get_curve_id());
    jwk.kid = kid;
    jwk.kty = JsonWebKeyType::OKP;
    return jwk;
  }
}
