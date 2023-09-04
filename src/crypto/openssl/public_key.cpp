// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/public_key.h"

#include "ccf/ds/logger.h"
#include "crypto/openssl/hash.h"
#include "openssl_wrappers.h"

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#  include <openssl/param_build.h>
#endif

namespace crypto
{
  using namespace OpenSSL;

  PublicKey_OpenSSL::PublicKey_OpenSSL() {}

  PublicKey_OpenSSL::PublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(const std::vector<uint8_t>& der)
  {
    Unique_BIO buf(der);
    key = d2i_PUBKEY_bio(buf, &key);
    if (!key)
    {
      throw std::runtime_error("Could not read DER");
    }
  }

  std::pair<Unique_BIGNUM, Unique_BIGNUM> get_components(
    const JsonWebKeyECPublic& jwk)
  {
    if (jwk.kty != JsonWebKeyType::EC)
    {
      throw std::logic_error("Cannot construct public key from non-EC JWK");
    }

    std::pair<Unique_BIGNUM, Unique_BIGNUM> xy;
    auto x_raw = raw_from_b64url(jwk.x);
    auto y_raw = raw_from_b64url(jwk.y);
    OpenSSL::CHECKNULL(BN_bin2bn(x_raw.data(), x_raw.size(), xy.first));
    OpenSSL::CHECKNULL(BN_bin2bn(y_raw.data(), y_raw.size(), xy.second));

    return xy;
  }

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  std::vector<uint8_t> PublicKey_OpenSSL::ec_point_public_from_jwk(
    const JsonWebKeyECPublic& jwk)
  {
    auto nid = get_openssl_group_id(jwk_curve_to_curve_id(jwk.crv));
    auto [x, y] = get_components(jwk);

    Unique_BN_CTX bn_ctx;
    Unique_EC_GROUP group(nid);
    Unique_EC_POINT p(group);
    CHECK1(EC_POINT_set_affine_coordinates(group, p, x, y, bn_ctx));
    size_t buf_size = EC_POINT_point2oct(
      group, p, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, bn_ctx);
    std::vector<uint8_t> buf(buf_size);
    CHECKPOSITIVE(EC_POINT_point2oct(
      group, p, POINT_CONVERSION_UNCOMPRESSED, buf.data(), buf.size(), bn_ctx));
    return buf;
  }
#else
  Unique_EC_KEY PublicKey_OpenSSL::ec_key_public_from_jwk(
    const JsonWebKeyECPublic& jwk)
  {
    auto nid = get_openssl_group_id(jwk_curve_to_curve_id(jwk.crv));
    auto [x, y] = get_components(jwk);

    Unique_EC_KEY ec_key(nid);
    CHECK1(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y));
    return ec_key;
  }
#endif

  PublicKey_OpenSSL::PublicKey_OpenSSL(const JsonWebKeyECPublic& jwk)
  {
    key = EVP_PKEY_new();
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    auto nid = get_openssl_group_id(jwk_curve_to_curve_id(jwk.crv));
    auto buf = ec_point_public_from_jwk(jwk);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(
      OSSL_PKEY_PARAM_GROUP_NAME, (char*)OSSL_EC_curve_nid2name(nid), 0);
    params[1] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PUB_KEY, buf.data(), buf.size());
    params[2] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("EC");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    CHECK1(EVP_PKEY_fromdata(pctx, &key, EVP_PKEY_PUBLIC_KEY, params));
#else
    CHECK1(EVP_PKEY_set1_EC_KEY(key, ec_key_public_from_jwk(jwk)));
#endif
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(EVP_PKEY* key) : key(key) {}

  PublicKey_OpenSSL::~PublicKey_OpenSSL()
  {
    if (key)
    {
      EVP_PKEY_free(key);
    }
  }

  CurveID PublicKey_OpenSSL::get_curve_id() const
  {
    int nid = get_openssl_group_id();
    switch (nid)
    {
      case NID_secp384r1:
        return CurveID::SECP384R1;
      case NID_X9_62_prime256v1:
        return CurveID::SECP256R1;
      case NID_secp256k1:
        return CurveID::SECP256K1;
      default:
        throw std::runtime_error(fmt::format("Unknown OpenSSL curve {}", nid));
    }
    return CurveID::NONE;
  }

  int PublicKey_OpenSSL::get_openssl_group_id() const
  {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    size_t gname_len = 0;
    CHECK1(EVP_PKEY_get_group_name(key, NULL, 0, &gname_len));
    std::string gname(gname_len + 1, 0);
    CHECK1(EVP_PKEY_get_group_name(
      key, (char*)gname.data(), gname.size(), &gname_len));
    gname.resize(gname_len);
    if (gname == SN_secp384r1)
    {
      return NID_secp384r1;
    }
    else if (gname == SN_X9_62_prime256v1)
    {
      return NID_X9_62_prime256v1;
    }
    else if (gname == SN_secp256k1)
    {
      return NID_secp256k1;
    }
    else
    {
      throw std::runtime_error(fmt::format("Unknown OpenSSL group {}", gname));
    }
#else
    return EC_GROUP_get_curve_name(
      EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));
#endif
  }

  int PublicKey_OpenSSL::get_openssl_group_id(CurveID gid)
  {
    switch (gid)
    {
      case CurveID::NONE:
        return NID_undef;
      case CurveID::SECP384R1:
        return NID_secp384r1;
      case CurveID::SECP256R1:
        return NID_X9_62_prime256v1;
      case CurveID::SECP256K1:
        return NID_secp256k1;
      default:
        throw std::logic_error(
          fmt::format("unsupported OpenSSL CurveID {}", gid));
    }
    return NID_undef;
  }

  bool PublicKey_OpenSSL::verify(
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
    OpenSSLHashProvider hp;
    bytes = hp.Hash(contents, contents_size, md_type);
    return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
  }

  bool PublicKey_OpenSSL::verify_hash(
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

    Unique_EVP_PKEY_CTX pctx(key);
    OpenSSL::CHECK1(EVP_PKEY_verify_init(pctx));
    if (md_type != MDType::NONE)
    {
      OpenSSL::CHECK1(
        EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    }
    int rc = EVP_PKEY_verify(pctx, sig, sig_size, hash, hash_size);

    bool ok = rc == 1;
    if (!ok)
    {
      int ec = ERR_get_error();
      LOG_DEBUG_FMT(
        "OpenSSL signature verification failure: {}",
        OpenSSL::error_string(ec));
    }

    return ok;
  }

  Pem PublicKey_OpenSSL::public_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  std::vector<uint8_t> PublicKey_OpenSSL::public_key_der() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PUBKEY_bio(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
  }

  std::vector<uint8_t> PublicKey_OpenSSL::public_key_raw() const
  {
    Unique_BIO buf;

    unsigned char* p = NULL;
    size_t n = i2d_PublicKey(key, &p);

    std::vector<uint8_t> r;
    if (p)
    {
      r = {p, p + n};
    }
    free(p);
    return r;
  }

  Unique_PKEY key_from_raw_ec_point(const std::vector<uint8_t>& raw, int nid)
  {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    const unsigned char* pp = raw.data();
    EVP_PKEY* pkey = NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
      OSSL_PKEY_PARAM_GROUP_NAME, (char*)OSSL_EC_curve_nid2name(nid), 0);
    params[1] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("EC");
    EVP_PKEY_fromdata_init(pctx);
    EVP_PKEY_fromdata(
      pctx, &pkey, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params);

    pkey = d2i_PublicKey(EVP_PKEY_EC, &pkey, &pp, raw.size());
    if (pkey == NULL)
    {
      EVP_PKEY_free(pkey);
      throw std::logic_error("Error loading public key");
    }

    Unique_PKEY pk(pkey);
    EVP_PKEY_up_ref(pk);
    EVP_PKEY_free(pkey);
    return pk;
#else
    Unique_BN_CTX bn_ctx;
    Unique_EC_GROUP group(nid);
    Unique_EC_POINT p(group);
    CHECK1(EC_POINT_oct2point(group, p, raw.data(), raw.size(), bn_ctx));
    Unique_EC_KEY ec_key(nid);

    Unique_PKEY pk;
    CHECK1(EC_KEY_set_public_key(ec_key, p));
    CHECK1(EVP_PKEY_set1_EC_KEY(pk, ec_key));
    EVP_PKEY_up_ref(pk);
    return pk;
#endif
  }

  PublicKey::Coordinates PublicKey_OpenSSL::coordinates() const
  {
    Coordinates r;
    Unique_BIGNUM x, y;
    Unique_EC_GROUP group(get_openssl_group_id());
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    BIGNUM* bn_x = NULL;
    BIGNUM* bn_y = NULL;
    CHECK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x));
    x.reset(bn_x);
    CHECK1(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y));
    y.reset(bn_y);
#else
    Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(key));
    const EC_POINT* p = EC_KEY_get0_public_key(eckey);
    Unique_BN_CTX bn_ctx;
    CHECK1(EC_POINT_get_affine_coordinates(group, p, x, y, bn_ctx));
#endif
    int sz = EC_GROUP_get_degree(group) / 8;
    r.x.resize(sz);
    r.y.resize(sz);
    BN_bn2binpad(x, r.x.data(), sz);
    BN_bn2binpad(y, r.y.data(), sz);
    return r;
  }

  JsonWebKeyECPublic PublicKey_OpenSSL::public_key_jwk(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyECPublic jwk;
    auto coords = coordinates();
    jwk.x = b64url_from_raw(coords.x, false /* with_padding */);
    jwk.y = b64url_from_raw(coords.y, false /* with_padding */);
    jwk.crv = curve_id_to_jwk_curve(get_curve_id());
    jwk.kid = kid;
    jwk.kty = JsonWebKeyType::EC;
    return jwk;
  }
}
