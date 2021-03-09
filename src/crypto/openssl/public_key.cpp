// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "public_key.h"

#include "openssl_wrappers.h"

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  using namespace OpenSSL;

  PublicKey_OpenSSL::PublicKey_OpenSSL() {}

  PublicKey_OpenSSL::PublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem.data(), -1);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
      throw std::runtime_error("could not parse PEM");
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(const std::vector<uint8_t>& der)
  {
    const unsigned char* pp = der.data();
    key = d2i_PublicKey(EVP_PKEY_EC, &key, &pp, der.size());
    if (!key)
    {
      throw new std::runtime_error("Could not read DER");
    }
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(EVP_PKEY* key) : key(key) {}

  PublicKey_OpenSSL::~PublicKey_OpenSSL()
  {
    if (key)
      EVP_PKEY_free(key);
  }

  CurveID PublicKey_OpenSSL::get_curve_id() const
  {
    int nid =
      EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));
    switch (nid)
    {
      case NID_secp384r1:
        return CurveID::SECP384R1;
      case NID_X9_62_prime256v1:
        return CurveID::SECP256R1;
      default:
        throw std::runtime_error(fmt::format("Unknown OpenSSL curve {}", nid));
    }
    return CurveID::NONE;
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
        ERR_error_string(ec, NULL));
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
}
