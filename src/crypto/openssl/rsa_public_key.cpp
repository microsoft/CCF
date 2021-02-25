// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "openssl_wrappers.h"
#include "rsa_key_pair.h"

namespace crypto
{
  using namespace OpenSSL;

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(EVP_PKEY* c) : PublicKey_OpenSSL(c)
  {
    if (!EVP_PKEY_get0_RSA(key))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem.data(), -1);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key || !EVP_PKEY_get0_RSA(key))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const std::vector<uint8_t>& der)
  {
    const unsigned char* pp = der.data();
    RSA* rsa = NULL;
    if (
      ((rsa = d2i_RSA_PUBKEY(NULL, &pp, der.size())) ==
       NULL) && // "SubjectPublicKeyInfo structure" format
      ((rsa = d2i_RSAPublicKey(NULL, &pp, der.size())) ==
       NULL)) // PKCS#1 structure format
    {
      unsigned long ec = ERR_get_error();
      const char* msg = ERR_error_string(ec, NULL);
      throw new std::runtime_error(fmt::format("OpenSSL error: {}", msg));
    }

    key = EVP_PKEY_new();
    OpenSSL::CHECK1(EVP_PKEY_set1_RSA(key, rsa));
    RSA_free(rsa);
  }

  size_t RSAPublicKey_OpenSSL::key_size() const
  {
    return EVP_PKEY_bits(key);
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::wrap(
    const uint8_t* input,
    size_t input_size,
    const uint8_t* label,
    size_t label_size)
  {
    Unique_EVP_PKEY_CTX ctx(key);
    OpenSSL::CHECK1(EVP_PKEY_encrypt_init(ctx));
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    if (label)
    {
      unsigned char* openssl_label = (unsigned char*)OPENSSL_malloc(label_size);
      std::copy(label, label + label_size, openssl_label);
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, openssl_label, label_size);
    }
    else
    {
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);
    }

    size_t olen;
    OpenSSL::CHECK1(EVP_PKEY_encrypt(ctx, NULL, &olen, input, input_size));

    std::vector<uint8_t> output(olen);
    OpenSSL::CHECK1(
      EVP_PKEY_encrypt(ctx, output.data(), &olen, input, input_size));

    output.resize(olen);
    return output;
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::wrap(
    const std::vector<uint8_t>& input, std::optional<std::string> label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->c_str());
      label_size = label->size();
    }

    return wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }
}