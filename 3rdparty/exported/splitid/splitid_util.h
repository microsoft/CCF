// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstring>
#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace SplitIdentity
{
  inline void CHECK1(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc != 1 && ec != 0)
    {
      throw std::runtime_error(
        std::string("OpenSSL error: ") + ERR_error_string(ec, NULL));
    }
  }

  inline void CHECK0(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc == 0 && ec != 0)
    {
      throw std::runtime_error(
        std::string("OpenSSL error: ") + ERR_error_string(ec, NULL));
    }
  }

  inline void CHECKNULL(void* ptr)
  {
    if (ptr == NULL)
    {
      throw std::runtime_error("OpenSSL error: missing object");
    }
  }

  class Wrapped_EVP_PKEY_CTX
  {
  protected:
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> p;

  public:
    Wrapped_EVP_PKEY_CTX(EVP_PKEY* key) :
      p(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
    {
      CHECKNULL(p.get());
    }
    Wrapped_EVP_PKEY_CTX() :
      p(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
    {
      CHECKNULL(p.get());
    }
    operator EVP_PKEY_CTX*()
    {
      return p.get();
    }
  };

  class Wrapped_BIO
  {
  protected:
    std::unique_ptr<BIO, void (*)(BIO*)> p;

  public:
    Wrapped_BIO() : p(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
    {
      CHECKNULL(p.get());
    }
    Wrapped_BIO(const void* buf, int len) :
      p(BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
    {
      CHECKNULL(p.get());
    }
    Wrapped_BIO(const std::vector<uint8_t>& d) :
      p(BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
    {
      CHECKNULL(p.get());
    }
    operator BIO*()
    {
      return p.get();
    }
  };

  static std::string base64_encode(const uint8_t* buf, size_t len)
  {
    Wrapped_BIO bio;

    std::unique_ptr<BIO, void (*)(BIO*)> b64bio(
      BIO_new(BIO_f_base64()), [](auto x) { BIO_free_all(x); });

    BIO_push(b64bio.get(), bio);
    BIO_write(b64bio.get(), buf, len);
    BIO_flush(b64bio.get());

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string r(bptr->data, bptr->length);
    BUF_MEM_free(bptr);
    return r;
  }

  static std::vector<uint8_t> base64_decode(const std::string& b64)
  {
    Wrapped_BIO inbio(b64.data(), b64.size()), outbio;

    std::unique_ptr<BIO, void (*)(BIO*)> b64bio(
      BIO_new(BIO_f_base64()), [](auto x) { BIO_free_all(x); });

    char inbuf[512];
    int inlen;

    BIO_push(b64bio.get(), inbio);
    while ((inlen = BIO_read(b64bio.get(), inbuf, 512)) > 0)
      BIO_write(outbio, inbuf, inlen);
    BIO_flush(outbio);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(outbio, &bptr);
    std::vector<uint8_t> r(bptr->data, bptr->data + bptr->length);
    BUF_MEM_free(bptr);
    return r;
  }

  static inline std::vector<uint8_t> serialise_size_t(size_t sz)
  {
    size_t num_bytes = sizeof(sz);
    std::vector<uint8_t> r(num_bytes);
    auto data = r.data();
    const auto src = reinterpret_cast<const uint8_t*>(&sz);
    std::memcpy(data, src, sizeof(sz));
    return r;
  }

  static inline size_t deserialise_size_t(const uint8_t*& data, size_t& sz)
  {
    if (sz < sizeof(size_t))
      throw std::logic_error("Insufficient space, this is not a size_t");

    size_t v;
    std::memcpy(reinterpret_cast<uint8_t*>(&v), data, sizeof(sz));
    data += sizeof(v);
    sz -= sizeof(v);
    return v;
  }

  constexpr size_t GCM_SIZE_KEY = 32;
  constexpr size_t GCM_SIZE_TAG = 16;
  constexpr size_t GCM_SIZE_IV = 12;

  static inline std::vector<uint8_t> encrypt_buffer(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plain)
  {
    std::vector<uint8_t> tag(GCM_SIZE_TAG, 0);
    std::vector<uint8_t> cipher(plain.size() + GCM_SIZE_TAG);

    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> ctx(
      EVP_CIPHER_CTX_new(), [](auto* x) { EVP_CIPHER_CTX_free(x); });
    auto evp_cipher = EVP_aes_256_gcm();
    auto evp_cipher_wrap_pad = EVP_aes_256_wrap_pad();
    auto ctxp = ctx.get();
    int len = 0;

    CHECK1(EVP_EncryptInit_ex(ctxp, evp_cipher, NULL, key.data(), NULL));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctxp, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL));
    CHECK1(EVP_EncryptInit_ex(ctxp, NULL, NULL, key.data(), iv.data()));
    CHECK1(
      EVP_EncryptUpdate(ctxp, cipher.data(), &len, plain.data(), plain.size()));
    CHECK1(EVP_EncryptFinal_ex(ctxp, cipher.data() + len, &len));
    CHECK1(EVP_CIPHER_CTX_ctrl(
      ctxp, EVP_CTRL_GCM_GET_TAG, GCM_SIZE_TAG, &cipher.data()[plain.size()]));

    if (plain.size() != cipher.size() - GCM_SIZE_TAG)
    {
      throw std::runtime_error("encryption failure");
    }

    return cipher;
  }

  static inline std::vector<uint8_t> decrypt_buffer(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& cipher)
  {
    if (cipher.size() <= GCM_SIZE_TAG)
    {
      throw std::runtime_error("missing tag");
    }

    std::vector<uint8_t> cb =
      std::vector<uint8_t>(cipher.begin(), cipher.end() - GCM_SIZE_TAG);
    std::vector<uint8_t> tag =
      std::vector<uint8_t>(cipher.end() - GCM_SIZE_TAG, cipher.end());
    std::vector<uint8_t> plain(cb.size(), 0);

    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> ctx(
      EVP_CIPHER_CTX_new(), [](auto* x) { EVP_CIPHER_CTX_free(x); });
    auto evp_cipher = EVP_aes_256_gcm();
    auto evp_cipher_wrap_pad = EVP_aes_256_wrap_pad();
    auto ctxp = ctx.get();
    int len = 0;

    CHECK1(EVP_DecryptInit_ex(ctxp, evp_cipher, NULL, NULL, NULL));
    CHECK1(EVP_CIPHER_CTX_ctrl(ctxp, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL));
    CHECK1(EVP_DecryptInit_ex(ctxp, NULL, NULL, key.data(), iv.data()));
    CHECK1(EVP_DecryptUpdate(ctxp, plain.data(), &len, cb.data(), cb.size()));
    CHECK1(EVP_CIPHER_CTX_ctrl(
      ctxp, EVP_CTRL_GCM_SET_TAG, GCM_SIZE_TAG, tag.data()));
    CHECK1(EVP_DecryptFinal_ex(ctxp, plain.data() + len, &len));

    if (plain.size() != cipher.size() - GCM_SIZE_TAG)
    {
      throw std::runtime_error("decryption failure");
    }

    return plain;
  }
}