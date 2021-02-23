// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace crypto
{
  class Unique_BIO
  {
    std::unique_ptr<BIO, void (*)(BIO*)> p;

  public:
    Unique_BIO() : p(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    Unique_BIO(const void* buf, int len) :
      p(BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    operator BIO*()
    {
      return p.get();
    }
  };

  class Unique_EVP_PKEY_CTX
  {
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)> p;

  public:
    Unique_EVP_PKEY_CTX(EVP_PKEY* key) :
      p(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    Unique_EVP_PKEY_CTX() :
      p(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    operator EVP_PKEY_CTX*()
    {
      return p.get();
    }
  };

  class Unique_X509_REQ
  {
    std::unique_ptr<X509_REQ, void (*)(X509_REQ*)> p;

  public:
    Unique_X509_REQ() : p(X509_REQ_new(), X509_REQ_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    Unique_X509_REQ(BIO* mem) :
      p(PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL), X509_REQ_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    operator X509_REQ*()
    {
      return p.get();
    }
  };

  class Unique_X509
  {
    std::unique_ptr<X509, void (*)(X509*)> p;

  public:
    Unique_X509() : p(X509_new(), X509_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    Unique_X509(BIO* mem) :
      p(PEM_read_bio_X509(mem, NULL, NULL, NULL), X509_free)
    {
      if (!p)
        throw std::runtime_error("out of memory");
    }
    operator X509*()
    {
      return p.get();
    }
  };
}
