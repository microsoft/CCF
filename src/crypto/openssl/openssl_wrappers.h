// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <crypto/pem.h>
#include <fmt/format.h>
#include <memory>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace crypto
{
  namespace OpenSSL
  {
    inline void CHECK1(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc != 1 && ec != 0)
      {
        throw std::runtime_error(
          fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
      }
    }

    inline void CHECK0(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc == 0 && ec != 0)
      {
        throw std::runtime_error(
          fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
      }
    }

    inline void CHECKNULL(void* ptr)
    {
      if (ptr == NULL)
      {
        throw std::runtime_error("OpenSSL error: missing object");
      }
    }

    class Unique_BIO
    {
      std::unique_ptr<BIO, void (*)(BIO*)> p;

    public:
      Unique_BIO() : p(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
      {
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_BIO(const void* buf, int len) :
        p(BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
      {
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_BIO(const std::vector<uint8_t>& d) :
        p(BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
      {
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_BIO(const Pem& pem) :
        p(BIO_new_mem_buf(pem.data(), -1), [](auto x) { BIO_free(x); })
      {
        OpenSSL::CHECKNULL(p.get());
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
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_EVP_PKEY_CTX() :
        p(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
      {
        OpenSSL::CHECKNULL(p.get());
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
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_X509_REQ(BIO* mem) :
        p(PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL), X509_REQ_free)
      {
        OpenSSL::CHECKNULL(p.get());
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
        OpenSSL::CHECKNULL(p.get());
      }
      Unique_X509(BIO* mem, bool pem) :
        p(pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) :
                d2i_X509_bio(mem, NULL),
          X509_free)
      {
        // p == nullptr is OK (e.g. wrong format)
      }
      operator X509*()
      {
        return p.get();
      }
    };

    class Unique_X509_STORE
    {
      std::unique_ptr<X509_STORE, void (*)(X509_STORE*)> p;

    public:
      Unique_X509_STORE() : p(X509_STORE_new(), X509_STORE_free)
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator X509_STORE*()
      {
        return p.get();
      }
    };

    class Unique_X509_STORE_CTX
    {
      std::unique_ptr<X509_STORE_CTX, void (*)(X509_STORE_CTX*)> p;

    public:
      Unique_X509_STORE_CTX() : p(X509_STORE_CTX_new(), X509_STORE_CTX_free)
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator X509_STORE_CTX*()
      {
        return p.get();
      }
    };

    class Unique_EVP_CIPHER_CTX
    {
      std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> p;

    public:
      Unique_EVP_CIPHER_CTX() : p(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator EVP_CIPHER_CTX*()
      {
        return p.get();
      }
    };

    class Unique_STACK_OF_X509
    {
      std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509)*)> p;

    public:
      Unique_STACK_OF_X509() :
        p(sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator STACK_OF(X509) * ()
      {
        return p.get();
      }
    };

    class Unique_STACK_OF_X509_EXTENSIONS
    {
      std::unique_ptr<
        STACK_OF(X509_EXTENSION),
        void (*)(STACK_OF(X509_EXTENSION)*)>
        p;

    public:
      Unique_STACK_OF_X509_EXTENSIONS() :
        p(sk_X509_EXTENSION_new_null(),
          [](auto x) { sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free); })
      {
        OpenSSL::CHECKNULL(p.get());
      }

      Unique_STACK_OF_X509_EXTENSIONS(STACK_OF(X509_EXTENSION) * exts) :
        p(exts,
          [](auto x) { sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free); })
      {}

      operator STACK_OF(X509_EXTENSION) * ()
      {
        return p.get();
      }
    };

    class Unique_ECDSA_SIG
    {
      std::unique_ptr<ECDSA_SIG, void (*)(ECDSA_SIG*)> p;

    public:
      Unique_ECDSA_SIG() : p(ECDSA_SIG_new(), ECDSA_SIG_free)
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator ECDSA_SIG*()
      {
        return p.get();
      }
    };

    class Unique_BIGNUM
    {
      std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> p;

    public:
      Unique_BIGNUM() : p(BN_new(), BN_free)
      {
        OpenSSL::CHECKNULL(p.get());
      }
      operator BIGNUM*()
      {
        return p.get();
      }
      void release()
      {
        p.release();
      }
    };

    inline std::string error_string(int ec)
    {
      return ERR_error_string((unsigned long)ec, NULL);
    }
  }
}
