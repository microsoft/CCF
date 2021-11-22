// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <crypto/pem.h>
#include <fmt/format.h>
#include <memory>
#include <openssl/asn1.h>
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
    /*
     * Generic OpenSSL error handling
     */

    /// Throws if rc is 1 and has error
    inline void CHECK1(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc != 1 && ec != 0)
      {
        throw std::runtime_error(
          fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
      }
    }

    /// Throws if rc is 0 and has error
    inline void CHECK0(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc == 0 && ec != 0)
      {
        throw std::runtime_error(
          fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
      }
    }

    /// Throws if ptr is null
    inline void CHECKNULL(void* ptr)
    {
      if (ptr == NULL)
      {
        throw std::runtime_error("OpenSSL error: missing object");
      }
    }

    /// Returns the error string from an error code
    inline std::string error_string(int ec)
    {
      return ERR_error_string((unsigned long)ec, NULL);
    }

    /*
     * Unique pointer wrappers for SSL objects, with SSL' specific constructors
     * and destructors. Some objects need special functionality, others are just
     * wrappers around the same template interface Unique_SSL_OBJECT.
     */

    /// Generic template interface for different types of objects below
    /// If there are no c-tors in the derived class that matches this one,
    /// pass `nullptr` to the CTOR/DTOR parameters and make sure to implement
    /// and delete the appropriate c-tors in the derived class.
    template <class T, T* (*CTOR)(), void (*DTOR)(T*)>
    class Unique_SSL_OBJECT
    {
    protected:
      /// Pointer owning storage
      std::unique_ptr<T, void (*)(T*)> p;

    public:
      /// C-tor with new pointer via T's c-tor
      Unique_SSL_OBJECT() : p(CTOR(), DTOR)
      {
        CHECKNULL(p.get());
      }
      /// C-tor with pointer created in base class
      Unique_SSL_OBJECT(T* ptr, void (*dtor)(T*), bool check_null = true) :
        p(ptr, dtor)
      {
        if (check_null)
          CHECKNULL(p.get());
      }
      /// Type cast to underlying pointer
      operator T*()
      {
        return p.get();
      }
      /// Type cast to underlying pointer
      operator T*() const
      {
        return p.get();
      }
      /// Release pointer, so it's freed elsewhere (CAUTION!)
      T* release()
      {
        return p.release();
      }
    };

    struct Unique_BIO : public Unique_SSL_OBJECT<BIO, nullptr, nullptr>
    {
      Unique_BIO() :
        Unique_SSL_OBJECT(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const void* buf, int len) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const std::vector<uint8_t>& d) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const Pem& pem) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(pem.data(), -1), [](auto x) { BIO_free(x); })
      {}
    };

    struct Unique_EVP_PKEY_CTX
      : public Unique_SSL_OBJECT<EVP_PKEY_CTX, nullptr, nullptr>
    {
      Unique_EVP_PKEY_CTX(EVP_PKEY* key) :
        Unique_SSL_OBJECT(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
      {}
      Unique_EVP_PKEY_CTX() :
        Unique_SSL_OBJECT(
          EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
      {}
    };

    struct Unique_X509_REQ
      : public Unique_SSL_OBJECT<X509_REQ, X509_REQ_new, X509_REQ_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_REQ(BIO* mem) :
        Unique_SSL_OBJECT(
          PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL), X509_REQ_free)
      {}
    };

    struct Unique_X509 : public Unique_SSL_OBJECT<X509, X509_new, X509_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      // p == nullptr is OK (e.g. wrong format)
      Unique_X509(BIO* mem, bool pem) :
        Unique_SSL_OBJECT(
          pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) :
                d2i_X509_bio(mem, NULL),
          X509_free,
          /*check_null=*/false)
      {}
    };

    struct Unique_X509_STORE
      : public Unique_SSL_OBJECT<X509_STORE, X509_STORE_new, X509_STORE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_X509_STORE_CTX : public Unique_SSL_OBJECT<
                                     X509_STORE_CTX,
                                     X509_STORE_CTX_new,
                                     X509_STORE_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_EVP_CIPHER_CTX : public Unique_SSL_OBJECT<
                                     EVP_CIPHER_CTX,
                                     EVP_CIPHER_CTX_new,
                                     EVP_CIPHER_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_STACK_OF_X509
      : public Unique_SSL_OBJECT<STACK_OF(X509), nullptr, nullptr>
    {
      Unique_STACK_OF_X509() :
        Unique_SSL_OBJECT(
          sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {}
    };

    struct Unique_STACK_OF_X509_EXTENSIONS
      : public Unique_SSL_OBJECT<STACK_OF(X509_EXTENSION), nullptr, nullptr>
    {
      Unique_STACK_OF_X509_EXTENSIONS() :
        Unique_SSL_OBJECT(sk_X509_EXTENSION_new_null(), [](auto x) {
          sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free);
        })
      {}
      Unique_STACK_OF_X509_EXTENSIONS(STACK_OF(X509_EXTENSION) * exts) :
        Unique_SSL_OBJECT(
          exts,
          [](auto x) { sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free); },
          /*check_null=*/false)
      {}
    };

    struct Unique_ECDSA_SIG
      : public Unique_SSL_OBJECT<ECDSA_SIG, ECDSA_SIG_new, ECDSA_SIG_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_BIGNUM : public Unique_SSL_OBJECT<BIGNUM, BN_new, BN_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_X509_TIME
      : public Unique_SSL_OBJECT<ASN1_TIME, ASN1_TIME_new, ASN1_TIME_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_TIME(const std::string& s) :
        Unique_SSL_OBJECT(ASN1_TIME_new(), ASN1_TIME_free, /*check_null=*/false)
      {
        CHECK1(ASN1_TIME_set_string(*this, s.c_str()));
        CHECK1(ASN1_TIME_normalize(*this));
      }
      Unique_X509_TIME(ASN1_TIME* t) :
        Unique_SSL_OBJECT(t, ASN1_TIME_free, /*check_null=*/false)
      {}
    };
  }
}
