// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstring>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace OpenSSL
{
  /*
   * Generic OpenSSL error handling
   */

  class asn1_format_exception : public std::runtime_error
  {
  public:
    asn1_format_exception(std::string detail) :
      std::runtime_error("incorrectly formatted ASN.1 structure: " + detail)
    {}
    virtual ~asn1_format_exception() = default;
  };

  /// Returns the error string from an error code
  inline std::string error_string(int ec)
  {
    // ERR_error_string doesn't really expect the code could actually be zero
    // and uses the `static char buf[256]` which is NOT cleaned nor checked
    // if it has changed. So we use ERR_error_string_n directly.
    if (ec)
    {
      std::string err(256, '\0');
      ERR_error_string_n((unsigned long)ec, err.data(), err.size());
      // Remove any trailing NULs before returning
      err.resize(std::strlen(err.c_str()));
      return err;
    }
    else
    {
      return "unknown error";
    }
  }

  /// Throws if rc is 1 and has error
  inline void CHECK1(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc != 1 && ec != 0)
    {
      throw std::runtime_error(
        std::string("OpenSSL error: ") + error_string(ec));
    }
  }

  /// Throws if rc is 0 and has error
  inline void
#ifdef _DEBUG
    __attribute__((noinline))
#endif
    CHECK0(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc == 0 && ec != 0)
    {
      throw std::runtime_error(
        std::string("OpenSSL error: ") + error_string(ec));
    }
  }

  /// Throws if ptr is null
  static void
#ifdef _DEBUG
    __attribute__((noinline))
#endif
    CHECKNULL(void* ptr)
  {
    if (ptr == NULL)
    {
      unsigned long ec = ERR_get_error();
      throw std::runtime_error(
        std::string("OpenSSL error: missing object: ") + error_string(ec));
    }
  }

  /*
   * Unique pointer wrappers for SSL objects, with SSL' specific constructors
   * and destructors. Some objects need special functionality, others are just
   * wrappers around the same template interface Unique_SSL_OBJECT.
   */

  /// Generic template interface for different types of objects below.
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
    /// No copy constructors
    Unique_SSL_OBJECT(const Unique_SSL_OBJECT&) = delete;

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
    /// Enable field/member lookups
    const T* operator->() const
    {
      return p.get();
    }
    /// Reset pointer, free old if any
    void reset(T* other)
    {
      p.reset(other);
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
      Unique_SSL_OBJECT(BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(const std::string& s) :
      Unique_SSL_OBJECT(
        BIO_new_mem_buf(s.data(), s.size()), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(const std::string_view& s) :
      Unique_SSL_OBJECT(
        BIO_new_mem_buf(s.data(), s.size()), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(const std::vector<uint8_t>& d) :
      Unique_SSL_OBJECT(
        BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(const std::span<const uint8_t>& d) :
      Unique_SSL_OBJECT(
        BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(const BIO_METHOD* method) :
      Unique_SSL_OBJECT(BIO_new(method), [](auto x) { BIO_free(x); })
    {}
    Unique_BIO(Unique_BIO&& b, Unique_BIO&& next) :
      Unique_SSL_OBJECT(BIO_push(b, next), [](auto x) { BIO_free_all(x); })
    {
      b.release();
      next.release();
    }

    std::string to_string() const
    {
      BUF_MEM* bptr;
      BIO_get_mem_ptr(p.get(), &bptr);
      return std::string(bptr->data, bptr->length);
    }
  };

  struct Unique_EC_KEY : public Unique_SSL_OBJECT<EC_KEY, nullptr, nullptr>
  {
    Unique_EC_KEY(int nid) :
      Unique_SSL_OBJECT(
        EC_KEY_new_by_curve_name(nid), EC_KEY_free, /*check_null=*/true)
    {}
    Unique_EC_KEY(const Unique_EC_KEY& other) :
      Unique_SSL_OBJECT(other, EC_KEY_free, /*check_null=*/true)
    {
      EC_KEY_up_ref(p.get());
    }
  };

  struct Unique_BIGNUM : public Unique_SSL_OBJECT<BIGNUM, BN_new, BN_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    Unique_BIGNUM(const unsigned char* buf, int sz) :
      Unique_SSL_OBJECT(BN_bin2bn(buf, sz, NULL), BN_free, /*check_null=*/false)
    {}
  };

  struct Unique_EC_KEY_P256 : public Unique_EC_KEY
  {
    Unique_EC_KEY_P256(const std::span<const uint8_t>& coordinates) :
      Unique_EC_KEY(NID_X9_62_prime256v1)
    {
      EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
      Unique_BIGNUM x(&coordinates[0], 32);
      Unique_BIGNUM y(&coordinates[32], 32);
      CHECK1(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y));
      p.reset(ec_key);
    }
  };

  struct Unique_X509_REVOKED : public Unique_SSL_OBJECT<
                                 X509_REVOKED,
                                 X509_REVOKED_new,
                                 X509_REVOKED_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

    Unique_X509_REVOKED(X509_REVOKED* x) :
      Unique_SSL_OBJECT(X509_REVOKED_dup(x), X509_REVOKED_free, true)
    {}

    std::string serial() const
    {
      auto sn = X509_REVOKED_get0_serialNumber(*this);
      char* c = i2s_ASN1_INTEGER(NULL, sn);
      std::string r = c;
      free(c);
      return r;
    }
  };

  struct Unique_STACK_OF_X509_REVOKED
    : public Unique_SSL_OBJECT<STACK_OF(X509_REVOKED), nullptr, nullptr>
  {
    Unique_STACK_OF_X509_REVOKED() :
      Unique_SSL_OBJECT(sk_X509_REVOKED_new_null(), [](auto x) {
        sk_X509_REVOKED_pop_free(x, X509_REVOKED_free);
      })
    {}

    Unique_STACK_OF_X509_REVOKED(STACK_OF(X509_REVOKED) * x) :
      Unique_SSL_OBJECT(
        x,
        [](auto x) { sk_X509_REVOKED_pop_free(x, X509_REVOKED_free); },
        /*check_null=*/false)
    {}

    size_t size() const
    {
      int r = sk_X509_REVOKED_num(*this);
      return r == (-1) ? 0 : r;
    }

    bool empty() const
    {
      return size() == 0;
    }

    Unique_X509_REVOKED at(size_t i) const
    {
      if (i >= size())
        throw std::out_of_range("index into CRL stack too large");
      return sk_X509_REVOKED_value(p.get(), i);
    }
  };

  struct Unique_X509_CRL
    : public Unique_SSL_OBJECT<X509_CRL, X509_CRL_new, X509_CRL_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    Unique_X509_CRL(const Unique_BIO& mem) :
      Unique_SSL_OBJECT(
        PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL), X509_CRL_free)
    {}
    Unique_X509_CRL(const std::span<const uint8_t>& data, bool pem = true) :
      Unique_SSL_OBJECT(
        pem ? PEM_read_bio_X509_CRL(
                Unique_BIO(data.data(), data.size()), NULL, NULL, NULL) :
              d2i_X509_CRL_bio(Unique_BIO(data.data(), data.size()), NULL),
        X509_CRL_free)
    {}
    Unique_X509_CRL(const std::string& pem) :
      Unique_X509_CRL(
        std::span<const uint8_t>((uint8_t*)pem.data(), pem.size()), true)
    {}
    Unique_X509_CRL(Unique_X509_CRL&& other)
    {
      p.reset(other.p.release());
    }

    Unique_X509_CRL& operator=(Unique_X509_CRL&& other)
    {
      p.reset(other.release());
      return *this;
    }

    std::string issuer(size_t indent = 0) const
    {
      auto name = X509_CRL_get_issuer(*this);
      Unique_BIO bio;
      CHECK1(X509_NAME_print(bio, name, indent));
      return bio.to_string();
    }

    Unique_STACK_OF_X509_REVOKED revoked() const
    {
      auto sk = X509_CRL_get_REVOKED(*this);
      if (!sk)
        return Unique_STACK_OF_X509_REVOKED();
      else
      {
        auto copy = sk_X509_REVOKED_deep_copy(
          sk,
          [](const X509_REVOKED* x) {
            return X509_REVOKED_dup(const_cast<X509_REVOKED*>(x));
          },
          X509_REVOKED_free);
        return Unique_STACK_OF_X509_REVOKED(copy);
      }
    }

    std::string pem() const
    {
      Unique_BIO bio;
      PEM_write_bio_X509_CRL(bio, *this);
      return bio.to_string();
    }

    std::string to_string_short(size_t indent = 0) const
    {
      std::stringstream ss;
      auto rkd = revoked();
      std::string ins(indent, ' ');
      ss << ins << "- Issuer: " << issuer() << std::endl;
      ss << ins << "- Revoked serial numbers: ";
      if (rkd.size() == 0)
        ss << "none";
      ss << std::endl;
      for (size_t i = 0; i < rkd.size(); i++)
      {
        ss << ins << "- " << rkd.at(i).serial() << std::endl;
      }
      ss << ins << "- Last update: " << last_update()
         << "  Next update: " << next_update();
      return ss.str();
    }

    std::string last_update() const
    {
      auto lu = X509_CRL_get0_lastUpdate(*this);
      Unique_BIO bio;
      CHECK1(ASN1_TIME_print(bio, lu));
      return bio.to_string();
    }

    std::string next_update() const
    {
      auto t = X509_CRL_get0_nextUpdate(*this);
      Unique_BIO bio;
      ASN1_TIME_print(bio, t);
      return bio.to_string();
    }
  };

  struct Unique_ASN1_OBJECT
    : public Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    Unique_ASN1_OBJECT(const std::string& oid) :
      Unique_SSL_OBJECT(OBJ_txt2obj(oid.c_str(), 0), ASN1_OBJECT_free)
    {}
    Unique_ASN1_OBJECT(ASN1_OBJECT* o) :
      Unique_SSL_OBJECT(OBJ_dup(o), ASN1_OBJECT_free, true)
    {}

    bool operator==(const Unique_ASN1_OBJECT& other) const
    {
      return OBJ_cmp(*this, other) == 0;
    }

    bool operator!=(const Unique_ASN1_OBJECT& other) const
    {
      return !(*this == other);
    }
  };

  struct Unique_EVP_PKEY;

  struct Unique_X509_EXTENSION : public Unique_SSL_OBJECT<
                                   X509_EXTENSION,
                                   X509_EXTENSION_new,
                                   X509_EXTENSION_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    Unique_X509_EXTENSION(X509_EXTENSION* ext) :
      Unique_SSL_OBJECT(X509_EXTENSION_dup(ext), X509_EXTENSION_free, true)
    {}
  };

  struct Unique_X509 : public Unique_SSL_OBJECT<X509, X509_new, X509_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    // p == nullptr is OK (e.g. wrong format)
    Unique_X509(const Unique_BIO& mem, bool pem, bool check_null = true) :
      Unique_SSL_OBJECT(
        pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) :
              d2i_X509_bio(mem, NULL),
        X509_free,
        check_null)
    {}

    Unique_X509(const std::string& pem, bool check_null = true) :
      Unique_SSL_OBJECT(
        PEM_read_bio_X509(Unique_BIO(pem), NULL, NULL, NULL),
        X509_free,
        check_null)
    {}

    Unique_X509(Unique_X509&& other) : Unique_SSL_OBJECT(NULL, X509_free, false)
    {
      X509* ptr = other;
      other.release();
      p.reset(ptr);
    }

    Unique_X509(X509* x509) : Unique_SSL_OBJECT(x509, X509_free, true)
    {
      X509_up_ref(x509);
    }

    Unique_X509& operator=(const Unique_X509& other)
    {
      X509_up_ref(other);
      p.reset(other.p.get());
      return *this;
    }

    Unique_X509& operator=(Unique_X509&& other)
    {
      p.reset(other.p.release());
      return *this;
    }

    bool is_ca() const
    {
      return X509_check_ca(p.get()) != 0;
    }

    int extension_index(const std::string& oid) const
    {
      return X509_get_ext_by_OBJ(*this, Unique_ASN1_OBJECT(oid.c_str()), -1);
    }

    Unique_X509_EXTENSION extension(const std::string& oid) const
    {
      return X509_get_ext(*this, extension_index(oid));
    }

    bool has_common_name(const std::string& expected_name) const
    {
      auto subject_name = X509_get_subject_name(*this);
      int cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
      while (cn_i != -1)
      {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, cn_i);
        ASN1_STRING* entry_string = X509_NAME_ENTRY_get_data(entry);
        std::string common_name = (char*)ASN1_STRING_get0_data(entry_string);
        if (common_name == expected_name)
          return true;
        cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, cn_i);
      }
      return false;
    }

    std::string pem() const
    {
      Unique_BIO mem;
      CHECK1(PEM_write_bio_X509(mem, *this));
      return mem.to_string();
    }

    std::string to_string_short(size_t indent = 0) const
    {
      std::string ins(indent, ' ');
      std::stringstream ss;

      ss << ins << "- Subject: " << subject_name() << std::endl;

      std::string subj_key_id =
        has_subject_key_id() ? subject_key_id() : "none";
      ss << ins << "  - Subject key ID: " << subj_key_id << std::endl;

      std::string auth_key_id =
        has_authority_key_id() ? authority_key_id() : "none";
      ss << ins << "  - Authority key ID: " << auth_key_id << std::endl;

      ss << ins << "  - CA: " << (is_ca() ? "yes" : "no") << std::endl;
      ss << ins << "  - Not before: " << not_before()
         << "  Not after: " << not_after();
      return ss.str();
    }

    std::string subject_name(size_t indent = 0) const
    {
      Unique_BIO bio;
      auto subject_name = X509_get_subject_name(*this);
      CHECK1(X509_NAME_print(bio, subject_name, indent));
      return bio.to_string();
    }

    bool has_subject_key_id() const
    {
      return X509_get0_subject_key_id(*this) != NULL;
    }

    std::string subject_key_id() const
    {
      const ASN1_OCTET_STRING* key_id = X509_get0_subject_key_id(*this);
      if (!key_id)
        throw std::runtime_error(
          "certificate does not contain a subject key id");
      char* c = i2s_ASN1_OCTET_STRING(NULL, key_id);
      std::string r = c;
      free(c);
      return r;
    }

    bool has_authority_key_id() const
    {
      return X509_get0_authority_key_id(*this) != NULL;
    }

    std::string authority_key_id() const
    {
      const ASN1_OCTET_STRING* key_id = X509_get0_authority_key_id(*this);
      if (!key_id)
        throw std::runtime_error(
          "certificate does not contain an authority key id");
      char* c = i2s_ASN1_OCTET_STRING(NULL, key_id);
      std::string r = c;
      free(c);
      return r;
    }

    std::string not_before() const
    {
      auto t = X509_get0_notBefore(*this);
      Unique_BIO bio;
      CHECK1(ASN1_TIME_print(bio, t));
      return bio.to_string();
    }

    std::string not_after() const
    {
      auto t = X509_get0_notAfter(*this);
      Unique_BIO bio;
      CHECK1(ASN1_TIME_print(bio, t));
      return bio.to_string();
    }

    bool has_public_key(const Unique_EVP_PKEY& target) const;
    bool has_public_key(Unique_EVP_PKEY&& target) const;
    bool has_public_key(const std::string& target) const;
  };

  struct Unique_X509_STORE
    : public Unique_SSL_OBJECT<X509_STORE, X509_STORE_new, X509_STORE_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

    void set_flags(int flags)
    {
      X509_STORE_set_flags(p.get(), flags);
    }

    void add(const Unique_X509& x509)
    {
      X509_STORE_add_cert(p.get(), x509);
    }

    void add(const std::span<const uint8_t>& data, bool pem = true)
    {
      Unique_X509 x509(Unique_BIO(data), pem);
      add(x509);
    }

    void add(const std::string& pem)
    {
      add({(uint8_t*)pem.data(), pem.size()}, true);
    }

    void add_crl(const std::span<const uint8_t>& data)
    {
      if (!data.empty())
      {
        Unique_X509_CRL crl(
          data); // TODO: PEM only; some CRLs may be in DER format?
        CHECK1(X509_STORE_add_crl(p.get(), crl));
      }
    }

    void add_crl(const std::string& pem)
    {
      add_crl(std::span((uint8_t*)pem.data(), pem.size()));
    }

    void add_crl(const std::optional<Unique_X509_CRL>& crl)
    {
      if (crl)
        CHECK1(X509_STORE_add_crl(p.get(), *crl));
    }
  };

  struct Unique_X509_STORE_CTX : public Unique_SSL_OBJECT<
                                   X509_STORE_CTX,
                                   X509_STORE_CTX_new,
                                   X509_STORE_CTX_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
  };

  struct Unique_EVP_PKEY
    : public Unique_SSL_OBJECT<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    Unique_EVP_PKEY(const Unique_BIO& mem, bool pem = true) :
      Unique_SSL_OBJECT(
        pem ? PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL) :
              d2i_PUBKEY_bio(mem, NULL),
        EVP_PKEY_free)
    {}
    Unique_EVP_PKEY(const Unique_EC_KEY& ec_key) :
      Unique_SSL_OBJECT(EVP_PKEY_new(), EVP_PKEY_free)
    {
      EVP_PKEY_set1_EC_KEY(p.get(), ec_key);
    }
    Unique_EVP_PKEY(const Unique_X509& x509) :
      Unique_SSL_OBJECT(X509_get_pubkey(x509), EVP_PKEY_free)
    {}

    bool operator==(const Unique_EVP_PKEY& other) const
    {
      // TODO: Do the parameters need to match? (They don't match for the
      // SEV/SNP root CA.)
      return // EVP_PKEY_cmp_parameters((*this), other) == 1 &&
        EVP_PKEY_cmp((*this), other) == 1;
    }

    bool operator!=(const Unique_EVP_PKEY& other) const
    {
      return !(*this == other);
    }
  };

  struct Unique_EVP_PKEY_CTX
    : public Unique_SSL_OBJECT<EVP_PKEY_CTX, nullptr, nullptr>
  {
    Unique_EVP_PKEY_CTX(const Unique_EVP_PKEY& key) :
      Unique_SSL_OBJECT(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
    {}
    Unique_EVP_PKEY_CTX() :
      Unique_SSL_OBJECT(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
    {}
  };

  inline bool Unique_X509::has_public_key(const Unique_EVP_PKEY& target) const
  {
    return Unique_EVP_PKEY(*this) == target;
  }

  inline bool Unique_X509::has_public_key(Unique_EVP_PKEY&& target) const
  {
    return has_public_key((Unique_EVP_PKEY&)target);
  }

  inline bool Unique_X509::has_public_key(const std::string& target) const
  {
    return has_public_key(Unique_EVP_PKEY(Unique_BIO(target)));
  }

  struct Unique_STACK_OF_X509
    : public Unique_SSL_OBJECT<STACK_OF(X509), nullptr, nullptr>
  {
    Unique_STACK_OF_X509() :
      Unique_SSL_OBJECT(
        sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
    {}
    Unique_STACK_OF_X509(const Unique_X509_STORE_CTX& ctx) :
      Unique_SSL_OBJECT(X509_STORE_CTX_get1_chain(ctx), [](auto x) {
        sk_X509_pop_free(x, X509_free);
      })
    {}
    Unique_STACK_OF_X509(Unique_STACK_OF_X509&& other) :
      Unique_SSL_OBJECT(other, [](auto x) { sk_X509_pop_free(x, X509_free); })
    {
      other.release();
    }

    Unique_STACK_OF_X509(const std::span<const uint8_t>& data) :
      Unique_SSL_OBJECT(
        NULL, [](auto x) { sk_X509_pop_free(x, X509_free); }, false)
    {
      Unique_BIO mem(data);
      STACK_OF(X509_INFO)* sk_info =
        PEM_X509_INFO_read_bio(mem, NULL, NULL, NULL);
      int sz = sk_X509_INFO_num(sk_info);
      p.reset(sk_X509_new_null());
      for (int i = 0; i < sz; i++)
      {
        auto sk_i = sk_X509_INFO_value(sk_info, i);
        if (!sk_i->x509)
          throw std::runtime_error("invalid PEM element");
        X509_up_ref(sk_i->x509);
        sk_X509_push(*this, sk_i->x509);
      }
      sk_X509_INFO_pop_free(sk_info, X509_INFO_free);
    }

    Unique_STACK_OF_X509(const std::string& data) :
      Unique_STACK_OF_X509(
        std::span<const uint8_t>((uint8_t*)data.data(), data.size()))
    {}

    Unique_STACK_OF_X509& operator=(Unique_STACK_OF_X509&& other)
    {
      p.reset(other.p.release());
      return *this;
    }

    size_t size() const
    {
      int r = sk_X509_num(p.get());
      return r == (-1) ? 0 : r;
    }

    Unique_X509 at(size_t i) const
    {
      if (i >= size())
        throw std::out_of_range("index into certificate stack too large");
      return sk_X509_value(p.get(), i);
    }

    void insert(size_t i, Unique_X509&& x)
    {
      X509_up_ref(x);
      CHECK0(sk_X509_insert(p.get(), x, i));
    }

    void push(Unique_X509&& x509)
    {
      sk_X509_push(p.get(), x509.release());
    }

    Unique_X509 front() const
    {
      return (*this).at(0);
    }

    Unique_X509 back() const
    {
      return (*this).at(size() - 1);
    }

    std::pair<struct tm, struct tm> get_validity_range()
    {
      if (size() == 0)
        throw std::runtime_error(
          "no certificate change to compute validity ranges for");

      const ASN1_TIME *latest_from = nullptr, *earliest_to = nullptr;
      for (size_t i = 0; i < size(); i++)
      {
        const auto& c = at(i);
        const ASN1_TIME* not_before = X509_get0_notBefore(c);
        if (!latest_from || ASN1_TIME_compare(latest_from, not_before) == -1)
          latest_from = not_before;
        const ASN1_TIME* not_after = X509_get0_notAfter(c);
        if (!earliest_to || ASN1_TIME_compare(earliest_to, not_after) == 1)
          earliest_to = not_after;
      }

      std::pair<struct tm, struct tm> r;
      ASN1_TIME_to_tm(latest_from, &r.first);
      ASN1_TIME_to_tm(earliest_to, &r.second);
      return r;
    }

    std::string to_string_short(size_t indent = 0) const
    {
      std::stringstream ss;
      for (size_t i = 0; i < size(); i++)
      {
        if (i != 0)
          ss << std::endl;
        ss << at(i).to_string_short(indent + 2);
      }
      return ss.str();
    }

    std::string pem() const
    {
      std::string r;
      for (size_t i = 0; i < size(); i++)
        r += at(i).pem();
      return r;
    }
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
    Unique_ECDSA_SIG(const std::vector<uint8_t>& sig) :
      Unique_SSL_OBJECT(
        [&sig]() {
          const unsigned char* pp = sig.data();
          return d2i_ECDSA_SIG(NULL, &pp, sig.size());
        }(),
        ECDSA_SIG_free,
        false)
    {}
  };
  ;

  struct Unique_ASN1_TYPE
    : public Unique_SSL_OBJECT<ASN1_TYPE, ASN1_TYPE_new, ASN1_TYPE_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

    Unique_ASN1_TYPE(ASN1_TYPE* t) :
      Unique_SSL_OBJECT(
        [&t]() {
          ASN1_TYPE* n = ASN1_TYPE_new();
          CHECK1(ASN1_TYPE_set1(n, t->type, t->value.ptr));
          return n;
        }(),
        ASN1_TYPE_free)
    {}

    Unique_ASN1_TYPE(int type, void* value) :
      Unique_SSL_OBJECT(
        [&type, &value]() {
          ASN1_TYPE* n = ASN1_TYPE_new();
          CHECK1(ASN1_TYPE_set1(n, type, value));
          return n;
        }(),
        ASN1_TYPE_free,
        true)
    {}
  };

  struct Unique_ASN1_OCTET_STRING : public Unique_SSL_OBJECT<
                                      ASN1_OCTET_STRING,
                                      ASN1_OCTET_STRING_new,
                                      ASN1_OCTET_STRING_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

    Unique_ASN1_OCTET_STRING(const ASN1_OCTET_STRING* t) :
      Unique_SSL_OBJECT(ASN1_OCTET_STRING_dup(t), ASN1_OCTET_STRING_free)
    {}

    bool operator==(const Unique_ASN1_OCTET_STRING& other) const
    {
      return ASN1_OCTET_STRING_cmp(*this, other) == 0;
    }

    bool operator!=(const Unique_ASN1_OCTET_STRING& other) const
    {
      return !(*this == other);
    }
  };

  struct Unique_ASN1_SEQUENCE : public Unique_SSL_OBJECT<
                                  ASN1_SEQUENCE_ANY,
                                  sk_ASN1_TYPE_new_null,
                                  sk_ASN1_TYPE_free>
  {
    using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

    Unique_ASN1_SEQUENCE(const ASN1_OCTET_STRING* os) :
      Unique_SSL_OBJECT(
        [&os]() {
          ASN1_SEQUENCE_ANY* seq = NULL;
          const unsigned char* pp = os->data;
          CHECKNULL(d2i_ASN1_SEQUENCE_ANY(&seq, &pp, os->length));
          return seq;
        }(),
        [](STACK_OF(ASN1_TYPE) * p) {
          for (size_t i = 0; i < (size_t)sk_ASN1_TYPE_num(p); i++)
            ASN1_TYPE_free(sk_ASN1_TYPE_value(p, i));
          sk_ASN1_TYPE_free(p);
        })
    {}

    Unique_ASN1_TYPE at(int index) const
    {
      return Unique_ASN1_TYPE(sk_ASN1_TYPE_value(p.get(), index));
    }

    int size() const
    {
      return sk_ASN1_TYPE_num(p.get());
    }

    Unique_ASN1_TYPE get_obj_value(
      int index, const std::string& expected_oid, int expected_value_type) const
    {
      Unique_ASN1_TYPE type = at(index);

      if (type->type != V_ASN1_SEQUENCE)
        throw asn1_format_exception("ASN.1 object not a sequence");

      Unique_ASN1_SEQUENCE ss(type->value.sequence);

      if (ss.size() != 2)
        throw asn1_format_exception("ASN.1 sequence of invalid size");

      // OID
      Unique_ASN1_TYPE tt = ss.at(0);

      if (tt->type != V_ASN1_OBJECT)
        throw asn1_format_exception("ASN.1 object value of invalid type");

      if (
        Unique_ASN1_OBJECT(tt->value.object) !=
        Unique_ASN1_OBJECT(expected_oid))
        throw asn1_format_exception("ASN.1 object with unexpected id");

      // VALUE
      Unique_ASN1_TYPE tv = ss.at(1);
      if (tv->type != expected_value_type)
        throw asn1_format_exception("ASN.1 value of unexpected type");

      return Unique_ASN1_TYPE(tv->type, tv->value.ptr);
    }

    uint8_t get_uint8(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_INTEGER);

      Unique_BIGNUM bn;
      ASN1_INTEGER_to_BN(v->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      int is_zero = BN_is_zero(bn);
      if (num_bytes != 1 && !is_zero)
        throw asn1_format_exception("ASN.1 integer value not a uint8_t");
      uint8_t r = 0;
      BN_bn2bin(bn, &r);
      return r;
    }

    uint16_t get_uint16(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_INTEGER);

      Unique_BIGNUM bn;
      ASN1_INTEGER_to_BN(v->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      if (num_bytes > 2)
        throw asn1_format_exception("ASN.1 integer value not a uint16_t");
      std::vector<uint8_t> r(num_bytes);
      BN_bn2bin(bn, r.data());
      return num_bytes == 0 ? 0 : num_bytes == 1 ? r[0] : (r[0] | r[1] << 8);
    }

    int64_t get_enum(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_ENUMERATED);
      int64_t r = 0;
      CHECK1(ASN1_ENUMERATED_get_int64(&r, v->value.enumerated));
      return r;
    }

    std::vector<uint8_t> get_octet_string(
      int index, const std::string& expected_oid) const
    {
      Unique_ASN1_TYPE v =
        get_obj_value(index, expected_oid, V_ASN1_OCTET_STRING);

      return std::vector<uint8_t>(
        v->value.octet_string->data,
        v->value.octet_string->data + v->value.octet_string->length);
    }

    Unique_ASN1_SEQUENCE get_seq(
      int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_SEQUENCE);
      return Unique_ASN1_SEQUENCE(v->value.sequence);
    }

    bool get_bool(int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_BOOLEAN);
      return v->value.boolean;
    }
  };
}
