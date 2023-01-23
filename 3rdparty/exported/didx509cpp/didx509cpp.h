// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstring>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#  include <openssl/types.h>
#endif

namespace didx509
{
  namespace
  {
    inline std::string error_string(int ec)
#ifdef _DEBUG
      __attribute__((noinline))
#endif
    {
      if (ec)
        return std::string(ERR_error_string((unsigned long)ec, NULL));
      else
        return "unknown error";
    }

    /// Throws if rc is different from and there is an error
    inline void CHECK1(int rc)
#ifdef _DEBUG
      __attribute__((noinline))
#endif
    {
      unsigned long ec = ERR_get_error();
      if (rc != 1 && ec != 0)
        throw std::runtime_error(
          std::string("OpenSSL error: ") + error_string(ec));
    }

    /// Throws if rc is 0 and there is an error
    inline void CHECK0(int rc)
#ifdef _DEBUG
      __attribute__((noinline))
#endif
    {
      unsigned long ec = ERR_get_error();
      if (rc == 0 && ec != 0)
        throw std::runtime_error(
          std::string("OpenSSL error: ") + error_string(ec));
    }

    /// Throws if ptr is null
    inline void CHECKNULL(void* ptr)
#ifdef _DEBUG
      __attribute__((noinline))
#endif
    {
      if (ptr == NULL)
      {
        unsigned long ec = ERR_get_error();
        throw std::runtime_error(
          std::string("OpenSSL error: missing object: ") + error_string(ec));
      }
    }

    inline std::string to_base64(const std::vector<uint8_t>& bytes)
    {
      size_t r_sz = 4 * ((bytes.size() + 2) / 3);
      std::string r(r_sz, 0);
      auto out_sz =
        EVP_EncodeBlock((unsigned char*)r.data(), bytes.data(), bytes.size());
      if (r_sz != out_sz)
        throw std::runtime_error("base64 conversion failed");
      while (r.back() == '=')
        r.pop_back();
      return r;
    }

    inline std::string to_base64url(const std::vector<uint8_t>& bytes)
    {
      auto r = to_base64(bytes);
      for (size_t i = 0; i < r.size(); i++)
        if (r[i] == '+')
          r[i] = '-';
        else if (r[i] == '/')
          r[i] = '_';
      return r;
    }

    template <class T, T* (*CTOR)(), void (*DTOR)(T*)>
    class UqSSLOBJECT
    {
    protected:
      std::unique_ptr<T, void (*)(T*)> p;

    public:
      UqSSLOBJECT() : p(CTOR(), DTOR)
      {
        CHECKNULL(p.get());
      }

      UqSSLOBJECT(T* ptr, void (*dtor)(T*), bool check_null = true) :
        p(ptr, dtor)
      {
        if (check_null)
          CHECKNULL(p.get());
      }

      UqSSLOBJECT(const UqSSLOBJECT&) = delete;
      UqSSLOBJECT& operator=(const UqSSLOBJECT&) = delete;

      operator T*()
      {
        return p.get();
      }

      operator T*() const
      {
        return p.get();
      }

      const T* operator->() const
      {
        return p.get();
      }

      void reset(T* other)
      {
        p.reset(other);
      }

      T* release()
      {
        return p.release();
      }
    };

    struct UqBIGNUM : public UqSSLOBJECT<BIGNUM, BN_new, BN_free>
    {
      UqBIGNUM(const BIGNUM* n) : UqSSLOBJECT(BN_dup(n), BN_free) {}

      UqBIGNUM(UqBIGNUM&& other) : UqSSLOBJECT(nullptr, BN_free, false)
      {
        p.reset(other.p.release());
      }
    };

    struct UqBIO : public UqSSLOBJECT<BIO, nullptr, nullptr>
    {
      UqBIO() : UqSSLOBJECT(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
      {}

      UqBIO(const void* buf, int len) :
        UqSSLOBJECT(BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
      {}

      UqBIO(const std::string& s) :
        UqSSLOBJECT(
          BIO_new_mem_buf(s.data(), s.size()), [](auto x) { BIO_free(x); })
      {}

      UqBIO(const std::vector<uint8_t>& d) :
        UqSSLOBJECT(
          BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
      {}

      UqBIO(UqBIO&& b, UqBIO&& next) :
        UqSSLOBJECT(BIO_push(b, next), [](auto x) { BIO_free_all(x); })
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

      std::vector<uint8_t> to_vector() const
      {
        BUF_MEM* bptr;
        BIO_get_mem_ptr(p.get(), &bptr);
        return std::vector<uint8_t>(bptr->data, bptr->data + bptr->length);
      }
    };

    struct UqASN1_OBJECT
      : public UqSSLOBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>
    {
      UqASN1_OBJECT(const std::string& oid) :
        UqSSLOBJECT(OBJ_txt2obj(oid.c_str(), 1), ASN1_OBJECT_free)
      {}

      UqASN1_OBJECT(const ASN1_OBJECT* obj) :
        UqSSLOBJECT(OBJ_dup(obj), ASN1_OBJECT_free, true)
      {}

      UqASN1_OBJECT(int nid) :
        UqSSLOBJECT(OBJ_nid2obj(nid), ASN1_OBJECT_free, true)
      {}

      UqASN1_OBJECT(UqASN1_OBJECT&& other) :
        UqSSLOBJECT(NULL, ASN1_OBJECT_free, false)
      {
        p.reset(other.p.release());
      }

      bool operator==(const UqASN1_OBJECT& other) const
      {
        return OBJ_cmp(*this, other) == 0;
      }

      bool operator!=(const UqASN1_OBJECT& other) const
      {
        return !(*this == other);
      }
    };

    struct UqASN1_OCTET_STRING : public UqSSLOBJECT<
                                   ASN1_OCTET_STRING,
                                   ASN1_OCTET_STRING_new,
                                   ASN1_OCTET_STRING_free>
    {
      UqASN1_OCTET_STRING(const ASN1_OCTET_STRING* str) :
        UqSSLOBJECT(ASN1_OCTET_STRING_dup(str), ASN1_OCTET_STRING_free)
      {}

      UqASN1_OCTET_STRING(UqASN1_OCTET_STRING&& other) :
        UqSSLOBJECT(NULL, ASN1_OCTET_STRING_free, false)
      {
        p.reset(other.p.release());
      }

      operator std::string() const
      {
        UqBIO bio;
        ASN1_STRING_print(bio, *this);
        return bio.to_string();
      }
    };

    struct UqX509_EXTENSION : public UqSSLOBJECT<
                                X509_EXTENSION,
                                X509_EXTENSION_new,
                                X509_EXTENSION_free>
    {
      UqX509_EXTENSION(X509_EXTENSION* ext) :
        UqSSLOBJECT(X509_EXTENSION_dup(ext), X509_EXTENSION_free, true)
      {}

      UqX509_EXTENSION(const UqX509_EXTENSION& ext) :
        UqSSLOBJECT(X509_EXTENSION_dup(ext), X509_EXTENSION_free, true)
      {}

      UqX509_EXTENSION(UqX509_EXTENSION&& ext) :
        UqSSLOBJECT(ext, X509_EXTENSION_free, true)
      {}

      UqASN1_OBJECT object() const
      {
        return X509_EXTENSION_get_object(*this);
      }

      UqASN1_OCTET_STRING data() const
      {
        return X509_EXTENSION_get_data(*this);
      }
    };

    struct UqGENERAL_NAME
      : public UqSSLOBJECT<GENERAL_NAME, GENERAL_NAME_new, GENERAL_NAME_free>
    {
      UqGENERAL_NAME(GENERAL_NAME* n) :
        UqSSLOBJECT(GENERAL_NAME_dup(n), GENERAL_NAME_free)
      {}

      UqGENERAL_NAME(UqGENERAL_NAME&& other) :
        UqSSLOBJECT(NULL, GENERAL_NAME_free, false)
      {
        p.reset(other.p.release());
      }
    };

    struct UqSUBJECT_ALT_NAME
      : public UqSSLOBJECT<STACK_OF(GENERAL_NAME), nullptr, nullptr>
    {
      UqSUBJECT_ALT_NAME() :
        UqSSLOBJECT(sk_GENERAL_NAME_new_null(), [](auto x) {
          sk_GENERAL_NAME_pop_free(x, GENERAL_NAME_free);
        })
      {}

      UqSUBJECT_ALT_NAME(const UqX509_EXTENSION& ext) :
        UqSSLOBJECT(
          NULL,
          [](auto x) { sk_GENERAL_NAME_pop_free(x, GENERAL_NAME_free); },
          false)
      {
        UqASN1_OBJECT ext_obj(X509_EXTENSION_get_object(ext));
        UqASN1_OBJECT ext_key_obj(NID_subject_alt_name);
        if (ext_obj != ext_key_obj)
          throw std::runtime_error("invalid extension type");
        auto data = static_cast<STACK_OF(GENERAL_NAME)*>(X509V3_EXT_d2i(ext));
        if (!data)
          throw std::runtime_error("SAN extension could not be decoded");
        p.reset(data);
      }

      UqSUBJECT_ALT_NAME(UqSUBJECT_ALT_NAME&& other) :
        UqSSLOBJECT(
          NULL, [](auto x) { sk_GENERAL_NAME_pop_free(x, GENERAL_NAME_free); })
      {
        p.reset(other.p.release());
      }

      size_t size() const
      {
        return sk_GENERAL_NAME_num(*this);
      }

      UqGENERAL_NAME at(size_t i) const
      {
        if (i >= size())
          throw std::out_of_range("extended key usage index out of range");
        return sk_GENERAL_NAME_value(*this, i);
      }
    };

    struct UqEXTENDED_KEY_USAGE : public UqSSLOBJECT<
                                    EXTENDED_KEY_USAGE,
                                    EXTENDED_KEY_USAGE_new,
                                    EXTENDED_KEY_USAGE_free>
    {
      UqEXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE* eku) :
        UqSSLOBJECT(sk_ASN1_OBJECT_dup(eku), EXTENDED_KEY_USAGE_free)
      {}

      UqEXTENDED_KEY_USAGE(const UqX509_EXTENSION& ext) :
        UqSSLOBJECT(NULL, EXTENDED_KEY_USAGE_free, false)
      {
        UqASN1_OBJECT ext_obj = UqASN1_OBJECT(X509_EXTENSION_get_object(ext));
        UqASN1_OBJECT ext_key_obj(NID_ext_key_usage);
        if (ext_obj != ext_key_obj)
          throw std::runtime_error("invalid extension type");
        auto data = static_cast<EXTENDED_KEY_USAGE*>(X509V3_EXT_d2i(ext));
        if (!data)
          throw std::runtime_error("key usage extension could not be decoded");
        p.reset(data);
      }

      UqEXTENDED_KEY_USAGE(UqEXTENDED_KEY_USAGE&& other) :
        UqSSLOBJECT(NULL, EXTENDED_KEY_USAGE_free, false)
      {
        p.reset(other.p.release());
      }

      size_t size() const
      {
        return sk_ASN1_OBJECT_num(*this);
      }

      UqASN1_OBJECT at(size_t i) const
      {
        if (i >= size())
          throw std::out_of_range("extended key usage index out of range");
        return UqASN1_OBJECT(sk_ASN1_OBJECT_value(*this, i));
      }
    };

    struct UqX509;

    struct UqEVP_PKEY
      : public UqSSLOBJECT<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free>
    {
      UqEVP_PKEY(const UqX509& x509);

      UqEVP_PKEY(const EVP_PKEY* key);

      UqEVP_PKEY(UqEVP_PKEY&& other) :
        UqSSLOBJECT(nullptr, EVP_PKEY_free, false)
      {
        p.reset(other.p.release());
      }

      bool operator==(const UqEVP_PKEY& other) const
      {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
        return EVP_PKEY_eq(*this, other) == 1;
#else
        return EVP_PKEY_cmp(*this, other) == 1;
#endif
      }

      bool operator!=(const UqEVP_PKEY& other) const
      {
        return !(*this == other);
      }

      bool verify_signature(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature) const;

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      UqBIGNUM get_bn_param(const char* key_name) const
      {
        BIGNUM* bn = NULL;
        CHECK1(EVP_PKEY_get_bn_param(*this, key_name, &bn));
        UqBIGNUM r(bn);
        BN_free(bn);
        return r;
      }
#endif
    };

    struct UqEVP_PKEY_CTX : public UqSSLOBJECT<EVP_PKEY_CTX, nullptr, nullptr>
    {
      UqEVP_PKEY_CTX(int nid) :
        UqSSLOBJECT(EVP_PKEY_CTX_new_id(nid, NULL), EVP_PKEY_CTX_free)
      {}
    };

    struct UqX509 : public UqSSLOBJECT<X509, X509_new, X509_free>
    {
      UqX509(const std::string& pem, bool check_null = true) :
        UqSSLOBJECT(
          PEM_read_bio_X509(UqBIO(pem), NULL, NULL, NULL),
          X509_free,
          check_null)
      {}

      UqX509(UqX509&& other) : UqSSLOBJECT(NULL, X509_free, false)
      {
        X509* ptr = other;
        other.release();
        p.reset(ptr);
      }

      UqX509(X509* x509) : UqSSLOBJECT(x509, X509_free)
      {
        X509_up_ref(x509);
      }

      UqX509& operator=(const UqX509& other)
      {
        X509_up_ref(other);
        p.reset(other.p.get());
        return *this;
      }

      UqX509& operator=(UqX509&& other)
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
        return X509_get_ext_by_OBJ(*this, UqASN1_OBJECT(oid.c_str()), -1);
      }

      template <typename T>
      std::vector<T> extensions(const UqASN1_OBJECT& obj) const
      {
        std::vector<T> r;
        auto count = X509_get_ext_count(*this);
        int index = -1;
        do
        {
          index = X509_get_ext_by_OBJ(*this, obj, index);
          if (index != -1)
            r.emplace_back(X509_get_ext(*this, index));
        } while (index != -1 && index < count);
        return r;
      }

      template <typename T>
      std::vector<T> extensions(const std::string& oid) const
      {
        return extensions<T>(UqASN1_OBJECT(oid));
      }

      std::vector<UqSUBJECT_ALT_NAME> subject_alternative_name() const
      {
        return extensions<UqSUBJECT_ALT_NAME>(
          UqASN1_OBJECT(NID_subject_alt_name));
      };

      std::vector<UqEXTENDED_KEY_USAGE> extended_key_usage() const
      {
        return extensions<UqEXTENDED_KEY_USAGE>(
          UqASN1_OBJECT(NID_ext_key_usage));
      };

      bool has_key_usage() const
      {
        return (X509_get_extension_flags(*this) & EXFLAG_KUSAGE) != 0;
      }

      bool has_key_usage_digital_signature() const
      {
        return has_key_usage() &&
          (X509_get_key_usage(*this) & KU_DIGITAL_SIGNATURE) != 0;
      }

      bool has_key_usage_key_agreement() const
      {
        return has_key_usage() &&
          (X509_get_key_usage(*this) & KU_KEY_AGREEMENT) != 0;
      }

      bool has_common_name(const std::string& expected_name) const;

      std::map<std::string, std::vector<std::string>> subject() const
      {
        std::map<std::string, std::vector<std::string>> r;

        auto name = X509_get_subject_name(*this);
        CHECKNULL(name);
        auto n = X509_NAME_entry_count(name);
        for (auto i = 0; i < n; i++)
        {
          X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
          CHECKNULL(entry);

          ASN1_OBJECT* oid = X509_NAME_ENTRY_get_object(entry);
          CHECKNULL(oid);

          std::string key;
          std::map<int, std::string> short_name_map = {
            // As specified by the did-x509 spec
            {NID_commonName, "CN"},
            {NID_localityName, "L"},
            {NID_stateOrProvinceName, "ST"},
            {NID_organizationName, "O"},
            {NID_organizationalUnitName, "OU"},
            {NID_countryName, "C"},
            {NID_streetAddress, "STREET"},
          };

          auto snit = short_name_map.find(OBJ_obj2nid(oid));
          if (snit != short_name_map.end())
            key = snit->second;
          else
          {
            int sz = OBJ_obj2txt(NULL, 0, oid, 1);
            key.resize(sz + 1, 0);
            OBJ_obj2txt((char*)key.data(), key.size(), oid, 1);
          }

          ASN1_STRING* val_asn1 = X509_NAME_ENTRY_get_data(entry);
          CHECKNULL(val_asn1);
          UqBIO value_bio;
          ASN1_STRING_print(value_bio, val_asn1);
          auto value = value_bio.to_string();

          r[key].push_back(value);
        }

        return r;
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

      inline bool has_san(const std::string& san_type, const std::string& value)
      {
        if (san_type == "dns")
        {
          if (X509_check_host(*this, value.c_str(), value.size(), 0, NULL) == 1)
            return true;
        }
        else if (san_type == "email")
        {
          if (X509_check_email(*this, value.c_str(), value.size(), 0) == 1)
            return true;
        }
        else if (san_type == "ipaddress")
        {
          if (
            X509_check_ip(
              *this, (unsigned char*)value.c_str(), value.size(), 0) == 1)
            return true;
        }
        else if (san_type == "uri")
        {
          auto san_exts = subject_alternative_name();
          for (const auto& ext : san_exts)
          {
            for (size_t i = 0; i < ext.size(); i++)
            {
              const auto& san_i = ext.at(i);
              switch (san_i->type)
              {
                case GEN_URI: {
                  ASN1_STRING* x = san_i->d.uniformResourceIdentifier;
                  std::string gen_uri = (const char*)ASN1_STRING_get0_data(x);
                  if (gen_uri == value)
                    return true;
                }
                default:;
              }
            }
          }
        }
        else
          throw std::runtime_error(
            std::string("unknown SAN type: ") + san_type);

        return false;
      }

      std::vector<uint8_t> der() const
      {
        std::vector<uint8_t> r;
        UqBIO mem;
        i2d_X509_bio(mem, *this);
        return mem.to_vector();
      }

      UqEVP_PKEY public_key() const
      {
        return X509_get0_pubkey(*this);
      }

      std::string public_jwk() const
      {
        std::string r = "{";

        UqEVP_PKEY pk = X509_get0_pubkey(*this);
        auto base_id = EVP_PKEY_base_id(pk);
        switch (base_id)
        {
          case EVP_PKEY_RSA: {
            r += "\"kty\":\"RSA\",";
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
            UqEVP_PKEY_CTX ek_ctx(EVP_PKEY_RSA);
            auto n = pk.get_bn_param(OSSL_PKEY_PARAM_RSA_N);
            auto e = pk.get_bn_param(OSSL_PKEY_PARAM_RSA_E);
#else
            auto rsa = EVP_PKEY_get0_RSA(pk);
            const BIGNUM *n = NULL, *e = NULL, *d = NULL;
            RSA_get0_key(rsa, &n, &e, &d);
#endif
            auto n_len = BN_num_bytes(n);
            auto e_len = BN_num_bytes(e);
            std::vector<uint8_t> nv(n_len), ev(e_len);
            BN_bn2bin(n, nv.data());
            BN_bn2bin(e, ev.data());
            r += "\"n\":\"" + to_base64url(nv) + "\",";
            r += "\"e\":\"" + to_base64url(ev) + "\"";
            break;
          }
          case EVP_PKEY_EC: {
            r += "\"kty\":\"EC\",";
            r += "\"crv\":\"";
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
            BIGNUM *x = NULL, *y = NULL;
            EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &x);
            EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
            size_t gname_len = 0;
            CHECK1(EVP_PKEY_get_group_name(pk, NULL, 0, &gname_len));
            std::string gname(gname_len + 1, 0);
            CHECK1(EVP_PKEY_get_group_name(
              pk, (char*)gname.data(), gname.size(), &gname_len));
            gname.resize(gname_len);
            if (gname == SN_X9_62_prime256v1)
              r += "P-256";
            else if (gname == SN_secp384r1)
              r += "P-384";
            else if (gname == SN_secp521r1)
              r += "P-521";
            else
              throw std::runtime_error("unsupported EC key curve");
#else
            auto ec_key = EVP_PKEY_get0_EC_KEY(pk);
            const EC_GROUP* grp = EC_KEY_get0_group(ec_key);
            int curve_nid = EC_GROUP_get_curve_name(grp);
            const EC_POINT* pnt = EC_KEY_get0_public_key(ec_key);
            BIGNUM *x = BN_new(), *y = BN_new();
            CHECK1(EC_POINT_get_affine_coordinates(grp, pnt, x, y, NULL));
            if (curve_nid == NID_X9_62_prime256v1)
              r += "P-256";
            else if (curve_nid == NID_secp384r1)
              r += "P-384";
            else if (curve_nid == NID_secp521r1)
              r += "P-521";
            else
              throw std::runtime_error("unsupported EC key curve");
#endif
            r += "\",";
            auto x_len = BN_num_bytes(x);
            auto y_len = BN_num_bytes(y);
            std::vector<uint8_t> xv(x_len), yv(y_len);
            BN_bn2bin(x, xv.data());
            BN_bn2bin(y, yv.data());
            r += "\"x\":\"" + to_base64url(xv) + "\",";
            r += "\"y\":\"" + to_base64url(yv) + "\"";
            BN_free(x);
            BN_free(y);
            break;
          }
          default:
            throw std::runtime_error("unsupported key base id");
        }
        r += "}";
        return r;
      }
    };

    UqEVP_PKEY::UqEVP_PKEY(const UqX509& x509) :
      UqSSLOBJECT(X509_get_pubkey(x509), EVP_PKEY_free)
    {}

    UqEVP_PKEY::UqEVP_PKEY(const EVP_PKEY* key) :
      UqSSLOBJECT((EVP_PKEY*)key, EVP_PKEY_free)
    {
      EVP_PKEY_up_ref((EVP_PKEY*)key);
    }

    struct UqX509_NAME
      : public UqSSLOBJECT<X509_NAME, X509_NAME_new, X509_NAME_free>
    {
      UqX509_NAME(const UqX509& x509) :
        UqSSLOBJECT(X509_get_subject_name(x509), X509_NAME_free, true)
      {}
    };

    struct UqX509_NAME_ENTRY : public UqSSLOBJECT<
                                 X509_NAME_ENTRY,
                                 X509_NAME_ENTRY_new,
                                 X509_NAME_ENTRY_free>
    {
      UqX509_NAME_ENTRY(const UqX509_NAME& name, int i) :
        UqSSLOBJECT(X509_NAME_get_entry(name, i), X509_NAME_ENTRY_free, true)
      {}
    };

    inline bool UqX509::has_common_name(const std::string& expected_name) const
    {
      UqX509_NAME subject_name(*this);
      int cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
      while (cn_i != -1)
      {
        UqX509_NAME_ENTRY entry(subject_name, cn_i);
        ASN1_STRING* entry_string = X509_NAME_ENTRY_get_data(entry);
        std::string common_name = (char*)ASN1_STRING_get0_data(entry_string);
        if (common_name == expected_name)
          return true;
        cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, cn_i);
      }
      return false;
    }

    struct UqEVP_MD_CTX
      : public UqSSLOBJECT<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free>
    {
      void init(const EVP_MD* md)
      {
        md_size = EVP_MD_size(md);
        CHECK1(EVP_DigestInit_ex(p.get(), md, NULL));
      }

      void update(const std::vector<uint8_t>& message)
      {
        CHECK1(EVP_DigestUpdate(p.get(), message.data(), message.size()));
      }

      std::vector<uint8_t> final()
      {
        std::vector<uint8_t> r(md_size);
        unsigned sz = r.size();
        CHECK1(EVP_DigestFinal_ex(p.get(), r.data(), &sz));
        return r;
      }

    protected:
      size_t md_size;
    };

    struct UqX509_STORE_CTX : public UqSSLOBJECT<
                                X509_STORE_CTX,
                                X509_STORE_CTX_new,
                                X509_STORE_CTX_free>
    {};

    struct UqX509_STORE
      : public UqSSLOBJECT<X509_STORE, X509_STORE_new, X509_STORE_free>
    {
      void set_flags(int flags)
      {
        X509_STORE_set_flags(p.get(), flags);
      }

      void add(const UqX509& x509)
      {
        X509_STORE_add_cert(p.get(), x509);
      }

      void add(const std::string& pem)
      {
        add(UqX509(pem));
      }
    };

    struct UqSTACK_OF_X509
      : public UqSSLOBJECT<STACK_OF(X509), nullptr, nullptr>
    {
      UqSTACK_OF_X509() :
        UqSSLOBJECT(
          sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {}

      UqSTACK_OF_X509(const UqX509_STORE_CTX& ctx) :
        UqSSLOBJECT(X509_STORE_CTX_get1_chain(ctx), [](auto x) {
          sk_X509_pop_free(x, X509_free);
        })
      {}

      UqSTACK_OF_X509(UqSTACK_OF_X509&& other) :
        UqSSLOBJECT(other, [](auto x) { sk_X509_pop_free(x, X509_free); })
      {
        other.release();
      }

      UqSTACK_OF_X509(const std::string& pem) :
        UqSSLOBJECT(
          NULL, [](auto x) { sk_X509_pop_free(x, X509_free); }, false)
      {
        UqBIO mem(pem);
        STACK_OF(X509_INFO)* sk_info =
          PEM_X509_INFO_read_bio(mem, NULL, NULL, NULL);
        if (!sk_info)
          throw std::runtime_error("could not parse PEM chain");
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

      UqSTACK_OF_X509& operator=(UqSTACK_OF_X509&& other)
      {
        p.reset(other.p.release());
        return *this;
      }

      size_t size() const
      {
        int r = sk_X509_num(p.get());
        return r == (-1) ? 0 : r;
      }

      bool empty() const
      {
        return size() == 0;
      }

      UqX509 at(size_t i) const
      {
        if (i >= size())
          throw std::out_of_range("index into certificate stack too large");
        return sk_X509_value(p.get(), i);
      }

      void insert(size_t i, UqX509&& x)
      {
        X509_up_ref(x);
        CHECK0(sk_X509_insert(p.get(), x, i));
      }

      void push(UqX509&& x509)
      {
        sk_X509_push(p.get(), x509.release());
      }

      UqX509 front() const
      {
        return (*this).at(0);
      }

      UqX509 back() const
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

      UqSTACK_OF_X509 verify(
        const std::vector<UqX509>& roots,
        bool ignore_time = false,
        bool no_auth_key_id_ok = true)
      {
        if (size() <= 1)
          throw std::runtime_error("certificate chain too short");

        UqX509_STORE store;

        for (const auto& c : roots)
          CHECK1(X509_STORE_add_cert(store, back()));

        auto target = at(0);

        UqX509_STORE_CTX store_ctx;
        CHECK1(X509_STORE_CTX_init(store_ctx, store, target, *this));

        X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set_depth(param, INT_MAX);
        X509_VERIFY_PARAM_set_auth_level(param, 0);

        CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT));
        CHECK1(
          X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE));
        CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN));

        if (ignore_time)
          CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME));

        X509_STORE_CTX_set0_param(store_ctx, param);

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
        if (no_auth_key_id_ok)
        {
          X509_STORE_CTX_set_verify_cb(
            store_ctx, [](int ok, X509_STORE_CTX* store_ctx) {
              int ec = X509_STORE_CTX_get_error(store_ctx);
              if (ec == X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER)
                return 1;
              return ok;
            });
        }
#endif

        int rc = X509_verify_cert(store_ctx);

        if (rc == 1)
          return UqSTACK_OF_X509(store_ctx);
        else if (rc == 0)
        {
          int err_code = X509_STORE_CTX_get_error(store_ctx);
          int depth = X509_STORE_CTX_get_error_depth(store_ctx);
          const char* err_str = X509_verify_cert_error_string(err_code);
          throw std::runtime_error(
            std::string("certificate chain verification failed: ") + err_str +
            " (depth: " + std::to_string(depth) + ")");
          throw std::runtime_error("no chain or signature invalid");
        }
        else
        {
          auto msg = std::string(ERR_error_string(ERR_get_error(), NULL));
          throw std::runtime_error(std::string("OpenSSL error: ") + msg);
        }
      }
    };

    inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& message)
    {
      UqEVP_MD_CTX ctx;
      ctx.init(EVP_sha256());
      ctx.update(message);
      return ctx.final();
    }

    inline std::vector<uint8_t> sha384(const std::vector<uint8_t>& message)
    {
      UqEVP_MD_CTX ctx;
      ctx.init(EVP_sha384());
      ctx.update(message);
      return ctx.final();
    }

    inline std::vector<uint8_t> sha512(const std::vector<uint8_t>& message)
    {
      UqEVP_MD_CTX ctx;
      ctx.init(EVP_sha512());
      ctx.update(message);
      return ctx.final();
    }

    inline void check_fingerprint(
      const UqSTACK_OF_X509& chain,
      const std::string& fingerprint_alg,
      const std::string& fingerprint)
    {
      std::unordered_set<std::string> valid_fingerprints;

      for (size_t i = 1; i < chain.size(); i++)
      {
        const auto& cert = chain.at(i).der();

        std::vector<uint8_t> hash;
        if (fingerprint_alg == "sha256")
          hash = sha256(cert);
        else if (fingerprint_alg == "sha384")
          hash = sha384(cert);
        else if (fingerprint_alg == "sha512")
          hash = sha512(cert);
        else
          throw std::runtime_error("unsupported fingerprint algorithm");

        auto b64 = to_base64url(hash);
        if (fingerprint == b64)
          return;
      }

      throw std::runtime_error("invalid certificate fingerprint");
    }

    inline bool is_hex_digit(char digit)
    {
      return (digit >= 0x30 && digit <= 0x39) ||
        (digit >= 0x41 && digit <= 0x46) || (digit >= 0x61 && digit <= 0x66);
    }

    // Adapted from curl:
    // https://github.com/curl/curl/blob/e335d778e3eaa41ebbe209e9b8110e8a0d9a72f3/lib/escape.c#L134
    inline std::string url_unescape(const std::string& is)
    {
      std::string r;

      const char* string = is.data();
      for (size_t i = 0; i < is.size(); i++)
      {
        if (
          is[i] == '%' && i + 2 < is.size() && is_hex_digit(is[i + 1]) &&
          is_hex_digit(is[i + 2]))
        {
          /* this is two hexadecimal digits following a '%' */
          char hexstr[3], *ptr;
          hexstr[0] = is[i + 1];
          hexstr[1] = is[i + 2];
          hexstr[2] = 0;
          char c = (char)strtoul(hexstr, &ptr, 16);
          r.push_back(c);
          i += 2;
        }
        else
          r.push_back(is[i]);
      }

      return r;
    }

    inline std::vector<std::string> url_unescape(
      const std::vector<std::string>& urls)
    {
      std::vector<std::string> r;
      r.reserve(urls.size());
      for (const auto& url : urls)
        r.push_back(url_unescape(url));
      return r;
    }

    inline std::vector<std::string> split(
      const std::string& s, const std::string& delimiter)
    {
      std::vector<std::string> r;
      size_t start = 0, end = 0;

      do
      {
        end = s.find(delimiter, start);
        r.push_back(s.substr(start, end - start));
        start = end + delimiter.size();
      } while (end != std::string::npos);

      return r;
    }

    inline void verify(const UqSTACK_OF_X509& chain, const std::string& did)
    {
      auto top_tokens = split(did, "::");

      if (top_tokens.size() <= 1)
        throw std::runtime_error("invalid DID string");

      // Check prefix
      auto prefix = top_tokens[0];
      auto pretokens = split(prefix, ":");

      if (
        pretokens.size() < 5 || pretokens[0] != "did" || pretokens[1] != "x509")
        throw std::runtime_error("unsupported method/prefix");

      if (pretokens[2] != "0")
        throw std::runtime_error("unsupported did:x509 version");

      // Check fingerprint
      const auto& ca_fingerprint_alg = pretokens[3];
      const auto& ca_fingerprint = pretokens[4];

      check_fingerprint(chain, ca_fingerprint_alg, ca_fingerprint);

      // Check policies
      for (size_t i = 1; i < top_tokens.size(); i++)
      {
        const auto& policy = top_tokens[i];
        auto parts = split(policy, ":");

        if (parts.size() < 2)
          throw std::runtime_error("invalid policy");

        auto policy_name = parts[0];
        auto args = std::vector<std::string>(parts.begin() + 1, parts.end());

        if (policy_name == "subject")
        {
          if (args.size() % 2 != 0)
            throw std::runtime_error("key-value pairs required");

          if (args.size() < 2)
            throw std::runtime_error("at least one key-value pair is required");

          std::unordered_set<std::string> seen_fields;
          for (size_t i = 0; i < args.size(); i += 2)
          {
            const auto& k = args[i];
            const auto& v = url_unescape(args[i + 1]);

            if (seen_fields.find(k) != seen_fields.end())
              throw std::runtime_error(
                std::string("duplicate field '") + k + "'");
            seen_fields.insert(k);

            const auto& lc = chain.at(0);
            auto subject = lc.subject();

            auto sit = subject.find(k);
            if (sit == subject.end())
              throw std::runtime_error(
                std::string("unsupported subject key: '") + k + "'");

            bool found = false;
            for (const auto& fv : sit->second)
            {
              if (fv.find(v) != std::string::npos)
              {
                found = true;
                break;
              }
            }
            if (!found)
              throw std::runtime_error(
                std::string("invalid subject key/value: " + k + "=" + v));
          }
        }
        else if (policy_name == "san")
        {
          if (args.size() != 2)
            throw std::runtime_error("exactly one SAN type and value required");

          auto san_type = args[0];
          auto san_value = url_unescape(args[1]);

          if (!chain.at(0).has_san(san_type, san_value))
            throw std::runtime_error(
              std::string("SAN not found: ") + san_value);
        }
        else if (policy_name == "eku")
        {
          if (args.size() != 1)
            throw std::runtime_error("exactly one EKU required");

          UqASN1_OBJECT oid(args[0]);

          bool found_eku = false;
          auto eku_exts = chain.at(0).extended_key_usage();
          for (size_t i = 0; i < eku_exts.size() && !found_eku; i++)
          {
            const auto& eku_ext_i = eku_exts.at(i);
            for (size_t j = 0; j < eku_ext_i.size() && !found_eku; j++)
              if (eku_ext_i.at(j) == oid)
                found_eku = true;
          }
          if (!found_eku)
            throw std::runtime_error(std::string("EKU not found: ") + args[0]);
        }
        else if (policy_name == "fulcio-issuer")
        {
          if (args.size() != 1)
            throw std::runtime_error("excessive arguments to fulcio-issuer");

          const std::string fulcio_oid("1.3.6.1.4.1.57264.1.1");
          auto decoded_arg = url_unescape(args[0]);
          auto fulcio_issuer = "https://" + decoded_arg;

          bool found = false;
          auto exts = chain.at(0).extensions<UqX509_EXTENSION>(fulcio_oid);
          for (const auto& ext : exts)
          {
            if ((std::string)ext.data() == fulcio_issuer)
            {
              found = true;
              break;
            }
          }
          if (!found)
            throw std::runtime_error(
              std::string("invalid fulcio-issuer: ") + fulcio_issuer);
        }
        else
          throw std::runtime_error(
            std::string("unsupported did:x509 scheme '") + policy_name + "'");
      }
    }

    inline std::string create_did_document(
      const std::string& did, const UqSTACK_OF_X509& chain)
    {
      std::string format = R"({
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "_DID_",
    "verificationMethod": [{
        "id": "_DID_#key-1",
        "type": "JsonWebKey2020",
        "controller": "_DID_",
        "publicKeyJwk": _LEAF_JWK_
    }]
    _ASSERTION_METHOD_
    _KEY_AGREEMENT_
})";

      const auto& leaf = chain.front();
      bool include_assertion_method =
        !leaf.has_key_usage() || leaf.has_key_usage_digital_signature();
      bool include_key_agreement =
        !leaf.has_key_usage() || leaf.has_key_usage_key_agreement();
      if (!include_assertion_method && !include_key_agreement)
        throw std::runtime_error(
          "leaf certificate key usage must include digital signature or key "
          "agreement");

      std::string am, ka;
      if (include_assertion_method)
        am = ",\"assertionMethod\": \"" + did + "#key-1\"";
      if (include_key_agreement)
        ka = ",\"keyAgreement\": \"" + did + "#key-1\"";

      const auto& leaf_jwk = leaf.public_jwk();

      auto t = std::regex_replace(format, std::regex("_DID_"), did);
      t = std::regex_replace(t, std::regex("_ASSERTION_METHOD_"), am);
      t = std::regex_replace(t, std::regex("_KEY_AGREEMENT_"), ka);
      t = std::regex_replace(t, std::regex("_LEAF_JWK_"), leaf_jwk);

      return t;
    }
  }

  inline std::string resolve(
    const std::string& chain_pem,
    const std::string& did,
    bool ignore_time = false)
  {
    UqSTACK_OF_X509 chain(chain_pem);

    if (chain.empty())
      throw std::runtime_error("no certificate chain");

    // The last certificate in the chain is assumed to be the trusted root.
    UqX509 root = chain.back();

    std::vector<UqX509> roots;
    roots.emplace_back(std::move(root));

    const auto& valid_chain = chain.verify(roots, ignore_time);

    verify(valid_chain, did);

    return create_did_document(did, valid_chain);
  }
}