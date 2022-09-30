// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "crypto_options.h"
#include "util.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#ifdef HAVE_OPENSSL
#  include "crypto_openssl.h"
#else
#  error No crypto library available.
#endif

namespace ravl
{
  namespace crypto
  {
#ifdef HAVE_OPENSSL
    using namespace OpenSSL;
#endif

    inline std::string to_base64(const std::span<const uint8_t>& bytes)
    {
      Unique_BIO bio_chain((Unique_BIO(BIO_f_base64())), Unique_BIO());

      BIO_set_flags(bio_chain, BIO_FLAGS_BASE64_NO_NL);
      BIO_set_close(bio_chain, BIO_CLOSE);
      int n = BIO_write(bio_chain, bytes.data(), bytes.size());
      BIO_flush(bio_chain);

      if (n < 0)
        throw std::runtime_error("base64 encoding error");

      return bio_chain.to_string();
    }

    inline std::vector<uint8_t> from_base64(const std::string& b64)
    {
      Unique_BIO bio_chain((Unique_BIO(BIO_f_base64())), Unique_BIO(b64));

      std::vector<uint8_t> out(b64.size());
      BIO_set_flags(bio_chain, BIO_FLAGS_BASE64_NO_NL);
      BIO_set_close(bio_chain, BIO_CLOSE);
      int n = BIO_read(bio_chain, out.data(), b64.size());

      if (n < 0)
        throw std::runtime_error("base64 decoding error");

      out.resize(n);

      return out;
    }

    inline std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& r,
      const std::span<const uint8_t>& s,
      bool little_endian = false)
    {
      if (r.size() != s.size())
        throw std::runtime_error("incompatible signature coordinates");

      Unique_ECDSA_SIG sig;
      {
        Unique_BIGNUM r_bn;
        Unique_BIGNUM s_bn;
        if (little_endian)
        {
          CHECKNULL(BN_lebin2bn(r.data(), r.size(), r_bn));
          CHECKNULL(BN_lebin2bn(s.data(), s.size(), s_bn));
        }
        else
        {
          CHECKNULL(BN_bin2bn(r.data(), r.size(), r_bn));
          CHECKNULL(BN_bin2bn(s.data(), s.size(), s_bn));
        }
        CHECK1(ECDSA_SIG_set0(sig, r_bn, s_bn));
        r_bn.release(); // r, s now owned by the signature object
        s_bn.release();
      }
      int der_size = i2d_ECDSA_SIG(sig, NULL);
      CHECK0(der_size);
      if (der_size < 0)
        throw std::runtime_error("not an ECDSA signature");
      std::vector<uint8_t> res(der_size);
      auto der_sig_buf = res.data();
      CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
      return res;
    }

    inline std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& signature, bool little_endian = false)
    {
      auto half_size = signature.size() / 2;
      return convert_signature_to_der(
        {signature.data(), half_size},
        {signature.data() + half_size, half_size},
        little_endian);
    }

    inline std::string_view extract_pem_certificate(std::string_view& data)
    {
      static std::string begin = "-----BEGIN CERTIFICATE-----";
      static std::string end = "-----END CERTIFICATE-----";

      if (data.empty())
        return "";
      size_t from = data.find(begin);
      if (from == std::string::npos)
      {
        data.remove_prefix(data.size());
        return "";
      }
      size_t to = data.find(end, from + begin.size());
      if (to == std::string::npos)
      {
        data.remove_prefix(data.size());
        return "";
      }
      to += end.size();
      auto pem = data.substr(from, to - from);
      from = data.find(begin, to);
      data.remove_prefix(from == std::string::npos ? data.size() : from);
      return pem;
    }

    inline std::string_view extract_pem_certificate(
      const std::span<const uint8_t>& data)
    {
      std::string_view sv((char*)data.data(), data.size());
      return extract_pem_certificate(sv);
    }

    inline std::vector<std::string> extract_pem_certificates(
      const std::span<const uint8_t>& data)
    {
      std::vector<std::string> r;
      std::string_view sv((char*)data.data(), data.size());

      while (!sv.empty())
      {
        auto pem = extract_pem_certificate(sv);
        if (!pem.empty())
          r.push_back(std::string(pem));
      }

      return r;
    }

    inline bool verify_certificate(
      const Unique_X509_STORE& store,
      const Unique_X509& certificate,
      const CertificateValidationOptions& options)
    {
      Unique_X509_STORE_CTX store_ctx;
      CHECK1(X509_STORE_CTX_init(store_ctx, store, certificate, NULL));

      X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
      X509_VERIFY_PARAM_set_depth(param, INT_MAX);
      X509_VERIFY_PARAM_set_auth_level(param, 0);

      CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT));
      CHECK1(
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE));

      if (options.ignore_time)
      {
        CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME));
      }

      if (options.verification_time)
      {
        X509_STORE_CTX_set_time(store_ctx, 0, *options.verification_time);
      }

      X509_STORE_CTX_set0_param(store_ctx, param);

      int rc = X509_verify_cert(store_ctx);

      if (rc == 1)
        return true;
      else if (rc == 0)
        throw std::runtime_error(
          "certificate not self-signed or signature invalid");
      else
      {
        unsigned long openssl_err = ERR_get_error();
        char buf[4096];
        ERR_error_string(openssl_err, buf);
        throw std::runtime_error(fmt::format("OpenSSL error: {}", buf));
      }
    }

    inline Unique_STACK_OF_X509 verify_certificate_chain(
      const Unique_X509_STORE& store,
      const Unique_STACK_OF_X509& stack,
      const CertificateValidationOptions& options,
      bool trusted_root = false)
    {
      if (stack.size() <= 1)
        throw std::runtime_error("certificate stack too small");

      if (trusted_root)
        CHECK1(X509_STORE_add_cert(store, stack.back()));

      auto target = stack.at(0);

      Unique_X509_STORE_CTX store_ctx;
      CHECK1(X509_STORE_CTX_init(store_ctx, store, target, stack));

      X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
      X509_VERIFY_PARAM_set_depth(param, INT_MAX);
      X509_VERIFY_PARAM_set_auth_level(param, 0);

      CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT));
      CHECK1(
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CHECK_SS_SIGNATURE));

      if (options.ignore_time)
      {
        CHECK1(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME));
      }

      if (options.verification_time)
      {
        X509_STORE_CTX_set_time(store_ctx, 0, *options.verification_time);
      }

      X509_STORE_CTX_set0_param(store_ctx, param);

      int rc = X509_verify_cert(store_ctx);

      if (rc == 1)
        return Unique_STACK_OF_X509(store_ctx);
      else if (rc == 0)
        throw std::runtime_error("no chain or signature invalid");
      else
      {
        unsigned long openssl_err = ERR_get_error();
        char buf[4096];
        ERR_error_string(openssl_err, buf);
        throw std::runtime_error(fmt::format("OpenSSL error: {}", buf));
      }
    }

    inline Unique_STACK_OF_X509 load_certificates(
      const std::vector<std::string>& certificates)
    {
      // Leaf tracking/searching may be unnecessary as the chains should
      // be in order anyways.

      Unique_STACK_OF_X509 r;
      X509* leaf = NULL;

      for (const auto& cert : certificates)
      {
        Unique_BIO cert_bio(cert.data(), cert.size());
        Unique_X509 x509(cert_bio, true);

        if (!x509.is_ca())
        {
          if (leaf)
            throw std::runtime_error("multiple leaves in certificate set");

          leaf = x509;
        }

        r.push(std::move(x509));
      }

      if (!leaf)
      {
        // Some chains, e.g. pck_crl_issuer_chain, contain only CAs, so
        // the leaf isn't easy to detect, so we look for the certificate
        // that isn't used as an authority.
        for (size_t ii = 0; ii < r.size(); ii++)
        {
          const auto& i = r.at(ii);
          Unique_ASN1_OCTET_STRING subj_key_id(X509_get0_subject_key_id(i));

          bool i_appears_as_ca = false;
          for (size_t ji = 0; ji < r.size(); ji++)
          {
            if (ii == ji)
              continue;

            const auto& j = r.at(ji);

            if (j.has_authority_key_id())
            {
              Unique_ASN1_OCTET_STRING auth_key_id(
                X509_get0_authority_key_id(j));

              if (subj_key_id == auth_key_id)
              {
                i_appears_as_ca = true;
                break;
              }
            }
          }

          if (!i_appears_as_ca)
          {
            if (leaf)
              throw std::runtime_error("multiple leaves in certificate set");

            leaf = i;
          }
        }
      }

      if (!leaf)
        throw std::runtime_error("no leaf certificate found");

      if (r.at(0) != leaf)
        throw std::runtime_error(
          "leaf certificate not at the front of the certificate chain");

      return r;
    }

    inline Unique_STACK_OF_X509 verify_certificate_chain(
      const Unique_STACK_OF_X509& stack,
      const Unique_X509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      if (verbosity > 0)
      {
        for (size_t i = 0; i < stack.size(); i++)
        {
          auto c = stack.at(i);
          log(c.to_string_short(indent));
          if (verbosity > 1)
          {
            log(std::string(indent + 2, ' ') + "- PEM:");
            auto s = c.pem();
            log(indentate(s, indent + 4));
          }
        }
      }

      try
      {
        auto chain =
          verify_certificate_chain(store, stack, options, trusted_root);

        if (chain.size() < 2)
          throw std::runtime_error("certificate chain is too short");

        if (verbosity > 0)
          log("- certificate chain verification successful", indent);

        return chain;
      }
      catch (std::exception& ex)
      {
        log(fmt::format("- verification failed: {}", ex.what()), indent);
        throw std::runtime_error("certificate chain verification failed");
      }
      catch (...)
      {
        log("- verification failed with unknown exception", indent);
        throw std::runtime_error("certificate chain verification failed");
      }
    }

    inline Unique_STACK_OF_X509 verify_certificate_chain(
      const std::span<const uint8_t> data,
      const Unique_X509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      std::vector<std::string> certificates = extract_pem_certificates(data);
      auto stack = load_certificates(certificates);
      return verify_certificate_chain(
        stack, store, options, trusted_root, verbosity, indent);
    }

    inline Unique_STACK_OF_X509 verify_certificate_chain(
      const std::string& pem,
      const Unique_X509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      std::span<const uint8_t> span((uint8_t*)pem.data(), pem.size());
      return verify_certificate_chain(
        span, store, options, trusted_root, verbosity, indent);
    }
  }
}