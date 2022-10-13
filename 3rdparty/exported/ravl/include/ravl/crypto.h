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

#ifdef RAVL_HAVE_OPENSSL
#  include "crypto_openssl.h"
#else
#  error No crypto library available.
#endif

namespace ravl
{
  namespace crypto
  {
    using Unique_STACK_OF_X509 = OpenSSL::Unique_STACK_OF_X509;
    using Unique_BIO = OpenSSL::Unique_BIO;
    using Unique_X509 = OpenSSL::Unique_X509;
    using Unique_X509_STORE = OpenSSL::Unique_X509_STORE;
    using Unique_X509_CRL = OpenSSL::Unique_X509_CRL;
    using Unique_EVP_PKEY = OpenSSL::Unique_EVP_PKEY;
    using Unique_EVP_MD_CTX = OpenSSL::Unique_EVP_MD_CTX;
    using Unique_ASN1_SEQUENCE = OpenSSL::Unique_ASN1_SEQUENCE;
    using Unique_EVP_PKEY_P256 = OpenSSL::Unique_EVP_PKEY_P256;
    using Unique_EVP_PKEY_CTX = OpenSSL::Unique_EVP_PKEY_CTX;
    using Unique_ASN1_OCTET_STRING = OpenSSL::Unique_ASN1_OCTET_STRING;

    inline std::string to_base64(const std::span<const uint8_t>& bytes)
    {
      return OpenSSL::to_base64(bytes);
    }

    inline std::vector<uint8_t> from_base64(const std::string& b64)
    {
      return OpenSSL::from_base64(b64);
    }

    inline std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& r,
      const std::span<const uint8_t>& s,
      bool little_endian = false)
    {
      return OpenSSL::convert_signature_to_der(r, s, little_endian);
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
        if (verbosity > 0)
          log(fmt::format("- failed: {}", ex.what()), indent);
        throw std::runtime_error(ex.what());
      }
      catch (...)
      {
        if (verbosity > 0)
          log(fmt::format("- failed: unknown exception"), indent);
        throw std::runtime_error("unknown exception");
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

    inline std::vector<uint8_t> sha256(const std::span<const uint8_t>& message)
    {
      return OpenSSL::sha256(message);
    }

    inline std::vector<uint8_t> sha384(const std::span<const uint8_t>& message)
    {
      return OpenSSL::sha384(message);
    }

    inline std::vector<uint8_t> sha512(const std::span<const uint8_t>& message)
    {
      return OpenSSL::sha512(message);
    }

    inline bool verify_certificate(
      const Unique_X509_STORE& store,
      const Unique_X509& certificate,
      const CertificateValidationOptions& options)
    {
      return OpenSSL::verify_certificate(store, certificate, options);
    }

    inline Unique_STACK_OF_X509 verify_certificate_chain(
      const Unique_X509_STORE& store,
      const Unique_STACK_OF_X509& stack,
      const CertificateValidationOptions& options,
      bool trusted_root = false)
    {
      return OpenSSL::verify_certificate_chain(
        store, stack, options, trusted_root);
    }
  }
}
