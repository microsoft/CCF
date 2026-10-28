// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/csr.h"

#include "ccf/ds/nonstd.h"
#include "crypto/openssl/x509_time.h"

#define FMT_HEADER_ONLY
#include <array>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <map>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>

namespace ccf::crypto::OpenSSL
{
  namespace
  {
    using Unique_ASN1_INTEGER =
      Unique_SSL_OBJECT<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>;
    using Unique_X509_EXTENSION = Unique_SSL_OBJECT<
      X509_EXTENSION,
      X509_EXTENSION_new,
      X509_EXTENSION_free>;

    std::map<std::string, std::string> parse_name(const std::string& name)
    {
      std::map<std::string, std::string> result;
      for (const auto& part : ccf::nonstd::split(name, ","))
      {
        const auto [field, value] = ccf::nonstd::split_1(part, "=");
        result.emplace(std::string(field), std::string(value));
      }
      return result;
    }

    void add_extension(X509* crt, X509V3_CTX* ctx, int nid, const char* value)
    {
      const Unique_X509_EXTENSION ext(
        X509V3_EXT_conf_nid(nullptr, ctx, nid, value), X509_EXTENSION_free);
      CHECK1(X509_add_ext(crt, ext, -1));
    }
  }

  Unique_X509_NAME subject_name_from_string(const std::string& name)
  {
    Unique_X509_NAME subject_name;
    for (const auto& [field, value] : parse_name(name))
    {
      CHECK1(X509_NAME_add_entry_by_txt(
        subject_name,
        field.c_str(),
        MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()),
        -1,
        0));
    }
    return subject_name;
  }

  Unique_X509_NAME subject_name_from_der(const std::vector<uint8_t>& der)
  {
    const unsigned char* p = der.data();
    Unique_X509_NAME subject_name(
      d2i_X509_NAME(nullptr, &p, static_cast<long>(der.size())),
      X509_NAME_free,
      /*check_null=*/false);
    if (subject_name == nullptr)
    {
      throw std::invalid_argument(fmt::format(
        "Subject name is not a DER-encoded X.501 Name: {}", first_error()));
    }
    if (p != der.data() + der.size())
    {
      throw std::invalid_argument(
        "Subject name has trailing bytes after the DER-encoded X.501 Name");
    }
    return subject_name;
  }

  Pem csr_to_pem(X509_REQ* req)
  {
    Unique_BIO mem;
    CHECK1(PEM_write_bio_X509_REQ(mem, req));
    return Pem(bio_contents(mem));
  }

  Unique_X509_REQ make_csr(
    EVP_PKEY* signing_key,
    const EVP_MD* md,
    const X509_NAME* subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key)
  {
    Unique_X509_REQ req;

    if (public_key.has_value())
    {
      Unique_BIO mem(*public_key);
      Unique_PKEY pubkey(mem);
      CHECK1(X509_REQ_set_pubkey(req, pubkey));
    }
    else
    {
      CHECK1(X509_REQ_set_pubkey(req, signing_key));
    }

    CHECK1(X509_REQ_set_subject_name(req, subject_name));

    if (!subject_alt_names.empty())
    {
      Unique_STACK_OF_X509_EXTENSIONS exts;
      X509_EXTENSION* ext = nullptr;
      CHECKNULL(
        ext = X509V3_EXT_conf_nid(
          nullptr,
          nullptr,
          NID_subject_alt_name,
          fmt::format("{}", fmt::join(subject_alt_names, ", ")).c_str()));
      CHECKPOSITIVE(sk_X509_EXTENSION_push(exts, ext));
      CHECK1(X509_REQ_add_extensions(req, exts));
    }

    CHECKPOSITIVE(X509_REQ_sign(req, signing_key, md));
    return req;
  }

  Pem sign_csr(
    EVP_PKEY* signing_key,
    const EVP_MD* md,
    const std::optional<Pem>& issuer_cert,
    const Pem& signing_request,
    const std::string& valid_from,
    const std::string& valid_to,
    bool ca,
    CSRSigner signer)
  {
    Unique_BIO mem(signing_request);
    Unique_X509_REQ csr(mem);
    EVP_PKEY* req_pubkey = X509_REQ_get0_pubkey(csr);
    CHECKNULL(req_pubkey);

    if (signer == CSRSigner::SUBJECT)
    {
      CHECK1(X509_REQ_verify(csr, req_pubkey));
    }

    Unique_X509 crt;
    CHECK1(X509_set_version(crt, X509_VERSION_3));

    constexpr size_t SERIAL_NUMBER_SIZE = 16;
    std::array<unsigned char, SERIAL_NUMBER_SIZE> serial_bytes{};
    CHECK1(
      RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())));
    Unique_BIGNUM bn;
    CHECKNULL(BN_bin2bn(
      serial_bytes.data(), static_cast<int>(serial_bytes.size()), bn));
    Unique_ASN1_INTEGER serial;
    CHECKNULL(BN_to_ASN1_INTEGER(bn, serial));
    CHECK1(X509_set_serialNumber(crt, serial));

    std::optional<Unique_X509> icrt;
    if (issuer_cert.has_value())
    {
      Unique_BIO imem(*issuer_cert);
      icrt.emplace(
        PEM_read_bio_X509(imem, nullptr, nullptr, nullptr),
        /*check_null=*/true);
      CHECK1(X509_set_issuer_name(crt, X509_get_subject_name(*icrt)));

      if (signer == CSRSigner::ISSUER)
      {
        CHECK1(X509_REQ_verify(csr, X509_get0_pubkey(*icrt)));
      }
    }
    else
    {
      if (signer == CSRSigner::ISSUER)
      {
        throw std::logic_error(
          "A self-signed certificate request must be signed by its subject");
      }
      CHECK1(X509_set_issuer_name(crt, X509_REQ_get_subject_name(csr)));
    }

    Unique_X509_TIME not_before(valid_from);
    Unique_X509_TIME not_after(valid_to);
    if (!validate_chronological_times(not_before, not_after))
    {
      throw std::logic_error(fmt::format(
        "Certificate cannot be created with not_before date {} > not_after "
        "date {}",
        to_x509_time_string(not_before),
        to_x509_time_string(not_after)));
    }
    CHECK1(X509_set1_notBefore(crt, not_before));
    CHECK1(X509_set1_notAfter(crt, not_after));

    CHECK1(X509_set_subject_name(crt, X509_REQ_get_subject_name(csr)));
    CHECK1(X509_set_pubkey(crt, req_pubkey));

    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(
      &v3ctx, icrt.has_value() ? *icrt : crt, nullptr, csr, nullptr, 0);

    // pathlen 1 allows intermediate CAs with a different subject name, which
    // occur in service endorsements of some services.
    add_extension(
      crt,
      &v3ctx,
      NID_basic_constraints,
      ca ? "critical,CA:TRUE,pathlen:1" : "critical,CA:FALSE");
    if (ca)
    {
      add_extension(
        crt, &v3ctx, NID_key_usage, "critical, keyCertSign, digitalSignature");
    }
    // The authority key identifier copies the issuer's subject key
    // identifier, which for a self-signed certificate is the one just added.
    add_extension(crt, &v3ctx, NID_subject_key_identifier, "hash");
    add_extension(crt, &v3ctx, NID_authority_key_identifier, "keyid:always");

    Unique_STACK_OF_X509_EXTENSIONS exts(X509_REQ_get_extensions(csr));
    const int extension_count = sk_X509_EXTENSION_num(exts);
    for (int i = 0; i < extension_count; i++)
    {
      X509_EXTENSION* csr_ext = sk_X509_EXTENSION_value(exts, i);
      if (
        OBJ_obj2nid(X509_EXTENSION_get_object(csr_ext)) == NID_subject_alt_name)
      {
        CHECK1(X509_add_ext(crt, csr_ext, -1));
      }
    }

    CHECKPOSITIVE(X509_sign(crt, signing_key, md));

    Unique_BIO out;
    CHECK1(PEM_write_bio_X509(out, crt));
    const auto data = bio_contents(out);
    return {data.data(), data.size()};
  }
}
