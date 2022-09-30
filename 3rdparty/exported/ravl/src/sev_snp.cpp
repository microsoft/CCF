// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/sev_snp.h"

#include "ravl/crypto.h"
#include "ravl/crypto_openssl.h"
#include "ravl/http_client.h"
#include "ravl/ravl.h"

#include <stdexcept>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace ravl::crypto;

namespace ravl
{
  namespace sev_snp
  {
    // Based on the SEV-SNP ABI Spec document at
    // https://www.amd.com/system/files/TechDocs/56860.pdf

    // ARK = AMD Root Key
    // ASK = AMD SEV Signing Key (intermediate)
    // VCEK = Versioned Chip Endorsement Key (VCEK) (leaf)

    static const std::string kds_url = "https://kdsintf.amd.com";

    static constexpr size_t attestation_report_data_size = 64;
    using attestation_report_data =
      std::array<uint8_t, attestation_report_data_size>;
    static constexpr size_t attestation_measurement_size = 48;
    using attestation_measurement =
      std::array<uint8_t, attestation_measurement_size>;

    namespace snp
    {

      // From https://developer.amd.com/sev/
      static const std::string amd_milan_root_signing_public_key =
        R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----
)";

      // Table 3
#pragma pack(push, 1)
      struct TcbVersion
      {
        uint8_t boot_loader;
        uint8_t tee;
        uint8_t reserved[4];
        uint8_t snp;
        uint8_t microcode;
      };
#pragma pack(pop)
      static_assert(
        sizeof(TcbVersion) == sizeof(uint64_t),
        "Can't cast TcbVersion to uint64_t");

#pragma pack(push, 1)
      struct Signature
      {
        uint8_t r[72];
        uint8_t s[72];
        uint8_t reserved[512 - 144];
      };
#pragma pack(pop)

      // Table. 105
      enum class SignatureAlgorithm : uint32_t
      {
        invalid = 0,
        ecdsa_p384_sha384 = 1
      };

#pragma pack(push, 1)
      // Table 21
      struct Attestation
      {
        uint32_t version; /* 0x000 */
        uint32_t guest_svn; /* 0x004 */
        uint64_t policy; /* 0x008 */
        uint8_t family_id[16]; /* 0x010 */
        uint8_t image_id[16]; /* 0x020 */
        uint32_t vmpl; /* 0x030 */
        SignatureAlgorithm signature_algo; /* 0x034 */
        struct TcbVersion platform_version; /* 0x038 */
        uint64_t platform_info; /* 0x040 */
        uint32_t flags; /* 0x048 */
        uint32_t reserved0; /* 0x04C */
        uint8_t report_data[attestation_report_data_size]; /* 0x050 */
        uint8_t measurement[attestation_measurement_size]; /* 0x090 */
        uint8_t host_data[32]; /* 0x0C0 */
        uint8_t id_key_digest[48]; /* 0x0E0 */
        uint8_t author_key_digest[48]; /* 0x110 */
        uint8_t report_id[32]; /* 0x140 */
        uint8_t report_id_ma[32]; /* 0x160 */
        struct TcbVersion reported_tcb; /* 0x180 */
        uint8_t reserved1[24]; /* 0x188 */
        uint8_t chip_id[64]; /* 0x1A0 */
        struct TcbVersion committed_tcb; /* 0x1E0 */
        uint8_t current_minor; /* 0x1E8 */
        uint8_t current_build; /* 0x1E9 */
        uint8_t current_major; /* 0x1EA */
        uint8_t reserved2; /* 0x1EB */
        uint8_t committed_build; /* 0x1EC */
        uint8_t committed_minor; /* 0x1ED */
        uint8_t committed_major; /* 0x1EE */
        uint8_t reserved3; /* 0x1EF */
        struct TcbVersion launch_tcb; /* 0x1F0 */
        uint8_t reserved4[168]; /* 0x1F8 */
        struct Signature signature; /* 0x2A0 */
      };
#pragma pack(pop)

      // Table 20
      struct AttestationReq
      {
        uint8_t report_data[attestation_report_data_size];
        uint32_t vmpl;
        uint8_t reserved[28];
      };

      // Table 23
#pragma pack(push, 1)
      struct AttestationResp
      {
        uint32_t status;
        uint32_t report_size;
        uint8_t reserved[0x20 - 0x8];
        struct Attestation report;
        uint8_t padding[64];
        // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
      };
#pragma pack(pop)

      struct GuestRequest
      {
        uint8_t req_msg_type;
        uint8_t rsp_msg_type;
        uint8_t msg_version;
        uint16_t request_len;
        uint64_t request_uaddr;
        uint16_t response_len;
        uint64_t response_uaddr;
        uint32_t error; /* firmware error code on failure (see psp-sev.h) */
      };

      // Table 99
      enum MsgType
      {
        MSG_TYPE_INVALID = 0,
        MSG_CPUID_REQ,
        MSG_CPUID_RSP,
        MSG_KEY_REQ,
        MSG_KEY_RSP,
        MSG_REPORT_REQ,
        MSG_REPORT_RSP,
        MSG_EXPORT_REQ,
        MSG_EXPORT_RSP,
        MSG_IMPORT_REQ,
        MSG_IMPORT_RSP,
        MSG_ABSORB_REQ,
        MSG_ABSORB_RSP,
        MSG_VMRK_REQ,
        MSG_VMRK_RSP,
        MSG_TYPE_MAX
      };
    }

#define SEV_GUEST_IOC_TYPE 'S'
#define SEV_SNP_GUEST_MSG_REPORT \
  _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct snp::GuestRequest)

    Unique_X509 parse_root_cert(
      const std::vector<HTTPResponse>& url_response_set)
    {
      if (url_response_set.size() != 1)
        throw std::runtime_error("collateral download request set failed");
      auto issuer_chain = url_response_set[0].body;
      Unique_STACK_OF_X509 stack(issuer_chain);
      if (stack.size() != 2)
        throw std::runtime_error("unexpected size of issuer certificate chain");
      return stack.at(1).pem();
    }

    HTTPRequests download_root_ca_pem(const std::string& product_name)
    {
      std::string r;

      HTTPRequests requests;

      auto vcek_issuer_chain_url =
        fmt::format("{}/vcek/v1/{}/cert_chain", kds_url, product_name);

      requests.emplace_back(vcek_issuer_chain_url);

      return requests;
    }

    struct EndorsementsEtc
    {
      std::optional<Unique_X509> root_ca_certificate;
      Unique_STACK_OF_X509 vcek_certificate_chain;
      std::optional<Unique_X509_CRL> vcek_issuer_chain_crl;

      std::string to_string(uint32_t verbosity, size_t indent = 0) const
      {
        std::stringstream ss;
        ss << std::string(indent + 2, ' ') << "- Endorsements" << std::endl;

        std::string ins(indent + 4, ' ');
        const Unique_STACK_OF_X509& st = vcek_certificate_chain;
        ss << ins << "- VCEK certificate chain:" << std::endl;
        ss << st.to_string_short(indent + 4) << std::endl;

        if (verbosity > 1)
          ss << ins << "  - PEM:" << std::endl
             << indentate(st.pem(), 8) << std::endl;

        ss << ins << "- VCEK issuer CRL: ";
        if (!vcek_issuer_chain_crl)
          ss << "none";
        else
        {
          const Unique_X509_CRL& vcek_issuer_crl = *vcek_issuer_chain_crl;
          ss << std::endl << vcek_issuer_crl.to_string_short(indent + 6);
          if (verbosity > 1)
            ss << std::endl
               << ins << "  - PEM:" << std::endl
               << indentate(vcek_issuer_crl.pem(), 8);
        }
        return ss.str();
      }
    };

    static EndorsementsEtc parse_url_responses(
      const Options& options, const std::vector<HTTPResponse>& url_response_set)
    {
      EndorsementsEtc r;

      if (options.root_ca_certificate)
        r.root_ca_certificate = *options.root_ca_certificate;

      if (options.sev_snp_endorsement_cache_url_template)
      {
        if (url_response_set.size() != 2)
          throw std::runtime_error("unexpected number of URL responses");

        auto issuer_chain = url_response_set[0].body;
        Unique_STACK_OF_X509 stack(issuer_chain);

        if (stack.size() != 3)
          throw std::runtime_error(
            "unexpected size of issuer certificate chain");

        r.root_ca_certificate = stack.at(2);
        r.vcek_certificate_chain = std::move(stack);

        auto issuer_crl_der = std::span<const uint8_t>(
          (uint8_t*)url_response_set[1].body.data(),
          url_response_set[1].body.size());
        auto q = Unique_X509_CRL(issuer_crl_der, false);
        r.vcek_issuer_chain_crl = std::move(q);
      }
      else
      {
        if (url_response_set.size() != 3)
          throw std::runtime_error("unexpected number of URL responses");

        // TODO: wait/retry if rate limits are hit (should be a HTTP 429
        // with retry-after header)

        auto issuer_chain = url_response_set[1].body;

        Unique_STACK_OF_X509 stack(issuer_chain);
        if (stack.size() != 2)
          throw std::runtime_error(
            "unexpected size of issuer certificate chain");

        r.root_ca_certificate = stack.at(1);

        auto vcek_cert = url_response_set[0].body;
        stack.insert(0, Unique_X509(Unique_BIO(vcek_cert), false));
        r.vcek_certificate_chain = std::move(stack);

        auto issuer_crl_der = std::span<const uint8_t>(
          (uint8_t*)url_response_set[2].body.data(),
          url_response_set[2].body.size());
        r.vcek_issuer_chain_crl = Unique_X509_CRL(issuer_crl_der, false);
      }

      return r;
    }

    HTTPRequests download_endorsements(
      const std::string& product_name,
      const std::span<const uint8_t>& chip_id,
      const snp::TcbVersion& tcb_version,
      const Options& options)
    {
      HTTPRequests requests;

      auto hwid = fmt::format("{:02x}", fmt::join(chip_id, ""));
      auto vcek_issuer_crl_url =
        fmt::format("{}/vcek/v1/{}/crl", kds_url, product_name);

      if (options.sev_snp_endorsement_cache_url_template)
      {
        auto tcb_version_str = fmt::format("{:08x}", *(uint64_t*)&tcb_version);
        const auto& url_template =
          *options.sev_snp_endorsement_cache_url_template;
        auto chain_url = fmt::vformat(
          url_template, fmt::make_format_args(hwid, tcb_version_str));

        requests.emplace_back(chain_url);

        // TODO: Does the cache also provide CRLs?
        requests.emplace_back(vcek_issuer_crl_url);
      }
      else
      {
        // https://www.amd.com/system/files/TechDocs/57230.pdf Chapter 4
        auto tcb_parameters = fmt::format(
          "blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
          tcb_version.boot_loader,
          tcb_version.tee,
          tcb_version.snp,
          tcb_version.microcode);
        auto vcek_url = fmt::format(
          "{}/vcek/v1/{}/{}?{}", kds_url, product_name, hwid, tcb_parameters);
        auto vcek_issuer_chain_url =
          fmt::format("{}/vcek/v1/{}/cert_chain", kds_url, product_name);

        requests.emplace_back(vcek_url);
        requests.emplace_back(vcek_issuer_chain_url);
        requests.emplace_back(vcek_issuer_crl_url);
      }

      return requests;
    }

    static bool verify_signature(
      const Unique_EVP_PKEY& pkey,
      const std::span<const uint8_t>& message,
      const snp::Signature& signature)
    {
      SHA512_CTX ctx;
      SHA384_Init(&ctx);
      SHA384_Update(&ctx, message.data(), message.size());
      std::vector<uint8_t> hash(ctx.md_len, 0);
      SHA384_Final(hash.data(), &ctx);

      auto signature_der =
        convert_signature_to_der(signature.r, signature.s, true);

      Unique_EVP_PKEY_CTX pctx(pkey);
      CHECK1(EVP_PKEY_verify_init(pctx));
      int rc = EVP_PKEY_verify(
        pctx,
        signature_der.data(),
        signature_der.size(),
        hash.data(),
        hash.size());

      return rc == 1;
    }

    std::optional<HTTPRequests> Attestation::prepare_endorsements(
      const Options& options) const
    {
      const auto& snp_att =
        *reinterpret_cast<const ravl::sev_snp::snp::Attestation*>(
          evidence.data());

      if (snp_att.version != 2)
        throw std::runtime_error("unsupported attestation format version");

      std::string product_name =
        "Milan"; // TODO: How can we determine that from snp_att?

      std::optional<HTTPRequests> r = std::nullopt;

      if (!endorsements.empty() && !options.fresh_endorsements)
      {
        if (!options.root_ca_certificate && options.fresh_root_ca_certificate)
          r = download_root_ca_pem(product_name);
      }
      else
      {
        r = download_endorsements(
          product_name, snp_att.chip_id, snp_att.reported_tcb, options);
      }

      return r;
    }

#define SET_ARRAY(TO, FROM) \
  std::copy(std::begin(FROM), std::end(FROM), std::begin(TO))

    static void set_tcb_version(
      Claims::TCBVersion& to, const struct snp::TcbVersion& from)
    {
      to.boot_loader = from.boot_loader;
      to.tee = from.tee;
      to.snp = from.snp;
      to.microcode = from.microcode;
    }

    static std::shared_ptr<Claims> make_claims(
      const ravl::sev_snp::snp::Attestation& a)
    {
      auto r = std::make_shared<Claims>();

      r->version = a.version;
      r->guest_svn = a.guest_svn;
      r->policy = a.policy;
      SET_ARRAY(r->family_id, a.family_id);
      SET_ARRAY(r->image_id, a.image_id);
      r->vmpl = a.vmpl;
      r->signature_algo = static_cast<uint32_t>(a.signature_algo);
      set_tcb_version(r->platform_version, a.platform_version);
      r->platform_info = a.platform_info;
      r->flags = a.flags;
      SET_ARRAY(r->report_data, a.report_data);
      SET_ARRAY(r->measurement, a.measurement);
      SET_ARRAY(r->host_data, a.host_data);
      SET_ARRAY(r->id_key_digest, a.id_key_digest);
      SET_ARRAY(r->author_key_digest, a.author_key_digest);
      SET_ARRAY(r->report_id, a.report_id);
      SET_ARRAY(r->report_id_ma, a.report_id_ma);
      set_tcb_version(r->reported_tcb, a.reported_tcb);
      SET_ARRAY(r->chip_id, a.chip_id);
      set_tcb_version(r->committed_tcb, a.committed_tcb);
      r->current_minor = a.current_minor;
      r->current_build = a.current_build;
      r->current_major = a.current_major;
      r->committed_build = a.committed_build;
      r->committed_minor = a.committed_minor;
      r->committed_major = a.committed_major;
      set_tcb_version(r->launch_tcb, a.launch_tcb);
      SET_ARRAY(r->signature.r, a.signature.r);
      SET_ARRAY(r->signature.s, a.signature.s);

      return r;
    }

    std::shared_ptr<ravl::Claims> Attestation::verify(
      const Options& options,
      const std::optional<std::vector<HTTPResponse>>& url_response_set) const
    {
      if (
        endorsements.empty() &&
        (!url_response_set || url_response_set->empty()))
        throw std::runtime_error("missing endorsements");

      size_t indent = 0;

      const auto& snp_att =
        *reinterpret_cast<const ravl::sev_snp::snp::Attestation*>(
          evidence.data());

      Unique_X509_STORE store;

      EndorsementsEtc endorsements_etc;

      if (!endorsements.empty() && !options.fresh_endorsements)
      {
        endorsements_etc.vcek_certificate_chain = vec2str(endorsements);
        if (options.root_ca_certificate)
          endorsements_etc.root_ca_certificate =
            Unique_X509(*options.root_ca_certificate);
        else if (options.fresh_root_ca_certificate)
          endorsements_etc.root_ca_certificate =
            parse_root_cert(*url_response_set);
      }
      else
      {
        if (!url_response_set)
          throw std::runtime_error("missing endorsements");
        endorsements_etc = parse_url_responses(options, *url_response_set);
      }

      if (options.verbosity > 0)
        log(endorsements_etc.to_string(options.verbosity, indent));

      store.set_flags(X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
      store.add_crl(endorsements_etc.vcek_issuer_chain_crl);

      bool trusted_root = false;

      if (endorsements_etc.root_ca_certificate)
        store.add(*endorsements_etc.root_ca_certificate);
      else
        trusted_root = true;

      if (options.verbosity > 0)
        log("- VCEK issuer certificate chain verification", indent + 2);
      auto chain = crypto::verify_certificate_chain(
        endorsements_etc.vcek_certificate_chain,
        store,
        options.certificate_verification,
        trusted_root,
        options.verbosity,
        indent + 4);

      if (chain.size() != 3)
        throw std::runtime_error("unexpected certificate chain length");

      auto vcek_certificate = chain.at(0);
      auto ask_certificate = chain.at(1);
      auto ark_certificate = chain.at(2);

      if (!ark_certificate.has_public_key(
            snp::amd_milan_root_signing_public_key))
        throw std::runtime_error(
          "Root CA certificate does not have the expected AMD Milan public "
          "key");

      if (!ark_certificate.is_ca())
        throw std::runtime_error("Root CA certificate is not a CA");

      if (snp_att.signature_algo != snp::SignatureAlgorithm::ecdsa_p384_sha384)
        throw std::runtime_error("unexpected signature algorithm");

      std::span msg(
        evidence.data(), evidence.size() - sizeof(snp_att.signature));

      Unique_EVP_PKEY vcek_pk(vcek_certificate);
      if (!verify_signature(vcek_pk, msg, snp_att.signature))
        throw std::runtime_error("invalid VCEK signature");

      return make_claims(snp_att);
    }
  }

  template <>
  std::shared_ptr<sev_snp::Claims> Claims::get(std::shared_ptr<Claims>& claims)
  {
    if (claims->source != Source::SEV_SNP)
      throw std::runtime_error("invalid request for SEV/SNP claim conversion");
    return static_pointer_cast<sev_snp::Claims>(claims);
  }
}