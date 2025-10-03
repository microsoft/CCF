// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "canary.h"

#include "ccf/ds/quote_info.h"

std::string read_in(const std::string& path)
{
  auto expanded_path = ccf::env::expand_envvars_in_path(path);
  LOG_TRACE_FMT("Reading from: {}", expanded_path);
  auto str_opt = files::try_slurp_string(expanded_path);
  if (!str_opt.has_value())
  {
    throw std::invalid_argument("Could not read from: " + expanded_path);
  }
  return str_opt.value();
}

void validate_endorsements(
  const std::string& snp_endorsements,
  const ccf::pal::snp::TcbVersionRaw& attested_tcb,
  std::vector<uint8_t>& endorsements_pem)
{
  const auto raw_data = ccf::crypto::raw_from_b64(snp_endorsements);

  const auto j = nlohmann::json::parse(raw_data);
  const auto aci_endorsements = j.get<ccf::pal::snp::ACIReportEndorsements>();

  // tcbm is a single hex value, like DB18000000000004. To match
  // that with a TcbVersion, reverse the bytes.
  const auto* tcb_begin = reinterpret_cast<const uint8_t*>(&attested_tcb);
  const std::span<const uint8_t> tcb_bytes{
    tcb_begin, tcb_begin + sizeof(attested_tcb)};
  auto tcb_as_hex =
    fmt::format("{:02x}", fmt::join(tcb_bytes.rbegin(), tcb_bytes.rend(), ""));
  ccf::nonstd::to_upper(tcb_as_hex);

  if (tcb_as_hex == aci_endorsements.tcbm)
  {
    LOG_INFO_FMT(
      "Using SNP endorsements loaded from file, endorsing TCB {}", tcb_as_hex);
  }
  else
  {
    throw std::runtime_error(fmt::format(
      "SNP endorsements loaded from disk contained tcbm {}, which does not "
      "match reported TCB of current attestation {}. ",
      aci_endorsements.tcbm,
      tcb_as_hex));
  }

  endorsements_pem.clear();
  endorsements_pem.insert(
    endorsements_pem.end(),
    aci_endorsements.vcek_cert.begin(),
    aci_endorsements.vcek_cert.end());
  endorsements_pem.insert(
    endorsements_pem.end(),
    aci_endorsements.certificate_chain.begin(),
    aci_endorsements.certificate_chain.end());
}

// Verify that the security policy matches the quoted digest of the policy
void validate_security_policy(
  const ccf::QuoteInfo& quote_info, const std::string& security_policy)
{
  auto quoted_digest = ccf::AttestationProvider::get_host_data(quote_info);
  if (!quoted_digest.has_value())
  {
    throw std::logic_error("Unable to find host data in attestation");
  }

  auto security_policy_digest =
    quote_info.format == ccf::QuoteFormat::amd_sev_snp_v1 ?
    ccf::crypto::Sha256Hash(ccf::crypto::raw_from_b64(security_policy)) :
    ccf::crypto::Sha256Hash(security_policy);
  if (security_policy_digest != quoted_digest.value())
  {
    throw std::logic_error(fmt::format(
      "Digest of decoded security policy \"{}\" {} does not match "
      "attestation host data {}",
      security_policy,
      security_policy_digest.hex_str(),
      quoted_digest.value().hex_str()));
  }
  LOG_INFO_FMT(
    "Successfully verified attested security policy {}",
    security_policy_digest);
}

void validate_uvm_endorsements(
  ccf::QuoteInfo& quote_info, const std::string& uvm_endorsements)
{
  try
  {
    auto uvm_endorsements_raw = ccf::crypto::raw_from_b64(uvm_endorsements);
    auto snp_uvm_endorsements = ccf::pal::verify_uvm_endorsements_descriptor(
      uvm_endorsements_raw,
      ccf::AttestationProvider::get_measurement(quote_info).value());
    LOG_INFO_FMT(
      "Successfully verified attested UVM endorsements: {}",
      snp_uvm_endorsements.to_str());
    quote_info.uvm_endorsements = uvm_endorsements_raw;
  }
  catch (const std::exception& e)
  {
    throw std::logic_error(
      fmt::format("Error verifying UVM endorsements: {}", e.what()));
  }
}

ccf::QuoteVerificationResult validate_join_policy(
  ccf::QuoteInfo quote_info, std::vector<uint8_t> expected_pubk_der)
{
  ccf::pal::PlatformAttestationMeasurement measurement = {};
  ccf::crypto::Sha256Hash quoted_hash;
  ccf::pal::PlatformAttestationReportData report_data;
  try
  {
    ccf::pal::verify_quote(quote_info, measurement, report_data);
    quoted_hash = report_data.to_sha256_hash();
  }
  catch (const std::exception& e)
  {
    LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
    return ccf::QuoteVerificationResult::Failed;
  }

  // auto rc = verify_host_data_against_store(tx, quote_info);
  // No non-join-policy steps

  // rc = verify_enclave_measurement_against_store(
  // Only non-join-policy step
  // ccf::verify_uvm_endorsements_against_roots_of_trust(
  //   quote_info.uvm_endorsements.value(),
  //   measurement,
  //   uvm_endorsements_roots_of_trust);
  ccf::pal::verify_uvm_endorsements_descriptor(
    quote_info.uvm_endorsements.value(), measurement);

  // rc = verify_tcb_version_against_store(tx, quote_info);
  // No non-join-policy steps

  return ccf::verify_quoted_node_public_key(expected_pubk_der, quoted_hash);
}

int main(int argc, char** argv)
{
  if (!ccf::pal::snp::supports_sev_snp())
  {
    std::cout << "Skipping canary test as this is not running in SEV-SNP"
              << std::endl;
    return 0;
  }
  ccf::logger::config::level() = ccf::LoggerLevel::TRACE;
  ccf::logger::config::add_text_console_logger();

  if (argc < 2 || argc > 4)
  {
    std::cout << "Usage <program> <snp_endorsements_path> "
                 "[uvm_endorsements_path] [security_policy_path]"
              << std::endl;
    return 1;
  }

  const std::string endorsements_path = argv[1];

  std::optional<std::string> uvm_endorsements_path;
  if (argc >= 3)
  {
    uvm_endorsements_path = argv[2];
  }

  std::optional<std::string> security_policy_path = std::nullopt;
  if (argc >= 4)
  {
    security_policy_path = argv[3];
  }

  try
  {
    LOG_INFO_FMT("Reading SNP endorsements from: {}", endorsements_path);
    std::string endorsements = read_in(endorsements_path);

    LOG_INFO_FMT(
      "Reading SNP UVM endorsements from: {}", uvm_endorsements_path);
    std::optional<std::string> uvm_endorsements = std::nullopt;
    if (uvm_endorsements_path.has_value())
    {
      uvm_endorsements = read_in(uvm_endorsements_path.value());
    }
    else
    {
      LOG_INFO_FMT("No UVM endorsements provided, skipping");
    }

    std::optional<std::string> security_policy = std::nullopt;
    if (security_policy_path.has_value())
    {
      LOG_INFO_FMT(
        "Reading SNP security policy from: {}", security_policy_path);
      security_policy = read_in(security_policy_path.value());
    }
    else
    {
      LOG_INFO_FMT("No SNP security policy provided, skipping");
    }

    LOG_INFO_FMT("Generating attestation");

    // generate private key
    ccf::crypto::KeyPair_OpenSSL node_sign_kp(ccf::crypto::CurveID::SECP384R1);
    ccf::pal::PlatformAttestationReportData report_data =
      ccf::crypto::Sha256Hash(node_sign_kp.public_key_der());
    ccf::pal::generate_quote(
      report_data,
      [&](
        const ccf::QuoteInfo& qi,
        const ccf::pal::snp::EndorsementEndpointsConfiguration&
        /*endpoint_config*/) {
        ccf::QuoteInfo quote_info = qi;

        CCF_ASSERT_FMT(
          quote_info.format == ccf::QuoteFormat::amd_sev_snp_v1,
          "Expected SNP quote format");

        LOG_INFO_FMT("Verifying endorsements");
        const auto* attestation_unverified =
          reinterpret_cast<const ccf::pal::snp::Attestation*>(
            quote_info.quote.data());
        validate_endorsements(
          endorsements,
          attestation_unverified->reported_tcb,
          quote_info.endorsements);

        LOG_INFO_FMT("Verifying quote");
        ccf::pal::PlatformAttestationMeasurement d = {};
        ccf::pal::PlatformAttestationReportData r = {};
        ccf::pal::verify_quote(quote_info, d, r);

        LOG_INFO_FMT("Verifying security policy");
        if (security_policy.has_value())
        {
          validate_security_policy(quote_info, security_policy.value());
        }

        LOG_INFO_FMT("Verifying UVM endorsements");
        if (uvm_endorsements.has_value())
        {
          validate_uvm_endorsements(quote_info, uvm_endorsements.value());
        }

        LOG_INFO_FMT("Running join policy validation");
        auto rc =
          validate_join_policy(quote_info, node_sign_kp.public_key_der());
        if (rc != ccf::QuoteVerificationResult::Verified)
        {
          throw std::logic_error(
            fmt::format("Join policy validation failed: {}", (int)rc));
        }
      },
      {});
  }
  catch (const std::invalid_argument& e)
  {
    LOG_FAIL_FMT("Error: {}", e.what());
    return 2;
  }
  LOG_INFO_FMT("Successfully ran canary.");
  return 0;
}