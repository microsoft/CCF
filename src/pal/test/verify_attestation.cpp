// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "attestation_sev_snp_endorsements.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger_level.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ds/files.h"
#include "ds/thread_messaging.h"
#include "node/quote_endorsements_client.h"
#include "pal/test/snp_attestation_validation_data.h"

#include <CLI11/CLI11.hpp>
#include <curl/curl.h>
#include <uv.h>

namespace threading
{
  std::unique_ptr<::threading::ThreadMessaging> ThreadMessaging::singleton =
    nullptr;
}

void fetch_endorsements(
  const std::vector<uint8_t>& attestation_raw, std::vector<uint8_t>& output)
{
  auto attestation = *reinterpret_cast<const ccf::pal::snp::Attestation*>(
    attestation_raw.data());

  auto endorsement_config =
    ccf::pal::snp::make_endorsement_endpoint_configuration(
      (attestation),
      {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "kdsintf.amd.com:443",
      }});

  auto client = std::make_shared<ccf::QuoteEndorsementsClient>(
    endorsement_config, [&output](std::vector<uint8_t>&& endorsements) {
      uv_stop(uv_default_loop());
      output = endorsements;
    });
  client->fetch_endorsements();
}

void run_loop()
{
  struct RunLoopState
  {
    uv_loop_t* loop;
    uint64_t last_tick_ms;
  } state = {uv_default_loop(), 0};

  uv_update_time(state.loop);
  state.last_tick_ms = uv_now(state.loop);

  uv_idle_t idle;
  uv_idle_init(state.loop, &idle);
  idle.data = &state;
  uv_idle_start(&idle, [](uv_idle_t* handle) {
    auto& state = *reinterpret_cast<RunLoopState*>(handle->data);

    uv_update_time(state.loop);
    const auto now_ms = uv_now(state.loop);
    if (now_ms > state.last_tick_ms)
    {
      threading::ThreadMessaging::instance().tick(
        std::chrono::milliseconds(now_ms - state.last_tick_ms));
      state.last_tick_ms = now_ms;
    }

    while (threading::ThreadMessaging::instance().run_one())
    {
    }
  });

  // run the uv loop to completion
  uv_run(state.loop, UV_RUN_DEFAULT);
}

int main(int argc, char** argv)
{
  CLI::App app{"SEV-SNP Endorsements Fetcher"};

  std::string attestation_hex =
    ccf::ds::to_hex(ccf::pal::snp::testing::milan_attestation);

  app
    .add_option(
      "-a,--attestation", attestation_hex, "Attestation in hex format")
    ->check([](const std::string& attestation_hex) {
      auto attest = ccf::ds::from_hex(attestation_hex);
      if (attest.size() != sizeof(ccf::pal::snp::Attestation))
      {
        return std::string(fmt::format(
          "Attestation size is incorrect {} != {}",
          attest.size(),
          sizeof(ccf::pal::snp::Attestation)));
      }
      return std::string();
    });

  ccf::LoggerLevel log_level = ccf::LoggerLevel::INFO;
  std::map<std::string, ccf::LoggerLevel> log_level_options;
  for (auto i = static_cast<uint8_t>(ccf::logger::MOST_VERBOSE);
       i < static_cast<uint8_t>(ccf::LoggerLevel::MAX_LOG_LEVEL);
       ++i)
  {
    const auto level = static_cast<ccf::LoggerLevel>(i);
    log_level_options[ccf::logger::to_string(level)] = level;
  }

  app.add_option("--log-level", log_level, "Logging level")
    ->transform(CLI::CheckedTransformer(log_level_options, CLI::ignore_case));

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  ccf::logger::config::add_text_console_logger();
  ccf::logger::config::level() = log_level;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  threading::ThreadMessaging::init(1);
  auto curl_libuv_context =
    ccf::curl::CurlmLibuvContextSingleton(uv_default_loop());

  ccf::QuoteInfo quote = {};
  quote.format = ccf::QuoteFormat::amd_sev_snp_v1;
  quote.quote = ccf::ds::from_hex(attestation_hex);

  fetch_endorsements(quote.quote, quote.endorsements);
  run_loop();
  CCF_APP_INFO("Successfully fetched endorsements from AMD");

  const auto* attestation_unverified =
    reinterpret_cast<const ccf::pal::snp::Attestation*>(quote.quote.data());
  ccf::pal::PlatformAttestationMeasurement m = {};
  ccf::pal::PlatformAttestationReportData rd = {};
  ccf::pal::verify_quote(quote, m, rd);

  CCF_APP_INFO(
    "Successfully verified attestation against fetched endorsements");
  CCF_APP_INFO("Measurement: {}", ccf::ds::to_hex(m.data));
  CCF_APP_INFO("Report Data: {}", ccf::ds::to_hex(rd.data));

  threading::ThreadMessaging::shutdown();
  curl_global_cleanup();

  return 0;
}
