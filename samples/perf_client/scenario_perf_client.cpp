// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/files.h"
#include "perf_client.h"

#include <nlohmann/json.hpp>
#include <string>

struct ScenarioPerfClientOptions : public client::PerfOptions
{
  size_t repetitions = 1;
  std::string scenario_file;

  ScenarioPerfClientOptions(
    CLI::App& app, const std::string& default_pid_file) :
    client::PerfOptions("scenario_perf", default_pid_file, app)
  {
    app.add_option("--repetitions", repetitions)->capture_default_str();
    app.add_option("--scenario-file", scenario_file)
      ->required(true)
      ->check(CLI::ExistingFile);
  }
};

using Base = client::PerfBase<ScenarioPerfClientOptions>;

class ScenarioPerfClient : public Base
{
private:
  nlohmann::json scenario_json;

  RpcTlsClient::Response send_verbose_transactions(
    const std::shared_ptr<RpcTlsClient>& connection, char const* element_name)
  {
    const auto it = scenario_json.find(element_name);

    RpcTlsClient::Response response;

    if (it != scenario_json.end())
    {
      const auto transactions = *it;
      if (!transactions.is_array())
      {
        throw std::runtime_error(fmt::format(
          "Expected scenario to contain '{}' field containing an array of "
          "transaction objects",
          element_name));
      }

      LOG_INFO_FMT(
        "Sending {} {} transactions", transactions.size(), element_name);
      for (const auto& transaction : transactions)
      {
        const auto method = transaction["method"];
        const auto params = transaction["params"];

        LOG_INFO_FMT("Sending {}: {}", method, params.dump(2));
        response = connection->call(method, params);
        const auto response_body = connection->unpack_body(response);
        LOG_INFO_FMT("Response: {} {}", response.status, response_body.dump(2));
      }
    }

    return response;
  }

  void pre_creation_hook() override
  {
    scenario_json = files::slurp_json(options.scenario_file);
  }

  std::optional<RpcTlsClient::Response> send_creation_transactions() override
  {
    return send_verbose_transactions(get_connection(), "setup");
  }

  void post_timing_body_hook() override
  {
    send_verbose_transactions(get_connection(), "cleanup");
  }

  void prepare_transactions() override
  {
    constexpr auto transactions_element_name = "transactions";

    const auto transactions = scenario_json[transactions_element_name];
    if (!transactions.is_array())
    {
      throw std::runtime_error(fmt::format(
        "Expected scenario to contain '{}' field containing an array of "
        "transaction objects",
        transactions_element_name));
    }

    // Reserve space for transactions
    prepared_txs.reserve(transactions.size() * options.repetitions);

    for (size_t r = 0; r < options.repetitions; ++r)
    {
      for (size_t i = 0; i < transactions.size(); ++i)
      {
        const auto& transaction = transactions[i];

        add_prepared_tx(
          transaction["method"], transaction["params"], true, std::nullopt);
      }
    }
  }

public:
  ScenarioPerfClient(const ScenarioPerfClientOptions& o) : Base(o) {}
};

int main(int argc, char** argv)
{
  CLI::App cli_app{"Scenario Perf Client"};
  ScenarioPerfClientOptions options(cli_app, argv[0]);
  CLI11_PARSE(cli_app, argc, argv);

  ScenarioPerfClient client(options);
  client.run();

  return 0;
}
