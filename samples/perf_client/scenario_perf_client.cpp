// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/files.h"
#include "perf_client.h"

#include <nlohmann/json.hpp>
#include <string>

using Base = client::PerfBase;

class ScenarioPerfClient : public Base
{
private:
  size_t repetitions = 1;
  std::string scenario_file;
  nlohmann::json scenario_json;

  void send_verbose_transactions(
    const std::shared_ptr<RpcTlsClient>& connection, char const* element_name)
  {
    const auto it = scenario_json.find(element_name);

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

      std::cout << fmt::format(
                     "Sending {} {} transactions",
                     transactions.size(),
                     element_name)
                << std::endl;
      for (const auto& transaction : transactions)
      {
        const auto method = transaction["method"];
        const auto params = transaction["params"];

        std::cout << fmt::format("Sending {}: {}", method, params.dump(2))
                  << std::endl;
        const auto response = connection->call(method, params);
        std::cout << fmt::format("Response: {}", response.dump(2)) << std::endl;
      }
    }
  }

  void pre_creation_hook() override
  {
    scenario_json = files::slurp_json(scenario_file);
  }

  void send_creation_transactions(
    const std::shared_ptr<RpcTlsClient>& connection) override
  {
    send_verbose_transactions(connection, "setup");
  }

  void post_timing_body_hook() override
  {
    const auto connection = create_connection();
    send_verbose_transactions(connection, "cleanup");
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
    prepared_txs.reserve(transactions.size() * repetitions);

    for (size_t r = 0; r < repetitions; ++r)
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
  ScenarioPerfClient() : Base("scenario_perf") {}

  void setup_parser(CLI::App& app) override
  {
    Base::setup_parser(app);

    app.add_option("--repetitions", repetitions);
    app.add_option("--scenario-file", scenario_file)
      ->required(true)
      ->check(CLI::ExistingFile);
  }
};

int main(int argc, char** argv)
{
  ScenarioPerfClient client;
  CLI::App cli_app{"Scenario Perf Client"};
  client.setup_parser(cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  client.run();

  return 0;
}
