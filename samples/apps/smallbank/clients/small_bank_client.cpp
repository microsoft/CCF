// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "perf_client.h"

using namespace std;
using namespace nlohmann;

using Base = client::PerfBase;

class SmallBankClient : public Base
{
private:
  enum class TransactionTypes : uint8_t
  {
    TransactSavings = 0,
    Amalgamate,
    WriteCheck,
    DepositChecking,
    GetBalance,

    NumberTransactions
  };

  const char* OPERATION_C_STR[5]{"SmallBank_transact_savings",
                                 "SmallBank_amalgamate",
                                 "SmallBank_write_check",
                                 "SmallBank_deposit_checking",
                                 "SmallBank_balance"};

  size_t total_accounts = 10;

  void print_accounts(const string& header = {})
  {
    if (!header.empty())
    {
      cout << header << endl;
    }

    // Create new connection to read balances
    auto conn = create_connection();

    nlohmann::json accs = nlohmann::json::array();

    for (auto i = 0ul; i < total_accounts; i++)
    {
      json j;
      j["name"] = to_string(i);
      const auto response =
        json::from_msgpack(conn->call("SmallBank_balance", j));

      check_response(response);
      accs.push_back({{"account", i}, {"balance", response["result"]}});
    }

    std::cout << accs.dump(4) << std::endl;
  }

  void send_creation_transactions(
    const std::shared_ptr<RpcTlsClient>& connection) override
  {
    const auto from = 0;
    const auto to = total_accounts;

    cout << "Creating accounts: from " << from << " to " << to << endl;

    json j;
    j["from"] = from;
    j["to"] = to;
    j["checking_amt"] = 1000;
    j["savings_amt"] = 1000;
    connection->call("SmallBank_create_batch", j);
  }

  void prepare_transactions() override
  {
    // Reserve space for transfer transactions
    prepared_txs.resize(num_transactions);

    for (decltype(num_transactions) i = 0; i < num_transactions; i++)
    {
      uint8_t operation =
        rand_range((uint8_t)TransactionTypes::NumberTransactions);

      json j;

      switch ((TransactionTypes)operation)
      {
        case TransactionTypes::TransactSavings:
          j["name"] = to_string(rand_range(total_accounts));
          j["value"] = rand_range<int>(-50, 50);
          break;

        case TransactionTypes::Amalgamate:
        {
          unsigned int src_account = rand_range(total_accounts);
          j["name_src"] = to_string(src_account);

          unsigned int dest_account = rand_range(total_accounts - 1);
          if (dest_account >= src_account)
            dest_account += 1;

          j["name_dest"] = to_string(dest_account);
        }
        break;

        case TransactionTypes::WriteCheck:
          j["name"] = to_string(rand_range(total_accounts));
          j["value"] = rand_range<int>(50);
          break;

        case TransactionTypes::DepositChecking:
          j["name"] = to_string(rand_range(total_accounts));
          j["value"] = rand_range<int>(50) + 1;
          break;

        case TransactionTypes::GetBalance:
          j["name"] = to_string(rand_range(total_accounts));
          break;

        default:
          throw logic_error("Unknown operation");
      }

      add_prepared_tx(
        OPERATION_C_STR[operation],
        j,
        operation != (uint8_t)TransactionTypes::GetBalance,
        i);
    }
  }

  bool check_response(const json& j) override
  {
    // TODO: Add custom error code for this, rather than string matching?
    const auto error_it = j.find("error");
    if (error_it != j.end())
    {
      const auto dumped = j.dump();
      if (dumped.find("Not enough money in savings account") == string::npos)
      {
        throw logic_error(dumped);
        return false;
      }
    }

    return true;
  }

  void pre_creation_hook() override
  {
    if (verbosity >= 1)
    {
      cout << "Creating " << total_accounts << " accounts..." << endl;
    }
  }

  void post_creation_hook() override
  {
    if (verbosity >= 2)
    {
      print_accounts("Initial accounts:");
    }
  }

  void post_timing_body_hook() override
  {
    if (verbosity >= 2)
    {
      print_accounts("Final accounts:");
    }
  }

  void verify_params(const nlohmann::json& expected) override
  {
    Base::verify_params(expected);

    {
      const auto it = expected.find("accounts");
      if (it != expected.end())
      {
        const auto expected_accounts = it->get<decltype(total_accounts)>();
        if (expected_accounts != total_accounts)
        {
          throw std::runtime_error(
            "Verification file is only applicable for " +
            std::to_string(expected_accounts) +
            " accounts, but currently have " + std::to_string(total_accounts));
        }
      }
    }
  }

  void verify_state(const std::string& prefix, const nlohmann::json& expected)
  {
    if (expected.is_null())
    {
      return;
    }

    auto expected_type_msg = [&prefix](const nlohmann::json& problematic) {
      return prefix +
        " state should be a list of (account, balance) objects, not: " +
        problematic.dump();
    };

    if (!expected.is_array())
    {
      throw std::runtime_error(expected_type_msg(expected));
    }

    // Create new connection to read balances
    auto conn = create_connection();

    for (const auto& entry : expected)
    {
      auto account_it = entry.find("account");
      auto balance_it = entry.find("balance");
      if (account_it == entry.end() || balance_it == entry.end())
      {
        throw std::runtime_error(expected_type_msg(entry));
      }

      json j;
      j["name"] = to_string(account_it->get<size_t>());
      const auto response =
        json::from_msgpack(conn->call("SmallBank_balance", j));

      auto result_it = response.find("result");
      if (result_it == response.end())
      {
        throw std::runtime_error(
          "No result in verification response: " + response.dump());
      }

      auto expected_balance = balance_it->get<int64_t>();
      auto actual_balance = result_it->get<int64_t>();
      if (expected_balance != actual_balance)
      {
        throw std::runtime_error(
          "Expected account " + account_it->dump() + " to have balance " +
          std::to_string(expected_balance) + ", actual balance is " +
          std::to_string(actual_balance));
      }
    }
  }

  void verify_initial_state(const nlohmann::json& expected) override
  {
    verify_state("Initial", expected);
  }

  void verify_final_state(const nlohmann::json& expected) override
  {
    verify_state("Final", expected);
  }

public:
  SmallBankClient() : Base("Small_Bank_ClientCpp") {}

  void setup_parser(CLI::App& app) override
  {
    Base::setup_parser(app);

    app.add_option("--accounts", total_accounts);
  }
};

int main(int argc, char** argv)
{
  SmallBankClient client;
  CLI::App cli_app{"Small Bank Client"};
  client.setup_parser(cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  client.run();

  return 0;
}
