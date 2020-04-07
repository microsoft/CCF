// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "perf_client.h"

using namespace std;
using namespace nlohmann;

struct SmallBankClientOptions : public client::PerfOptions
{
  size_t total_accounts = 10;

  SmallBankClientOptions(CLI::App& app, const std::string& default_pid_file) :
    client::PerfOptions("Small_Bank_ClientCpp", default_pid_file, app)
  {
    app.add_option("--accounts", total_accounts)->capture_default_str();
  }
};

using Base = client::PerfBase<SmallBankClientOptions>;

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

  void print_accounts(const string& header = {})
  {
    if (!header.empty())
    {
      LOG_INFO_FMT(header);
    }

    auto conn = get_connection();

    nlohmann::json accs = nlohmann::json::array();

    for (auto i = 0ul; i < options.total_accounts; i++)
    {
      json j;
      j["name"] = to_string(i);
      const auto response = conn->call("SmallBank_balance", j);

      check_response(response);
      const auto result = conn->unpack_body(response);
      accs.push_back({{"account", i}, {"balance", result}});
    }

    LOG_INFO_FMT("Accounts:\n{}", accs.dump(4));
  }

  std::optional<RpcTlsClient::Response> send_creation_transactions() override
  {
    const auto from = 0;
    const auto to = options.total_accounts;

    auto connection = get_connection();
    LOG_INFO_FMT("Creating accounts from {} to {}", from, to);

    json j;
    j["from"] = from;
    j["to"] = to;
    j["checking_amt"] = 1000;
    j["savings_amt"] = 1000;
    const auto response = connection->call("SmallBank_create_batch", j);
    check_response(response);

    return response;
  }

  void prepare_transactions() override
  {
    // Reserve space for transfer transactions
    prepared_txs.resize(options.num_transactions);

    for (decltype(options.num_transactions) i = 0; i < options.num_transactions;
         i++)
    {
      uint8_t operation =
        rand_range((uint8_t)TransactionTypes::NumberTransactions);

      json j;

      switch ((TransactionTypes)operation)
      {
        case TransactionTypes::TransactSavings:
          j["name"] = to_string(rand_range(options.total_accounts));
          j["value"] = rand_range<int>(-50, 50);
          break;

        case TransactionTypes::Amalgamate:
        {
          unsigned int src_account = rand_range(options.total_accounts);
          j["name_src"] = to_string(src_account);

          unsigned int dest_account = rand_range(options.total_accounts - 1);
          if (dest_account >= src_account)
            dest_account += 1;

          j["name_dest"] = to_string(dest_account);
        }
        break;

        case TransactionTypes::WriteCheck:
          j["name"] = to_string(rand_range(options.total_accounts));
          j["value"] = rand_range<int>(50);
          break;

        case TransactionTypes::DepositChecking:
          j["name"] = to_string(rand_range(options.total_accounts));
          j["value"] = rand_range<int>(50) + 1;
          break;

        case TransactionTypes::GetBalance:
          j["name"] = to_string(rand_range(options.total_accounts));
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

  bool check_response(const RpcTlsClient::Response& r) override
  {
    if (r.status != HTTP_STATUS_OK)
    {
      const std::string error_msg(r.body.begin(), r.body.end());
      if (
        error_msg.find("Not enough money in savings account") == string::npos &&
        error_msg.find("Account already exists in accounts table") ==
          string::npos)
      {
        throw logic_error(error_msg);
        return false;
      }
    }

    return true;
  }

  void pre_creation_hook() override
  {
    LOG_DEBUG_FMT("Creating {} accounts", options.total_accounts);
  }

  void post_creation_hook() override
  {
    LOG_TRACE_FMT("Initial accounts:");
  }

  void post_timing_body_hook() override
  {
    LOG_TRACE_FMT("Final accounts:");
  }

  void verify_params(const nlohmann::json& expected) override
  {
    Base::verify_params(expected);

    {
      const auto it = expected.find("accounts");
      if (it != expected.end())
      {
        const auto expected_accounts =
          it->get<decltype(options.total_accounts)>();
        if (expected_accounts != options.total_accounts)
        {
          throw std::runtime_error(
            "Verification file is only applicable for " +
            std::to_string(expected_accounts) +
            " accounts, but currently have " +
            std::to_string(options.total_accounts));
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
    auto conn = get_connection();

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
      const auto response = conn->call("SmallBank_balance", j);
      const auto response_body = conn->unpack_body(response);

      if (response.status != HTTP_STATUS_OK)
      {
        throw std::runtime_error(fmt::format(
          "Error in verification response: {}", response_body.dump(2)));
      }

      auto expected_balance = balance_it->get<int64_t>();
      auto actual_balance = response_body.get<int64_t>();
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
  SmallBankClient(const SmallBankClientOptions& o) : Base(o) {}
};

int main(int argc, char** argv)
{
  CLI::App cli_app{"Small Bank Client"};
  SmallBankClientOptions options(cli_app, argv[0]);
  CLI11_PARSE(cli_app, argc, argv);

  SmallBankClient client(options);
  client.run();

  return 0;
}
