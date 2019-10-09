// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "node/entities.h"
#include "node/rpc/nodeinterface.h"
#include "node/rpc/userfrontend.h"

using namespace std;
using namespace nlohmann;
using namespace ccf;

//#define PRINT_LOGS

namespace ccfapp
{
  struct Procs
  {
    // small banking application for benchmarking
    static constexpr auto SMALL_BANKING_CREATE = "SmallBank_create";
    static constexpr auto SMALL_BANKING_CREATE_BATCH = "SmallBank_create_batch";
    static constexpr auto SMALL_BANKING_BALANCE = "SmallBank_balance";
    static constexpr auto SMALL_BANKING_DEPOSIT_CHECKING =
      "SmallBank_deposit_checking";
    static constexpr auto SMALL_BANKING_TRANSACT_SAVINGS =
      "SmallBank_transact_savings";
    static constexpr auto SMALL_BANKING_AMALGAMATE = "SmallBank_amalgamate";
    static constexpr auto SMALL_BANKING_WRITE_CHECK = "SmallBank_write_check";
  };

  class SmallBank : public ccf::UserRpcFrontend
  {
  private:
    Store::Map<std::string, uint64_t>& accountTable;
    Store::Map<uint64_t, int64_t>& savingsTable;
    Store::Map<uint64_t, int64_t>& checkingTable;

  public:
    SmallBank(Store& tables) :
      UserRpcFrontend(tables),
      accountTable(tables.create<std::string, uint64_t>("a")),
      savingsTable(tables.create<uint64_t, int64_t>("b")),
      checkingTable(tables.create<uint64_t, int64_t>("c"))
    {
      auto create = [this](Store::Tx& tx, const nlohmann::json& params) {
        // Create an account with a balance from thin air.
        std::string name = params["name"];
        uint64_t acc_id = params["id"];
        int64_t checking_amt = params["checking_amt"];
        int64_t savings_amt = params["savings_amt"];
        auto account_view = tx.get_view(accountTable);
        auto account_r = account_view->get(name);

        if (account_r.has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Account already exists");
        }

        account_view->put(name, acc_id);

        auto savings_view = tx.get_view(savingsTable);
        auto savings_r = savings_view->get(acc_id);

        if (savings_r.has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Account already exists");
        }

        savings_view->put(acc_id, savings_amt);

        auto checking_view = tx.get_view(checkingTable);
        auto checking_r = checking_view->get(acc_id);

        if (checking_r.has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Account already exists");
        }

        checking_view->put(acc_id, checking_amt);

        return jsonrpc::success(true);
      };

      auto create_batch = [this](Store::Tx& tx, const nlohmann::json& params) {
        // Create N accounts with identical balances from thin air.
        uint64_t from = params["from"];
        uint64_t to = params["to"];
        int64_t checking_amt = params["checking_amt"];
        int64_t savings_amt = params["savings_amt"];

        auto account_view = tx.get_view(accountTable);
        auto savings_view = tx.get_view(savingsTable);
        auto checking_view = tx.get_view(checkingTable);

        for (auto acc_id = from; acc_id < to; ++acc_id)
        {
          std::string name = std::to_string(acc_id);

          auto account_r = account_view->get(name);
          if (account_r.has_value())
          {
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Account already exists in accounts table: " + name);
          }
          account_view->put(name, acc_id);

          auto savings_r = savings_view->get(acc_id);
          if (savings_r.has_value())
          {
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Account already exists in savings table: " + name);
          }
          savings_view->put(acc_id, savings_amt);

          auto checking_r = checking_view->get(acc_id);
          if (checking_r.has_value())
          {
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Account already exists in checkings table: " + name);
          }
          checking_view->put(acc_id, checking_amt);
        }

        return jsonrpc::success(true);
      };

      auto balance = [this](Store::Tx& tx, const nlohmann::json& params) {
        // Check the combined balance of an account
        std::string name = params["name"];
        auto account_view = tx.get_view(accountTable);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Account does not exist");

        auto savings_view = tx.get_view(savingsTable);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Savings account does not exist");

        auto checking_view = tx.get_view(checkingTable);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Checking account does not exist");

        auto result = checking_r.value() + savings_r.value();
        return jsonrpc::success(result);
      };

      auto transact_savings =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          // Add or remove money to the savings account
          std::string name = params["name"];
          int value = params["value"];

          if (name.empty())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "A name must be specified");

          auto account_view = tx.get_view(accountTable);
          auto account_r = account_view->get(name);

          if (!account_r.has_value())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Account does not exist");

          auto savings_view = tx.get_view(savingsTable);
          auto savings_r = savings_view->get(account_r.value());

          if (!savings_r.has_value())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Savings account does not exist");

          if (savings_r.value() + value < 0)
          {
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Not enough money in savings account");
          }

          savings_view->put(account_r.value(), value + savings_r.value());

          return jsonrpc::success(true);
        };

      auto deposit_checking =
        [this](Store::Tx& tx, const nlohmann::json& params) {
          // Desposit money into the checking account out of thin air
          std::string name = params["name"];
          int64_t value = params["value"];

          if (name.empty())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "A name must be specified");

          if (value <= 0)
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS, "Value <= 0");

          auto account_view = tx.get_view(accountTable);
          auto account_r = account_view->get(name);

          if (!account_r.has_value())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Account does not exist");

          auto checking_view = tx.get_view(checkingTable);
          auto checking_r = checking_view->get(account_r.value());

          if (!checking_r.has_value())
            return error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              "Checking account does not exist");

          checking_view->put(account_r.value(), value + checking_r.value());

          return jsonrpc::success(true);
        };

      auto amalgamate = [this](Store::Tx& tx, const nlohmann::json& params) {
        // Move the contents of one users account to another users account
        std::string name_1 = params["name_src"];
        std::string name_2 = params["name_dest"];
        auto account_view = tx.get_view(accountTable);
        auto account_1_r = account_view->get(name_1);

        if (!account_1_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Source account does not exist");

        auto account_2_r = account_view->get(name_2);

        if (!account_2_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Destination account does not exist");

        auto savings_view = tx.get_view(savingsTable);
        auto savings_r = savings_view->get(account_1_r.value());

        if (!savings_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Source savings account does not exist");

        auto checking_view = tx.get_view(checkingTable);
        auto checking_r = checking_view->get(account_1_r.value());

        if (!checking_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Source checking account does not exist");

        auto sum_account_1 = checking_r.value() + savings_r.value();
        checking_view->put(account_1_r.value(), 0);
        savings_view->put(account_1_r.value(), 0);

        auto checking_2_view = tx.get_view(checkingTable);
        auto checking_2_r = checking_2_view->get(account_2_r.value());

        if (!checking_2_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Destination checking account does not exist");

        checking_2_view->put(
          account_2_r.value(), checking_2_r.value() + sum_account_1);

        return jsonrpc::success(true);
      };

      auto writeCheck = [this](Store::Tx& tx, const nlohmann::json& params) {
        // Write a check, if not enough funds then also charge an extra 1 money
        std::string name = params["name"];
        uint32_t amount = params["value"];
        auto account_view = tx.get_view(accountTable);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Account does not exist");

        auto savings_view = tx.get_view(savingsTable);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Savings account does not exist");

        auto checking_view = tx.get_view(checkingTable);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
          return error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            "Checking account does not exist");

        auto account_value = checking_r.value() + savings_r.value();
        if (account_value < amount)
        {
          ++amount;
        }
        checking_view->put(account_r.value(), account_value - amount);

        return jsonrpc::success(true);
      };

      install(Procs::SMALL_BANKING_CREATE, create, Write);
      install(Procs::SMALL_BANKING_CREATE_BATCH, create_batch, Write);
      install(Procs::SMALL_BANKING_BALANCE, balance, Read);
      install(Procs::SMALL_BANKING_TRANSACT_SAVINGS, transact_savings, Write);
      install(Procs::SMALL_BANKING_DEPOSIT_CHECKING, deposit_checking, Write);
      install(Procs::SMALL_BANKING_AMALGAMATE, amalgamate, Write);
      install(Procs::SMALL_BANKING_WRITE_CHECK, writeCheck, Write);
      disable_request_storing();
    }
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return make_shared<SmallBank>(*nwt.tables);
  }
}
