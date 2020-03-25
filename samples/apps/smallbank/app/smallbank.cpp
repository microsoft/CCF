// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "node/rpc/user_frontend.h"

using namespace std;
using namespace nlohmann;
using namespace ccf;

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

  struct SmallBankTables
  {
    Store::Map<std::string, uint64_t>& accounts;
    Store::Map<uint64_t, int64_t>& savings;
    Store::Map<uint64_t, int64_t>& checkings;

    SmallBankTables(Store& store) :
      accounts(store.create<std::string, uint64_t>("a")),
      savings(store.create<uint64_t, int64_t>("b")),
      checkings(store.create<uint64_t, int64_t>("c"))
    {}
  };

  class SmallBankHandlers : public UserHandlerRegistry
  {
  private:
    SmallBankTables tables;

  public:
    SmallBankHandlers(Store& store) : UserHandlerRegistry(store), tables(store)
    {}

    void init_handlers(Store& store) override
    {
      UserHandlerRegistry::init_handlers(store);

      auto create = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Create an account with a balance from thin air.
        std::string name = params["name"];
        uint64_t acc_id = params["id"];
        int64_t checking_amt = params["checking_amt"];
        int64_t savings_amt = params["savings_amt"];
        auto account_view = tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (account_r.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account already exists");
        }

        account_view->put(name, acc_id);

        auto savings_view = tx.get_view(tables.savings);
        auto savings_r = savings_view->get(acc_id);

        if (savings_r.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account already exists");
        }

        savings_view->put(acc_id, savings_amt);

        auto checking_view = tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(acc_id);

        if (checking_r.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account already exists");
        }

        checking_view->put(acc_id, checking_amt);

        return make_success(true);
      };

      auto create_batch = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Create N accounts with identical balances from thin air.
        uint64_t from = params["from"];
        uint64_t to = params["to"];
        int64_t checking_amt = params["checking_amt"];
        int64_t savings_amt = params["savings_amt"];

        auto account_view = tx.get_view(tables.accounts);
        auto savings_view = tx.get_view(tables.savings);
        auto checking_view = tx.get_view(tables.checkings);

        for (auto acc_id = from; acc_id < to; ++acc_id)
        {
          std::string name = std::to_string(acc_id);

          auto account_r = account_view->get(name);
          if (account_r.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              "Account already exists in accounts table: " + name);
          }
          account_view->put(name, acc_id);

          auto savings_r = savings_view->get(acc_id);
          if (savings_r.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              "Account already exists in savings table: " + name);
          }
          savings_view->put(acc_id, savings_amt);

          auto checking_r = checking_view->get(acc_id);
          if (checking_r.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              "Account already exists in checkings table: " + name);
          }
          checking_view->put(acc_id, checking_amt);
        }

        return make_success(true);
      };

      auto balance = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Check the combined balance of an account
        std::string name = params["name"];
        auto account_view = tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account does not exist");

        auto savings_view = tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");

        auto checking_view = tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");

        auto result = checking_r.value() + savings_r.value();
        return make_success(result);
      };

      auto transact_savings = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Add or remove money to the savings account
        std::string name = params["name"];
        int value = params["value"];

        if (name.empty())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "A name must be specified");

        auto account_view = tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account does not exist");

        auto savings_view = tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");

        if (savings_r.value() + value < 0)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Not enough money in savings account");
        }

        savings_view->put(account_r.value(), value + savings_r.value());

        return make_success(true);
      };

      auto deposit_checking = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Desposit money into the checking account out of thin air
        std::string name = params["name"];
        int64_t value = params["value"];

        if (name.empty())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "A name must be specified");

        if (value <= 0)
          return make_error(HTTP_STATUS_BAD_REQUEST, "Value <= 0");

        auto account_view = tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account does not exist");

        auto checking_view = tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");

        checking_view->put(account_r.value(), value + checking_r.value());

        return make_success(true);
      };

      auto amalgamate = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Move the contents of one users account to another users account
        std::string name_1 = params["name_src"];
        std::string name_2 = params["name_dest"];
        auto account_view = tx.get_view(tables.accounts);
        auto account_1_r = account_view->get(name_1);

        if (!account_1_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Source account does not exist");

        auto account_2_r = account_view->get(name_2);

        if (!account_2_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Destination account does not exist");

        auto savings_view = tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_1_r.value());

        if (!savings_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Source savings account does not exist");

        auto checking_view = tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_1_r.value());

        if (!checking_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Source checking account does not exist");

        auto sum_account_1 = checking_r.value() + savings_r.value();
        checking_view->put(account_1_r.value(), 0);
        savings_view->put(account_1_r.value(), 0);

        auto checking_2_view = tx.get_view(tables.checkings);
        auto checking_2_r = checking_2_view->get(account_2_r.value());

        if (!checking_2_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            "Destination checking account does not exist");

        checking_2_view->put(
          account_2_r.value(), checking_2_r.value() + sum_account_1);

        return make_success(true);
      };

      auto writeCheck = [this](Store::Tx& tx, nlohmann::json&& params) {
        // Write a check, if not enough funds then also charge an extra 1 money
        std::string name = params["name"];
        uint32_t amount = params["value"];
        auto account_view = tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
          return make_error(HTTP_STATUS_BAD_REQUEST, "Account does not exist");

        auto savings_view = tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");

        auto checking_view = tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");

        auto account_value = checking_r.value() + savings_r.value();
        if (account_value < amount)
        {
          ++amount;
        }
        checking_view->put(account_r.value(), account_value - amount);

        return make_success(true);
      };

      install(
        Procs::SMALL_BANKING_CREATE,
        json_adapter(create),
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_CREATE_BATCH,
        json_adapter(create_batch),
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_BALANCE,
        json_adapter(balance),
        HandlerRegistry::Read);
      install(
        Procs::SMALL_BANKING_TRANSACT_SAVINGS,
        json_adapter(transact_savings),
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_DEPOSIT_CHECKING,
        json_adapter(deposit_checking),
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_AMALGAMATE,
        json_adapter(amalgamate),
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_WRITE_CHECK,
        json_adapter(writeCheck),
        HandlerRegistry::Write);
    }
  };

  class SmallBank : public ccf::UserRpcFrontend
  {
  private:
    SmallBankHandlers sb_handlers;

  public:
    SmallBank(Store& store) :
      UserRpcFrontend(store, sb_handlers),
      sb_handlers(store)
    {
      disable_request_storing();
    }
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return make_shared<SmallBank>(*nwt.tables);
  }
}
