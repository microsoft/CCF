// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "flatbuffer_wrapper.h"
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

    bool headers_unmatched(RequestArgs& args)
    {
      // Check the combined balance of an account
      const auto expected = http::headervalues::contenttype::TEXT;
      const auto actual =
        args.rpc_ctx->get_request_header(http::headers::CONTENT_TYPE)
          .value_or("");
      if (expected != actual)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Expected content-type '{}'. Got '{}'.", expected, actual));
        return true;
      }
      return false;
    }

    void set_error_status(RequestArgs& args, int status, std::string&& message)
    {
      args.rpc_ctx->set_response_status(status);
      args.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
      args.rpc_ctx->set_response_body(std::move(message));
    }

    void set_ok_status(RequestArgs& args)
    {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      args.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
    }

  public:
    SmallBankHandlers(Store& store) : UserHandlerRegistry(store), tables(store)
    {}

    void init_handlers(Store& store) override
    {
      UserHandlerRegistry::init_handlers(store);

      // auto create = [this](RequestArgs& args) {
      //   if (headers_unmatched(args))
      //   {
      //     return;
      //   }
      //   // Create an account with a balance from thin air.
      //   auto body = args.rpc_ctx->get_request_body().data();
      //   kv::bank::BankDeserializer fbd(body);
      //   auto name = fbd.name();
      //   auto acc_id = fbd.id();
      //   int64_t checking_amt = fbd.checking_amt();
      //   int64_t savings_amt = fbd.savings_amt();
      //   auto account_view = args.tx.get_view(tables.accounts);
      //   auto account_r = account_view->get(name);

      //   if (account_r.has_value())
      //   {
      //     set_error_status(args, HTTP_STATUS_BAD_REQUEST, "Account already
      //     exists"); return;
      //   }

      //   account_view->put(name, acc_id);

      //   auto savings_view = args.tx.get_view(tables.savings);
      //   auto savings_r = savings_view->get(acc_id);

      //   if (savings_r.has_value())
      //   {
      //     set_error_status(args, HTTP_STATUS_BAD_REQUEST, "Account already
      //     exists"); return;
      //   }

      //   savings_view->put(acc_id, savings_amt);

      //   auto checking_view = args.tx.get_view(tables.checkings);
      //   auto checking_r = checking_view->get(acc_id);

      //   if (checking_r.has_value())
      //   {
      //     set_error_status(args, HTTP_STATUS_BAD_REQUEST, "Account already
      //     exists"); return;
      //   }

      //   checking_view->put(acc_id, checking_amt);

      //   set_ok_status(args);
      // };

      auto create_batch = [this](RequestArgs& args) {
        // Create N accounts with identical balances from thin air.
        if (headers_unmatched(args))
        {
          return;
        }
        // Create an account with a balance from thin air.
        auto body = args.rpc_ctx->get_request_body().data();
        kv::bank::AccountsDeserializer fbd(body);
        auto from = fbd.from();
        auto to = fbd.to();
        auto checking_amt = fbd.checking_amt();
        auto savings_amt = fbd.savings_amt();

        auto account_view = args.tx.get_view(tables.accounts);
        auto savings_view = args.tx.get_view(tables.savings);
        auto checking_view = args.tx.get_view(tables.checkings);

        for (auto acc_id = from; acc_id < to; ++acc_id)
        {
          std::string name = std::to_string(acc_id);

          auto account_r = account_view->get(name);
          if (account_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in accounts table: '{}'", name));
            return;
          }
          account_view->put(name, acc_id);

          auto savings_r = savings_view->get(acc_id);
          if (savings_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in savings table: '{}'", name));
            return;
          }
          savings_view->put(acc_id, savings_amt);

          auto checking_r = checking_view->get(acc_id);
          if (checking_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in checkings table: '{}'", name));
            return;
          }
          checking_view->put(acc_id, checking_amt);
        }

        set_ok_status(args);
      };

      auto balance = [this](RequestArgs& args) {
        if (headers_unmatched(args))
        {
          return;
        }

        auto name = kv::bank::name(args.rpc_ctx->get_request_body().data());
        auto account_view = args.tx.get_view(tables.accounts);
        auto account_r = account_view->get(std::to_string(name));

        if (!account_r.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Account does not exist"));
          return;
        }

        auto savings_view = args.tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Savings account does not exist"));
          return;
        }

        auto checking_view = args.tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Checking account does not exist"));
          return;
        }

        auto result = checking_r.value() + savings_r.value();

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        // make this a flatbuffer response maybe?
        nlohmann::json r(result);
        args.rpc_ctx->set_response_body(r.dump());
      };

      auto transact_savings = [this](RequestArgs& args) {
        // Add or remove money to the savings account
        if (headers_unmatched(args))
        {
          return;
        }

        kv::bank::TransactionDeserializer fbd(
          args.rpc_ctx->get_request_body().data());

        auto name = to_string(fbd.name());
        auto value = fbd.value();

        if (name.empty())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "A name must be specified");
          return;
        }

        auto account_view = args.tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
        }

        auto savings_view = args.tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        if (savings_r.value() + value < 0)
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Not enough money in savings account");
          return;
        }

        savings_view->put(account_r.value(), value + savings_r.value());
        set_ok_status(args);
      };

      auto deposit_checking = [this](RequestArgs& args) {
        // Desposit money into the checking account out of thin air
        if (headers_unmatched(args))
        {
          return;
        }
        kv::bank::TransactionDeserializer fbd(
          args.rpc_ctx->get_request_body().data());
        auto name = to_string(fbd.name());
        auto value = fbd.value();

        if (name.empty())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "A name must be specified");
          return;
        }

        if (value <= 0)
        {
          set_error_status(args, HTTP_STATUS_BAD_REQUEST, "Value <= 0");
          return;
        }

        auto account_view = args.tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto checking_view = args.tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }
        checking_view->put(account_r.value(), value + checking_r.value());
        set_ok_status(args);
      };

      auto amalgamate = [this](RequestArgs& args) {
        // Move the contents of one users account to another users account
        if (headers_unmatched(args))
        {
          return;
        }
        kv::bank::AmalgamateDeserializer fbd(
          args.rpc_ctx->get_request_body().data());

        auto name_1 = to_string(fbd.name_src());
        auto name_2 = to_string(fbd.name_dest());
        ;
        auto account_view = args.tx.get_view(tables.accounts);
        auto account_1_r = account_view->get(name_1);

        if (!account_1_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Source account does not exist");
          return;
        }

        auto account_2_r = account_view->get(name_2);

        if (!account_2_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Destination account does not exist");
          return;
        }

        auto savings_view = args.tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_1_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Source savings account does not exist");
          return;
        }

        auto checking_view = args.tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_1_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Source checking account does not exist");
          return;
        }

        auto sum_account_1 = checking_r.value() + savings_r.value();
        checking_view->put(account_1_r.value(), 0);
        savings_view->put(account_1_r.value(), 0);

        auto checking_2_view = args.tx.get_view(tables.checkings);
        auto checking_2_r = checking_2_view->get(account_2_r.value());

        if (!checking_2_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Destination checking account does not exist");
          return;
        }

        checking_2_view->put(
          account_2_r.value(), checking_2_r.value() + sum_account_1);

        set_ok_status(args);
      };

      auto writeCheck = [this](RequestArgs& args) {
        // Write a check, if not enough funds then also charge an extra 1 money
        if (headers_unmatched(args))
        {
          return;
        }
        kv::bank::TransactionDeserializer fbd(
          args.rpc_ctx->get_request_body().data());
        auto name = to_string(fbd.name());
        auto amount = fbd.value();

        auto account_view = args.tx.get_view(tables.accounts);
        auto account_r = account_view->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto savings_view = args.tx.get_view(tables.savings);
        auto savings_r = savings_view->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        auto checking_view = args.tx.get_view(tables.checkings);
        auto checking_r = checking_view->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }

        auto account_value = checking_r.value() + savings_r.value();
        if (account_value < amount)
        {
          ++amount;
        }
        checking_view->put(account_r.value(), account_value - amount);
        set_ok_status(args);
      };

      // install(
      //   Procs::SMALL_BANKING_CREATE,
      //   create,
      //   HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_CREATE_BATCH,
        create_batch,
        HandlerRegistry::Write);
      install(Procs::SMALL_BANKING_BALANCE, balance, HandlerRegistry::Read);
      install(
        Procs::SMALL_BANKING_TRANSACT_SAVINGS,
        transact_savings,
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_DEPOSIT_CHECKING,
        deposit_checking,
        HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_AMALGAMATE, amalgamate, HandlerRegistry::Write);
      install(
        Procs::SMALL_BANKING_WRITE_CHECK, writeCheck, HandlerRegistry::Write);
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
