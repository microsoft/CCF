// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../smallbank_serializer.h"
#include "enclave/app_interface.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"

#include <charconv>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  struct SmallBankTables
  {
    kv::Map<std::string, uint64_t> accounts;
    kv::Map<uint64_t, int64_t> savings;
    kv::Map<uint64_t, int64_t> checkings;

    SmallBankTables() : accounts("a"), savings("b"), checkings("c") {}
  };

  class SmallBankHandlers : public UserEndpointRegistry
  {
  private:
    SmallBankTables tables;
    metrics::Tracker metrics_tracker;

    void set_error_status(
      EndpointContext& args, int status, std::string&& message)
    {
      args.rpc_ctx->set_response_status(status);
      args.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
      args.rpc_ctx->set_response_body(std::move(message));
    }

    void set_ok_status(EndpointContext& args)
    {
      args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      args.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE,
        http::headervalues::contenttype::OCTET_STREAM);
    }

    void set_no_content_status(EndpointContext& args)
    {
      args.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
    }

  public:
    SmallBankHandlers(ccf::AbstractNodeState& node_state) :
      UserEndpointRegistry(node_state),
      tables()
    {}

    void init_handlers() override
    {
      UserEndpointRegistry::init_handlers();

      auto create = [this](auto& args) {
        // Create an account with a balance from thin air.
        const auto& body = args.rpc_ctx->get_request_body();
        auto ai = smallbank::AccountInfo::deserialize(body.data(), body.size());
        auto name = ai.name;
        uint64_t acc_id;
        std::from_chars(name.data(), name.data() + name.size(), acc_id);
        int64_t checking_amt = ai.checking_amt;
        int64_t savings_amt = ai.savings_amt;
        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_r = accounts->get(name);

        if (account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        accounts->put(name, acc_id);

        auto savings = args.tx.get_handle(tables.savings);
        auto savings_r = savings->get(acc_id);

        if (savings_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        savings->put(acc_id, savings_amt);

        auto checkings = args.tx.get_handle(tables.checkings);
        auto checking_r = checkings->get(acc_id);

        if (checking_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        checkings->put(acc_id, checking_amt);

        set_no_content_status(args);
      };

      auto create_batch = [this](auto& args) {
        // Create N accounts with identical balances from thin air.
        const auto& body = args.rpc_ctx->get_request_body();
        auto ac =
          smallbank::AccountCreation::deserialize(body.data(), body.size());

        auto accounts = args.tx.get_handle(tables.accounts);
        auto savings = args.tx.get_handle(tables.savings);
        auto checkings = args.tx.get_handle(tables.checkings);

        for (auto acc_id = ac.new_id_from; acc_id < ac.new_id_to; ++acc_id)
        {
          std::string name = std::to_string(acc_id);

          auto account_r = accounts->get(name);
          if (account_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in accounts table: '{}'", name));
            return;
          }
          accounts->put(name, acc_id);

          auto savings_r = savings->get(acc_id);
          if (savings_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in savings table: '{}'", name));
            return;
          }
          savings->put(acc_id, ac.initial_savings_amt);

          auto checking_r = checkings->get(acc_id);
          if (checking_r.has_value())
          {
            set_error_status(
              args,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in checkings table: '{}'", name));
            return;
          }
          checkings->put(acc_id, ac.initial_checking_amt);
        }

        set_no_content_status(args);
      };

      auto balance = [this](auto& args) {
        // Check the combined balance of an account
        const auto& body = args.rpc_ctx->get_request_body();
        auto account =
          smallbank::AccountName::deserialize(body.data(), body.size());
        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_r = accounts->get(account.name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto savings = args.tx.get_handle(tables.savings);
        auto savings_r = savings->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        auto checkings = args.tx.get_handle(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }

        auto result = checking_r.value() + savings_r.value();

        set_ok_status(args);

        smallbank::Balance b;
        b.value = result;
        args.rpc_ctx->set_response_body(b.serialize());
      };

      auto transact_savings = [this](auto& args) {
        // Add or remove money to the savings account
        const auto& body = args.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto value = transaction.value;

        if (name.empty())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "A name must be specified");
          return;
        }

        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
        }

        auto savings = args.tx.get_handle(tables.savings);
        auto savings_r = savings->get(account_r.value());

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

        savings->put(account_r.value(), value + savings_r.value());
        set_no_content_status(args);
      };

      auto deposit_checking = [this](auto& args) {
        // Desposit money into the checking account out of thin air
        const auto& body = args.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto value = transaction.value;

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

        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto checkings = args.tx.get_handle(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }
        checkings->put(account_r.value(), value + checking_r.value());
        set_no_content_status(args);
      };

      auto amalgamate = [this](auto& args) {
        // Move the contents of one users account to another users account
        const auto& body = args.rpc_ctx->get_request_body();
        auto ad = smallbank::Amalgamate::deserialize(body.data(), body.size());
        auto name_1 = ad.src;
        auto name_2 = ad.dst;
        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_1_r = accounts->get(name_1);

        if (!account_1_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Source account does not exist");
          return;
        }

        auto account_2_r = accounts->get(name_2);

        if (!account_2_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Destination account does not exist");
          return;
        }

        auto savings = args.tx.get_handle(tables.savings);
        auto savings_r = savings->get(account_1_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Source savings account does not exist");
          return;
        }

        auto checkings = args.tx.get_handle(tables.checkings);
        auto checking_r = checkings->get(account_1_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Source checking account does not exist");
          return;
        }

        auto sum_account_1 = checking_r.value() + savings_r.value();
        checkings->put(account_1_r.value(), 0);
        savings->put(account_1_r.value(), 0);

        auto checking_2_r = checkings->get(account_2_r.value());

        if (!checking_2_r.has_value())
        {
          set_error_status(
            args,
            HTTP_STATUS_BAD_REQUEST,
            "Destination checking account does not exist");
          return;
        }

        checkings->put(
          account_2_r.value(), checking_2_r.value() + sum_account_1);

        set_no_content_status(args);
      };

      auto writeCheck = [this](auto& args) {
        // Write a check, if not enough funds then also charge an extra 1 money
        const auto& body = args.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto amount = transaction.value;

        auto accounts = args.tx.get_handle(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto savings = args.tx.get_handle(tables.savings);
        auto savings_r = savings->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            args, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        auto checkings = args.tx.get_handle(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

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
        checkings->put(account_r.value(), account_value - amount);
        set_no_content_status(args);
      };

      const ccf::endpoints::AuthnPolicies user_sig_or_cert = {
        user_signature_auth_policy, user_cert_auth_policy};

      std::vector<ccf::RESTVerb> verbs = {HTTP_POST, ws::Verb::WEBSOCKET};
      for (auto verb : verbs)
      {
        make_endpoint("SmallBank_create", verb, create, user_sig_or_cert)
          .install();
        make_endpoint(
          "SmallBank_create_batch", verb, create_batch, user_sig_or_cert)
          .install();
        make_endpoint("SmallBank_balance", verb, balance, user_sig_or_cert)
          .install();
        make_endpoint(
          "SmallBank_transact_savings",
          verb,
          transact_savings,
          user_sig_or_cert)
          .install();
        make_endpoint(
          "SmallBank_deposit_checking",
          verb,
          deposit_checking,
          user_sig_or_cert)
          .install();
        make_endpoint(
          "SmallBank_amalgamate", verb, amalgamate, user_sig_or_cert)
          .install();
        make_endpoint(
          "SmallBank_write_check", verb, writeCheck, user_sig_or_cert)
          .install();
      }

      metrics_tracker.install_endpoint(*this);
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics_tracker.tick(elapsed, stats);

      ccf::UserEndpointRegistry::tick(elapsed, stats);
    }
  };

  class SmallBank : public ccf::UserRpcFrontend
  {
  private:
    SmallBankHandlers sb_handlers;

  public:
    SmallBank(kv::Store& store, ccfapp::AbstractNodeContext& node_context) :
      UserRpcFrontend(store, sb_handlers),
      sb_handlers(node_context.get_node_state())
    {}
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, ccfapp::AbstractNodeContext& node_context)
  {
    return make_shared<SmallBank>(*nwt.tables, node_context);
  }
}
