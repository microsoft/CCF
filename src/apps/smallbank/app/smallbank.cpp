// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "apps/smallbank/smallbank_serializer.h"
#include "apps/utils/metrics_tracker.h"
#include "ccf/app_interface.h"
#include "ccf/user_frontend.h"

#include <charconv>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  struct SmallBankTables
  {
    kv::RawCopySerialisedMap<std::string, uint64_t> accounts;
    kv::RawCopySerialisedMap<uint64_t, int64_t> savings;
    kv::RawCopySerialisedMap<uint64_t, int64_t> checkings;

    SmallBankTables() : accounts("a"), savings("b"), checkings("c") {}
  };

  class SmallBankHandlers : public UserEndpointRegistry
  {
  private:
    SmallBankTables tables;
    metrics::Tracker metrics_tracker;

    void set_error_status(
      ccf::endpoints::EndpointContext& ctx, int status, std::string&& message)
    {
      ctx.rpc_ctx->set_response_status(status);
      ctx.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
      ctx.rpc_ctx->set_response_body(std::move(message));
    }

    void set_ok_status(ccf::endpoints::EndpointContext& ctx)
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      ctx.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE,
        http::headervalues::contenttype::OCTET_STREAM);
    }

    void set_no_content_status(ccf::endpoints::EndpointContext& ctx)
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
    }

  public:
    SmallBankHandlers(AbstractNodeContext& context) :
      UserEndpointRegistry(context),
      tables()
    {}

    void init_handlers() override
    {
      UserEndpointRegistry::init_handlers();

      auto create = [this](auto& ctx) {
        // Create an account with a balance from thin air.
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto ai = smallbank::AccountInfo::deserialize(body.data(), body.size());
        auto name = ai.name;
        uint64_t acc_id;
        std::from_chars(name.data(), name.data() + name.size(), acc_id);
        int64_t checking_amt = ai.checking_amt;
        int64_t savings_amt = ai.savings_amt;
        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_r = accounts->get(name);

        if (account_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        accounts->put(name, acc_id);

        auto savings = ctx.tx.rw(tables.savings);
        auto savings_r = savings->get(acc_id);

        if (savings_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        savings->put(acc_id, savings_amt);

        auto checkings = ctx.tx.rw(tables.checkings);
        auto checking_r = checkings->get(acc_id);

        if (checking_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account already exists");
          return;
        }

        checkings->put(acc_id, checking_amt);

        set_no_content_status(ctx);
      };

      auto create_batch = [this](auto& ctx) {
        // Create N accounts with identical balances from thin air.
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto ac =
          smallbank::AccountCreation::deserialize(body.data(), body.size());

        auto accounts = ctx.tx.rw(tables.accounts);
        auto savings = ctx.tx.rw(tables.savings);
        auto checkings = ctx.tx.rw(tables.checkings);

        for (auto acc_id = ac.new_id_from; acc_id < ac.new_id_to; ++acc_id)
        {
          std::string name = std::to_string(acc_id);

          auto account_r = accounts->get(name);
          if (account_r.has_value())
          {
            set_error_status(
              ctx,
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
              ctx,
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
              ctx,
              HTTP_STATUS_BAD_REQUEST,
              fmt::format(
                "Account already exists in checkings table: '{}'", name));
            return;
          }
          checkings->put(acc_id, ac.initial_checking_amt);
        }

        set_no_content_status(ctx);
      };

      auto balance = [this](auto& ctx) {
        // Check the combined balance of an account
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto account =
          smallbank::AccountName::deserialize(body.data(), body.size());
        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_r = accounts->get(account.name);

        if (!account_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto savings = ctx.tx.rw(tables.savings);
        auto savings_r = savings->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        auto checkings = ctx.tx.rw(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }

        auto result = checking_r.value() + savings_r.value();

        set_ok_status(ctx);

        smallbank::Balance b;
        b.value = result;
        ctx.rpc_ctx->set_response_body(b.serialize());
      };

      auto transact_savings = [this](auto& ctx) {
        // Add or remove money to the savings account
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto value = transaction.value;

        if (name.empty())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "A name must be specified");
          return;
        }

        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
        }

        auto savings = ctx.tx.rw(tables.savings);
        auto savings_r = savings->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        if (savings_r.value() + value < 0)
        {
          set_error_status(
            ctx,
            HTTP_STATUS_BAD_REQUEST,
            "Not enough money in savings account");
          return;
        }

        savings->put(account_r.value(), value + savings_r.value());
        set_no_content_status(ctx);
      };

      auto deposit_checking = [this](auto& ctx) {
        // Desposit money into the checking account out of thin air
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto value = transaction.value;

        if (name.empty())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "A name must be specified");
          return;
        }

        if (value <= 0)
        {
          set_error_status(ctx, HTTP_STATUS_BAD_REQUEST, "Value <= 0");
          return;
        }

        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto checkings = ctx.tx.rw(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }
        checkings->put(account_r.value(), value + checking_r.value());
        set_no_content_status(ctx);
      };

      auto amalgamate = [this](auto& ctx) {
        // Move the contents of one users account to another users account
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto ad = smallbank::Amalgamate::deserialize(body.data(), body.size());
        auto name_1 = ad.src;
        auto name_2 = ad.dst;
        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_1_r = accounts->get(name_1);

        if (!account_1_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Source account does not exist");
          return;
        }

        auto account_2_r = accounts->get(name_2);

        if (!account_2_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Destination account does not exist");
          return;
        }

        auto savings = ctx.tx.rw(tables.savings);
        auto savings_r = savings->get(account_1_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            ctx,
            HTTP_STATUS_BAD_REQUEST,
            "Source savings account does not exist");
          return;
        }

        auto checkings = ctx.tx.rw(tables.checkings);
        auto checking_r = checkings->get(account_1_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            ctx,
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
            ctx,
            HTTP_STATUS_BAD_REQUEST,
            "Destination checking account does not exist");
          return;
        }

        checkings->put(
          account_2_r.value(), checking_2_r.value() + sum_account_1);

        set_no_content_status(ctx);
      };

      auto writeCheck = [this](auto& ctx) {
        // Write a check, if not enough funds then also charge an extra 1 money
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto transaction =
          smallbank::Transaction::deserialize(body.data(), body.size());
        auto name = transaction.name;
        auto amount = transaction.value;

        auto accounts = ctx.tx.rw(tables.accounts);
        auto account_r = accounts->get(name);

        if (!account_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Account does not exist");
          return;
        }

        auto savings = ctx.tx.rw(tables.savings);
        auto savings_r = savings->get(account_r.value());

        if (!savings_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Savings account does not exist");
          return;
        }

        auto checkings = ctx.tx.rw(tables.checkings);
        auto checking_r = checkings->get(account_r.value());

        if (!checking_r.has_value())
        {
          set_error_status(
            ctx, HTTP_STATUS_BAD_REQUEST, "Checking account does not exist");
          return;
        }

        auto account_value = checking_r.value() + savings_r.value();
        if (account_value < amount)
        {
          ++amount;
        }
        checkings->put(account_r.value(), account_value - amount);
        set_no_content_status(ctx);
      };

      const ccf::AuthnPolicies user_sig_or_cert = {user_signature_auth_policy,
                                                   user_cert_auth_policy};


      make_endpoint("SmallBank_create", HTTP_POST, create, user_sig_or_cert)
        .install();
      make_endpoint(
        "SmallBank_create_batch", HTTP_POST, create_batch, user_sig_or_cert)
        .install();
      make_endpoint("SmallBank_balance", HTTP_POST, balance, user_sig_or_cert)
        .install();
      make_endpoint(
        "SmallBank_transact_savings",
        HTTP_POST,
        transact_savings,
        user_sig_or_cert)
        .install();
      make_endpoint(
        "SmallBank_deposit_checking",
        HTTP_POST,
        deposit_checking,
        user_sig_or_cert)
        .install();
      make_endpoint(
        "SmallBank_amalgamate", HTTP_POST, amalgamate, user_sig_or_cert)
        .install();
      make_endpoint(
        "SmallBank_write_check", HTTP_POST, writeCheck, user_sig_or_cert)
        .install();

      metrics_tracker.install_endpoint(*this);
    }

    void tick(std::chrono::milliseconds elapsed, size_t tx_count) override
    {
      metrics_tracker.tick(elapsed, tx_count);

      ccf::UserEndpointRegistry::tick(elapsed, tx_count);
    }
  };

  class SmallBank : public ccf::RpcFrontend
  {
  private:
    SmallBankHandlers sb_handlers;

  public:
    SmallBank(kv::Store& store, AbstractNodeContext& context) :
      RpcFrontend(store, sb_handlers),
      sb_handlers(context)
    {}
  };

  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    NetworkTables& nwt, AbstractNodeContext& context)
  {
    return make_shared<SmallBank>(*nwt.tables, context);
  }
}
