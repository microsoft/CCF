// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../tpcc_serializer.h"
#include "apps/utils/metrics_tracker.h"
#include "ccf/app_interface.h"
#include "ccf/user_frontend.h"
#include "tpcc_setup.h"
#include "tpcc_tables.h"
#include "tpcc_transactions.h"

#include <charconv>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  class TpccHandlers : public UserEndpointRegistry
  {
  private:
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
    TpccHandlers(AbstractNodeContext& context) : UserEndpointRegistry(context)
    {}

    void init_handlers() override
    {
      UserEndpointRegistry::init_handlers();

      auto create = [this](auto& ctx) {
        LOG_DEBUG_FMT("Creating tpcc database");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto db = tpcc::DbCreation::deserialize(body.data(), body.size());
        tpcc::SetupDb setup_db(ctx, db.new_orders_per_district, db.seed);
        setup_db.run();
        LOG_DEBUG_FMT("Creating tpcc database - end");

        set_no_content_status(ctx);
      };

      auto do_stock_level = [this](auto& ctx) {
        LOG_DEBUG_FMT("stock level");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::StockLevel::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.stock_level(info.warehouse_id, info.district_id, info.threshold);
        LOG_DEBUG_FMT("stock level - end");

        set_no_content_status(ctx);
      };

      auto do_order_status = [this](auto& ctx) {
        LOG_DEBUG_FMT("order status");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.order_status();
        LOG_DEBUG_FMT("order status - end");

        set_no_content_status(ctx);
      };

      auto do_delivery = [this](auto& ctx) {
        LOG_DEBUG_FMT("delivery");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.delivery();
        LOG_DEBUG_FMT("delivery - end");

        set_no_content_status(ctx);
      };

      auto do_payment = [this](auto& ctx) {
        LOG_DEBUG_FMT("payment");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.payment();
        LOG_DEBUG_FMT("payment - end");

        set_no_content_status(ctx);
      };

      auto do_new_order = [this](auto& ctx) {
        LOG_DEBUG_FMT("new order");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.new_order();
        LOG_DEBUG_FMT("new order - end");

        set_no_content_status(ctx);
      };

      const ccf::AuthnPolicies user_sig_or_cert = {user_signature_auth_policy,
                                                   user_cert_auth_policy};

      make_endpoint("/tpcc_create", HTTP_POST, create, user_sig_or_cert)
        .install();
      make_endpoint("/stock_level", HTTP_POST, do_stock_level, user_sig_or_cert)
        .install();
      make_endpoint(
        "/order_status", HTTP_POST, do_order_status, user_sig_or_cert)
        .install();
      make_endpoint("/delivery", HTTP_POST, do_delivery, user_sig_or_cert)
        .install();
      make_endpoint("/payment", HTTP_POST, do_payment, user_sig_or_cert)
        .install();
      make_endpoint("/new_order", HTTP_POST, do_new_order, user_sig_or_cert)
        .install();

      metrics_tracker.install_endpoint(*this);
    }

    void tick(std::chrono::milliseconds elapsed, size_t tx_count) override
    {
      metrics_tracker.tick(elapsed, tx_count);

      ccf::UserEndpointRegistry::tick(elapsed, tx_count);
    }
  };

  class Tpcc : public ccf::RpcFrontend
  {
  private:
    TpccHandlers tpcc_handlers;

  public:
    Tpcc(kv::Store& store, AbstractNodeContext& context) :
      RpcFrontend(store, tpcc_handlers),
      tpcc_handlers(context)
    {}
  };

  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    NetworkTables& nwt, AbstractNodeContext& context)
  {
    return make_shared<Tpcc>(*nwt.tables, context);
  }
}

tpcc::TpccMap<tpcc::Stock::Key, tpcc::Stock> tpcc::TpccTables::stocks("stocks");
tpcc::TpccMap<tpcc::Warehouse::Key, tpcc::Warehouse> tpcc::TpccTables::
  warehouses("warehouses");
tpcc::TpccMap<tpcc::District::Key, tpcc::District> tpcc::TpccTables::districts(
  "districts");
tpcc::TpccMap<tpcc::History::Key, tpcc::History> tpcc::TpccTables::histories(
  "histories");
std::unordered_map<uint64_t, tpcc::TpccMap<tpcc::Customer::Key, tpcc::Customer>>
  tpcc::TpccTables::customers;
std::unordered_map<uint64_t, tpcc::TpccMap<tpcc::Order::Key, tpcc::Order>>
  tpcc::TpccTables::orders;
tpcc::TpccMap<tpcc::OrderLine::Key, tpcc::OrderLine> tpcc::TpccTables::
  order_lines("order_lines");
std::unordered_map<uint64_t, tpcc::TpccMap<tpcc::NewOrder::Key, tpcc::NewOrder>>
  tpcc::TpccTables::new_orders;
tpcc::TpccMap<tpcc::Item::Key, tpcc::Item> tpcc::TpccTables::items("items");