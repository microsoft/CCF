// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../tpcc_serializer.h"
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/logger.h"
#include "tpcc_setup.h"
#include "tpcc_tables.h"
#include "tpcc_transactions.h"

#include <charconv>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccf
{
  class TpccHandlers : public UserEndpointRegistry
  {
  private:
    void set_error_status(
      ccf::endpoints::EndpointContext& ctx, int status, std::string&& message)
    {
      ctx.rpc_ctx->set_response_status(status);
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        http::headervalues::contenttype::TEXT);
      ctx.rpc_ctx->set_response_body(std::move(message));
    }

    void set_ok_status(ccf::endpoints::EndpointContext& ctx)
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_TYPE,
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
        CCF_APP_DEBUG("Creating tpcc database");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto db = tpcc::DbCreation::deserialize(body.data(), body.size());
        tpcc::SetupDb setup_db(ctx, db.new_orders_per_district, db.seed);
        setup_db.run();
        CCF_APP_DEBUG("Creating tpcc database - end");

        set_no_content_status(ctx);
      };

      auto do_stock_level = [this](auto& ctx) {
        CCF_APP_DEBUG("stock level");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::StockLevel::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.stock_level(info.warehouse_id, info.district_id, info.threshold);
        CCF_APP_DEBUG("stock level - end");

        set_no_content_status(ctx);
      };

      auto do_order_status = [this](auto& ctx) {
        CCF_APP_DEBUG("order status");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.order_status();
        CCF_APP_DEBUG("order status - end");

        set_no_content_status(ctx);
      };

      auto do_delivery = [this](auto& ctx) {
        CCF_APP_DEBUG("delivery");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.delivery();
        CCF_APP_DEBUG("delivery - end");

        set_no_content_status(ctx);
      };

      auto do_payment = [this](auto& ctx) {
        CCF_APP_DEBUG("payment");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.payment();
        CCF_APP_DEBUG("payment - end");

        set_no_content_status(ctx);
      };

      auto do_new_order = [this](auto& ctx) {
        CCF_APP_DEBUG("new order");
        const auto& body = ctx.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(ctx, info.seed);
        tx.new_order();
        CCF_APP_DEBUG("new order - end");

        set_no_content_status(ctx);
      };

      make_endpoint("/tpcc_create", HTTP_POST, create, {user_cert_auth_policy})
        .install();
      make_endpoint(
        "/stock_level", HTTP_POST, do_stock_level, {user_cert_auth_policy})
        .install();
      make_endpoint(
        "/order_status", HTTP_POST, do_order_status, {user_cert_auth_policy})
        .install();
      make_endpoint(
        "/delivery", HTTP_POST, do_delivery, {user_cert_auth_policy})
        .install();
      make_endpoint("/payment", HTTP_POST, do_payment, {user_cert_auth_policy})
        .install();
      make_endpoint(
        "/new_order", HTTP_POST, do_new_order, {user_cert_auth_policy})
        .install();
    }
  };

  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<TpccHandlers>(context);
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