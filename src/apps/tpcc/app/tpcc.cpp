// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../tpcc_serializer.h"
#include "enclave/app_interface.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"
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
    TpccHandlers(ccf::AbstractNodeState& node_state) :
      UserEndpointRegistry(node_state)
    {}

    void init_handlers() override
    {
      UserEndpointRegistry::init_handlers();

      auto create = [this](auto& args) {
        LOG_DEBUG_FMT("Creating tpcc database");
        const auto& body = args.rpc_ctx->get_request_body();
        auto db = tpcc::DbCreation::deserialize(body.data(), body.size());
        tpcc::SetupDb setup_db(args, db.new_orders_per_district, db.seed);
        setup_db.run();
        LOG_DEBUG_FMT("Creating tpcc database - end");

        set_no_content_status(args);
      };

      auto do_stock_level = [this](auto& args) {
        LOG_DEBUG_FMT("stock level");
        const auto& body = args.rpc_ctx->get_request_body();
        auto info = tpcc::StockLevel::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(args, info.seed);
        tx.stock_level(info.warehouse_id, info.district_id, info.threshold);
        LOG_DEBUG_FMT("stock level - end");

        set_no_content_status(args);
      };

      auto do_order_status = [this](auto& args) {
        LOG_DEBUG_FMT("order status");
        const auto& body = args.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(args, info.seed);
        tx.order_status();
        LOG_DEBUG_FMT("order status - end");

        set_no_content_status(args);
      };

      auto do_delivery = [this](auto& args) {
        LOG_DEBUG_FMT("delivery");
        const auto& body = args.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(args, info.seed);
        tx.delivery();
        LOG_DEBUG_FMT("delivery - end");

        set_no_content_status(args);
      };

      auto do_payment = [this](auto& args) {
        LOG_DEBUG_FMT("payment");
        const auto& body = args.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(args, info.seed);
        tx.payment();
        LOG_DEBUG_FMT("payment - end");

        set_no_content_status(args);
      };

      auto do_new_order = [this](auto& args) {
        LOG_DEBUG_FMT("new order");
        const auto& body = args.rpc_ctx->get_request_body();
        auto info = tpcc::TxInfo::deserialize(body.data(), body.size());
        tpcc::TpccTransactions tx(args, info.seed);
        tx.new_order();
        LOG_DEBUG_FMT("new order - end");

        set_no_content_status(args);
      };

      const ccf::endpoints::AuthnPolicies user_sig_or_cert = {
        user_signature_auth_policy, user_cert_auth_policy};

      std::vector<ccf::RESTVerb> verbs = {HTTP_POST, ws::Verb::WEBSOCKET};
      for (auto verb : verbs)
      {
        make_endpoint("tpcc_create", verb, create, user_sig_or_cert).install();
        make_endpoint("stock_level", verb, do_stock_level, user_sig_or_cert)
          .install();
        make_endpoint("order_status", verb, do_order_status, user_sig_or_cert)
          .install();
        make_endpoint("delivery", verb, do_delivery, user_sig_or_cert)
          .install();
        make_endpoint("payment", verb, do_payment, user_sig_or_cert).install();
        make_endpoint("new_order", verb, do_new_order, user_sig_or_cert)
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

  class Tpcc : public ccf::UserRpcFrontend
  {
  private:
    TpccHandlers tpcc_handlers;

  public:
    Tpcc(kv::Store& store, ccfapp::AbstractNodeContext& node_context) :
      UserRpcFrontend(store, tpcc_handlers),
      tpcc_handlers(node_context.get_node_state())
    {}
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, ccfapp::AbstractNodeContext& node_context)
  {
    return make_shared<Tpcc>(*nwt.tables, node_context);
  }
}

kv::Map<tpcc::Stock::Key, tpcc::Stock> tpcc::TpccTables::stocks("stocks");
kv::Map<tpcc::Warehouse::Key, tpcc::Warehouse> tpcc::TpccTables::warehouses(
  "warehouses");
kv::Map<tpcc::District::Key, tpcc::District> tpcc::TpccTables::districts(
  "districts");
kv::Map<tpcc::History::Key, tpcc::History> tpcc::TpccTables::histories(
  "histories");
std::unordered_map<uint64_t, kv::Map<tpcc::Customer::Key, tpcc::Customer>>
  tpcc::TpccTables::customers;
std::unordered_map<uint64_t, kv::Map<tpcc::Order::Key, tpcc::Order>>
  tpcc::TpccTables::orders;
kv::Map<tpcc::OrderLine::Key, tpcc::OrderLine> tpcc::TpccTables::order_lines(
  "order_lines");
std::unordered_map<uint64_t, kv::Map<tpcc::NewOrder::Key, tpcc::NewOrder>>
  tpcc::TpccTables::new_orders;
kv::Map<tpcc::Item::Key, tpcc::Item> tpcc::TpccTables::items("items");