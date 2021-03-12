// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../tpcc_serializer.h"
#include "enclave/app_interface.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"
#include "tpcc_tables.h"
#include "setup_tpcc.h"
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
        LOG_INFO_FMT("Creating tpcc database");
        std::array<char, tpcc::DATETIME_SIZE + 1> now = {"12345 time"};
        tpcc::SetupDb setup_db(args, 10, 1000, 10, 10, 10, now);
        setup_db.run();

        set_no_content_status(args);
      };

      auto do_stock_level = [this](auto& args) {
        LOG_INFO_FMT("stock level");
        tpcc::TpccTransactions tx(args, 10, 10, 10);
        tx.stock_level(1,1,100);
        
        set_no_content_status(args);
      };

      auto do_order_status = [this](auto& args) {
        LOG_INFO_FMT("order status");
        tpcc::TpccTransactions tx(args, 10, 10, 10);
        tx.order_status();
        
        set_no_content_status(args);
      };

      auto do_delivery = [this](auto& args) {
        LOG_INFO_FMT("delivery");
        tpcc::TpccTransactions tx(args, 10, 10, 10);
        tx.delivery();
        
        set_no_content_status(args);
      };

      auto do_payment = [this](auto& args) {
        LOG_INFO_FMT("payment");
        tpcc::TpccTransactions tx(args, 10, 10, 10);
        tx.payment();
        
        set_no_content_status(args);
      };

      const ccf::endpoints::AuthnPolicies user_sig_or_cert = {
        user_signature_auth_policy, user_cert_auth_policy};

      std::vector<ccf::RESTVerb> verbs = {HTTP_POST, ws::Verb::WEBSOCKET};
      for (auto verb : verbs)
      {
        make_endpoint("tpcc_create", verb, create, user_sig_or_cert)
          .install();
        make_endpoint("stock_level", verb, do_stock_level, user_sig_or_cert)
          .install();
        make_endpoint("order_status", verb, do_order_status, user_sig_or_cert)
          .install();
        make_endpoint("delivery", verb, do_delivery, user_sig_or_cert)
          .install();
        make_endpoint("payment", verb, do_payment, user_sig_or_cert)
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
kv::Map<tpcc::Warehouse::Key, tpcc::Warehouse> tpcc::TpccTables::warehouses("warehouses");
kv::Map<tpcc::District::Key, tpcc::District> tpcc::TpccTables::districts("districts");
kv::Map<tpcc::History::Key, tpcc::History> tpcc::TpccTables::histories("histories");
kv::Map<tpcc::Customer::Key, tpcc::Customer> tpcc::TpccTables::customers("customers");
kv::Map<tpcc::Order::Key, tpcc::Order> tpcc::TpccTables::orders("orders");
kv::Map<tpcc::OrderLine::Key, tpcc::OrderLine> tpcc::TpccTables::order_lines("order_lines");
kv::Map<tpcc::NewOrder::Key, tpcc::NewOrder> tpcc::TpccTables::new_orders("new_orders");