// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../smallbank_serializer.h"
#include "enclave/app_interface.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"
#include "tpcc_tables.h"
#include "setup_tpcc.h"

#include <charconv>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  struct TpccTables
  {
    kv::Map<std::string, uint64_t> accounts;
    kv::Map<uint64_t, int64_t> savings;
    kv::Map<uint64_t, int64_t> checkings;

    TpccTables() : accounts("a"), savings("b"), checkings("c") {}
  };

  class TpccHandlers : public UserEndpointRegistry
  {
  private:
    TpccTables tables;
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
      UserEndpointRegistry(node_state),
      tables()
    {}

    void init_handlers() override
    {
      UserEndpointRegistry::init_handlers();

      auto create = [this](auto& args) {
        tpcc::SetupDb setup_db(args, 10, 1000);
        setup_db.run();

        set_no_content_status(args);
      };

      const ccf::endpoints::AuthnPolicies user_sig_or_cert = {
        user_signature_auth_policy, user_cert_auth_policy};

      std::vector<ccf::RESTVerb> verbs = {HTTP_POST, ws::Verb::WEBSOCKET};
      for (auto verb : verbs)
      {
        make_endpoint("tpcc_create", verb, create, user_sig_or_cert)
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

kv::Map<int32_t, tpcc::Stock> tpcc::TpccTables::stocks("stocks");