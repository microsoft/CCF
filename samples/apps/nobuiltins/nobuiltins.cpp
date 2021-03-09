// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/json.h"
#include "enclave/app_interface.h"

namespace nobuiltins
{
  struct NodeSummary
  {
    ccf::QuoteFormat quote_format;
    std::string quote;
    std::string endorsements;

    kv::Consensus::View committed_view;
    kv::Consensus::SeqNo committed_seqno;
  };

  DECLARE_JSON_TYPE(NodeSummary)
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeSummary, quote_format, quote, committed_view, committed_seqno)

  // SNIPPET: registry_inheritance
  class NoBuiltinsRegistry : public ccf::BaseEndpointRegistry
  {
  public:
    NoBuiltinsRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::BaseEndpointRegistry("app", context)
    {
      auto node_summary = [this](ccf::EndpointContext& ctx) {
        ccf::ApiResult result;

        NodeSummary summary;

        {
          // SNIPPET_START: get_quote_api_v1
          ccf::QuoteInfo quote_info;
          result = get_quote_for_this_node_v1(ctx.tx, quote_info);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get quote: {}", ccf::api_result_to_str(result)));
            return;
          }

          summary.quote_format = quote_info.format;
          summary.quote =
            fmt::format("{:02x}", fmt::join(quote_info.quote, ""));
          summary.endorsements =
            fmt::format("{:02x}", fmt::join(quote_info.endorsements, ""));
          // SNIPPET_END: get_quote_api_v1
        }

        {
          result = get_last_committed_txid_v1(
            summary.committed_view, summary.committed_seqno);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get committed transaction: {}",
                ccf::api_result_to_str(result)));
            return;
          }
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(nlohmann::json(summary).dump(2));
      };
      make_endpoint(
        "node_summary", HTTP_GET, node_summary, ccf::no_auth_required)
        .set_auto_schema<void, NodeSummary>()
        .install();

      auto openapi = [this](kv::Tx& tx, nlohmann::json&&) {
        nlohmann::json document;
        const auto result = generate_openapi_document_v1(
          tx,
          openapi_info.title,
          "A CCF sample demonstrating a minimal app, with no default endpoints",
          "0.0.1",
          document);

        if (result == ccf::ApiResult::OK)
        {
          return ccf::make_success(document);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to generate OpenAPI: {}",
              ccf::api_result_to_str(result)));
        }
      };
      make_endpoint(
        "api", HTTP_GET, ccf::json_adapter(openapi), ccf::no_auth_required)
        .set_auto_schema<void, ccf::GetAPI::Out>()
        .install();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        ccf::GetCommit::Out out;
        const auto result = get_last_committed_txid_v1(out.view, out.seqno);

        if (result == ccf::ApiResult::OK)
        {
          return ccf::make_success(out);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get committed transaction: {}",
              ccf::api_result_to_str(result)));
        }
      };
      make_command_endpoint(
        "commit",
        HTTP_GET,
        ccf::json_command_adapter(get_commit),
        ccf::no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, ccf::GetCommit::Out>()
        .install();
    }
  };

  class NoBuiltinsFrontend : public ccf::RpcFrontend
  {
  private:
    NoBuiltinsRegistry nbr;

  public:
    NoBuiltinsFrontend(
      ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::RpcFrontend(*network.tables, nbr),
      nbr(context)
    {}
  };
}

namespace ccfapp
{
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return std::make_shared<nobuiltins::NoBuiltinsFrontend>(nwt, context);
  }
}
